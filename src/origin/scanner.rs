use crate::origin::cloudflare::partition_ips;
use crate::origin::confidence::calculate_confidence;
use crate::origin::dns::{create_resolver, resolve_ips};
use crate::origin::enumerator::{enumerate_candidate_ips, load_wordlist_file, EnumeratorOptions};
use crate::origin::error::{HunterError, Result};
use crate::origin::models::{
    CandidateIp, ConfidenceLevel, HunterFinding, ProbeResult, ScanReport, ScanSummary,
};
use crate::origin::prober::{create_probe_client, fetch_target_baseline, probe_candidate_ip};
use crate::origin::remediation::generate_remediation_plan;
use chrono::Utc;
use futures::stream::{self, StreamExt};
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub concurrency: usize,
    pub timeout_secs: u64,
    pub probe_ports: Vec<u16>,
    pub enable_crtsh: bool,
    pub enable_subdomains: bool,
    pub enable_dns: bool,
    pub wordlist_path: Option<PathBuf>,
    pub min_confidence: ConfidenceLevel,
    pub verbose: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            concurrency: 10,
            timeout_secs: 5,
            probe_ports: vec![80, 443, 8080, 8443],
            enable_crtsh: true,
            enable_subdomains: true,
            enable_dns: true,
            wordlist_path: None,
            min_confidence: ConfidenceLevel::Low,
            verbose: false,
        }
    }
}

/// Executes a full live audit against the specified target domain
pub async fn run_scan(target_domain: &str, options: &ScanOptions) -> Result<ScanReport> {
    let start_time = Instant::now();
    let scanned_at = Utc::now();
    let root = target_domain.trim().to_lowercase();

    if root.is_empty() {
        return Err(HunterError::InvalidTarget("Target domain cannot be empty".into()));
    }

    let resolver = create_resolver()?;
    let http_client = create_probe_client(options.timeout_secs)?;

    // 1. Establish Domain Baseline
    let resolved_ips = resolve_ips(&resolver, &root).await.unwrap_or_default();
    let (cf_edge_ips, direct_ips) = partition_ips(&resolved_ips);
    let is_behind_cf = !cf_edge_ips.is_empty();

    let baseline = fetch_target_baseline(
        &http_client,
        &root,
        &resolved_ips,
        is_behind_cf,
        &cf_edge_ips,
        &direct_ips,
    )
    .await;

    // 2. Candidate Origin IP Discovery
    let custom_wordlist = if let Some(ref path) = options.wordlist_path {
        Some(load_wordlist_file(path)?)
    } else {
        None
    };

    let enum_opts = EnumeratorOptions {
        concurrency: options.concurrency,
        enable_crtsh: options.enable_crtsh,
        enable_subdomains: options.enable_subdomains,
        enable_dns: options.enable_dns,
        custom_wordlist,
        timeout_secs: options.timeout_secs,
    };

    let candidates = enumerate_candidate_ips(&root, &resolver, &http_client, &enum_opts).await?;

    // 3. Direct HTTP/HTTPS Origin Probing
    let probe_tasks = {
        let mut tasks = Vec::new();
        for candidate in &candidates {
            for &port in &options.probe_ports {
                tasks.push((candidate.clone(), port));
            }
        }
        tasks
    };

    let mut probe_results_map: std::collections::HashMap<IpAddr, (CandidateIp, Vec<ProbeResult>)> =
        std::collections::HashMap::new();

    {
        let concurrency = options.concurrency.max(1);
        let target_for_probe = root.clone();
        let baseline_for_probe = baseline.clone();
        let client_for_probe = http_client.clone();

        let probe_stream = stream::iter(probe_tasks).map(move |(cand, port)| {
            let client = client_for_probe.clone();
            let target = target_for_probe.clone();
            let base = baseline_for_probe.clone();
            async move {
                let res = probe_candidate_ip(&client, cand.ip, port, &target, &base).await;
                (cand, res)
            }
        });

        let mut buffered_probes = probe_stream.buffer_unordered(concurrency);
        while let Some((cand, probe_res)) = buffered_probes.next().await {
            probe_results_map
                .entry(cand.ip)
                .or_insert_with(|| (cand.clone(), Vec::new()))
                .1
                .push(probe_res);
        }
    }

    // 4. Verification & Confidence Scoring
    let mut findings = Vec::new();
    for (ip, (cand, probes)) in probe_results_map {
        let mut successful = Vec::new();
        let mut failed = Vec::new();

        for probe in probes {
            if probe.success {
                successful.push(probe);
            } else {
                failed.push(probe);
            }
        }

        let (confidence_lvl, score, reason) =
            calculate_confidence(&baseline, &cand.source, &successful, &failed);

        if confidence_lvl >= options.min_confidence {
            let finding = HunterFinding {
                candidate_ip: ip,
                hostname: cand.hostname,
                discovery_source: cand.source,
                confidence: confidence_lvl,
                confidence_score: score,
                confidence_reason: reason,
                successful_probes: successful,
                failed_probes: failed,
                is_origin_confirmed: confidence_lvl == ConfidenceLevel::Confirmed,
            };
            findings.push(finding);
        }
    }

    findings.sort_by(|a, b| {
        b.confidence_score
            .cmp(&a.confidence_score)
            .then_with(|| a.candidate_ip.cmp(&b.candidate_ip))
    });

    let duration_seconds = start_time.elapsed().as_secs_f64();

    let origins_confirmed = findings
        .iter()
        .filter(|f| f.confidence == ConfidenceLevel::Confirmed)
        .count();
    let high_confidence = findings
        .iter()
        .filter(|f| f.confidence == ConfidenceLevel::High)
        .count();
    let medium_confidence = findings
        .iter()
        .filter(|f| f.confidence == ConfidenceLevel::Medium)
        .count();
    let low_confidence = findings
        .iter()
        .filter(|f| f.confidence == ConfidenceLevel::Low)
        .count();

    let is_origin_leaked = origins_confirmed > 0 || high_confidence > 0 || medium_confidence > 0;

    let summary = ScanSummary {
        target_domain: root,
        scanned_at,
        duration_seconds,
        is_behind_cloudflare: is_behind_cf,
        cloudflare_edge_ips: cf_edge_ips,
        candidates_discovered: candidates.len(),
        origins_confirmed,
        high_confidence_origins: high_confidence,
        medium_confidence_origins: medium_confidence,
        low_confidence_origins: low_confidence,
        is_origin_leaked,
    };

    let remediation = generate_remediation_plan();

    Ok(ScanReport {
        summary,
        baseline,
        findings,
        candidates,
        remediation,
    })
}
