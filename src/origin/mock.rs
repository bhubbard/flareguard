use crate::origin::confidence::calculate_confidence;
use crate::origin::models::{
    CandidateIp, ConfidenceLevel, DiscoverySource, HunterFinding, ProbeMatchDetails,
    ProbeResult, ScanReport, ScanSummary, TargetBaseline,
};
use crate::origin::remediation::generate_remediation_plan;
use chrono::Utc;
use std::collections::HashMap;
use std::net::IpAddr;

/// Generates a synthetic mock scan report for demonstration and offline testing
pub fn run_mock_scan(domain: &str) -> ScanReport {
    let target = if domain.trim().is_empty() {
        "example-corp.com"
    } else {
        domain.trim()
    };

    let cf_edge1: IpAddr = "104.21.55.10".parse().unwrap();
    let cf_edge2: IpAddr = "172.67.140.22".parse().unwrap();
    let baseline_hash = "d5a8b73f9e2c4a1b8e6f7d0c3a5e9b1f2e4d6c8a0b3e5f7a9c1d3e5f7a9c1d3e";
    let baseline_title = format!("{} | Secure Enterprise Gateway", target);

    let mut baseline_headers = HashMap::new();
    baseline_headers.insert("server".to_string(), "cloudflare".to_string());
    baseline_headers.insert("cf-ray".to_string(), "8df4567890abcdef-ORD".to_string());
    baseline_headers.insert("cf-cache-status".to_string(), "HIT".to_string());
    baseline_headers.insert("content-type".to_string(), "text/html; charset=UTF-8".to_string());

    let baseline = TargetBaseline {
        domain: target.to_string(),
        resolved_ips: vec![cf_edge1, cf_edge2],
        is_behind_cloudflare: true,
        cloudflare_ips: vec![cf_edge1, cf_edge2],
        non_cloudflare_ips: vec![],
        http_status: Some(200),
        html_title: Some(baseline_title.clone()),
        body_sha256: Some(baseline_hash.to_string()),
        body_length: 4520,
        server_header: Some("cloudflare".to_string()),
        headers: baseline_headers,
    };

    // 1. Confirmed Origin: direct/origin subdomain
    let origin_ip: IpAddr = "198.51.100.42".parse().unwrap();
    let candidate1 = CandidateIp {
        ip: origin_ip,
        source: DiscoverySource::Subdomain(format!("origin.{}", target)),
        hostname: Some(format!("origin.{}", target)),
        is_cloudflare: false,
        notes: vec![format!("Direct bypass subdomain origin.{} resolved to unmasked IP", target)],
    };

    let mut probe1_headers = HashMap::new();
    probe1_headers.insert("server".to_string(), "nginx/1.24.0 (Ubuntu)".to_string());
    probe1_headers.insert("x-powered-by".to_string(), "PHP/8.3".to_string());

    let probe1 = ProbeResult {
        ip: origin_ip,
        port: 443,
        protocol: "https".to_string(),
        url: format!("https://{}:443/", origin_ip),
        success: true,
        status_code: Some(200),
        html_title: Some(baseline_title.clone()),
        body_sha256: Some(baseline_hash.to_string()),
        body_length: 4520,
        server_header: Some("nginx/1.24.0 (Ubuntu)".to_string()),
        headers: probe1_headers,
        response_time_ms: 32,
        error: None,
        match_details: Some(ProbeMatchDetails {
            exact_body_hash_match: true,
            title_match: true,
            status_code_match: true,
            body_length_delta: 0,
            header_similarity_score: 0.95,
            cf_ray_present: false,
            direct_server_header: Some("nginx/1.24.0 (Ubuntu)".to_string()),
            baseline_server_header: Some("cloudflare".to_string()),
        }),
    };

    let (conf1_lvl, conf1_score, conf1_reason) = calculate_confidence(
        &baseline,
        &candidate1.source,
        &[probe1.clone()],
        &[],
    );

    let finding1 = HunterFinding {
        candidate_ip: origin_ip,
        hostname: candidate1.hostname.clone(),
        discovery_source: candidate1.source.clone(),
        confidence: conf1_lvl,
        confidence_score: conf1_score,
        confidence_reason: conf1_reason,
        successful_probes: vec![probe1],
        failed_probes: vec![],
        is_origin_confirmed: conf1_lvl == ConfidenceLevel::Confirmed,
    };

    // 2. High Confidence: Certificate Transparency Dev SAN
    let dev_ip: IpAddr = "198.51.100.44".parse().unwrap();
    let candidate2 = CandidateIp {
        ip: dev_ip,
        source: DiscoverySource::CertificateTransparency(format!("dev-backend.{}", target)),
        hostname: Some(format!("dev-backend.{}", target)),
        is_cloudflare: false,
        notes: vec![format!("Historical crt.sh SAN dev-backend.{} resolved to unmasked IP", target)],
    };

    let mut probe2_headers = HashMap::new();
    probe2_headers.insert("server".to_string(), "Apache/2.4.52 (Ubuntu)".to_string());

    let probe2 = ProbeResult {
        ip: dev_ip,
        port: 443,
        protocol: "https".to_string(),
        url: format!("https://{}:443/", dev_ip),
        success: true,
        status_code: Some(200),
        html_title: Some(baseline_title.clone()),
        body_sha256: Some("e7b1a2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1".to_string()),
        body_length: 4610,
        server_header: Some("Apache/2.4.52 (Ubuntu)".to_string()),
        headers: probe2_headers,
        response_time_ms: 48,
        error: None,
        match_details: Some(ProbeMatchDetails {
            exact_body_hash_match: false,
            title_match: true,
            status_code_match: true,
            body_length_delta: 90,
            header_similarity_score: 0.85,
            cf_ray_present: false,
            direct_server_header: Some("Apache/2.4.52 (Ubuntu)".to_string()),
            baseline_server_header: Some("cloudflare".to_string()),
        }),
    };

    let (conf2_lvl, conf2_score, conf2_reason) = calculate_confidence(
        &baseline,
        &candidate2.source,
        &[probe2.clone()],
        &[],
    );

    let finding2 = HunterFinding {
        candidate_ip: dev_ip,
        hostname: candidate2.hostname.clone(),
        discovery_source: candidate2.source.clone(),
        confidence: conf2_lvl,
        confidence_score: conf2_score,
        confidence_reason: conf2_reason,
        successful_probes: vec![probe2],
        failed_probes: vec![],
        is_origin_confirmed: conf2_lvl == ConfidenceLevel::Confirmed,
    };

    // 3. Medium Confidence: Mail Server (MX)
    let mail_ip: IpAddr = "198.51.100.43".parse().unwrap();
    let candidate3 = CandidateIp {
        ip: mail_ip,
        source: DiscoverySource::MxRecord(format!("mail.{}", target)),
        hostname: Some(format!("mail.{}", target)),
        is_cloudflare: false,
        notes: vec![format!("MX record points to mail.{} on non-Cloudflare IP", target)],
    };

    let probe3 = ProbeResult {
        ip: mail_ip,
        port: 80,
        protocol: "http".to_string(),
        url: format!("http://{}:80/", mail_ip),
        success: true,
        status_code: Some(301),
        html_title: Some("Webmail Login".to_string()),
        body_sha256: Some("f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6b7a8f9e0d1c2b3a4f5e6d7c8b9a0f1e2".to_string()),
        body_length: 512,
        server_header: Some("cPanel Web Services".to_string()),
        headers: HashMap::new(),
        response_time_ms: 60,
        error: None,
        match_details: Some(ProbeMatchDetails {
            exact_body_hash_match: false,
            title_match: false,
            status_code_match: false,
            body_length_delta: -4008,
            header_similarity_score: 0.3,
            cf_ray_present: false,
            direct_server_header: Some("cPanel Web Services".to_string()),
            baseline_server_header: Some("cloudflare".to_string()),
        }),
    };

    let (conf3_lvl, conf3_score, conf3_reason) = calculate_confidence(
        &baseline,
        &candidate3.source,
        &[probe3.clone()],
        &[],
    );

    let finding3 = HunterFinding {
        candidate_ip: mail_ip,
        hostname: candidate3.hostname.clone(),
        discovery_source: candidate3.source.clone(),
        confidence: conf3_lvl,
        confidence_score: conf3_score,
        confidence_reason: conf3_reason,
        successful_probes: vec![probe3],
        failed_probes: vec![],
        is_origin_confirmed: conf3_lvl == ConfidenceLevel::Confirmed,
    };

    // 4. Medium Confidence: SPF IP (Firewalled)
    let spf_ip: IpAddr = "203.0.113.10".parse().unwrap();
    let candidate4 = CandidateIp {
        ip: spf_ip,
        source: DiscoverySource::SpfRecord(format!("v=spf1 ip4:{} include:_spf.google.com ~all", spf_ip)),
        hostname: None,
        is_cloudflare: false,
        notes: vec!["Extracted from SPF policy declaration".into()],
    };

    let failed_probe = ProbeResult {
        ip: spf_ip,
        port: 443,
        protocol: "https".to_string(),
        url: format!("https://{}:443/", spf_ip),
        success: false,
        status_code: None,
        html_title: None,
        body_sha256: None,
        body_length: 0,
        server_header: None,
        headers: HashMap::new(),
        response_time_ms: 2000,
        error: Some("Connection timed out (no route to host / firewalled)".to_string()),
        match_details: None,
    };

    let (conf4_lvl, conf4_score, conf4_reason) = calculate_confidence(
        &baseline,
        &candidate4.source,
        &[],
        &[failed_probe.clone()],
    );

    let finding4 = HunterFinding {
        candidate_ip: spf_ip,
        hostname: candidate4.hostname.clone(),
        discovery_source: candidate4.source.clone(),
        confidence: conf4_lvl,
        confidence_score: conf4_score,
        confidence_reason: conf4_reason,
        successful_probes: vec![],
        failed_probes: vec![failed_probe],
        is_origin_confirmed: conf4_lvl == ConfidenceLevel::Confirmed,
    };

    let findings = vec![finding1, finding2, finding3, finding4];
    let candidates = vec![candidate1, candidate2, candidate3, candidate4];

    let summary = ScanSummary {
        target_domain: target.to_string(),
        scanned_at: Utc::now(),
        duration_seconds: 1.42,
        is_behind_cloudflare: true,
        cloudflare_edge_ips: vec![cf_edge1, cf_edge2],
        candidates_discovered: candidates.len(),
        origins_confirmed: findings.iter().filter(|f| f.confidence == ConfidenceLevel::Confirmed).count(),
        high_confidence_origins: findings.iter().filter(|f| f.confidence == ConfidenceLevel::High).count(),
        medium_confidence_origins: findings.iter().filter(|f| f.confidence == ConfidenceLevel::Medium).count(),
        low_confidence_origins: findings.iter().filter(|f| f.confidence == ConfidenceLevel::Low).count(),
        is_origin_leaked: true,
    };

    let remediation = generate_remediation_plan();

    ScanReport {
        summary,
        baseline,
        findings,
        candidates,
        remediation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_scan_generation() {
        let report = run_mock_scan("test-target.com");
        assert_eq!(report.summary.target_domain, "test-target.com");
        assert!(report.summary.is_behind_cloudflare);
        assert_eq!(report.findings.len(), 4);
        assert_eq!(report.summary.origins_confirmed, 1);
        assert_eq!(report.summary.high_confidence_origins, 1);
        assert_eq!(report.summary.medium_confidence_origins, 2);
        assert!(report.summary.is_origin_leaked);
    }
}
