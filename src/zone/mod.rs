pub mod cli;
pub mod client;
pub mod mock_data;
pub mod models;
pub mod reporters;
pub mod rules;
pub mod scoring;

use anyhow::{bail, Context, Result};
use cli::{AuditArgs, OutputFormat};
use client::{CloudflareClient, ZoneDataProvider};
use mock_data::{MockZoneProvider};
use models::AggregateAuditReport;
use rules::evaluate_zone;
use std::fs;

/// Core auditor execution engine
pub async fn run_audit(args: &AuditArgs) -> Result<AggregateAuditReport> {
    let provider: Box<dyn ZoneDataProvider> = if let Some(ref input_path) = args.input {
        Box::new(MockZoneProvider::from_file(input_path)?)
    } else if args.mock {
        Box::new(MockZoneProvider::new_builtin())
    } else if let Some(ref token) = args.token {
        Box::new(CloudflareClient::new(token, args.account_id.clone())?)
    } else {
        bail!(
            "Missing authentication. Please provide a Cloudflare API token via '--token <TOKEN>' \
             or 'CF_API_TOKEN' environment variable, or use '--mock' / '--input <FILE>' for offline auditing."
        );
    };

    let zone_filter = args.zone.as_deref();
    let zone_data_list = provider
        .fetch_all_zones(zone_filter)
        .await
        .context("Failed to fetch zone data")?;

    if zone_data_list.is_empty() {
        if let Some(filter) = zone_filter {
            bail!("No zones found matching filter '{}'", filter);
        } else {
            bail!("No zones found in the Cloudflare account");
        }
    }

    let mut zone_reports = Vec::with_capacity(zone_data_list.len());
    for data in &zone_data_list {
        zone_reports.push(evaluate_zone(data));
    }

    let aggregate = AggregateAuditReport::new(zone_reports, args.account_id.clone());
    Ok(aggregate)
}

/// Formats and outputs the aggregate audit report according to CLI arguments
pub fn output_report(report: &AggregateAuditReport, args: &AuditArgs) -> Result<String> {
    let output_str = match args.format {
        OutputFormat::Table => reporters::render_terminal(report, args.verbose),
        OutputFormat::Json => reporters::render_json(report)?,
        OutputFormat::Html => reporters::render_html(report),
        OutputFormat::Sarif => reporters::render_sarif(report)?,
    };

    if let Some(ref out_path) = args.output {
        fs::write(out_path, &output_str)
            .with_context(|| format!("Failed to write report to '{}'", out_path.display()))?;
    }

    Ok(output_str)
}

/// Evaluates CI compliance gates and returns true if passing, false if failed
pub fn evaluate_compliance_gates(report: &AggregateAuditReport, args: &AuditArgs) -> (bool, Vec<String>) {
    let mut passed = true;
    let mut failure_reasons = Vec::new();

    let fail_on_critical = args.fail_on_critical || args.check;
    let fail_on_high = args.fail_on_high || args.check;
    let min_score = if args.check && args.min_score.is_none() {
        Some(80)
    } else {
        args.min_score
    };

    if fail_on_critical && report.total_findings.critical > 0 {
        passed = false;
        failure_reasons.push(format!(
            "Failed CI Gate: Found {} CRITICAL severity security finding(s)",
            report.total_findings.critical
        ));
    }

    if fail_on_high && report.total_findings.high > 0 {
        passed = false;
        failure_reasons.push(format!(
            "Failed CI Gate: Found {} HIGH severity security finding(s)",
            report.total_findings.high
        ));
    }

    if let Some(min) = min_score {
        if report.average_score < (min as f64) {
            passed = false;
            failure_reasons.push(format!(
                "Failed CI Gate: Account security score {:.1} is below minimum threshold of {}",
                report.average_score, min
            ));
        }

        for z in &report.zone_reports {
            if z.score < min {
                passed = false;
                failure_reasons.push(format!(
                    "Failed CI Gate: Zone '{}' security score {} is below minimum threshold of {}",
                    z.zone_name, z.score, min
                ));
            }
        }
    }

    (passed, failure_reasons)
}
