use clap::Parser;
use flareguard::origin::cli::Cli;
use flareguard::origin::cloudflare::is_cloudflare_asn;
use flareguard::origin::confidence::calculate_confidence;
use flareguard::origin::crtsh::{CrtShEntry, extract_subdomains_from_crtsh};
use flareguard::origin::dns::extract_ips_from_spf;
use flareguard::origin::enumerator::load_wordlist_file;
use flareguard::origin::mock::run_mock_scan;
use flareguard::origin::models::{
    ConfidenceLevel, DiscoverySource, ProbeMatchDetails, ProbeResult, ScanReport, TargetBaseline,
};
use flareguard::origin::remediation::generate_remediation_plan;
use flareguard::origin::report::{OutputFormat, render_report};
use std::collections::HashMap;
use std::io::Write;
use tempfile::NamedTempFile;

#[test]
fn test_cli_argument_parsing() {
    let args = vec![
        "cf-origin-hunter",
        "example.com",
        "--mock",
        "--format",
        "json",
        "--check",
    ];
    let cli = Cli::try_parse_from(args).expect("CLI should parse successfully");
    assert_eq!(cli.target.as_deref(), Some("example.com"));
    assert!(cli.mock);
    assert!(cli.check);
    assert_eq!(cli.get_output_format(), OutputFormat::Json);
}

#[test]
fn test_cli_ports_parsing() {
    let args = vec![
        "cf-origin-hunter",
        "example.com",
        "--ports",
        "80,443,8443,9000",
    ];
    let cli = Cli::try_parse_from(args).expect("CLI should parse successfully");
    assert_eq!(cli.get_probe_ports(), vec![80, 443, 8443, 9000]);
}

#[test]
fn test_mock_scan_and_json_serialization() {
    let report = run_mock_scan("acme-corp.com");
    assert_eq!(report.summary.target_domain, "acme-corp.com");
    assert!(report.summary.is_behind_cloudflare);
    assert_eq!(report.summary.origins_confirmed, 1);

    let json_str =
        render_report(&report, OutputFormat::Json).expect("JSON rendering should succeed");
    let deserialized: ScanReport =
        serde_json::from_str(&json_str).expect("JSON should deserialize to ScanReport");
    assert_eq!(deserialized.summary.target_domain, "acme-corp.com");
    assert_eq!(deserialized.findings.len(), 4);
}

#[test]
fn test_sarif_vulnerability_structure() {
    let report = run_mock_scan("security-test.com");
    let sarif_str =
        render_report(&report, OutputFormat::Sarif).expect("SARIF rendering should succeed");
    let v: serde_json::Value = serde_json::from_str(&sarif_str).expect("SARIF must be valid JSON");

    assert_eq!(v["version"], "2.1.0");
    assert_eq!(v["runs"][0]["tool"]["driver"]["name"], "cf-origin-hunter");

    let results = v["runs"][0]["results"]
        .as_array()
        .expect("Results array must exist");
    assert_eq!(results.len(), 4);
    assert_eq!(results[0]["ruleId"], "CF-ORIGIN-LEAK-CONFIRMED");
    assert_eq!(results[0]["level"], "error");
}

#[test]
fn test_html_report_rendering() {
    let report = run_mock_scan("dashboard.corp");
    let html = render_report(&report, OutputFormat::Html).expect("HTML rendering should succeed");

    assert!(html.contains("<!DOCTYPE html>"));
    assert!(html.contains("dashboard.corp"));
    assert!(html.contains("Confirmed Origins"));
    assert!(html.contains("CONFIRMED 100%"));
    assert!(html.contains("REM-001"));
}

#[test]
fn test_wordlist_loader() {
    let mut tmp = NamedTempFile::new().unwrap();
    writeln!(tmp, "# Comment line").unwrap();
    writeln!(tmp, "direct").unwrap();
    writeln!(tmp).unwrap();
    writeln!(tmp, "origin-backup").unwrap();
    writeln!(tmp, "dev-api").unwrap();

    let words = load_wordlist_file(tmp.path()).expect("Wordlist loader should succeed");
    assert_eq!(words, vec!["direct", "origin-backup", "dev-api"]);
}

#[test]
fn test_crtsh_complex_san_parsing() {
    let entries = vec![CrtShEntry {
        issuer_ca_id: Some(1),
        issuer_name: Some("Let's Encrypt".into()),
        common_name: Some("*.backend.acme.com\nacme.com".into()),
        name_value: Some(
            "*.backend.acme.com\nportal.acme.com\nadmin.corp.acme.com\nother.org".into(),
        ),
        id: Some(1),
        entry_timestamp: None,
        not_before: None,
        not_after: None,
        serial_number: None,
    }];

    let subs = extract_subdomains_from_crtsh(&entries, "acme.com");
    assert!(subs.contains(&"backend.acme.com".to_string()));
    assert!(subs.contains(&"portal.acme.com".to_string()));
    assert!(subs.contains(&"admin.corp.acme.com".to_string()));
    assert!(subs.contains(&"acme.com".to_string()));
    assert!(!subs.contains(&"other.org".to_string()));
}

#[test]
fn test_spf_parser_edge_cases() {
    let spf = "v=spf1 ip4:192.0.2.1 ip4:198.51.100.0/24 ip6:2001:db8::1/64 -all";
    let ips = extract_ips_from_spf(spf);
    assert_eq!(ips.len(), 3);
    assert!(ips.contains(&"192.0.2.1".parse().unwrap()));
    assert!(ips.contains(&"198.51.100.0".parse().unwrap()));
    assert!(ips.contains(&"2001:db8::1".parse().unwrap()));

    let empty = extract_ips_from_spf("v=spf1 include:_spf.google.com ~all");
    assert!(empty.is_empty());
}

#[test]
fn test_cloudflare_asn_matching() {
    assert!(is_cloudflare_asn("AS13335 CLOUDFLARENET"));
    assert!(is_cloudflare_asn("AS209242"));
    assert!(is_cloudflare_asn("Cloudflare, Inc."));
    assert!(!is_cloudflare_asn("AS15169 GOOGLE"));
    assert!(!is_cloudflare_asn("AS16509 AMAZON"));
}

#[test]
fn test_remediation_plan_generation() {
    let plan = generate_remediation_plan();
    assert_eq!(plan.len(), 4);
    assert!(
        plan.iter()
            .any(|r| r.id == "REM-001" && r.priority == "CRITICAL")
    );
    assert!(
        plan.iter()
            .any(|r| r.id == "REM-002" && r.priority == "CRITICAL")
    );
    assert!(
        plan.iter()
            .any(|r| r.id == "REM-003" && r.priority == "HIGH")
    );
    assert!(
        plan.iter()
            .any(|r| r.id == "REM-004" && r.priority == "HIGH")
    );
}

#[test]
fn test_confidence_boundary_scoring() {
    let baseline = TargetBaseline {
        domain: "test.com".to_string(),
        resolved_ips: vec!["104.21.1.1".parse().unwrap()],
        is_behind_cloudflare: true,
        cloudflare_ips: vec!["104.21.1.1".parse().unwrap()],
        non_cloudflare_ips: vec![],
        http_status: Some(200),
        html_title: Some("Target Test".to_string()),
        body_sha256: Some("1122334455667788".to_string()),
        body_length: 500,
        server_header: Some("cloudflare".to_string()),
        headers: HashMap::new(),
    };

    // Unresponsive subdomain should be Low confidence
    let (level, score, reason) = calculate_confidence(
        &baseline,
        &DiscoverySource::Subdomain("unresponsive.test.com".into()),
        &[],
        &[],
    );
    assert_eq!(level, ConfidenceLevel::Low);
    assert_eq!(score, 30);
    assert!(reason.contains("Subdomain"));

    // Responsive MX record should be Medium confidence
    let probe = ProbeResult {
        ip: "198.51.100.99".parse().unwrap(),
        port: 80,
        protocol: "http".to_string(),
        url: "http://198.51.100.99:80/".to_string(),
        success: true,
        status_code: Some(200),
        html_title: Some("Generic Web Server".to_string()),
        body_sha256: Some("9999999999999999".to_string()),
        body_length: 120,
        server_header: Some("nginx".to_string()),
        headers: HashMap::new(),
        response_time_ms: 25,
        error: None,
        match_details: Some(ProbeMatchDetails {
            exact_body_hash_match: false,
            title_match: false,
            status_code_match: true,
            body_length_delta: -380,
            header_similarity_score: 0.2,
            cf_ray_present: false,
            direct_server_header: Some("nginx".to_string()),
            baseline_server_header: Some("cloudflare".to_string()),
        }),
    };

    let (mx_level, mx_score, _) = calculate_confidence(
        &baseline,
        &DiscoverySource::MxRecord("mail.test.com".into()),
        &[probe],
        &[],
    );
    assert_eq!(mx_level, ConfidenceLevel::Medium);
    assert_eq!(mx_score, 65);
}
