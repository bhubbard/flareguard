use flareguard::secrets::rules::builtin::get_builtin_rules;
use flareguard::secrets::rules::types::Severity;
use flareguard::secrets::scanner::{scan_targets, ScannerOptions};
use flareguard::secrets::ignore::IgnoreFilter;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_builtin_rules_exist() {
    let rules = get_builtin_rules();
    assert!(!rules.is_empty(), "Builtin rules should not be empty");
    assert!(rules.iter().any(|r| r.id == "CF-001"), "Should contain CF-001 (API Token)");
    assert!(rules.iter().any(|r| r.id == "CF-004"), "Should contain CF-004 (Turnstile Secret)");
}

#[test]
fn test_scan_clean_directory() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("index.js");
    fs::write(&file_path, "console.log('Hello Cloudflare Workers!');").unwrap();

    let rules = get_builtin_rules();
    let ignore = IgnoreFilter::new();
    let options = ScannerOptions {
        max_file_size_bytes: 10 * 1024 * 1024,
        min_severity: Severity::Low,
        follow_symlinks: false,
    };

    let result = scan_targets(&[dir.path().to_path_buf()], &rules, &ignore, &options);
    assert!(result.findings.is_empty(), "Clean file should have 0 findings");
}

#[test]
fn test_detect_exposed_api_token() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("bundle.js");
    fs::write(
        &file_path,
        "const token = 'v1.0-abcdef1234567890abcdef1234567890abcdef12';",
    )
    .unwrap();

    let rules = get_builtin_rules();
    let ignore = IgnoreFilter::new();
    let options = ScannerOptions {
        max_file_size_bytes: 10 * 1024 * 1024,
        min_severity: Severity::Low,
        follow_symlinks: false,
    };

    let result = scan_targets(&[dir.path().to_path_buf()], &rules, &ignore, &options);
    assert!(!result.findings.is_empty(), "Should detect leaked token");
}
