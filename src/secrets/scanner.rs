use memmap2::Mmap;
use rayon::prelude::*;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;
use walkdir::WalkDir;

use crate::secrets::ignore::IgnoreFilter;
use crate::secrets::rules::entropy::is_high_entropy_token;
use crate::secrets::rules::types::{redact_secret, Finding, Rule, Severity};

/// Known binary extensions that should not be scanned as text bundles.
const BINARY_EXTENSIONS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "webp", "avif", "ico", "svgz", "mp4", "webm", "mp3", "wav",
    "woff", "woff2", "ttf", "eot", "otf", "wasm", "zip", "tar", "gz", "br", "zst", "7z", "pdf",
    "exe", "dll", "so", "dylib",
];

/// Options for configuring the directory and bundle scanner.
#[derive(Debug, Clone)]
pub struct ScannerOptions {
    pub max_file_size_bytes: u64,
    pub min_severity: Severity,
    pub follow_symlinks: bool,
}

impl Default for ScannerOptions {
    fn default() -> Self {
        Self {
            max_file_size_bytes: 50 * 1024 * 1024, // 50 MB
            min_severity: Severity::Low,
            follow_symlinks: false,
        }
    }
}

/// Statistics from a completed scan.
#[derive(Debug, Clone, Default)]
pub struct ScanStats {
    pub files_scanned: usize,
    pub bytes_scanned: usize,
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub duration_ms: u128,
}

/// Results of a scan.
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub findings: Vec<Finding>,
    pub stats: ScanStats,
}

/// Discovers candidate client asset directories if none are specified.
pub fn discover_default_targets(base: &Path) -> Vec<PathBuf> {
    let specific_dirs = [
        "dist/client",
        "dist/_astro",
        "build/client",
        "public",
        ".svelte-kit/output/client",
        ".next/static",
        "out",
    ];

    let mut found = Vec::new();
    for candidate in &specific_dirs {
        let p = base.join(candidate);
        if p.exists() && p.is_dir() {
            found.push(p);
        }
    }

    if found.is_empty() {
        let fallback_dirs = ["dist", "build"];
        for candidate in &fallback_dirs {
            let p = base.join(candidate);
            if p.exists() && p.is_dir() {
                found.push(p);
            }
        }
    }

    if found.is_empty() {
        // Fall back to base directory itself
        found.push(base.to_path_buf());
    }

    found
}

/// Scans the target directories or files for secret leaks.
pub fn scan_targets(
    targets: &[PathBuf],
    rules: &[Rule],
    ignore_filter: &IgnoreFilter,
    options: &ScannerOptions,
) -> ScanResult {
    let start_time = Instant::now();

    // 1. Collect all candidate file paths (deduplicated by canonical path)
    let mut files_to_scan = Vec::new();
    let mut seen_paths = std::collections::HashSet::new();

    for target in targets {
        if target.is_file() {
            if !should_skip_file(target, ignore_filter) {
                let canonical = target.canonicalize().unwrap_or_else(|_| target.clone());
                if seen_paths.insert(canonical) {
                    files_to_scan.push(target.clone());
                }
            }
        } else if target.is_dir() {
            let walker = WalkDir::new(target).follow_links(options.follow_symlinks);
            for entry in walker.into_iter().filter_map(|e| e.ok()) {
                let path = entry.path();
                if path.is_file() && !should_skip_file(path, ignore_filter) {
                    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
                    if seen_paths.insert(canonical) {
                        files_to_scan.push(path.to_path_buf());
                    }
                }
            }
        }
    }

    let files_count = AtomicUsize::new(0);
    let bytes_count = AtomicUsize::new(0);

    // 2. Multi-threaded scanning with rayon
    let findings: Vec<Finding> = files_to_scan
        .par_iter()
        .flat_map(|path| {
            let result = scan_file(path, rules, ignore_filter, options);
            if let Ok((scanned_bytes, file_findings)) = result {
                files_count.fetch_add(1, Ordering::Relaxed);
                bytes_count.fetch_add(scanned_bytes, Ordering::Relaxed);
                file_findings
            } else {
                Vec::new()
            }
        })
        .filter(|f| f.severity >= options.min_severity)
        .collect();

    let duration = start_time.elapsed().as_millis();

    let mut stats = ScanStats {
        files_scanned: files_count.load(Ordering::Relaxed),
        bytes_scanned: bytes_count.load(Ordering::Relaxed),
        total_findings: findings.len(),
        critical_count: 0,
        high_count: 0,
        medium_count: 0,
        low_count: 0,
        duration_ms: duration,
    };

    for finding in &findings {
        match finding.severity {
            Severity::Critical => stats.critical_count += 1,
            Severity::High => stats.high_count += 1,
            Severity::Medium => stats.medium_count += 1,
            Severity::Low => stats.low_count += 1,
        }
    }

    ScanResult { findings, stats }
}

/// Scans a single file against the provided rules.
pub fn scan_file(
    path: &Path,
    rules: &[Rule],
    ignore_filter: &IgnoreFilter,
    options: &ScannerOptions,
) -> Result<(usize, Vec<Finding>), std::io::Error> {
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    let file_len = metadata.len();

    if file_len == 0 || file_len > options.max_file_size_bytes {
        return Ok((0, Vec::new()));
    }

    // Use memory mapping for files >= 16KB, std::fs::read for smaller files
    let content_str = if file_len >= 16384 {
        let mmap = unsafe { Mmap::map(&file)? };
        if is_binary_content(&mmap) {
            return Ok((file_len as usize, Vec::new()));
        }
        match std::str::from_utf8(&mmap) {
            Ok(s) => s.to_string(),
            Err(_) => String::from_utf8_lossy(&mmap).into_owned(),
        }
    } else {
        let bytes = std::fs::read(path)?;
        if is_binary_content(&bytes) {
            return Ok((bytes.len(), Vec::new()));
        }
        match String::from_utf8(bytes) {
            Ok(s) => s,
            Err(e) => String::from_utf8_lossy(&e.into_bytes()).into_owned(),
        }
    };

    let findings = scan_content(&content_str, path.to_string_lossy().as_ref(), rules, ignore_filter);
    Ok((file_len as usize, findings))
}

/// Scans raw string content and returns findings.
pub fn scan_content(
    content: &str,
    file_path: &str,
    rules: &[Rule],
    ignore_filter: &IgnoreFilter,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for rule in rules {
        if ignore_filter.is_rule_ignored(&rule.id) {
            continue;
        }

        // Exact match rule (e.g. from .dev.vars or .env)
        if let Some(ref secret_val) = rule.exact_match {
            if secret_val.is_empty() || ignore_filter.is_secret_ignored(secret_val) {
                continue;
            }

            let mut start_idx = 0;
            while let Some(pos) = content[start_idx..].find(secret_val) {
                let match_start = start_idx + pos;
                let match_end = match_start + secret_val.len();
                start_idx = match_end;

                let (line_num, col_num, snippet) = extract_location_and_snippet(content, match_start, match_end, &rule.name);
                findings.push(Finding {
                    rule_id: rule.id.clone(),
                    rule_name: rule.name.clone(),
                    severity: rule.severity,
                    file_path: file_path.to_string(),
                    line_number: line_num,
                    column_number: col_num,
                    match_start,
                    match_end,
                    raw_secret: secret_val.clone(),
                    redacted_secret: redact_secret(secret_val),
                    line_content: snippet,
                    description: rule.description.clone(),
                    recommendation: rule.recommendation.clone(),
                });
            }
        }

        // Regex pattern rule
        if let Some(ref regex) = rule.pattern {
            for cap in regex.captures_iter(content) {
                // If regex has capture group 1, use that as the raw secret; otherwise use full match
                let matched_group = if let Some(m) = cap.get(1) {
                    m
                } else if let Some(m) = cap.get(2) {
                    m
                } else if let Some(m) = cap.get(0) {
                    m
                } else {
                    continue;
                };

                let raw_secret = matched_group.as_str();

                if ignore_filter.is_secret_ignored(raw_secret) {
                    continue;
                }

                // Check min entropy if configured
                if let Some(min_entropy) = rule.min_entropy
                    && !is_high_entropy_token(raw_secret, min_entropy)
                {
                    continue;
                }

                let match_start = matched_group.start();
                let match_end = matched_group.end();
                let (line_num, col_num, snippet) =
                    extract_location_and_snippet(content, match_start, match_end, &rule.name);

                findings.push(Finding {
                    rule_id: rule.id.clone(),
                    rule_name: rule.name.clone(),
                    severity: rule.severity,
                    file_path: file_path.to_string(),
                    line_number: line_num,
                    column_number: col_num,
                    match_start,
                    match_end,
                    raw_secret: raw_secret.to_string(),
                    redacted_secret: redact_secret(raw_secret),
                    line_content: snippet,
                    description: rule.description.clone(),
                    recommendation: rule.recommendation.clone(),
                });
            }
        }
    }

    findings
}

/// Checks if a file path should be skipped based on extension or ignore filter.
fn should_skip_file(path: &Path, ignore_filter: &IgnoreFilter) -> bool {
    if ignore_filter.is_file_ignored(path) {
        return true;
    }

    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        let lower = ext.to_ascii_lowercase();
        if BINARY_EXTENSIONS.contains(&lower.as_str()) {
            return true;
        }
    }

    false
}

/// Checks if the first 1KB of content contains null bytes (indicative of binary data).
fn is_binary_content(bytes: &[u8]) -> bool {
    let check_len = bytes.len().min(1024);
    bytes[..check_len].contains(&0)
}

/// Calculates 1-based line & column numbers and creates a sanitized/bounded snippet.
fn extract_location_and_snippet(
    content: &str,
    match_start: usize,
    match_end: usize,
    rule_name: &str,
) -> (usize, usize, String) {
    let prefix = &content[..match_start];
    let line_number = prefix.chars().filter(|&c| c == '\n').count() + 1;

    let line_start = prefix.rfind('\n').map(|idx| idx + 1).unwrap_or(0);
    let line_end = content[match_end..]
        .find('\n')
        .map(|idx| match_end + idx)
        .unwrap_or(content.len());

    let column_number = match_start.saturating_sub(line_start) + 1;

    let full_line = &content[line_start..line_end];
    let matched_slice = &content[match_start..match_end];
    let redacted = redact_secret(matched_slice);

    // If the line is very long (e.g. minified JS bundle), create a window around the match
    let snippet = if full_line.len() > 200 {
        let rel_start = match_start.saturating_sub(line_start);
        let rel_end = match_end.saturating_sub(line_start);

        let window_start = rel_start.saturating_sub(60);
        let window_end = (rel_end + 60).min(full_line.len());

        let mut window = String::new();
        if window_start > 0 {
            window.push_str("...");
        }
        window.push_str(&full_line[window_start..rel_start]);
        window.push_str(&format!("[REDACTED: {} ({})]", rule_name, redacted));
        window.push_str(&full_line[rel_end..window_end]);
        if window_end < full_line.len() {
            window.push_str("...");
        }
        window
    } else {
        let rel_start = match_start.saturating_sub(line_start);
        let rel_end = match_end.saturating_sub(line_start);
        let mut line_res = String::new();
        line_res.push_str(&full_line[..rel_start]);
        line_res.push_str(&format!("[REDACTED: {} ({})]", rule_name, redacted));
        line_res.push_str(&full_line[rel_end..]);
        line_res
    };

    (line_number, column_number, snippet.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::rules::builtin::get_builtin_rules;

    #[test]
    fn test_scan_content_turnstile() {
        let content = r#"
            // Client bundle
            const siteKey = "0x4AAAAAAAE-xyz1234567890abcdef";
            const config = {
                turnstileSecret: "0x4AAAAAAAE-xyz1234567890abcdef",
            };
        "#;

        let rules = get_builtin_rules();
        let ignore = IgnoreFilter::new();
        let findings = scan_content(content, "dist/client/app.js", &rules, &ignore);

        assert!(!findings.is_empty());
        assert_eq!(findings[0].rule_id, "CF-004");
        assert_eq!(findings[0].file_path, "dist/client/app.js");
        assert!(findings[0].line_content.contains("[REDACTED:"));
    }

    #[test]
    fn test_scan_content_env_leak() {
        let content = r#"
            const dbUri = "postgres://admin:topsecret1234@db.cloudflare.internal:5432/main";
        "#;

        let secret_rule = Rule::new_exact(
            "ENV-DB",
            "Database Secret",
            "Database secret leaked",
            Severity::Critical,
            "postgres://admin:topsecret1234@db.cloudflare.internal:5432/main",
            "Keep secret server side",
        );

        let rules = vec![secret_rule];
        let ignore = IgnoreFilter::new();
        let findings = scan_content(content, "dist/client/bundle.js", &rules, &ignore);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "ENV-DB");
        assert_eq!(findings[0].line_number, 2);
    }
}
