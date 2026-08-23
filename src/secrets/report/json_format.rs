use serde::{Deserialize, Serialize};
use crate::secrets::rules::types::Finding;
use crate::secrets::scanner::ScanStats;

/// Top-level JSON report structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonReport {
    pub tool_name: String,
    pub tool_version: String,
    pub timestamp: String,
    pub stats: JsonStats,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonStats {
    pub files_scanned: usize,
    pub bytes_scanned: usize,
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub duration_ms: u128,
}

impl From<ScanStats> for JsonStats {
    fn from(stats: ScanStats) -> Self {
        Self {
            files_scanned: stats.files_scanned,
            bytes_scanned: stats.bytes_scanned,
            total_findings: stats.total_findings,
            critical_count: stats.critical_count,
            high_count: stats.high_count,
            medium_count: stats.medium_count,
            low_count: stats.low_count,
            duration_ms: stats.duration_ms,
        }
    }
}

/// Formats scan results as pretty-printed JSON.
pub fn format_json_report(
    findings: &[Finding],
    stats: &ScanStats,
    tool_version: &str,
) -> Result<String, serde_json::Error> {
    let report = JsonReport {
        tool_name: "cf-secret-leak-guard".to_string(),
        tool_version: tool_version.to_string(),
        timestamp: "2026-08-22T00:00:00Z".to_string(),
        stats: stats.clone().into(),
        findings: findings.to_vec(),
    };

    serde_json::to_string_pretty(&report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::rules::types::Severity;

    #[test]
    fn test_json_report_format() {
        let stats = ScanStats {
            files_scanned: 10,
            bytes_scanned: 1024,
            total_findings: 1,
            critical_count: 1,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            duration_ms: 15,
        };

        let finding = Finding {
            rule_id: "CF-001".into(),
            rule_name: "Cloudflare API Token".into(),
            severity: Severity::Critical,
            file_path: "dist/client/main.js".into(),
            line_number: 10,
            column_number: 5,
            match_start: 100,
            match_end: 140,
            raw_secret: "secret123".into(),
            redacted_secret: "sec...123".into(),
            line_content: "token = [REDACTED]".into(),
            description: "Leaked token".into(),
            recommendation: "Rotate token".into(),
        };

        let json_str = format_json_report(&[finding], &stats, "0.1.0").unwrap();
        assert!(json_str.contains("cf-secret-leak-guard"));
        assert!(json_str.contains("CF-001"));
    }
}
