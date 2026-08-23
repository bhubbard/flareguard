use crate::zone::models::{AuditFinding, RiskLevel};

/// Baseline maximum score for a zone with 0 security findings
pub const BASELINE_SCORE: u32 = 100;

/// Calculates health score (0-100) for a zone given its security findings
pub fn calculate_zone_score(findings: &[AuditFinding]) -> u32 {
    let mut total_penalty: u32 = 0;
    let mut has_critical = false;

    for finding in findings {
        total_penalty = total_penalty.saturating_add(finding.score_penalty);
        if finding.risk_level == RiskLevel::Critical {
            has_critical = true;
        }
    }

    let mut score = BASELINE_SCORE.saturating_sub(total_penalty);

    // If any Critical risk exists (e.g. flexible SSL or 0.0.0.0/0 bypass),
    // the zone cannot score higher than 49 (Failing grade)
    if has_critical && score > 49 {
        score = 49;
    }

    score.min(100)
}

/// Converts a numerical health score (0-100) to a letter grade
pub fn calculate_grade(score: u32) -> &'static str {
    match score {
        95..=100 => "A+",
        90..=94 => "A",
        80..=89 => "B",
        70..=79 => "C",
        60..=69 => "D",
        _ => "F",
    }
}

/// Returns a human-friendly description of the security grade
pub fn grade_description(grade: &str) -> &'static str {
    match grade {
        "A+" => "Excellent Posture (Best-practice hardened)",
        "A" => "Strong Posture (Compliant)",
        "B" => "Good Posture (Minor enhancements recommended)",
        "C" => "Moderate Risk (Several security gaps)",
        "D" => "High Risk (Substantial vulnerabilities)",
        "F" => "Critical Risk (Urgent remediation required)",
        _ => "Unknown Posture",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zone::models::RuleCategory;

    #[test]
    fn test_perfect_score() {
        let findings = vec![];
        assert_eq!(calculate_zone_score(&findings), 100);
        assert_eq!(calculate_grade(100), "A+");
    }

    #[test]
    fn test_critical_finding_caps_score() {
        let findings = vec![AuditFinding {
            rule_id: "CF-SSL-001".to_string(),
            rule_name: "SSLModeCheck".to_string(),
            category: RuleCategory::SslTls,
            risk_level: RiskLevel::Critical,
            title: "Insecure SSL".to_string(),
            description: "Flexible mode".to_string(),
            actual_value: "flexible".to_string(),
            expected_value: "strict".to_string(),
            remediation: "Fix it".to_string(),
            score_penalty: 30,
            doc_url: None,
        }];
        let score = calculate_zone_score(&findings);
        assert!(score <= 49);
        assert_eq!(calculate_grade(score), "F");
    }

    #[test]
    fn test_minor_deductions() {
        let findings = vec![AuditFinding {
            rule_id: "CF-TLS-002".to_string(),
            rule_name: "Tls13Disabled".to_string(),
            category: RuleCategory::SslTls,
            risk_level: RiskLevel::Low,
            title: "TLS 1.3 Disabled".to_string(),
            description: "TLS 1.3 off".to_string(),
            actual_value: "off".to_string(),
            expected_value: "on".to_string(),
            remediation: "Enable TLS 1.3".to_string(),
            score_penalty: 5,
            doc_url: None,
        }];
        assert_eq!(calculate_zone_score(&findings), 95);
        assert_eq!(calculate_grade(95), "A+");
    }
}
