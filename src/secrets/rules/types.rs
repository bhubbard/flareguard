use serde::{Deserialize, Serialize};
use std::fmt;

/// Severity level of a secret leak finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    pub fn to_sarif_level(&self) -> &'static str {
        match self {
            Severity::Critical | Severity::High => "error",
            Severity::Medium => "warning",
            Severity::Low => "note",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

impl std::str::FromStr for Severity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "low" | "note" => Ok(Severity::Low),
            "medium" | "med" | "warning" | "warn" => Ok(Severity::Medium),
            "high" | "error" => Ok(Severity::High),
            "critical" | "crit" => Ok(Severity::Critical),
            _ => Err(format!(
                "Invalid severity '{}'. Valid values: low, medium, high, critical",
                s
            )),
        }
    }
}

/// A secret detection rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: Severity,
    #[serde(skip)]
    pub pattern: Option<regex::Regex>,
    #[serde(skip)]
    pub exact_match: Option<String>,
    pub recommendation: String,
    #[serde(default)]
    pub min_entropy: Option<f64>,
}

impl Rule {
    pub fn new_regex(
        id: impl Into<String>,
        name: impl Into<String>,
        description: impl Into<String>,
        severity: Severity,
        pattern: regex::Regex,
        recommendation: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: description.into(),
            severity,
            pattern: Some(pattern),
            exact_match: None,
            recommendation: recommendation.into(),
            min_entropy: None,
        }
    }

    pub fn new_exact(
        id: impl Into<String>,
        name: impl Into<String>,
        description: impl Into<String>,
        severity: Severity,
        secret_value: impl Into<String>,
        recommendation: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: description.into(),
            severity,
            pattern: None,
            exact_match: Some(secret_value.into()),
            recommendation: recommendation.into(),
            min_entropy: None,
        }
    }

    pub fn with_min_entropy(mut self, min_entropy: f64) -> Self {
        self.min_entropy = Some(min_entropy);
        self
    }
}

/// A detected secret leak match.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: Severity,
    pub file_path: String,
    pub line_number: usize,
    pub column_number: usize,
    pub match_start: usize,
    pub match_end: usize,
    pub raw_secret: String,
    pub redacted_secret: String,
    pub line_content: String,
    pub description: String,
    pub recommendation: String,
}

/// Redact a secret string for safe logging and reporting.
pub fn redact_secret(secret: &str) -> String {
    let len = secret.chars().count();
    if len <= 6 {
        "******".to_string()
    } else if len <= 12 {
        let prefix: String = secret.chars().take(2).collect();
        let suffix: String = secret.chars().skip(len - 2).collect();
        format!("{}...{}", prefix, suffix)
    } else if len <= 24 {
        let prefix: String = secret.chars().take(4).collect();
        let suffix: String = secret.chars().skip(len - 4).collect();
        format!("{}...{}", prefix, suffix)
    } else {
        let prefix: String = secret.chars().take(6).collect();
        let suffix: String = secret.chars().skip(len - 4).collect();
        format!("{}...{}", prefix, suffix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_secret() {
        assert_eq!(redact_secret("short"), "******");
        assert_eq!(redact_secret("12345678"), "12...78");
        assert_eq!(redact_secret("0x4AAAAAAAE-xyz1234567890"), "0x4AAA...7890");
        assert_eq!(
            redact_secret("c2547eb745079dac9320b638f5e22594b678a"),
            "c2547e...678a"
        );
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
    }
}
