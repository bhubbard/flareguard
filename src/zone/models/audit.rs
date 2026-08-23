use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Security risk severity level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RiskLevel {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RiskLevel::Critical => write!(f, "CRITICAL"),
            RiskLevel::High => write!(f, "HIGH"),
            RiskLevel::Medium => write!(f, "MEDIUM"),
            RiskLevel::Low => write!(f, "LOW"),
            RiskLevel::Info => write!(f, "INFO"),
        }
    }
}

impl RiskLevel {
    pub fn badge_str(&self) -> &'static str {
        match self {
            RiskLevel::Critical => "CRITICAL",
            RiskLevel::High => "HIGH",
            RiskLevel::Medium => "MEDIUM",
            RiskLevel::Low => "LOW",
            RiskLevel::Info => "INFO",
        }
    }
}

/// Category of security check
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleCategory {
    SslTls,
    HttpsEnforcement,
    Hsts,
    WafSecurity,
    BotManagement,
    Dnssec,
    AccessControl,
    SecurityLevel,
}

impl fmt::Display for RuleCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RuleCategory::SslTls => write!(f, "SSL/TLS Configuration"),
            RuleCategory::HttpsEnforcement => write!(f, "HTTPS Enforcement"),
            RuleCategory::Hsts => write!(f, "HSTS Security Headers"),
            RuleCategory::WafSecurity => write!(f, "WAF & Managed Rules"),
            RuleCategory::BotManagement => write!(f, "Bot Management"),
            RuleCategory::Dnssec => write!(f, "DNSSEC"),
            RuleCategory::AccessControl => write!(f, "Access Rules & Lockdown"),
            RuleCategory::SecurityLevel => write!(f, "Zone Security Level"),
        }
    }
}

/// A specific security finding detected during the zone audit
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditFinding {
    pub rule_id: String,
    pub rule_name: String,
    pub category: RuleCategory,
    pub risk_level: RiskLevel,
    pub title: String,
    pub description: String,
    pub actual_value: String,
    pub expected_value: String,
    pub remediation: String,
    pub score_penalty: u32,
    pub doc_url: Option<String>,
}

/// Summary of key settings for clean display in tables and reports
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ZoneSettingsSummary {
    pub ssl_mode: String,
    pub min_tls: String,
    pub always_https: String,
    pub hsts_status: String,
    pub dnssec_status: String,
    pub waf_status: String,
    pub bot_fight_mode: String,
    pub security_level: String,
}

/// Complete audit report for a single Cloudflare Zone
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ZoneAuditReport {
    pub zone_id: String,
    pub zone_name: String,
    pub plan_name: String,
    pub status: String,
    pub score: u32,
    pub grade: String,
    pub passed_checks_count: usize,
    pub total_checks_count: usize,
    pub settings_summary: ZoneSettingsSummary,
    pub findings: Vec<AuditFinding>,
}

impl ZoneAuditReport {
    pub fn count_by_severity(&self, severity: RiskLevel) -> usize {
        self.findings
            .iter()
            .filter(|f| f.risk_level == severity)
            .count()
    }

    pub fn has_critical(&self) -> bool {
        self.findings
            .iter()
            .any(|f| f.risk_level == RiskLevel::Critical)
    }

    pub fn has_high_or_critical(&self) -> bool {
        self.findings
            .iter()
            .any(|f| f.risk_level == RiskLevel::Critical || f.risk_level == RiskLevel::High)
    }
}

/// Breakdown of findings count by severity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SeverityCounts {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub total: usize,
}

/// Aggregated multi-zone compliance and security audit report
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AggregateAuditReport {
    pub timestamp: DateTime<Utc>,
    pub account_id: Option<String>,
    pub total_zones: usize,
    pub average_score: f64,
    pub overall_grade: String,
    pub total_findings: SeverityCounts,
    pub zone_reports: Vec<ZoneAuditReport>,
}

impl AggregateAuditReport {
    pub fn new(zone_reports: Vec<ZoneAuditReport>, account_id: Option<String>) -> Self {
        let total_zones = zone_reports.len();
        let average_score = if total_zones == 0 {
            100.0
        } else {
            let sum: u32 = zone_reports.iter().map(|z| z.score).sum();
            (sum as f64) / (total_zones as f64)
        };

        let overall_grade =
            crate::zone::scoring::calculate_grade(average_score.round() as u32).to_string();

        let mut total_findings = SeverityCounts::default();
        for z in &zone_reports {
            for f in &z.findings {
                total_findings.total += 1;
                match f.risk_level {
                    RiskLevel::Critical => total_findings.critical += 1,
                    RiskLevel::High => total_findings.high += 1,
                    RiskLevel::Medium => total_findings.medium += 1,
                    RiskLevel::Low => total_findings.low += 1,
                    RiskLevel::Info => total_findings.info += 1,
                }
            }
        }

        Self {
            timestamp: Utc::now(),
            account_id,
            total_zones,
            average_score: (average_score * 10.0).round() / 10.0,
            overall_grade,
            total_findings,
            zone_reports,
        }
    }
}
