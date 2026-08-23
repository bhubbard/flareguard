use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ConfidenceLevel {
    Low = 1,
    Medium = 2,
    High = 3,
    Confirmed = 4,
}

impl std::fmt::Display for ConfidenceLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfidenceLevel::Confirmed => write!(f, "CONFIRMED"),
            ConfidenceLevel::High => write!(f, "HIGH"),
            ConfidenceLevel::Medium => write!(f, "MEDIUM"),
            ConfidenceLevel::Low => write!(f, "LOW"),
        }
    }
}

impl std::str::FromStr for ConfidenceLevel {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "CONFIRMED" | "100" => Ok(ConfidenceLevel::Confirmed),
            "HIGH" | "85" => Ok(ConfidenceLevel::High),
            "MEDIUM" | "60" => Ok(ConfidenceLevel::Medium),
            "LOW" | "30" => Ok(ConfidenceLevel::Low),
            _ => Err(format!("Unknown confidence level: {}", s)),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetBaseline {
    pub domain: String,
    pub resolved_ips: Vec<IpAddr>,
    pub is_behind_cloudflare: bool,
    pub cloudflare_ips: Vec<IpAddr>,
    pub non_cloudflare_ips: Vec<IpAddr>,
    pub http_status: Option<u16>,
    pub html_title: Option<String>,
    pub body_sha256: Option<String>,
    pub body_length: usize,
    pub server_header: Option<String>,
    pub headers: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoverySource {
    Subdomain(String),
    MxRecord(String),
    SpfRecord(String),
    TxtRecord(String),
    CertificateTransparency(String),
    HistoricalDns(String),
    DirectDns(String),
    Custom(String),
}

impl std::fmt::Display for DiscoverySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DiscoverySource::Subdomain(sub) => write!(f, "Subdomain ({})", sub),
            DiscoverySource::MxRecord(mx) => write!(f, "MX Record ({})", mx),
            DiscoverySource::SpfRecord(spf) => write!(f, "SPF Record ({})", spf),
            DiscoverySource::TxtRecord(txt) => write!(f, "TXT Record ({})", txt),
            DiscoverySource::CertificateTransparency(san) => write!(f, "crt.sh SAN ({})", san),
            DiscoverySource::HistoricalDns(src) => write!(f, "Historical DNS ({})", src),
            DiscoverySource::DirectDns(rec) => write!(f, "Direct DNS ({})", rec),
            DiscoverySource::Custom(desc) => write!(f, "Custom ({})", desc),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidateIp {
    pub ip: IpAddr,
    pub source: DiscoverySource,
    pub hostname: Option<String>,
    pub is_cloudflare: bool,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeMatchDetails {
    pub exact_body_hash_match: bool,
    pub title_match: bool,
    pub status_code_match: bool,
    pub body_length_delta: i64,
    pub header_similarity_score: f32,
    pub cf_ray_present: bool,
    pub direct_server_header: Option<String>,
    pub baseline_server_header: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResult {
    pub ip: IpAddr,
    pub port: u16,
    pub protocol: String,
    pub url: String,
    pub success: bool,
    pub status_code: Option<u16>,
    pub html_title: Option<String>,
    pub body_sha256: Option<String>,
    pub body_length: usize,
    pub server_header: Option<String>,
    pub headers: HashMap<String, String>,
    pub response_time_ms: u64,
    pub error: Option<String>,
    pub match_details: Option<ProbeMatchDetails>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HunterFinding {
    pub candidate_ip: IpAddr,
    pub hostname: Option<String>,
    pub discovery_source: DiscoverySource,
    pub confidence: ConfidenceLevel,
    pub confidence_score: u8, // 0 - 100
    pub confidence_reason: String,
    pub successful_probes: Vec<ProbeResult>,
    pub failed_probes: Vec<ProbeResult>,
    pub is_origin_confirmed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub target_domain: String,
    pub scanned_at: DateTime<Utc>,
    pub duration_seconds: f64,
    pub is_behind_cloudflare: bool,
    pub cloudflare_edge_ips: Vec<IpAddr>,
    pub candidates_discovered: usize,
    pub origins_confirmed: usize,
    pub high_confidence_origins: usize,
    pub medium_confidence_origins: usize,
    pub low_confidence_origins: usize,
    pub is_origin_leaked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationStep {
    pub id: String,
    pub title: String,
    pub priority: String, // "CRITICAL", "HIGH", "MEDIUM"
    pub description: String,
    pub commands: Vec<String>,
    pub doc_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub summary: ScanSummary,
    pub baseline: TargetBaseline,
    pub findings: Vec<HunterFinding>,
    pub candidates: Vec<CandidateIp>,
    pub remediation: Vec<RemediationStep>,
}
