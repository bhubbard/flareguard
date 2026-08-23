use serde::{Deserialize, Serialize};

/// Account summary information associated with a zone
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AccountInfo {
    pub id: String,
    pub name: String,
}

/// Cloudflare Plan information (e.g. Free, Pro, Business, Enterprise)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PlanInfo {
    pub id: Option<String>,
    pub name: Option<String>,
    pub price: Option<i64>,
    pub currency: Option<String>,
    pub is_subscribed: Option<bool>,
}

/// Cloudflare Zone object
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Zone {
    pub id: String,
    pub name: String,
    pub status: String,
    #[serde(default)]
    pub paused: bool,
    #[serde(rename = "type")]
    pub zone_type: Option<String>,
    pub development_mode: Option<i64>,
    pub name_servers: Option<Vec<String>>,
    pub account: Option<AccountInfo>,
    pub plan: Option<PlanInfo>,
}

/// Strict Transport Security (HSTS) configuration within security_header
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct HstsSetting {
    #[serde(default)]
    pub enabled: bool,
    pub max_age: Option<u64>,
    #[serde(default)]
    pub include_subdomains: Option<bool>,
    #[serde(default)]
    pub preload: Option<bool>,
    #[serde(default)]
    pub nosniff: Option<bool>,
}

/// Security header setting wrapper
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SecurityHeaderSetting {
    pub strict_transport_security: Option<HstsSetting>,
}

/// Zone DNSSEC details
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct DnssecSetting {
    #[serde(default = "default_dnssec_status")]
    pub status: String,
    pub flags: Option<u32>,
    pub algorithm: Option<String>,
    pub key_type: Option<String>,
    pub digest_type: Option<String>,
    pub digest_algorithm: Option<String>,
    pub digest: Option<String>,
    pub ds: Option<String>,
    pub key_tag: Option<u32>,
    pub public_key: Option<String>,
}

fn default_dnssec_status() -> String {
    "disabled".to_string()
}

/// WAF Package representation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct WafPackage {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub detection_mode: Option<String>,
    pub zone_id: Option<String>,
    pub status: Option<String>,
}

/// Ruleset representation for Modern WAF
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct RulesetInfo {
    pub id: String,
    pub name: String,
    pub phase: Option<String>,
    pub kind: Option<String>,
    pub description: Option<String>,
    pub rules_count: Option<usize>,
}

/// Aggregated WAF Settings
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct WafSetting {
    #[serde(default)]
    pub waf_enabled: bool,
    #[serde(default)]
    pub managed_rules_active: bool,
    #[serde(default)]
    pub packages: Vec<WafPackage>,
    #[serde(default)]
    pub rulesets: Vec<RulesetInfo>,
}

/// Bot Management / Bot Fight Mode configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct BotManagementSetting {
    #[serde(default)]
    pub fight_mode: bool,
    #[serde(default)]
    pub using_latest_model: Option<bool>,
    #[serde(default)]
    pub optimize_wordpress: Option<bool>,
    pub sbfm_definitely_automated: Option<String>,
    pub sbfm_likely_automated: Option<String>,
    pub sbfm_verified_bots: Option<String>,
    pub sbfm_static_resource_protection: Option<bool>,
}

/// Rate limiting rule definition
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct RateLimitRule {
    pub id: String,
    pub disabled: Option<bool>,
    pub description: Option<String>,
    pub threshold: Option<u32>,
    pub period: Option<u32>,
    pub action: Option<String>,
}

/// Rate limiting settings
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct RateLimitSetting {
    #[serde(default)]
    pub rules: Vec<RateLimitRule>,
}

/// Zone lockdown configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ZoneLockdownRule {
    pub id: String,
    pub paused: Option<bool>,
    pub description: Option<String>,
    pub urls: Vec<String>,
    pub configurations: Vec<LockdownConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct LockdownConfig {
    pub target: String,
    pub value: String,
}

/// Zone Lockdown summary
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ZoneLockdownSetting {
    #[serde(default)]
    pub rules: Vec<ZoneLockdownRule>,
}

/// IP Access / Firewall Rule
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct IpAccessRule {
    pub id: String,
    pub mode: String, // "block", "challenge", "whitelist", "js_challenge", "managed_challenge"
    pub configuration: IpAccessConfig,
    pub notes: Option<String>,
    pub paused: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct IpAccessConfig {
    pub target: String, // "ip", "ip_range", "asn", "country"
    pub value: String,
}

/// IP Access Rules list
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct IpAccessRulesSetting {
    #[serde(default)]
    pub rules: Vec<IpAccessRule>,
}

/// Core Zone Settings (SSL, Min TLS, Always HTTPS, etc.)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ZoneSettings {
    pub ssl: Option<String>,                      // "off", "flexible", "full", "strict"
    pub min_tls_version: Option<String>,          // "1.0", "1.1", "1.2", "1.3"
    pub tls_1_3: Option<String>,                  // "on", "off", "zrt"
    pub always_use_https: Option<String>,          // "on", "off"
    pub automatic_https_rewrites: Option<String>, // "on", "off"
    pub opportunistic_encryption: Option<String>, // "on", "off"
    pub security_header: Option<SecurityHeaderSetting>,
    pub security_level: Option<String>,           // "essentially_off", "low", "medium", "high", "under_attack"
    pub browser_check: Option<String>,            // "on", "off"
    pub challenge_ttl: Option<i64>,
    pub brotli: Option<String>,
    pub early_hints: Option<String>,
}

/// Complete dataset gathered for a single Cloudflare Zone
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ZoneAuditData {
    pub zone: Zone,
    pub settings: ZoneSettings,
    pub dnssec: DnssecSetting,
    pub waf: WafSetting,
    pub bot_management: BotManagementSetting,
    pub rate_limits: RateLimitSetting,
    pub lockdowns: ZoneLockdownSetting,
    pub ip_access_rules: IpAccessRulesSetting,
}

/// Standard Cloudflare API Response Envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub errors: Option<Vec<ApiMessage>>,
    pub messages: Option<Vec<ApiMessage>>,
    pub result: Option<T>,
    pub result_info: Option<ResultInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiMessage {
    pub code: Option<i64>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultInfo {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
    pub count: Option<u32>,
    pub total_count: Option<u32>,
    pub total_pages: Option<u32>,
}

/// Single setting item returned from /zones/{id}/settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettingItem {
    pub id: String,
    pub value: serde_json::Value,
    pub editable: Option<bool>,
    pub modified_on: Option<String>,
}
