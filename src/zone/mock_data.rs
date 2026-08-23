use crate::zone::client::provider::ZoneDataProvider;
use crate::zone::models::{
    AccountInfo, BotManagementSetting, DnssecSetting, HstsSetting, IpAccessConfig, IpAccessRule,
    IpAccessRulesSetting, PlanInfo, RateLimitRule, RateLimitSetting, RulesetInfo,
    SecurityHeaderSetting, WafPackage, WafSetting, Zone, ZoneAuditData, ZoneLockdownRule,
    ZoneLockdownSetting, ZoneSettings,
};
use anyhow::{Context, Result};
use std::future::Future;
use std::path::Path;
use std::pin::Pin;

/// Generates built-in synthetic mock zones covering different security configurations
pub fn get_mock_zones() -> Vec<ZoneAuditData> {
    vec![
        // Zone 1: Hardened Enterprise Grade Zone (Score: 100, Grade: A+)
        ZoneAuditData {
            zone: Zone {
                id: "11111111111111111111111111111111".to_string(),
                name: "prod-banking.example.com".to_string(),
                status: "active".to_string(),
                paused: false,
                zone_type: Some("full".to_string()),
                development_mode: Some(0),
                name_servers: Some(vec![
                    "ns1.cloudflare.com".to_string(),
                    "ns2.cloudflare.com".to_string(),
                ]),
                account: Some(AccountInfo {
                    id: "acc_enterprise_999".to_string(),
                    name: "Apex Financial Group".to_string(),
                }),
                plan: Some(PlanInfo {
                    id: Some("enterprise".to_string()),
                    name: Some("Enterprise Plan".to_string()),
                    price: Some(5000),
                    currency: Some("USD".to_string()),
                    is_subscribed: Some(true),
                }),
            },
            settings: ZoneSettings {
                ssl: Some("strict".to_string()),
                min_tls_version: Some("1.3".to_string()),
                tls_1_3: Some("on".to_string()),
                always_use_https: Some("on".to_string()),
                automatic_https_rewrites: Some("on".to_string()),
                opportunistic_encryption: Some("on".to_string()),
                security_header: Some(SecurityHeaderSetting {
                    strict_transport_security: Some(HstsSetting {
                        enabled: true,
                        max_age: Some(31536000), // 1 year
                        include_subdomains: Some(true),
                        preload: Some(true),
                        nosniff: Some(true),
                    }),
                }),
                security_level: Some("high".to_string()),
                browser_check: Some("on".to_string()),
                challenge_ttl: Some(1800),
                brotli: Some("on".to_string()),
                early_hints: Some("on".to_string()),
            },
            dnssec: DnssecSetting {
                status: "active".to_string(),
                flags: Some(257),
                algorithm: Some("13".to_string()),
                key_type: Some("KSK".to_string()),
                digest_type: Some("2".to_string()),
                digest_algorithm: Some("SHA-256".to_string()),
                digest: Some("E2D3C4B5A6...".to_string()),
                ds: Some("prod-banking.example.com. IN DS 2371 13 2 E2D3C...".to_string()),
                key_tag: Some(2371),
                public_key: Some("mdssw58R58...".to_string()),
            },
            waf: WafSetting {
                waf_enabled: true,
                managed_rules_active: true,
                packages: vec![WafPackage {
                    id: "pkg_cf_core".to_string(),
                    name: "Cloudflare Managed Ruleset".to_string(),
                    description: Some("Core managed rules".to_string()),
                    detection_mode: Some("anomaly".to_string()),
                    zone_id: Some("11111111111111111111111111111111".to_string()),
                    status: Some("active".to_string()),
                }],
                rulesets: vec![RulesetInfo {
                    id: "rs_owasp".to_string(),
                    name: "Cloudflare OWASP Core Ruleset".to_string(),
                    phase: Some("http_request_firewall_managed".to_string()),
                    kind: Some("managed".to_string()),
                    description: Some("OWASP Top 10 protection".to_string()),
                    rules_count: Some(48),
                }],
            },
            bot_management: BotManagementSetting {
                fight_mode: true,
                using_latest_model: Some(true),
                optimize_wordpress: Some(false),
                sbfm_definitely_automated: Some("block".to_string()),
                sbfm_likely_automated: Some("managed_challenge".to_string()),
                sbfm_verified_bots: Some("allow".to_string()),
                sbfm_static_resource_protection: Some(true),
            },
            rate_limits: RateLimitSetting {
                rules: vec![
                    RateLimitRule {
                        id: "rl_login_bruteforce".to_string(),
                        disabled: Some(false),
                        description: Some(
                            "Protect /api/v1/auth/login from brute force".to_string(),
                        ),
                        threshold: Some(5),
                        period: Some(60),
                        action: Some("challenge".to_string()),
                    },
                    RateLimitRule {
                        id: "rl_api_rate_limit".to_string(),
                        disabled: Some(false),
                        description: Some("Global API rate limiting".to_string()),
                        threshold: Some(100),
                        period: Some(60),
                        action: Some("block".to_string()),
                    },
                ],
            },
            lockdowns: ZoneLockdownSetting {
                rules: vec![ZoneLockdownRule {
                    id: "lock_admin_portal".to_string(),
                    paused: Some(false),
                    description: Some("Restrict /admin/* to VPN gateway".to_string()),
                    urls: vec!["prod-banking.example.com/admin/*".to_string()],
                    configurations: vec![crate::zone::models::LockdownConfig {
                        target: "ip".to_string(),
                        value: "198.51.100.50".to_string(),
                    }],
                }],
            },
            ip_access_rules: IpAccessRulesSetting {
                rules: vec![IpAccessRule {
                    id: "ip_rule_corp_hq".to_string(),
                    mode: "whitelist".to_string(),
                    configuration: IpAccessConfig {
                        target: "ip".to_string(),
                        value: "198.51.100.10".to_string(),
                    },
                    notes: Some("Corporate Headquarters Egress IP".to_string()),
                    paused: Some(false),
                }],
            },
        },
        // Zone 2: Moderate / Good E-Commerce Shop (Score: ~85, Grade: B)
        ZoneAuditData {
            zone: Zone {
                id: "22222222222222222222222222222222".to_string(),
                name: "ecommerce-store.io".to_string(),
                status: "active".to_string(),
                paused: false,
                zone_type: Some("full".to_string()),
                development_mode: Some(0),
                name_servers: Some(vec![
                    "ns1.cloudflare.com".to_string(),
                    "ns2.cloudflare.com".to_string(),
                ]),
                account: Some(AccountInfo {
                    id: "acc_retail_456".to_string(),
                    name: "Direct Retailers LLC".to_string(),
                }),
                plan: Some(PlanInfo {
                    id: Some("pro".to_string()),
                    name: Some("Pro Plan".to_string()),
                    price: Some(25),
                    currency: Some("USD".to_string()),
                    is_subscribed: Some(true),
                }),
            },
            settings: ZoneSettings {
                ssl: Some("full".to_string()), // Triggers CF-SSL-002 (-10 pts)
                min_tls_version: Some("1.2".to_string()),
                tls_1_3: Some("on".to_string()),
                always_use_https: Some("on".to_string()),
                automatic_https_rewrites: Some("on".to_string()),
                opportunistic_encryption: Some("on".to_string()),
                security_header: Some(SecurityHeaderSetting {
                    strict_transport_security: Some(HstsSetting {
                        enabled: true,
                        max_age: Some(15552000), // 6 months -> triggers CF-HSTS-002 Low (-5 pts)
                        include_subdomains: Some(true),
                        preload: Some(false), // triggers CF-HSTS-004 (-5 pts)
                        nosniff: Some(true),
                    }),
                }),
                security_level: Some("medium".to_string()),
                browser_check: Some("on".to_string()),
                challenge_ttl: Some(3600),
                brotli: Some("on".to_string()),
                early_hints: Some("off".to_string()),
            },
            dnssec: DnssecSetting {
                status: "active".to_string(),
                flags: Some(257),
                algorithm: Some("13".to_string()),
                key_type: Some("KSK".to_string()),
                digest_type: Some("2".to_string()),
                digest_algorithm: Some("SHA-256".to_string()),
                digest: Some("A1B2C3...".to_string()),
                ds: Some("ecommerce-store.io. IN DS ...".to_string()),
                key_tag: Some(1234),
                public_key: Some("pubkey...".to_string()),
            },
            waf: WafSetting {
                waf_enabled: true,
                managed_rules_active: true,
                packages: vec![WafPackage {
                    id: "pkg_cf_core".to_string(),
                    name: "Cloudflare Managed Ruleset".to_string(),
                    description: Some("Core managed rules".to_string()),
                    detection_mode: Some("anomaly".to_string()),
                    zone_id: Some("22222222222222222222222222222222".to_string()),
                    status: Some("active".to_string()),
                }],
                rulesets: vec![],
            },
            bot_management: BotManagementSetting {
                fight_mode: true,
                using_latest_model: Some(false),
                optimize_wordpress: Some(false),
                sbfm_definitely_automated: None,
                sbfm_likely_automated: None,
                sbfm_verified_bots: None,
                sbfm_static_resource_protection: None,
            },
            rate_limits: RateLimitSetting {
                rules: vec![RateLimitRule {
                    id: "rl_checkout".to_string(),
                    disabled: Some(false),
                    description: Some("Rate limit checkout submissions".to_string()),
                    threshold: Some(10),
                    period: Some(60),
                    action: Some("challenge".to_string()),
                }],
            },
            lockdowns: ZoneLockdownSetting::default(),
            ip_access_rules: IpAccessRulesSetting::default(),
        },
        // Zone 3: Severely Insecure Legacy Portal (Score: < 20, Grade: F, Multiple Critical & High)
        ZoneAuditData {
            zone: Zone {
                id: "33333333333333333333333333333333".to_string(),
                name: "legacy-portal.example.org".to_string(),
                status: "active".to_string(),
                paused: false,
                zone_type: Some("full".to_string()),
                development_mode: Some(0),
                name_servers: Some(vec![
                    "ns1.cloudflare.com".to_string(),
                    "ns2.cloudflare.com".to_string(),
                ]),
                account: Some(AccountInfo {
                    id: "acc_legacy_111".to_string(),
                    name: "Legacy Operations".to_string(),
                }),
                plan: Some(PlanInfo {
                    id: Some("free".to_string()),
                    name: Some("Free Plan".to_string()),
                    price: Some(0),
                    currency: Some("USD".to_string()),
                    is_subscribed: Some(false),
                }),
            },
            settings: ZoneSettings {
                ssl: Some("flexible".to_string()), // CRITICAL: CF-SSL-001 (-30 pts, cap at 49)
                min_tls_version: Some("1.0".to_string()), // HIGH: CF-TLS-001 (-20 pts)
                tls_1_3: Some("off".to_string()),  // LOW: CF-TLS-002 (-5 pts)
                always_use_https: Some("off".to_string()), // HIGH: CF-HTTPS-001 (-20 pts)
                automatic_https_rewrites: Some("off".to_string()), // MEDIUM: CF-HTTPS-002 (-10 pts)
                opportunistic_encryption: Some("off".to_string()),
                security_header: Some(SecurityHeaderSetting {
                    strict_transport_security: Some(HstsSetting {
                        enabled: false, // HIGH: CF-HSTS-001 (-20 pts)
                        max_age: Some(0),
                        include_subdomains: Some(false),
                        preload: Some(false),
                        nosniff: Some(false),
                    }),
                }),
                security_level: Some("essentially_off".to_string()), // HIGH: CF-SEC-002 (-15 pts)
                browser_check: Some("off".to_string()),              // LOW: CF-SEC-003 (-5 pts)
                challenge_ttl: Some(86400),
                brotli: Some("off".to_string()),
                early_hints: Some("off".to_string()),
            },
            dnssec: DnssecSetting {
                status: "disabled".to_string(), // MEDIUM: CF-DNS-001 (-10 pts)
                ..Default::default()
            },
            waf: WafSetting {
                waf_enabled: false, // HIGH: CF-WAF-001 (-20 pts)
                managed_rules_active: false,
                packages: vec![],
                rulesets: vec![],
            },
            bot_management: BotManagementSetting {
                fight_mode: false, // MEDIUM: CF-BOT-001 (-10 pts)
                ..Default::default()
            },
            rate_limits: RateLimitSetting {
                rules: vec![], // LOW: CF-RATE-001 (-5 pts)
            },
            lockdowns: ZoneLockdownSetting::default(),
            ip_access_rules: IpAccessRulesSetting {
                rules: vec![IpAccessRule {
                    id: "ip_rule_wildcard_bypass".to_string(),
                    mode: "whitelist".to_string(),
                    configuration: IpAccessConfig {
                        target: "ip_range".to_string(),
                        value: "0.0.0.0/0".to_string(), // CRITICAL: CF-SEC-001 (-35 pts)
                    },
                    notes: Some("Temporary blanket bypass - forgotten in prod".to_string()),
                    paused: Some(false),
                }],
            },
        },
        // Zone 4: Development / Staging Gateway (Score: ~55-65, Grade: D)
        ZoneAuditData {
            zone: Zone {
                id: "44444444444444444444444444444444".to_string(),
                name: "dev-api-gateway.net".to_string(),
                status: "active".to_string(),
                paused: false,
                zone_type: Some("full".to_string()),
                development_mode: Some(1),
                name_servers: Some(vec![
                    "ns1.cloudflare.com".to_string(),
                    "ns2.cloudflare.com".to_string(),
                ]),
                account: Some(AccountInfo {
                    id: "acc_dev_222".to_string(),
                    name: "Internal Engineering".to_string(),
                }),
                plan: Some(PlanInfo {
                    id: Some("business".to_string()),
                    name: Some("Business Plan".to_string()),
                    price: Some(200),
                    currency: Some("USD".to_string()),
                    is_subscribed: Some(true),
                }),
            },
            settings: ZoneSettings {
                ssl: Some("strict".to_string()),
                min_tls_version: Some("1.2".to_string()),
                tls_1_3: Some("on".to_string()),
                always_use_https: Some("on".to_string()),
                automatic_https_rewrites: Some("off".to_string()), // MEDIUM (-10 pts)
                opportunistic_encryption: Some("on".to_string()),
                security_header: Some(SecurityHeaderSetting {
                    strict_transport_security: Some(HstsSetting {
                        enabled: false, // HIGH (-20 pts)
                        max_age: None,
                        include_subdomains: Some(false),
                        preload: Some(false),
                        nosniff: Some(false),
                    }),
                }),
                security_level: Some("low".to_string()), // MEDIUM (-5 pts)
                browser_check: Some("on".to_string()),
                challenge_ttl: Some(3600),
                brotli: Some("on".to_string()),
                early_hints: Some("off".to_string()),
            },
            dnssec: DnssecSetting {
                status: "pending".to_string(), // MEDIUM (-10 pts)
                ..Default::default()
            },
            waf: WafSetting {
                waf_enabled: true,
                managed_rules_active: true,
                packages: vec![WafPackage {
                    id: "pkg_cf_core".to_string(),
                    name: "Cloudflare Managed Ruleset".to_string(),
                    description: Some("Core rules".to_string()),
                    detection_mode: Some("anomaly".to_string()),
                    zone_id: Some("44444444444444444444444444444444".to_string()),
                    status: Some("active".to_string()),
                }],
                rulesets: vec![],
            },
            bot_management: BotManagementSetting {
                fight_mode: false, // MEDIUM (-10 pts)
                ..Default::default()
            },
            rate_limits: RateLimitSetting {
                rules: vec![], // LOW (-5 pts)
            },
            lockdowns: ZoneLockdownSetting::default(),
            ip_access_rules: IpAccessRulesSetting::default(),
        },
    ]
}

/// Reads mock zone configurations from a JSON file
pub fn load_mock_from_file(path: impl AsRef<Path>) -> Result<Vec<ZoneAuditData>> {
    let p = path.as_ref();
    let content = std::fs::read_to_string(p)
        .with_context(|| format!("Failed to read mock file from '{}'", p.display()))?;

    // Try parsing as array of ZoneAuditData
    if let Ok(zones) = serde_json::from_str::<Vec<ZoneAuditData>>(&content) {
        return Ok(zones);
    }

    // Try parsing as single ZoneAuditData
    if let Ok(single_zone) = serde_json::from_str::<ZoneAuditData>(&content) {
        return Ok(vec![single_zone]);
    }

    // Try parsing wrapped object { "zones": [...] }
    #[derive(serde::Deserialize)]
    struct WrappedZones {
        zones: Vec<ZoneAuditData>,
    }
    if let Ok(wrapped) = serde_json::from_str::<WrappedZones>(&content) {
        return Ok(wrapped.zones);
    }

    anyhow::bail!(
        "Failed to deserialize mock zone data from '{}'. Expected JSON format containing array of ZoneAuditData.",
        p.display()
    );
}

/// Serializes default mock dataset to pretty-printed JSON string
pub fn generate_sample_mock_json() -> String {
    serde_json::to_string_pretty(&get_mock_zones()).unwrap_or_else(|_| "[]".to_string())
}

/// Mock implementation of ZoneDataProvider
pub struct MockZoneProvider {
    zones: Vec<ZoneAuditData>,
}

impl MockZoneProvider {
    pub fn new_builtin() -> Self {
        Self {
            zones: get_mock_zones(),
        }
    }

    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let zones = load_mock_from_file(path)?;
        Ok(Self { zones })
    }

    pub fn from_zones(zones: Vec<ZoneAuditData>) -> Self {
        Self { zones }
    }
}

impl ZoneDataProvider for MockZoneProvider {
    fn fetch_all_zones<'a>(
        &'a self,
        zone_filter: Option<&'a str>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<ZoneAuditData>>> + Send + 'a>> {
        Box::pin(async move {
            if let Some(filter) = zone_filter
                && !filter.is_empty() {
                    let filtered: Vec<ZoneAuditData> = self
                        .zones
                        .iter()
                        .filter(|z| {
                            z.zone.name.eq_ignore_ascii_case(filter)
                                || z.zone.id.eq_ignore_ascii_case(filter)
                                || z.zone.name.to_lowercase().contains(&filter.to_lowercase())
                        })
                        .cloned()
                        .collect();
                    return Ok(filtered);
                }
            Ok(self.zones.clone())
        })
    }
}
