use crate::zone::client::provider::ZoneDataProvider;
use crate::zone::models::{
    ApiResponse, BotManagementSetting, DnssecSetting, HstsSetting, IpAccessRule,
    IpAccessRulesSetting, RateLimitRule, RateLimitSetting, RulesetInfo, SecurityHeaderSetting,
    SettingItem, WafPackage, WafSetting, Zone, ZoneAuditData, ZoneLockdownRule,
    ZoneLockdownSetting, ZoneSettings,
};
use anyhow::{Context, Result, bail};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue, USER_AGENT};
use reqwest::{Client, Response, StatusCode};
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

pub struct CloudflareClient {
    client: Client,
    base_url: String,
    account_id: Option<String>,
}

impl CloudflareClient {
    pub fn new(token: &str, account_id: Option<String>) -> Result<Self> {
        let mut headers = HeaderMap::new();
        let mut auth_val = HeaderValue::from_str(&format!("Bearer {}", token.trim()))
            .context("Invalid API token header format")?;
        auth_val.set_sensitive(true);
        headers.insert(AUTHORIZATION, auth_val);
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(
            USER_AGENT,
            HeaderValue::from_static("cf-zone-auditor/0.1.0 (Antigravity Security Auditor)"),
        );

        let client = Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(30))
            .build()
            .context("Failed to build HTTP client")?;

        Ok(Self {
            client,
            base_url: "https://api.cloudflare.com/client/v4".to_string(),
            account_id,
        })
    }

    #[allow(dead_code)]
    pub fn with_base_url(mut self, base_url: String) -> Self {
        self.base_url = base_url;
        self
    }

    /// Executes an HTTP GET request with automatic retry on 429 Too Many Requests
    async fn get_with_retry(&self, url: &str) -> Result<Response> {
        let mut retries = 0;
        let max_retries = 3;

        loop {
            let resp = self.client.get(url).send().await?;

            if resp.status() == StatusCode::TOO_MANY_REQUESTS && retries < max_retries {
                retries += 1;
                let wait_secs = resp
                    .headers()
                    .get("Retry-After")
                    .and_then(|h| h.to_str().ok())
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(2u64.pow(retries as u32));

                tokio::time::sleep(Duration::from_secs(wait_secs)).await;
                continue;
            }

            return Ok(resp);
        }
    }

    /// Fetch all zones with pagination and optional filter
    pub async fn fetch_zones_list(&self, zone_filter: Option<&str>) -> Result<Vec<Zone>> {
        let mut zones = Vec::new();
        let mut page = 1;
        let per_page = 50;

        loop {
            let mut url = format!(
                "{}/zones?page={}&per_page={}",
                self.base_url, page, per_page
            );

            if let Some(ref acc) = self.account_id {
                url.push_str(&format!("&account.id={}", acc));
            }

            if let Some(filter) = zone_filter
                && !filter.is_empty() {
                    // Check if filter looks like a domain name vs zone ID (32 hex characters)
                    if filter.len() == 32 && filter.chars().all(|c| c.is_ascii_hexdigit()) {
                        // Zone ID
                        let direct_url = format!("{}/zones/{}", self.base_url, filter);
                        let resp = self.get_with_retry(&direct_url).await?;
                        if !resp.status().is_success() {
                            let text = resp.text().await.unwrap_or_default();
                            bail!("Failed to fetch zone {}: {}", filter, text);
                        }
                        let envelope: ApiResponse<Zone> = resp.json().await?;
                        if let Some(z) = envelope.result {
                            return Ok(vec![z]);
                        } else {
                            return Ok(vec![]);
                        }
                    } else {
                        url.push_str(&format!("&name={}", filter));
                    }
                }

            let resp = self.get_with_retry(&url).await?;
            if !resp.status().is_success() {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                bail!("Cloudflare API error (HTTP {}): {}", status, text);
            }

            let envelope: ApiResponse<Vec<Zone>> = resp.json().await?;
            if !envelope.success {
                let errs = envelope
                    .errors
                    .unwrap_or_default()
                    .into_iter()
                    .map(|e| e.message)
                    .collect::<Vec<_>>()
                    .join(", ");
                bail!("Cloudflare API returned error: {}", errs);
            }

            let page_zones = envelope.result.unwrap_or_default();
            let count = page_zones.len();
            zones.extend(page_zones);

            if let Some(info) = envelope.result_info {
                let total_pages = info.total_pages.unwrap_or(1);
                if page >= total_pages || count == 0 {
                    break;
                }
            } else if count < per_page {
                break;
            }

            page += 1;
        }

        Ok(zones)
    }

    /// Fetch all settings for a specific zone
    pub async fn fetch_zone_settings(&self, zone_id: &str) -> Result<ZoneSettings> {
        let url = format!("{}/zones/{}/settings", self.base_url, zone_id);
        let resp = self.get_with_retry(&url).await?;

        if !resp.status().is_success() {
            return Ok(ZoneSettings::default());
        }

        let envelope: ApiResponse<Vec<SettingItem>> = resp.json().await.unwrap_or(ApiResponse {
            success: false,
            errors: None,
            messages: None,
            result: None,
            result_info: None,
        });

        let mut settings = ZoneSettings::default();
        if let Some(items) = envelope.result {
            for item in items {
                match item.id.as_str() {
                    "ssl" => {
                        if let Some(v) = item.value.as_str() {
                            settings.ssl = Some(v.to_string());
                        }
                    }
                    "min_tls_version" => {
                        if let Some(v) = item.value.as_str() {
                            settings.min_tls_version = Some(v.to_string());
                        }
                    }
                    "tls_1_3" => {
                        if let Some(v) = item.value.as_str() {
                            settings.tls_1_3 = Some(v.to_string());
                        }
                    }
                    "always_use_https" => {
                        if let Some(v) = item.value.as_str() {
                            settings.always_use_https = Some(v.to_string());
                        }
                    }
                    "automatic_https_rewrites" => {
                        if let Some(v) = item.value.as_str() {
                            settings.automatic_https_rewrites = Some(v.to_string());
                        }
                    }
                    "opportunistic_encryption" => {
                        if let Some(v) = item.value.as_str() {
                            settings.opportunistic_encryption = Some(v.to_string());
                        }
                    }
                    "security_header" => {
                        if let Ok(sh) =
                            serde_json::from_value::<SecurityHeaderSetting>(item.value.clone())
                        {
                            settings.security_header = Some(sh);
                        } else if let Some(obj) = item.value.as_object()
                            && let Some(sts) = obj.get("strict_transport_security")
                                && let Ok(hsts) = serde_json::from_value::<HstsSetting>(sts.clone())
                                {
                                    settings.security_header = Some(SecurityHeaderSetting {
                                        strict_transport_security: Some(hsts),
                                    });
                                }
                    }
                    "security_level" => {
                        if let Some(v) = item.value.as_str() {
                            settings.security_level = Some(v.to_string());
                        }
                    }
                    "browser_check" => {
                        if let Some(v) = item.value.as_str() {
                            settings.browser_check = Some(v.to_string());
                        }
                    }
                    "challenge_ttl" => {
                        if let Some(v) = item.value.as_i64() {
                            settings.challenge_ttl = Some(v);
                        }
                    }
                    "brotli" => {
                        if let Some(v) = item.value.as_str() {
                            settings.brotli = Some(v.to_string());
                        }
                    }
                    "early_hints" => {
                        if let Some(v) = item.value.as_str() {
                            settings.early_hints = Some(v.to_string());
                        }
                    }
                    _ => {}
                }
            }
        }

        Ok(settings)
    }

    /// Fetch DNSSEC configuration for a zone
    pub async fn fetch_dnssec(&self, zone_id: &str) -> Result<DnssecSetting> {
        let url = format!("{}/zones/{}/dnssec", self.base_url, zone_id);
        let resp = self.get_with_retry(&url).await?;

        if !resp.status().is_success() {
            return Ok(DnssecSetting::default());
        }

        let envelope: ApiResponse<DnssecSetting> = resp.json().await.unwrap_or(ApiResponse {
            success: false,
            errors: None,
            messages: None,
            result: None,
            result_info: None,
        });

        Ok(envelope.result.unwrap_or_default())
    }

    /// Fetch WAF configuration (Packages and Modern Rulesets)
    pub async fn fetch_waf(&self, zone_id: &str) -> Result<WafSetting> {
        let mut waf = WafSetting::default();

        // 1. Check WAF packages
        let pkg_url = format!("{}/zones/{}/firewall/waf/packages", self.base_url, zone_id);
        if let Ok(resp) = self.get_with_retry(&pkg_url).await
            && resp.status().is_success()
                && let Ok(envelope) = resp.json::<ApiResponse<Vec<WafPackage>>>().await
                    && let Some(pkgs) = envelope.result
                        && !pkgs.is_empty() {
                            waf.waf_enabled = true;
                            waf.managed_rules_active = true;
                            waf.packages = pkgs;
                        }

        // 2. Check Modern Rulesets
        let ruleset_url = format!("{}/zones/{}/rulesets", self.base_url, zone_id);
        if let Ok(resp) = self.get_with_retry(&ruleset_url).await
            && resp.status().is_success()
                && let Ok(envelope) = resp.json::<ApiResponse<Vec<RulesetInfo>>>().await
                    && let Some(rulesets) = envelope.result
                        && !rulesets.is_empty() {
                            waf.waf_enabled = true;
                            waf.managed_rules_active = true;
                            waf.rulesets = rulesets;
                        }

        Ok(waf)
    }

    /// Fetch Bot Management / Bot Fight Mode
    pub async fn fetch_bot_management(&self, zone_id: &str) -> Result<BotManagementSetting> {
        let url = format!("{}/zones/{}/bot_management", self.base_url, zone_id);
        if let Ok(resp) = self.get_with_retry(&url).await
            && resp.status().is_success()
                && let Ok(envelope) = resp.json::<ApiResponse<BotManagementSetting>>().await
                    && let Some(bot) = envelope.result {
                        return Ok(bot);
                    }
        Ok(BotManagementSetting::default())
    }

    /// Fetch Rate Limiting rules
    pub async fn fetch_rate_limits(&self, zone_id: &str) -> Result<RateLimitSetting> {
        let url = format!("{}/zones/{}/rate_limits", self.base_url, zone_id);
        if let Ok(resp) = self.get_with_retry(&url).await
            && resp.status().is_success()
                && let Ok(envelope) = resp.json::<ApiResponse<Vec<RateLimitRule>>>().await {
                    return Ok(RateLimitSetting {
                        rules: envelope.result.unwrap_or_default(),
                    });
                }
        Ok(RateLimitSetting::default())
    }

    /// Fetch Zone Lockdown rules
    pub async fn fetch_lockdowns(&self, zone_id: &str) -> Result<ZoneLockdownSetting> {
        let url = format!("{}/zones/{}/firewall/lockdowns", self.base_url, zone_id);
        if let Ok(resp) = self.get_with_retry(&url).await
            && resp.status().is_success()
                && let Ok(envelope) = resp.json::<ApiResponse<Vec<ZoneLockdownRule>>>().await {
                    return Ok(ZoneLockdownSetting {
                        rules: envelope.result.unwrap_or_default(),
                    });
                }
        Ok(ZoneLockdownSetting::default())
    }

    /// Fetch IP Access Rules
    pub async fn fetch_ip_access_rules(&self, zone_id: &str) -> Result<IpAccessRulesSetting> {
        let url = format!(
            "{}/zones/{}/firewall/access_rules/rules",
            self.base_url, zone_id
        );
        if let Ok(resp) = self.get_with_retry(&url).await
            && resp.status().is_success()
                && let Ok(envelope) = resp.json::<ApiResponse<Vec<IpAccessRule>>>().await {
                    return Ok(IpAccessRulesSetting {
                        rules: envelope.result.unwrap_or_default(),
                    });
                }
        Ok(IpAccessRulesSetting::default())
    }

    /// Fetches all audit data for a single zone concurrently
    pub async fn fetch_zone_audit_data(&self, zone: Zone) -> Result<ZoneAuditData> {
        let zone_id = zone.id.clone();

        let (settings_res, dnssec_res, waf_res, bot_res, rate_res, lock_res, ip_res) = tokio::join!(
            self.fetch_zone_settings(&zone_id),
            self.fetch_dnssec(&zone_id),
            self.fetch_waf(&zone_id),
            self.fetch_bot_management(&zone_id),
            self.fetch_rate_limits(&zone_id),
            self.fetch_lockdowns(&zone_id),
            self.fetch_ip_access_rules(&zone_id),
        );

        Ok(ZoneAuditData {
            zone,
            settings: settings_res.unwrap_or_default(),
            dnssec: dnssec_res.unwrap_or_default(),
            waf: waf_res.unwrap_or_default(),
            bot_management: bot_res.unwrap_or_default(),
            rate_limits: rate_res.unwrap_or_default(),
            lockdowns: lock_res.unwrap_or_default(),
            ip_access_rules: ip_res.unwrap_or_default(),
        })
    }
}

impl ZoneDataProvider for CloudflareClient {
    fn fetch_all_zones<'a>(
        &'a self,
        zone_filter: Option<&'a str>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<ZoneAuditData>>> + Send + 'a>> {
        Box::pin(async move {
            let zones = self.fetch_zones_list(zone_filter).await?;

            let mut tasks = Vec::new();
            for zone in zones {
                tasks.push(self.fetch_zone_audit_data(zone));
            }

            let mut results = Vec::with_capacity(tasks.len());
            for task in tasks {
                results.push(task.await?);
            }

            Ok(results)
        })
    }
}
