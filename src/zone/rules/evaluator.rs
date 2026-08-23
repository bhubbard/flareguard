use crate::zone::models::{
    AuditFinding, RiskLevel, ZoneAuditData, ZoneAuditReport, ZoneSettingsSummary,
};
use crate::zone::rules::definitions::get_rule_by_id;
use crate::zone::scoring::{calculate_grade, calculate_zone_score};

/// Audits a single zone against all security rules and returns a structured ZoneAuditReport
pub fn evaluate_zone(data: &ZoneAuditData) -> ZoneAuditReport {
    let mut findings: Vec<AuditFinding> = Vec::new();
    let mut passed_checks = 0usize;
    let mut total_checks = 0usize;

    // Helper macro to record finding
    macro_rules! check {
        ($rule_id:expr, $passed:expr, $actual:expr, $expected:expr, $severity_override:expr, $penalty:expr) => {{
            total_checks += 1;
            if $passed {
                passed_checks += 1;
            } else {
                if let Some(def) = get_rule_by_id($rule_id) {
                    let severity: RiskLevel = $severity_override.unwrap_or(def.default_severity);
                    findings.push(AuditFinding {
                        rule_id: def.id.to_string(),
                        rule_name: def.name.to_string(),
                        category: def.category,
                        risk_level: severity,
                        title: def.title.to_string(),
                        description: def.description.to_string(),
                        actual_value: $actual.to_string(),
                        expected_value: $expected.to_string(),
                        remediation: def.remediation.to_string(),
                        score_penalty: $penalty,
                        doc_url: Some(def.doc_url.to_string()),
                    });
                }
            }
        }};
    }

    // 1. SSL/TLS Mode Check (CF-SSL-001, CF-SSL-002)
    let ssl_mode = data.settings.ssl.as_deref().unwrap_or("unknown").to_lowercase();
    match ssl_mode.as_str() {
        "off" => {
            check!(
                "CF-SSL-001",
                false,
                "off (SSL disabled)",
                "strict (Full strict)",
                Some(RiskLevel::Critical),
                35
            );
        }
        "flexible" => {
            check!(
                "CF-SSL-001",
                false,
                "flexible (Insecure edge-only encryption)",
                "strict (Full strict)",
                Some(RiskLevel::Critical),
                30
            );
        }
        "full" => {
            check!(
                "CF-SSL-002",
                false,
                "full (Non-strict origin certificate)",
                "strict (Full strict)",
                Some(RiskLevel::Medium),
                10
            );
        }
        "strict" => {
            check!("CF-SSL-001", true, "strict", "strict", None, 0);
        }
        other => {
            check!(
                "CF-SSL-001",
                false,
                format!("unknown/unconfigured ({})", other),
                "strict",
                Some(RiskLevel::High),
                25
            );
        }
    }

    // 2. Minimum TLS Version (CF-TLS-001)
    let min_tls = data
        .settings
        .min_tls_version
        .as_deref()
        .unwrap_or("1.0")
        .to_string();
    let min_tls_passed = min_tls == "1.2" || min_tls == "1.3";
    check!(
        "CF-TLS-001",
        min_tls_passed,
        format!("TLS {}", min_tls),
        "TLS 1.2 or TLS 1.3",
        if !min_tls_passed { Some(RiskLevel::High) } else { None },
        if !min_tls_passed { 20 } else { 0 }
    );

    // 3. TLS 1.3 Protocol (CF-TLS-002)
    let tls13_on = data
        .settings
        .tls_1_3
        .as_deref()
        .map(|v| v.eq_ignore_ascii_case("on") || v.eq_ignore_ascii_case("zrt"))
        .unwrap_or(false);
    check!(
        "CF-TLS-002",
        tls13_on,
        if tls13_on { "on" } else { "off" },
        "on",
        Some(RiskLevel::Low),
        if !tls13_on { 5 } else { 0 }
    );

    // 4. Always Use HTTPS (CF-HTTPS-001)
    let always_https = data
        .settings
        .always_use_https
        .as_deref()
        .map(|v| v.eq_ignore_ascii_case("on"))
        .unwrap_or(false);
    check!(
        "CF-HTTPS-001",
        always_https,
        if always_https { "on" } else { "off" },
        "on",
        Some(RiskLevel::High),
        if !always_https { 20 } else { 0 }
    );

    // 5. Automatic HTTPS Rewrites (CF-HTTPS-002)
    let auto_rewrites = data
        .settings
        .automatic_https_rewrites
        .as_deref()
        .map(|v| v.eq_ignore_ascii_case("on"))
        .unwrap_or(false);
    check!(
        "CF-HTTPS-002",
        auto_rewrites,
        if auto_rewrites { "on" } else { "off" },
        "on",
        Some(RiskLevel::Medium),
        if !auto_rewrites { 10 } else { 0 }
    );

    // 6. HSTS (CF-HSTS-001, CF-HSTS-002, CF-HSTS-003, CF-HSTS-004, CF-HSTS-005)
    let hsts_opt = data
        .settings
        .security_header
        .as_ref()
        .and_then(|sh| sh.strict_transport_security.as_ref());

    let hsts_enabled = hsts_opt.map(|h| h.enabled).unwrap_or(false);
    check!(
        "CF-HSTS-001",
        hsts_enabled,
        if hsts_enabled { "enabled" } else { "disabled" },
        "enabled",
        Some(RiskLevel::High),
        if !hsts_enabled { 20 } else { 0 }
    );

    if hsts_enabled {
        if let Some(hsts) = hsts_opt {
            let max_age = hsts.max_age.unwrap_or(0);
            let six_months = 15_552_000u64;
            let one_year = 31_536_000u64;

            if max_age < six_months {
                check!(
                    "CF-HSTS-002",
                    false,
                    format!("{} seconds (~{:.1} months)", max_age, (max_age as f64) / 2_592_000.0),
                    ">= 15,552,000 seconds (6 months)",
                    Some(RiskLevel::Medium),
                    10
                );
            } else if max_age < one_year {
                check!(
                    "CF-HSTS-002",
                    false,
                    format!("{} seconds (~{:.1} months)", max_age, (max_age as f64) / 2_592_000.0),
                    ">= 31,536,000 seconds (1 year / Preload ready)",
                    Some(RiskLevel::Low),
                    5
                );
            } else {
                check!("CF-HSTS-002", true, format!("{}s", max_age), ">= 15,552,000s", None, 0);
            }

            let subdomains = hsts.include_subdomains.unwrap_or(false);
            check!(
                "CF-HSTS-003",
                subdomains,
                if subdomains { "true" } else { "false" },
                "true",
                Some(RiskLevel::Medium),
                if !subdomains { 10 } else { 0 }
            );

            let preload = hsts.preload.unwrap_or(false);
            check!(
                "CF-HSTS-004",
                preload,
                if preload { "true" } else { "false" },
                "true",
                Some(RiskLevel::Low),
                if !preload { 5 } else { 0 }
            );

            let nosniff = hsts.nosniff.unwrap_or(false);
            check!(
                "CF-HSTS-005",
                nosniff,
                if nosniff { "true" } else { "false" },
                "true",
                Some(RiskLevel::Low),
                if !nosniff { 5 } else { 0 }
            );
        }
    }

    // 7. WAF & Managed Rules (CF-WAF-001)
    let waf_active = data.waf.waf_enabled
        || data.waf.managed_rules_active
        || !data.waf.packages.is_empty()
        || !data.waf.rulesets.is_empty();
    check!(
        "CF-WAF-001",
        waf_active,
        if waf_active { "Active (Managed Rules/Rulesets Configured)" } else { "Disabled / Not Configured" },
        "Active (Cloudflare Managed Ruleset / OWASP enabled)",
        Some(RiskLevel::High),
        if !waf_active { 20 } else { 0 }
    );

    // 8. Bot Fight Mode (CF-BOT-001)
    let bot_active = data.bot_management.fight_mode
        || data.bot_management.sbfm_definitely_automated.is_some()
        || data.bot_management.using_latest_model.unwrap_or(false);
    check!(
        "CF-BOT-001",
        bot_active,
        if bot_active { "Active" } else { "Disabled" },
        "Active (Bot Fight Mode / Super Bot Fight Mode)",
        Some(RiskLevel::Medium),
        if !bot_active { 10 } else { 0 }
    );

    // 9. Rate Limiting (CF-RATE-001)
    let rate_limits_active = !data.rate_limits.rules.is_empty()
        && data.rate_limits.rules.iter().any(|r| !r.disabled.unwrap_or(false));
    check!(
        "CF-RATE-001",
        rate_limits_active,
        if rate_limits_active {
            format!("{} active rules", data.rate_limits.rules.len())
        } else {
            "0 rules configured".to_string()
        },
        ">= 1 Rate Limiting rule",
        Some(RiskLevel::Low),
        if !rate_limits_active { 5 } else { 0 }
    );

    // 10. DNSSEC (CF-DNS-001)
    let dnssec_active = data.dnssec.status.eq_ignore_ascii_case("active");
    check!(
        "CF-DNS-001",
        dnssec_active,
        &data.dnssec.status,
        "active",
        Some(RiskLevel::Medium),
        if !dnssec_active { 10 } else { 0 }
    );

    // 11. Overly Permissive IP Access Rules (CF-SEC-001)
    let mut permissive_rule_found = false;
    let mut permissive_reason = String::new();
    let mut permissive_severity = RiskLevel::High;
    let mut permissive_penalty = 20;

    for rule in &data.ip_access_rules.rules {
        if rule.paused.unwrap_or(false) {
            continue;
        }
        let mode = rule.mode.to_lowercase();
        if mode == "whitelist" || mode == "allow" || mode == "bypass" {
            let target_val = rule.configuration.value.trim().to_lowercase();
            if target_val == "0.0.0.0/0"
                || target_val == "::/0"
                || target_val == "0.0.0.0"
                || target_val == "any"
                || target_val == "*"
            {
                permissive_rule_found = true;
                permissive_severity = RiskLevel::Critical;
                permissive_penalty = 35;
                permissive_reason = format!(
                    "Rule ID '{}' sets global '{}' for target '{}'",
                    rule.id, rule.mode, rule.configuration.value
                );
                break;
            } else if target_val.ends_with("/0")
                || target_val.ends_with("/1")
                || target_val.ends_with("/2")
                || target_val.ends_with("/3")
                || target_val.ends_with("/4")
                || target_val.ends_with("/5")
                || target_val.ends_with("/6")
                || target_val.ends_with("/7")
                || target_val.ends_with("/8")
            {
                permissive_rule_found = true;
                permissive_severity = RiskLevel::High;
                permissive_penalty = 20;
                permissive_reason = format!(
                    "Rule ID '{}' allows excessive subnet range '{}'",
                    rule.id, rule.configuration.value
                );
            }
        }
    }

    check!(
        "CF-SEC-001",
        !permissive_rule_found,
        if permissive_rule_found {
            permissive_reason
        } else {
            "No overly broad IP access allow rules".to_string()
        },
        "Restricted specific IP addresses / narrow CIDRs",
        Some(permissive_severity),
        if permissive_rule_found { permissive_penalty } else { 0 }
    );

    // 12. Zone Security Level (CF-SEC-002)
    let sec_level = data
        .settings
        .security_level
        .as_deref()
        .unwrap_or("medium")
        .to_lowercase();
    match sec_level.as_str() {
        "essentially_off" => {
            check!(
                "CF-SEC-002",
                false,
                "essentially_off",
                "medium or high",
                Some(RiskLevel::High),
                15
            );
        }
        "low" => {
            check!(
                "CF-SEC-002",
                false,
                "low",
                "medium or high",
                Some(RiskLevel::Medium),
                5
            );
        }
        "medium" | "high" | "under_attack" => {
            check!("CF-SEC-002", true, &sec_level, "medium or high", None, 0);
        }
        _ => {
            check!("CF-SEC-002", true, &sec_level, "medium or high", None, 0);
        }
    }

    // 13. Browser Integrity Check (CF-SEC-003)
    let browser_check = data
        .settings
        .browser_check
        .as_deref()
        .map(|v| v.eq_ignore_ascii_case("on"))
        .unwrap_or(true); // default in CF is usually on
    check!(
        "CF-SEC-003",
        browser_check,
        if browser_check { "on" } else { "off" },
        "on",
        Some(RiskLevel::Low),
        if !browser_check { 5 } else { 0 }
    );

    // Calculate score & grade
    let score = calculate_zone_score(&findings);
    let grade = calculate_grade(score).to_string();

    let settings_summary = ZoneSettingsSummary {
        ssl_mode: data.settings.ssl.clone().unwrap_or_else(|| "none".to_string()),
        min_tls: format!("TLS {}", min_tls),
        always_https: if always_https { "Enabled".to_string() } else { "Disabled".to_string() },
        hsts_status: if hsts_enabled { "Enabled".to_string() } else { "Disabled".to_string() },
        dnssec_status: data.dnssec.status.clone(),
        waf_status: if waf_active { "Active".to_string() } else { "Inactive".to_string() },
        bot_fight_mode: if bot_active { "Active".to_string() } else { "Inactive".to_string() },
        security_level: sec_level,
    };

    ZoneAuditReport {
        zone_id: data.zone.id.clone(),
        zone_name: data.zone.name.clone(),
        plan_name: data
            .zone
            .plan
            .as_ref()
            .and_then(|p| p.name.clone())
            .unwrap_or_else(|| "Free Plan".to_string()),
        status: data.zone.status.clone(),
        score,
        grade,
        passed_checks_count: passed_checks,
        total_checks_count: total_checks,
        settings_summary,
        findings,
    }
}
