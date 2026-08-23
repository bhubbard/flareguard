use flareguard::zone::models::*;
use flareguard::zone::rules::definitions::ALL_RULES;
use flareguard::zone::rules::evaluator::evaluate_zone;
use flareguard::zone::scoring::{calculate_grade, grade_description};

fn make_base_zone_data() -> ZoneAuditData {
    ZoneAuditData {
        zone: Zone {
            id: "zone_test_001".to_string(),
            name: "test.example.com".to_string(),
            status: "active".to_string(),
            paused: false,
            zone_type: Some("full".to_string()),
            development_mode: Some(0),
            name_servers: Some(vec!["ns1.cloudflare.com".to_string()]),
            account: Some(AccountInfo {
                id: "acc_001".to_string(),
                name: "Test Org".to_string(),
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
                    max_age: Some(31536000),
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
            ..Default::default()
        },
        waf: WafSetting {
            waf_enabled: true,
            managed_rules_active: true,
            packages: vec![WafPackage {
                id: "pkg1".to_string(),
                name: "OWASP".to_string(),
                ..Default::default()
            }],
            rulesets: vec![],
        },
        bot_management: BotManagementSetting {
            fight_mode: true,
            ..Default::default()
        },
        rate_limits: RateLimitSetting {
            rules: vec![RateLimitRule {
                id: "rl1".to_string(),
                disabled: Some(false),
                threshold: Some(10),
                period: Some(60),
                ..Default::default()
            }],
        },
        lockdowns: ZoneLockdownSetting::default(),
        ip_access_rules: IpAccessRulesSetting::default(),
    }
}

#[test]
fn test_perfect_hardened_zone_evaluation() {
    let data = make_base_zone_data();
    let report = evaluate_zone(&data);

    assert_eq!(report.score, 100);
    assert_eq!(report.grade, "A+");
    assert_eq!(report.findings.len(), 0);
    assert!(report.passed_checks_count > 0);
    assert_eq!(report.passed_checks_count, report.total_checks_count);
}

#[test]
fn test_flexible_ssl_flagged_as_critical() {
    let mut data = make_base_zone_data();
    data.settings.ssl = Some("flexible".to_string());

    let report = evaluate_zone(&data);
    let crit = report.findings.iter().find(|f| f.rule_id == "CF-SSL-001");
    assert!(crit.is_some(), "CF-SSL-001 should trigger for flexible SSL");
    let finding = crit.unwrap();
    assert_eq!(finding.risk_level, RiskLevel::Critical);
    assert!(report.score <= 49, "Critical finding must cap score at <= 49");
    assert_eq!(report.grade, "F");
}

#[test]
fn test_ssl_full_non_strict_flagged_as_medium() {
    let mut data = make_base_zone_data();
    data.settings.ssl = Some("full".to_string());

    let report = evaluate_zone(&data);
    let med = report.findings.iter().find(|f| f.rule_id == "CF-SSL-002");
    assert!(med.is_some());
    assert_eq!(med.unwrap().risk_level, RiskLevel::Medium);
    assert_eq!(report.score, 90);
    assert_eq!(report.grade, "A");
}

#[test]
fn test_deprecated_tls_version_flagged_as_high() {
    let mut data = make_base_zone_data();
    data.settings.min_tls_version = Some("1.0".to_string());

    let report = evaluate_zone(&data);
    let tls_finding = report.findings.iter().find(|f| f.rule_id == "CF-TLS-001");
    assert!(tls_finding.is_some());
    assert_eq!(tls_finding.unwrap().risk_level, RiskLevel::High);
    assert_eq!(report.score, 80);
}

#[test]
fn test_always_use_https_disabled() {
    let mut data = make_base_zone_data();
    data.settings.always_use_https = Some("off".to_string());

    let report = evaluate_zone(&data);
    let https_finding = report.findings.iter().find(|f| f.rule_id == "CF-HTTPS-001");
    assert!(https_finding.is_some());
    assert_eq!(https_finding.unwrap().risk_level, RiskLevel::High);
}

#[test]
fn test_hsts_checks() {
    // 1. HSTS completely disabled
    let mut data = make_base_zone_data();
    data.settings.security_header = Some(SecurityHeaderSetting {
        strict_transport_security: Some(HstsSetting {
            enabled: false,
            ..Default::default()
        }),
    });

    let report = evaluate_zone(&data);
    let hsts_finding = report.findings.iter().find(|f| f.rule_id == "CF-HSTS-001");
    assert!(hsts_finding.is_some());
    assert_eq!(hsts_finding.unwrap().risk_level, RiskLevel::High);

    // 2. HSTS enabled but short max_age (3 months = 7776000s)
    let mut data2 = make_base_zone_data();
    data2.settings.security_header = Some(SecurityHeaderSetting {
        strict_transport_security: Some(HstsSetting {
            enabled: true,
            max_age: Some(7776000),
            include_subdomains: Some(false),
            preload: Some(false),
            nosniff: Some(false),
        }),
    });

    let report2 = evaluate_zone(&data2);
    assert!(report2.findings.iter().any(|f| f.rule_id == "CF-HSTS-002"));
    assert!(report2.findings.iter().any(|f| f.rule_id == "CF-HSTS-003"));
    assert!(report2.findings.iter().any(|f| f.rule_id == "CF-HSTS-004"));
    assert!(report2.findings.iter().any(|f| f.rule_id == "CF-HSTS-005"));
}

#[test]
fn test_permissive_ip_access_rules_critical() {
    let mut data = make_base_zone_data();
    data.ip_access_rules.rules.push(IpAccessRule {
        id: "ip_global_allow".to_string(),
        mode: "whitelist".to_string(),
        configuration: IpAccessConfig {
            target: "ip_range".to_string(),
            value: "0.0.0.0/0".to_string(),
        },
        notes: Some("Bad rule".to_string()),
        paused: Some(false),
    });

    let report = evaluate_zone(&data);
    let perm = report.findings.iter().find(|f| f.rule_id == "CF-SEC-001");
    assert!(perm.is_some());
    assert_eq!(perm.unwrap().risk_level, RiskLevel::Critical);
    assert!(report.score <= 49);
}

#[test]
fn test_paused_ip_access_rule_ignored() {
    let mut data = make_base_zone_data();
    data.ip_access_rules.rules.push(IpAccessRule {
        id: "ip_paused_rule".to_string(),
        mode: "whitelist".to_string(),
        configuration: IpAccessConfig {
            target: "ip_range".to_string(),
            value: "0.0.0.0/0".to_string(),
        },
        notes: Some("Paused rule".to_string()),
        paused: Some(true), // PAUSED!
    });

    let report = evaluate_zone(&data);
    assert!(!report.findings.iter().any(|f| f.rule_id == "CF-SEC-001"));
    assert_eq!(report.score, 100);
}

#[test]
fn test_dnssec_disabled() {
    let mut data = make_base_zone_data();
    data.dnssec.status = "disabled".to_string();

    let report = evaluate_zone(&data);
    let dns_finding = report.findings.iter().find(|f| f.rule_id == "CF-DNS-001");
    assert!(dns_finding.is_some());
    assert_eq!(dns_finding.unwrap().risk_level, RiskLevel::Medium);
}

#[test]
fn test_all_rules_metadata_integrity() {
    assert!(ALL_RULES.len() >= 12);
    for r in ALL_RULES {
        assert!(!r.id.is_empty());
        assert!(!r.name.is_empty());
        assert!(!r.title.is_empty());
        assert!(!r.description.is_empty());
        assert!(!r.remediation.is_empty());
        assert!(r.doc_url.starts_with("https://"));
    }
}

#[test]
fn test_grade_descriptions() {
    assert_eq!(calculate_grade(100), "A+");
    assert_eq!(calculate_grade(95), "A+");
    assert_eq!(calculate_grade(92), "A");
    assert_eq!(calculate_grade(85), "B");
    assert_eq!(calculate_grade(75), "C");
    assert_eq!(calculate_grade(65), "D");
    assert_eq!(calculate_grade(45), "F");
    assert!(grade_description("A+").contains("Excellent"));
}
