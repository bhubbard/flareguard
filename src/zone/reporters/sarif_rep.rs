use crate::zone::models::{
    AggregateAuditReport, RiskLevel, SarifArtifactLocation, SarifDriver, SarifLocation,
    SarifMessage, SarifPhysicalLocation, SarifProperties, SarifReport, SarifResult, SarifRun,
    SarifRuleConfiguration, SarifRuleDescriptor, SarifTool,
};
use crate::zone::rules::definitions::ALL_RULES;
use anyhow::Result;

pub fn render_sarif(report: &AggregateAuditReport) -> Result<String> {
    let mut sarif_rules = Vec::new();

    for def in ALL_RULES {
        let level = match def.default_severity {
            RiskLevel::Critical | RiskLevel::High => "error",
            RiskLevel::Medium => "warning",
            RiskLevel::Low | RiskLevel::Info => "note",
        };

        let sec_severity = match def.default_severity {
            RiskLevel::Critical => "9.0",
            RiskLevel::High => "7.5",
            RiskLevel::Medium => "5.0",
            RiskLevel::Low => "2.5",
            RiskLevel::Info => "1.0",
        };

        sarif_rules.push(SarifRuleDescriptor {
            id: def.id.to_string(),
            name: def.name.to_string(),
            short_description: SarifMessage {
                text: def.title.to_string(),
            },
            full_description: SarifMessage {
                text: format!("{}. Remediation: {}", def.description, def.remediation),
            },
            default_configuration: SarifRuleConfiguration {
                level: level.to_string(),
            },
            help_uri: Some(def.doc_url.to_string()),
            properties: Some(SarifProperties {
                tags: vec![
                    "security".to_string(),
                    "cloudflare".to_string(),
                    format!("{:?}", def.category).to_lowercase(),
                ],
                precision: "high".to_string(),
                security_severity: Some(sec_severity.to_string()),
            }),
        });
    }

    let mut results = Vec::new();

    for z in &report.zone_reports {
        for f in &z.findings {
            let level = match f.risk_level {
                RiskLevel::Critical | RiskLevel::High => "error",
                RiskLevel::Medium => "warning",
                RiskLevel::Low | RiskLevel::Info => "note",
            };

            let message_text = format!(
                "{}: {}. Actual: '{}', Expected: '{}'. Remediation: {}",
                f.title, f.description, f.actual_value, f.expected_value, f.remediation
            );

            results.push(SarifResult {
                rule_id: f.rule_id.clone(),
                level: level.to_string(),
                message: SarifMessage { text: message_text },
                locations: vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation {
                            uri: format!("zone:{}", z.zone_name),
                        },
                    },
                }],
            });
        }
    }

    let sarif = SarifReport {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".to_string(),
        version: "2.1.0".to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "cf-zone-auditor".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    information_uri: "https://github.com/cloudflare-security-report/cf-zone-auditor".to_string(),
                    rules: sarif_rules,
                },
            },
            results,
        }],
    };

    let json_str = serde_json::to_string_pretty(&sarif)?;
    Ok(json_str)
}
