use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::secrets::rules::types::{Finding, Rule};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifReport {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub version: String,
    pub runs: Vec<SarifRun>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRun {
    pub tool: SarifTool,
    pub results: Vec<SarifResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifTool {
    pub driver: SarifDriver,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifDriver {
    pub name: String,
    pub version: String,
    #[serde(rename = "informationUri")]
    pub information_uri: String,
    pub rules: Vec<SarifRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRule {
    pub id: String,
    pub name: String,
    #[serde(rename = "shortDescription")]
    pub short_description: SarifMessage,
    #[serde(rename = "fullDescription")]
    pub full_description: SarifMessage,
    #[serde(rename = "defaultConfiguration")]
    pub default_configuration: SarifConfig,
    pub help: SarifHelp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifConfig {
    pub level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifHelp {
    pub text: String,
    pub markdown: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifResult {
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    pub level: String,
    pub message: SarifMessage,
    pub locations: Vec<SarifLocation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifMessage {
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    pub physical_location: SarifPhysicalLocation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    pub artifact_location: SarifArtifactLocation,
    pub region: SarifRegion,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifArtifactLocation {
    pub uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRegion {
    #[serde(rename = "startLine")]
    pub start_line: usize,
    #[serde(rename = "startColumn")]
    pub start_column: usize,
    #[serde(rename = "endLine")]
    pub end_line: usize,
    #[serde(rename = "endColumn")]
    pub end_column: usize,
    pub snippet: SarifMessage,
}

/// Generates a SARIF v2.1.0 JSON report.
pub fn format_sarif_report(
    findings: &[Finding],
    rules: &[Rule],
    tool_version: &str,
) -> Result<String, serde_json::Error> {
    let mut rule_map: HashMap<String, &Rule> = HashMap::new();
    for rule in rules {
        rule_map.insert(rule.id.clone(), rule);
    }

    // Collect rules that actually have findings or all builtin rules
    let mut sarif_rules = Vec::new();
    for rule in rules {
        sarif_rules.push(SarifRule {
            id: rule.id.clone(),
            name: rule.name.replace(' ', ""),
            short_description: SarifMessage {
                text: rule.name.clone(),
            },
            full_description: SarifMessage {
                text: rule.description.clone(),
            },
            default_configuration: SarifConfig {
                level: rule.severity.to_sarif_level().to_string(),
            },
            help: SarifHelp {
                text: rule.recommendation.clone(),
                markdown: format!("### Remediation\n\n{}", rule.recommendation),
            },
        });
    }

    let mut sarif_results = Vec::new();
    for finding in findings {
        let match_len = finding.raw_secret.len().max(1);
        sarif_results.push(SarifResult {
            rule_id: finding.rule_id.clone(),
            level: finding.severity.to_sarif_level().to_string(),
            message: SarifMessage {
                text: format!(
                    "{}: {} (Secret redacted: {})",
                    finding.rule_name, finding.description, finding.redacted_secret
                ),
            },
            locations: vec![SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: finding.file_path.clone(),
                    },
                    region: SarifRegion {
                        start_line: finding.line_number,
                        start_column: finding.column_number,
                        end_line: finding.line_number,
                        end_column: finding.column_number + match_len,
                        snippet: SarifMessage {
                            text: finding.line_content.clone(),
                        },
                    },
                },
            }],
        });
    }

    let report = SarifReport {
        schema: "https://json.schemastore.org/sarif-2.1.0.json".to_string(),
        version: "2.1.0".to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "cf-secret-leak-guard".to_string(),
                    version: tool_version.to_string(),
                    information_uri: "https://github.com/cloudflare/cf-secret-leak-guard"
                        .to_string(),
                    rules: sarif_rules,
                },
            },
            results: sarif_results,
        }],
    };

    serde_json::to_string_pretty(&report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::rules::types::Severity;

    #[test]
    fn test_sarif_generation() {
        let rule = Rule::new_exact(
            "CF-001",
            "Cloudflare API Token",
            "Detects Cloudflare API Token",
            Severity::Critical,
            "secret_token_1234",
            "Move token to server environment variables",
        );

        let finding = Finding {
            rule_id: "CF-001".into(),
            rule_name: "Cloudflare API Token".into(),
            severity: Severity::Critical,
            file_path: "dist/client/app.js".into(),
            line_number: 12,
            column_number: 8,
            match_start: 50,
            match_end: 67,
            raw_secret: "secret_token_1234".into(),
            redacted_secret: "sec...1234".into(),
            line_content: "const token = [REDACTED]".into(),
            description: "Detects Cloudflare API Token".into(),
            recommendation: "Move token to server environment variables".into(),
        };

        let sarif_json = format_sarif_report(&[finding], &[rule], "0.1.0").unwrap();
        assert!(sarif_json.contains("https://json.schemastore.org/sarif-2.1.0.json"));
        assert!(sarif_json.contains("2.1.0"));
        assert!(sarif_json.contains("CF-001"));
        assert!(sarif_json.contains("dist/client/app.js"));
    }
}
