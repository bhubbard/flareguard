pub mod json_format;
pub mod sarif;
pub mod text;

use clap::ValueEnum;
use serde::{Deserialize, Serialize};

pub use json_format::format_json_report;
pub use sarif::format_sarif_report;
pub use text::format_terminal_report;

use crate::secrets::rules::types::Rule;
use crate::secrets::scanner::ScanResult;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    Text,
    Json,
    Sarif,
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputFormat::Text => write!(f, "text"),
            OutputFormat::Json => write!(f, "json"),
            OutputFormat::Sarif => write!(f, "sarif"),
        }
    }
}

/// Renders the scan result according to the specified output format.
pub fn render_report(
    format: OutputFormat,
    result: &ScanResult,
    rules: &[Rule],
    tool_version: &str,
    verbose: bool,
) -> Result<String, String> {
    match format {
        OutputFormat::Text => Ok(format_terminal_report(result, verbose)),
        OutputFormat::Json => format_json_report(&result.findings, &result.stats, tool_version)
            .map_err(|e| format!("Failed to serialize JSON report: {}", e)),
        OutputFormat::Sarif => format_sarif_report(&result.findings, rules, tool_version)
            .map_err(|e| format!("Failed to serialize SARIF report: {}", e)),
    }
}
