use crate::zone::models::AggregateAuditReport;
use anyhow::Result;

pub fn render_json(report: &AggregateAuditReport) -> Result<String> {
    let json_str = serde_json::to_string_pretty(report)?;
    Ok(json_str)
}
