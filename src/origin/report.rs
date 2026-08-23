use crate::origin::error::{HunterError, Result};
use crate::origin::models::{ConfidenceLevel, ScanReport};
use colored::Colorize;
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Attribute, Cell, Color, ContentArrangement, Table};
use serde_json::json;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
    Sarif,
    Html,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "text" | "term" | "terminal" | "table" => Ok(OutputFormat::Text),
            "json" => Ok(OutputFormat::Json),
            "sarif" => Ok(OutputFormat::Sarif),
            "html" => Ok(OutputFormat::Html),
            _ => Err(format!("Unsupported output format '{}'. Valid: text, json, sarif, html", s)),
        }
    }
}

/// Renders scan report in the requested output format
pub fn render_report(report: &ScanReport, format: OutputFormat) -> Result<String> {
    match format {
        OutputFormat::Text => Ok(render_text(report)),
        OutputFormat::Json => Ok(render_json(report)?),
        OutputFormat::Sarif => Ok(render_sarif(report)?),
        OutputFormat::Html => Ok(render_html(report)),
    }
}

/// Renders rich colored terminal report with comfy-table
pub fn render_text(report: &ScanReport) -> String {
    let mut out = String::new();

    out.push_str("\n");
    out.push_str(&"╔══════════════════════════════════════════════════════════════════════════════╗\n".bright_cyan().bold().to_string());
    out.push_str(&"║                      CLOUDFLARE ORIGIN HUNTER (v0.1.0)                       ║\n".bright_cyan().bold().to_string());
    out.push_str(&"╚══════════════════════════════════════════════════════════════════════════════╝\n".bright_cyan().bold().to_string());
    out.push_str("\n");

    out.push_str(&format!("  🎯 Target Domain:      {}\n", report.summary.target_domain.bright_yellow().bold()));
    out.push_str(&format!("  🕒 Scanned At:          {}\n", report.summary.scanned_at.format("%Y-%m-%d %H:%M:%S UTC").to_string().cyan()));
    out.push_str(&format!("  ⏱️  Scan Duration:       {:.2}s\n", report.summary.duration_seconds));
    
    let cf_status = if report.summary.is_behind_cloudflare {
        "PROXIED BEHIND CLOUDFLARE".bright_green().bold()
    } else {
        "DIRECT / NOT CLOUDFLARE PROXIED".bright_red().bold()
    };
    out.push_str(&format!("  🛡️  Cloudflare Edge:    {}\n", cf_status));

    let edge_ips_str = report
        .summary
        .cloudflare_edge_ips
        .iter()
        .map(|ip| ip.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    out.push_str(&format!("  🌐 Cloudflare Edge IPs: {}\n", if edge_ips_str.is_empty() { "None".dimmed().to_string() } else { edge_ips_str.cyan().to_string() }));

    if let Some(ref title) = report.baseline.html_title {
        out.push_str(&format!("  📄 Baseline Title:     {}\n", title.dimmed()));
    }
    if let Some(ref hash) = report.baseline.body_sha256 {
        out.push_str(&format!("  🔑 Baseline SHA-256:   {}\n", hash[..16].dimmed()));
    }

    out.push_str("\n");
    out.push_str(&"─── CANDIDATE ORIGIN IP FINDINGS ───────────────────────────────────────────────\n".bright_white().bold().to_string());

    if report.findings.is_empty() {
        out.push_str(&format!("  {}\n\n", "✅ No unmasked origin IP addresses detected. Target is well-protected.".bright_green().bold()));
    } else {
        let mut table = Table::new();
        table.load_preset(UTF8_FULL);
        table.apply_modifier(UTF8_ROUND_CORNERS);
        table.set_content_arrangement(ContentArrangement::Dynamic);

        table.set_header(vec![
            Cell::new("IP Address").add_attribute(Attribute::Bold),
            Cell::new("Confidence").add_attribute(Attribute::Bold),
            Cell::new("Score").add_attribute(Attribute::Bold),
            Cell::new("Source").add_attribute(Attribute::Bold),
            Cell::new("Direct Server").add_attribute(Attribute::Bold),
            Cell::new("Analysis / Reason").add_attribute(Attribute::Bold),
        ]);

        for finding in &report.findings {
            let conf_cell = match finding.confidence {
                ConfidenceLevel::Confirmed => Cell::new("CONFIRMED").fg(Color::Red).add_attribute(Attribute::Bold),
                ConfidenceLevel::High => Cell::new("HIGH").fg(Color::Yellow).add_attribute(Attribute::Bold),
                ConfidenceLevel::Medium => Cell::new("MEDIUM").fg(Color::Cyan),
                ConfidenceLevel::Low => Cell::new("LOW").fg(Color::DarkGrey),
            };

            let score_str = format!("{}%", finding.confidence_score);
            let score_cell = match finding.confidence {
                ConfidenceLevel::Confirmed => Cell::new(&score_str).fg(Color::Red).add_attribute(Attribute::Bold),
                ConfidenceLevel::High => Cell::new(&score_str).fg(Color::Yellow),
                _ => Cell::new(&score_str),
            };

            let server_name = finding
                .successful_probes
                .first()
                .and_then(|p| p.server_header.as_deref())
                .unwrap_or("N/A");

            let source_str = finding.discovery_source.to_string();

            table.add_row(vec![
                Cell::new(finding.candidate_ip.to_string()).add_attribute(Attribute::Bold),
                conf_cell,
                score_cell,
                Cell::new(source_str),
                Cell::new(server_name),
                Cell::new(&finding.confidence_reason),
            ]);
        }

        out.push_str(&table.to_string());
        out.push_str("\n\n");

        // Risk Summary Stats
        out.push_str(&format!(
            "  📊 Origin Leak Summary: {} Confirmed, {} High, {} Medium, {} Low\n\n",
            report.summary.origins_confirmed.to_string().bright_red().bold(),
            report.summary.high_confidence_origins.to_string().bright_yellow().bold(),
            report.summary.medium_confidence_origins.to_string().bright_cyan(),
            report.summary.low_confidence_origins.to_string().dimmed()
        ));
    }

    // Remediation Plan Section
    if report.summary.is_origin_leaked {
        out.push_str(&"─── ACTIONABLE REMEDIATION STEPS ──────────────────────────────────────────────\n".bright_red().bold().to_string());
        for step in &report.remediation {
            out.push_str(&format!("\n  [{}] {} ({})\n", step.id.bold().yellow(), step.title.bold().white(), step.priority.bright_red()));
            out.push_str(&format!("  📝 {}\n", step.description));
            if !step.commands.is_empty() {
                out.push_str("  💻 Commands:\n");
                for cmd in &step.commands {
                    out.push_str(&format!("     {}\n", cmd.bright_cyan()));
                }
            }
            out.push_str(&format!("  🔗 Docs: {}\n", step.doc_url.dimmed()));
        }
        out.push_str("\n");
    }

    out
}

/// Renders JSON format
pub fn render_json(report: &ScanReport) -> Result<String> {
    serde_json::to_string_pretty(report).map_err(HunterError::from)
}

/// Renders OASIS SARIF v2.1.0 format
pub fn render_sarif(report: &ScanReport) -> Result<String> {
    let mut results = Vec::new();

    for finding in &report.findings {
        let (rule_id, level, title) = match finding.confidence {
            ConfidenceLevel::Confirmed => ("CF-ORIGIN-LEAK-CONFIRMED", "error", "Cloudflare Origin IP Directly Exposed (Confirmed)"),
            ConfidenceLevel::High => ("CF-ORIGIN-LEAK-HIGH", "error", "Cloudflare Origin IP Likely Exposed (High Confidence)"),
            ConfidenceLevel::Medium => ("CF-ORIGIN-LEAK-MEDIUM", "warning", "Potential Cloudflare Origin IP Exposed (Medium Confidence)"),
            ConfidenceLevel::Low => ("CF-ORIGIN-LEAK-LOW", "note", "Unverified Candidate Origin IP (Low Confidence)"),
        };

        let result_obj = json!({
            "ruleId": rule_id,
            "level": level,
            "message": {
                "text": format!(
                    "{}: IP {} discovered via {}. {}",
                    title, finding.candidate_ip, finding.discovery_source, finding.confidence_reason
                )
            },
            "properties": {
                "candidateIp": finding.candidate_ip.to_string(),
                "confidenceLevel": finding.confidence.to_string(),
                "confidenceScore": finding.confidence_score,
                "hostname": finding.hostname,
                "discoverySource": finding.discovery_source.to_string()
            }
        });

        results.push(result_obj);
    }

    let sarif_obj = json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "cf-origin-hunter",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/cloudflare-security/cf-origin-hunter",
                        "rules": [
                            {
                                "id": "CF-ORIGIN-LEAK-CONFIRMED",
                                "shortDescription": { "text": "Cloudflare Origin IP Directly Exposed (Confirmed)" },
                                "defaultConfiguration": { "level": "error" }
                            },
                            {
                                "id": "CF-ORIGIN-LEAK-HIGH",
                                "shortDescription": { "text": "Cloudflare Origin IP Likely Exposed (High Confidence)" },
                                "defaultConfiguration": { "level": "error" }
                            },
                            {
                                "id": "CF-ORIGIN-LEAK-MEDIUM",
                                "shortDescription": { "text": "Potential Cloudflare Origin IP Exposed (Medium Confidence)" },
                                "defaultConfiguration": { "level": "warning" }
                            },
                            {
                                "id": "CF-ORIGIN-LEAK-LOW",
                                "shortDescription": { "text": "Unverified Candidate Origin IP (Low Confidence)" },
                                "defaultConfiguration": { "level": "note" }
                            }
                        ]
                    }
                },
                "results": results
            }
        ]
    });

    serde_json::to_string_pretty(&sarif_obj).map_err(HunterError::from)
}

/// Renders a modern HTML report
pub fn render_html(report: &ScanReport) -> String {
    let mut rows = String::new();

    for finding in &report.findings {
        let (badge_class, badge_label) = match finding.confidence {
            ConfidenceLevel::Confirmed => ("badge-confirmed", "CONFIRMED 100%"),
            ConfidenceLevel::High => ("badge-high", "HIGH"),
            ConfidenceLevel::Medium => ("badge-medium", "MEDIUM"),
            ConfidenceLevel::Low => ("badge-low", "LOW"),
        };

        let server_name = finding
            .successful_probes
            .first()
            .and_then(|p| p.server_header.as_deref())
            .unwrap_or("N/A");

        rows.push_str(&format!(
            r#"<tr>
                <td><code>{}</code></td>
                <td><span class="badge {}">{}</span></td>
                <td><strong>{}%</strong></td>
                <td>{}</td>
                <td><code>{}</code></td>
                <td>{}</td>
            </tr>"#,
            finding.candidate_ip,
            badge_class,
            badge_label,
            finding.confidence_score,
            finding.discovery_source,
            server_name,
            finding.confidence_reason
        ));
    }

    let mut rem_cards = String::new();
    for step in &report.remediation {
        let mut cmds = String::new();
        for cmd in &step.commands {
            cmds.push_str(&format!("<code>{}</code>\n", cmd));
        }

        rem_cards.push_str(&format!(
            r#"<div class="rem-card">
                <div class="rem-header">
                    <span class="rem-id">{}</span>
                    <h3>{}</h3>
                    <span class="badge-priority">{}</span>
                </div>
                <p>{}</p>
                <pre>{}</pre>
                <a href="{}" target="_blank" rel="noreferrer">Cloudflare Documentation &rarr;</a>
            </div>"#,
            step.id, step.title, step.priority, step.description, cmds, step.doc_url
        ));
    }

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cloudflare Origin Hunter Audit - {}</title>
    <style>
        :root {{
            --bg: #0f172a;
            --card-bg: #1e293b;
            --text: #f8fafc;
            --text-muted: #94a3b8;
            --accent: #f97316;
            --border: #334155;
            --red: #ef4444;
            --yellow: #f59e0b;
            --cyan: #06b6d4;
            --green: #10b981;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: var(--bg);
            color: var(--text);
            margin: 0;
            padding: 2rem;
            line-height: 1.5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        header {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 2rem;
        }}
        h1 {{
            margin: 0 0 0.5rem 0;
            color: var(--accent);
        }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 1rem;
            margin-top: 1rem;
        }}
        .stat-card {{
            background: #0f172a;
            padding: 1rem;
            border-radius: 8px;
            border: 1px solid var(--border);
        }}
        .stat-val {{
            font-size: 1.8rem;
            font-weight: bold;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: var(--card-bg);
            border-radius: 12px;
            overflow: hidden;
            border: 1px solid var(--border);
            margin-bottom: 2rem;
        }}
        th, td {{
            padding: 0.8rem 1rem;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }}
        th {{
            background: #0f172a;
            color: var(--text-muted);
            font-weight: 600;
        }}
        .badge {{
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: bold;
            display: inline-block;
        }}
        .badge-confirmed {{ background: #991b1b; color: #fee2e2; }}
        .badge-high {{ background: #854d0e; color: #fef9c3; }}
        .badge-medium {{ background: #155e75; color: #cffafe; }}
        .badge-low {{ background: #374151; color: #e5e7eb; }}
        .rem-card {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 1.25rem;
            margin-bottom: 1rem;
        }}
        .rem-header {{
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }}
        .rem-id {{
            background: var(--accent);
            color: #000;
            font-weight: bold;
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
        }}
        pre {{
            background: #0f172a;
            padding: 1rem;
            border-radius: 8px;
            overflow-x: auto;
            border: 1px solid var(--border);
        }}
        code {{
            font-family: monospace;
            color: #38bdf8;
        }}
        a {{
            color: var(--accent);
            text-decoration: none;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ Cloudflare Origin Hunter Audit</h1>
            <p>Target: <strong>{}</strong> | Generated at: {}</p>
            <div class="grid">
                <div class="stat-card">
                    <div style="color: var(--text-muted);">Confirmed Origins</div>
                    <div class="stat-val" style="color: var(--red);">{}</div>
                </div>
                <div class="stat-card">
                    <div style="color: var(--text-muted);">High Confidence</div>
                    <div class="stat-val" style="color: var(--yellow);">{}</div>
                </div>
                <div class="stat-card">
                    <div style="color: var(--text-muted);">Medium Candidates</div>
                    <div class="stat-val" style="color: var(--cyan);">{}</div>
                </div>
                <div class="stat-card">
                    <div style="color: var(--text-muted);">Proxy Status</div>
                    <div class="stat-val" style="color: var(--green);">{}</div>
                </div>
            </div>
        </header>

        <h2>Discovered Candidate Findings</h2>
        <table>
            <thead>
                <tr>
                    <th>IP Address</th>
                    <th>Confidence</th>
                    <th>Score</th>
                    <th>Source</th>
                    <th>Direct Server</th>
                    <th>Reason</th>
                </tr>
            </thead>
            <tbody>
                {}
            </tbody>
        </table>

        <h2>Actionable Mitigation Plan</h2>
        {}
    </div>
</body>
</html>"#,
        report.summary.target_domain,
        report.summary.target_domain,
        report.summary.scanned_at.format("%Y-%m-%d %H:%M:%S UTC"),
        report.summary.origins_confirmed,
        report.summary.high_confidence_origins,
        report.summary.medium_confidence_origins,
        if report.summary.is_behind_cloudflare { "Cloudflare Proxied" } else { "Direct" },
        rows,
        rem_cards
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::origin::mock::run_mock_scan;

    #[test]
    fn test_render_text() {
        let report = run_mock_scan("example.com");
        let txt = render_text(&report);
        assert!(txt.contains("CLOUDFLARE ORIGIN HUNTER"));
        assert!(txt.contains("198.51.100.42"));
        assert!(txt.contains("CONFIRMED"));
    }

    #[test]
    fn test_render_json() {
        let report = run_mock_scan("example.com");
        let json_str = render_json(&report).unwrap();
        assert!(json_str.contains("\"target_domain\": \"example.com\""));
    }

    #[test]
    fn test_render_sarif() {
        let report = run_mock_scan("example.com");
        let sarif_str = render_sarif(&report).unwrap();
        assert!(sarif_str.contains("CF-ORIGIN-LEAK-CONFIRMED"));
        assert!(sarif_str.contains("sarif-schema-2.1.0.json"));
    }

    #[test]
    fn test_render_html() {
        let report = run_mock_scan("example.com");
        let html_str = render_html(&report);
        assert!(html_str.contains("<html"));
        assert!(html_str.contains("198.51.100.42"));
    }
}
