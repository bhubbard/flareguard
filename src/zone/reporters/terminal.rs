use crate::zone::models::{AggregateAuditReport, RiskLevel};
use colored::*;
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Attribute, Cell, CellAlignment, Color, ContentArrangement, Table};

pub fn render_terminal(report: &AggregateAuditReport, verbose: bool) -> String {
    let mut out = String::new();

    // 1. Executive Header Banner
    out.push_str(&format!(
        "\n{}\n",
        "╔══════════════════════════════════════════════════════════════════════════════╗"
            .cyan()
            .bold()
    ));
    out.push_str(&format!(
        "║  {}  ║\n",
        "🛡️  CLOUDFLARE ZONE SECURITY AUDITOR (cf-zone-auditor)"
            .bright_white()
            .bold()
    ));
    out.push_str(&format!(
        "║  {}  ║\n",
        "   Posture Assessment & Compliance Enforcement Suite".dimmed()
    ));
    out.push_str(&format!(
        "{}\n\n",
        "╚══════════════════════════════════════════════════════════════════════════════╝"
            .cyan()
            .bold()
    ));

    // 2. Executive Score Card & Summary
    let grade_colored = match report.overall_grade.as_str() {
        "A+" => "A+ (EXCELLENT)".bright_green().bold(),
        "A" => "A (STRONG)".bright_green().bold(),
        "B" => "B (GOOD)".green().bold(),
        "C" => "C (MODERATE RISK)".yellow().bold(),
        "D" => "D (HIGH RISK)".bright_yellow().bold(),
        _ => "F (CRITICAL VULNERABILITIES)".bright_red().bold(),
    };

    let score_colored = if report.average_score >= 90.0 {
        format!("{:.1} / 100", report.average_score)
            .bright_green()
            .bold()
    } else if report.average_score >= 80.0 {
        format!("{:.1} / 100", report.average_score).green().bold()
    } else if report.average_score >= 70.0 {
        format!("{:.1} / 100", report.average_score).yellow().bold()
    } else {
        format!("{:.1} / 100", report.average_score)
            .bright_red()
            .bold()
    };

    out.push_str(&format!(
        "  📊 {} {}\n",
        "Audited Timestamp:".dimmed(),
        report.timestamp.to_rfc3339()
    ));
    if let Some(ref acc) = report.account_id {
        out.push_str(&format!("  🏢 {} {}\n", "Account ID:".dimmed(), acc));
    }
    out.push_str(&format!(
        "  🌐 {} {}\n",
        "Total Zones Audited:".dimmed(),
        report.total_zones.to_string().bold()
    ));
    out.push_str(&format!(
        "  🏆 {} {}\n",
        "Account Security Score:".dimmed(),
        score_colored
    ));
    out.push_str(&format!(
        "  🎖️ {} {}\n",
        "Overall Health Grade:".dimmed(),
        grade_colored
    ));
    out.push_str(&format!(
        "  🚨 {} [ {} {} | {} {} | {} {} | {} {} | {} {} ]\n\n",
        "Findings Summary:".dimmed(),
        report
            .total_findings
            .critical
            .to_string()
            .bright_red()
            .bold(),
        "CRITICAL".bright_red(),
        report
            .total_findings
            .high
            .to_string()
            .bright_yellow()
            .bold(),
        "HIGH".bright_yellow(),
        report.total_findings.medium.to_string().yellow(),
        "MEDIUM".yellow(),
        report.total_findings.low.to_string().cyan(),
        "LOW".cyan(),
        report.total_findings.info.to_string().white(),
        "INFO".white(),
    ));

    // 3. Multi-Zone Posture Overview Table
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("Zone Name").add_attribute(Attribute::Bold),
            Cell::new("Plan").add_attribute(Attribute::Bold),
            Cell::new("SSL Mode").add_attribute(Attribute::Bold),
            Cell::new("Min TLS").add_attribute(Attribute::Bold),
            Cell::new("Always HTTPS").add_attribute(Attribute::Bold),
            Cell::new("HSTS").add_attribute(Attribute::Bold),
            Cell::new("WAF").add_attribute(Attribute::Bold),
            Cell::new("DNSSEC").add_attribute(Attribute::Bold),
            Cell::new("Score")
                .add_attribute(Attribute::Bold)
                .set_alignment(CellAlignment::Center),
            Cell::new("Grade")
                .add_attribute(Attribute::Bold)
                .set_alignment(CellAlignment::Center),
        ]);

    for z in &report.zone_reports {
        let ssl_cell = format_ssl_cell(&z.settings_summary.ssl_mode);
        let tls_cell = format_tls_cell(&z.settings_summary.min_tls);
        let https_cell = format_bool_cell(&z.settings_summary.always_https);
        let hsts_cell = format_bool_cell(&z.settings_summary.hsts_status);
        let waf_cell = format_bool_cell(&z.settings_summary.waf_status);
        let dnssec_cell = format_dnssec_cell(&z.settings_summary.dnssec_status);
        let score_cell = format_score_cell(z.score);
        let grade_cell = format_grade_cell(&z.grade);

        table.add_row(vec![
            Cell::new(&z.zone_name).add_attribute(Attribute::Bold),
            Cell::new(&z.plan_name),
            ssl_cell,
            tls_cell,
            https_cell,
            hsts_cell,
            waf_cell,
            dnssec_cell,
            score_cell,
            grade_cell,
        ]);
    }

    out.push_str(&table.to_string());
    out.push_str("\n\n");

    // 4. Detailed Findings Breakdown (if there are findings or verbose mode)
    let has_any_findings = report.zone_reports.iter().any(|z| !z.findings.is_empty());
    if has_any_findings {
        out.push_str(&format!(
            "{}\n",
            "🔍 DETAILED SECURITY FINDINGS & REMEDIATION PLAN"
                .bright_cyan()
                .bold()
        ));
        out.push_str(&format!(
            "{}\n\n",
            "──────────────────────────────────────────────────────────────────────────────"
                .dimmed()
        ));

        for z in &report.zone_reports {
            if z.findings.is_empty() {
                if verbose {
                    out.push_str(&format!(
                        "  ✅ {}: {} (Score: {}/100, Grade: {})\n\n",
                        z.zone_name.bold(),
                        "All security checks passed with zero findings!".bright_green(),
                        z.score,
                        z.grade.bright_green()
                    ));
                }
                continue;
            }

            out.push_str(&format!(
                "  📁 Zone: {}  [ Score: {} | Grade: {} | {} findings ]\n",
                z.zone_name.bright_white().bold(),
                format_score_text(z.score),
                z.grade.bold(),
                z.findings.len()
            ));

            let mut finding_table = Table::new();
            finding_table
                .load_preset(UTF8_FULL)
                .apply_modifier(UTF8_ROUND_CORNERS)
                .set_content_arrangement(ContentArrangement::Dynamic)
                .set_header(vec![
                    Cell::new("ID").add_attribute(Attribute::Bold),
                    Cell::new("Severity").add_attribute(Attribute::Bold),
                    Cell::new("Title & Finding").add_attribute(Attribute::Bold),
                    Cell::new("Current vs Expected").add_attribute(Attribute::Bold),
                    Cell::new("Remediation Guidance").add_attribute(Attribute::Bold),
                ]);

            for f in &z.findings {
                let sev_cell = match f.risk_level {
                    RiskLevel::Critical => Cell::new("CRITICAL")
                        .fg(Color::Red)
                        .add_attribute(Attribute::Bold),
                    RiskLevel::High => Cell::new("HIGH")
                        .fg(Color::Yellow)
                        .add_attribute(Attribute::Bold),
                    RiskLevel::Medium => Cell::new("MEDIUM").fg(Color::Yellow),
                    RiskLevel::Low => Cell::new("LOW").fg(Color::Cyan),
                    RiskLevel::Info => Cell::new("INFO").fg(Color::White),
                };

                let desc_text = format!("{}\n{}", f.title.bold(), f.description.dimmed());
                let value_text = format!(
                    "Actual:   {}\nExpected: {}",
                    f.actual_value, f.expected_value
                );

                finding_table.add_row(vec![
                    Cell::new(&f.rule_id).add_attribute(Attribute::Bold),
                    sev_cell,
                    Cell::new(desc_text),
                    Cell::new(value_text),
                    Cell::new(&f.remediation),
                ]);
            }

            out.push_str(&finding_table.to_string());
            out.push_str("\n\n");
        }
    } else {
        out.push_str(&format!(
            "🎉 {}\n\n",
            "EXCELLENT: All audited zones passed 100% of security posture checks!"
                .bright_green()
                .bold()
        ));
    }

    out
}

fn format_ssl_cell(mode: &str) -> Cell {
    let m = mode.to_lowercase();
    if m == "strict" {
        Cell::new("strict").fg(Color::Green)
    } else if m == "full" {
        Cell::new("full").fg(Color::Yellow)
    } else {
        Cell::new(&m).fg(Color::Red).add_attribute(Attribute::Bold)
    }
}

fn format_tls_cell(tls: &str) -> Cell {
    if tls.contains("1.3") || tls.contains("1.2") {
        Cell::new(tls).fg(Color::Green)
    } else {
        Cell::new(tls).fg(Color::Red).add_attribute(Attribute::Bold)
    }
}

fn format_bool_cell(status: &str) -> Cell {
    let s = status.to_lowercase();
    if s == "enabled" || s == "active" || s == "on" || s == "true" {
        Cell::new("Enabled").fg(Color::Green)
    } else {
        Cell::new("Disabled").fg(Color::Red)
    }
}

fn format_dnssec_cell(status: &str) -> Cell {
    let s = status.to_lowercase();
    if s == "active" {
        Cell::new("Active").fg(Color::Green)
    } else if s == "pending" {
        Cell::new("Pending").fg(Color::Yellow)
    } else {
        Cell::new("Disabled").fg(Color::Red)
    }
}

fn format_score_cell(score: u32) -> Cell {
    let cell = Cell::new(score.to_string()).set_alignment(CellAlignment::Center);
    if score >= 90 {
        cell.fg(Color::Green).add_attribute(Attribute::Bold)
    } else if score >= 80 {
        cell.fg(Color::Green)
    } else if score >= 70 {
        cell.fg(Color::Yellow)
    } else {
        cell.fg(Color::Red).add_attribute(Attribute::Bold)
    }
}

fn format_score_text(score: u32) -> ColoredString {
    if score >= 90 {
        format!("{}/100", score).bright_green().bold()
    } else if score >= 80 {
        format!("{}/100", score).green().bold()
    } else if score >= 70 {
        format!("{}/100", score).yellow().bold()
    } else {
        format!("{}/100", score).bright_red().bold()
    }
}

fn format_grade_cell(grade: &str) -> Cell {
    let cell = Cell::new(grade).set_alignment(CellAlignment::Center);
    match grade {
        "A+" | "A" => cell.fg(Color::Green).add_attribute(Attribute::Bold),
        "B" => cell.fg(Color::Green),
        "C" => cell.fg(Color::Yellow),
        "D" => cell.fg(Color::Yellow).add_attribute(Attribute::Bold),
        _ => cell.fg(Color::Red).add_attribute(Attribute::Bold),
    }
}
