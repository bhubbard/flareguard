use crate::secrets::rules::types::Severity;
use crate::secrets::scanner::ScanResult;
use colored::Colorize;

/// Formats scan findings into human-readable colored terminal output.
pub fn format_terminal_report(result: &ScanResult, verbose: bool) -> String {
    let mut out = String::new();

    if result.findings.is_empty() {
        out.push_str(&format!(
            "\n{}\n",
            "✔ cf-secret-leak-guard: No Cloudflare secrets detected in client assets!"
                .green()
                .bold()
        ));
        out.push_str(&format!(
            "Scanned {} files ({:.2} MB) in {}ms\n",
            result.stats.files_scanned,
            result.stats.bytes_scanned as f64 / (1024.0 * 1024.0),
            result.stats.duration_ms
        ));
        return out;
    }

    out.push_str(&format!(
        "\n{}\n",
        "🚨 Cloudflare Secret Leaks Detected in Client Bundles!"
            .red()
            .bold()
    ));
    out.push_str(&format!(
        "{}\n\n",
        "================================================================================"
            .bright_red()
    ));

    for (idx, finding) in result.findings.iter().enumerate() {
        let severity_badge = match finding.severity {
            Severity::Critical => "[CRITICAL]".on_red().white().bold(),
            Severity::High => "[HIGH]".red().bold(),
            Severity::Medium => "[MEDIUM]".yellow().bold(),
            Severity::Low => "[LOW]".cyan().bold(),
        };

        out.push_str(&format!(
            "{}. {} {} - {}\n",
            (idx + 1).to_string().bold(),
            severity_badge,
            finding.rule_id.bright_yellow().bold(),
            finding.rule_name.bold()
        ));

        out.push_str(&format!(
            "   {} {}:{}:{}\n",
            "File:".bright_blue().bold(),
            finding.file_path.bright_white(),
            finding.line_number.to_string().cyan(),
            finding.column_number.to_string().cyan()
        ));

        out.push_str(&format!(
            "   {} {}\n",
            "Secret:".bright_blue().bold(),
            finding.redacted_secret.bright_red()
        ));

        out.push_str(&format!(
            "   {} {}\n",
            "Context:".bright_blue().bold(),
            finding.line_content.dimmed()
        ));

        if verbose || !finding.recommendation.is_empty() {
            out.push_str(&format!(
                "   {} {}\n",
                "Remediation:".bright_green().bold(),
                finding.recommendation
            ));
        }

        out.push('\n');
    }

    out.push_str(&format!(
        "{}\n",
        "--------------------------------------------------------------------------------"
            .bright_black()
    ));
    out.push_str(&format!(
        "Scan Summary: {} findings ({} Critical, {} High, {} Medium, {} Low)\n",
        result.stats.total_findings.to_string().red().bold(),
        result.stats.critical_count.to_string().red(),
        result.stats.high_count.to_string().bright_red(),
        result.stats.medium_count.to_string().yellow(),
        result.stats.low_count.to_string().cyan()
    ));
    out.push_str(&format!(
        "Files Scanned: {} ({:.2} MB) in {}ms\n\n",
        result.stats.files_scanned,
        result.stats.bytes_scanned as f64 / (1024.0 * 1024.0),
        result.stats.duration_ms
    ));

    out
}
