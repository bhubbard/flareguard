use crate::zone::models::{AggregateAuditReport, RiskLevel};

pub fn render_html(report: &AggregateAuditReport) -> String {
    let mut html = String::with_capacity(16384);

    let grade_badge_class = match report.overall_grade.as_str() {
        "A+" | "A" => "grade-a",
        "B" => "grade-b",
        "C" => "grade-c",
        "D" => "grade-d",
        _ => "grade-f",
    };

    let score_color = if report.average_score >= 90.0 {
        "#10b981"
    } else if report.average_score >= 80.0 {
        "#059669"
    } else if report.average_score >= 70.0 {
        "#f59e0b"
    } else {
        "#ef4444"
    };

    html.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
    html.push_str("<meta charset=\"UTF-8\">\n");
    html.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
    html.push_str("<title>Cloudflare Zone Security Audit Report</title>\n");
    html.push_str("<style>\n");
    html.push_str(r#"
:root {
  --bg-primary: #0f172a;
  --bg-card: #1e293b;
  --bg-card-hover: #334155;
  --text-primary: #f8fafc;
  --text-secondary: #94a3b8;
  --border-color: #334155;
  --accent: #38bdf8;
  --critical: #ef4444;
  --high: #f97316;
  --medium: #eab308;
  --low: #38bdf8;
  --info: #94a3b8;
  --pass: #10b981;
}

* { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; }
body { background-color: var(--bg-primary); color: var(--text-primary); padding: 2rem; line-height: 1.5; }
.container { max-width: 1200px; margin: 0 auto; }

header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border-color); padding-bottom: 1.5rem; margin-bottom: 2rem; }
.header-title h1 { font-size: 1.8rem; font-weight: 700; color: #fff; display: flex; align-items: center; gap: 0.5rem; }
.header-title p { color: var(--text-secondary); font-size: 0.95rem; margin-top: 0.25rem; }
.timestamp { font-size: 0.85rem; color: var(--text-secondary); }

.summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 1.25rem; margin-bottom: 2rem; }
.card { background-color: var(--bg-card); border: 1px solid var(--border-color); border-radius: 0.75rem; padding: 1.25rem; }
.card-label { font-size: 0.85rem; text-transform: uppercase; color: var(--text-secondary); font-weight: 600; letter-spacing: 0.05em; }
.card-val { font-size: 2rem; font-weight: 800; margin-top: 0.5rem; }

.grade-badge { display: inline-block; padding: 0.25rem 0.75rem; border-radius: 0.5rem; font-weight: 800; font-size: 1.5rem; }
.grade-a { background-color: rgba(16, 185, 129, 0.2); color: #10b981; border: 1px solid #10b981; }
.grade-b { background-color: rgba(5, 150, 105, 0.2); color: #34d399; border: 1px solid #34d399; }
.grade-c { background-color: rgba(234, 179, 8, 0.2); color: #eab308; border: 1px solid #eab308; }
.grade-d { background-color: rgba(249, 115, 22, 0.2); color: #f97316; border: 1px solid #f97316; }
.grade-f { background-color: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid #ef4444; }

.severity-pill-group { display: flex; gap: 0.5rem; flex-wrap: wrap; margin-top: 0.75rem; }
.pill { padding: 0.2rem 0.6rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 700; }
.pill-crit { background: rgba(239, 68, 68, 0.2); color: var(--critical); border: 1px solid var(--critical); }
.pill-high { background: rgba(249, 115, 22, 0.2); color: var(--high); border: 1px solid var(--high); }
.pill-med { background: rgba(234, 179, 8, 0.2); color: var(--medium); border: 1px solid var(--medium); }
.pill-low { background: rgba(56, 189, 248, 0.2); color: var(--low); border: 1px solid var(--low); }
.pill-info { background: rgba(148, 163, 184, 0.2); color: var(--info); border: 1px solid var(--info); }
.pill-pass { background: rgba(16, 185, 129, 0.2); color: var(--pass); border: 1px solid var(--pass); }

section { margin-bottom: 2.5rem; }
h2 { font-size: 1.3rem; margin-bottom: 1rem; color: #fff; border-left: 4px solid var(--accent); padding-left: 0.75rem; }

table { width: 100%; border-collapse: collapse; background-color: var(--bg-card); border-radius: 0.75rem; overflow: hidden; border: 1px solid var(--border-color); }
th, td { padding: 0.85rem 1rem; text-align: left; border-bottom: 1px solid var(--border-color); font-size: 0.9rem; }
th { background-color: rgba(15, 23, 42, 0.6); color: var(--text-secondary); font-weight: 600; text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.05em; }
tr:last-child td { border-bottom: none; }
tr:hover { background-color: rgba(51, 65, 85, 0.3); }

.zone-accordion { margin-bottom: 1rem; border: 1px solid var(--border-color); border-radius: 0.75rem; background-color: var(--bg-card); overflow: hidden; }
.zone-header { padding: 1rem 1.25rem; display: flex; justify-content: space-between; align-items: center; cursor: pointer; user-select: none; }
.zone-header:hover { background-color: var(--bg-card-hover); }
.zone-info { display: flex; align-items: center; gap: 1rem; }
.zone-name { font-weight: 700; font-size: 1.1rem; }
.zone-meta { color: var(--text-secondary); font-size: 0.85rem; }

.findings-list { padding: 1.25rem; border-top: 1px solid var(--border-color); background-color: rgba(15, 23, 42, 0.4); }
.finding-item { background-color: var(--bg-card); border: 1px solid var(--border-color); border-radius: 0.5rem; padding: 1rem; margin-bottom: 1rem; }
.finding-item:last-child { margin-bottom: 0; }
.finding-head { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 0.5rem; }
.finding-title { font-weight: 700; font-size: 0.95rem; color: #fff; }
.finding-desc { color: var(--text-secondary); font-size: 0.85rem; margin-bottom: 0.75rem; }
.finding-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem; background-color: rgba(15, 23, 42, 0.5); padding: 0.75rem; border-radius: 0.375rem; font-size: 0.85rem; margin-bottom: 0.75rem; }
.remediation-box { background-color: rgba(56, 189, 248, 0.1); border-left: 3px solid var(--accent); padding: 0.75rem; border-radius: 0.25rem; font-size: 0.85rem; }
.remediation-label { font-weight: 700; color: var(--accent); margin-bottom: 0.25rem; }

footer { margin-top: 3rem; text-align: center; color: var(--text-secondary); font-size: 0.8rem; border-top: 1px solid var(--border-color); padding-top: 1.5rem; }
"#);
    html.push_str("</style>\n</head>\n<body>\n<div class=\"container\">\n");

    // Header
    html.push_str("<header>\n<div class=\"header-title\">\n");
    html.push_str("<h1>🛡️ Cloudflare Zone Security Auditor</h1>\n");
    html.push_str("<p>Automated Multi-Zone Security Posture & Compliance Report</p>\n");
    html.push_str("</div>\n<div class=\"timestamp\">\n");
    html.push_str(&format!("Generated: {}<br>", report.timestamp.format("%Y-%m-%d %H:%M:%S UTC")));
    if let Some(ref acc) = report.account_id {
        html.push_str(&format!("Account: <code>{}</code>\n", acc));
    }
    html.push_str("</div>\n</header>\n");

    // Summary Cards
    html.push_str("<div class=\"summary-grid\">\n");
    
    // Card 1: Score
    html.push_str("<div class=\"card\">\n<div class=\"card-label\">Overall Security Score</div>\n");
    html.push_str(&format!(
        "<div class=\"card-val\" style=\"color: {};\">{:.1} <span style=\"font-size: 1rem; color: var(--text-secondary);\">/ 100</span></div>\n",
        score_color, report.average_score
    ));
    html.push_str("</div>\n");

    // Card 2: Health Grade
    html.push_str("<div class=\"card\">\n<div class=\"card-label\">Overall Health Grade</div>\n");
    html.push_str(&format!(
        "<div style=\"margin-top: 0.5rem;\"><span class=\"grade-badge {}\">{}</span></div>\n",
        grade_badge_class, report.overall_grade
    ));
    html.push_str("</div>\n");

    // Card 3: Total Zones
    html.push_str("<div class=\"card\">\n<div class=\"card-label\">Zones Audited</div>\n");
    html.push_str(&format!("<div class=\"card-val\">{}</div>\n", report.total_zones));
    html.push_str("</div>\n");

    // Card 4: Findings Breakdown
    html.push_str("<div class=\"card\">\n<div class=\"card-label\">Total Findings</div>\n");
    html.push_str(&format!("<div class=\"card-val\">{}</div>\n", report.total_findings.total));
    html.push_str("<div class=\"severity-pill-group\">\n");
    if report.total_findings.critical > 0 {
        html.push_str(&format!("<span class=\"pill pill-crit\">{} CRITICAL</span>\n", report.total_findings.critical));
    }
    if report.total_findings.high > 0 {
        html.push_str(&format!("<span class=\"pill pill-high\">{} HIGH</span>\n", report.total_findings.high));
    }
    if report.total_findings.medium > 0 {
        html.push_str(&format!("<span class=\"pill pill-med\">{} MED</span>\n", report.total_findings.medium));
    }
    if report.total_findings.low > 0 {
        html.push_str(&format!("<span class=\"pill pill-low\">{} LOW</span>\n", report.total_findings.low));
    }
    html.push_str("</div>\n</div>\n</div>\n");

    // Zone Posture Table
    html.push_str("<section>\n<h2>🌐 Zone Security Posture Overview</h2>\n");
    html.push_str("<table>\n<thead>\n<tr>\n");
    html.push_str("<th>Zone Name</th><th>Plan</th><th>SSL Mode</th><th>Min TLS</th><th>Always HTTPS</th><th>HSTS</th><th>WAF</th><th>DNSSEC</th><th>Score</th><th>Grade</th>\n");
    html.push_str("</tr>\n</thead>\n<tbody>\n");

    for z in &report.zone_reports {
        let ssl_pill = match z.settings_summary.ssl_mode.to_lowercase().as_str() {
            "strict" => "<span class=\"pill pill-pass\">strict</span>",
            "full" => "<span class=\"pill pill-med\">full</span>",
            _ => "<span class=\"pill pill-crit\">flexible / off</span>",
        };

        let tls_pill = if z.settings_summary.min_tls.contains("1.3") || z.settings_summary.min_tls.contains("1.2") {
            format!("<span class=\"pill pill-pass\">{}</span>", z.settings_summary.min_tls)
        } else {
            format!("<span class=\"pill pill-crit\">{}</span>", z.settings_summary.min_tls)
        };

        let bool_pill = |val: &str| {
            if val.eq_ignore_ascii_case("enabled") || val.eq_ignore_ascii_case("active") {
                "<span class=\"pill pill-pass\">Enabled</span>".to_string()
            } else {
                "<span class=\"pill pill-crit\">Disabled</span>".to_string()
            }
        };

        let dnssec_pill = match z.settings_summary.dnssec_status.to_lowercase().as_str() {
            "active" => "<span class=\"pill pill-pass\">Active</span>",
            "pending" => "<span class=\"pill pill-med\">Pending</span>",
            _ => "<span class=\"pill pill-crit\">Disabled</span>",
        };

        let zone_grade_class = match z.grade.as_str() {
            "A+" | "A" => "pill-pass",
            "B" => "pill-low",
            "C" => "pill-med",
            "D" => "pill-high",
            _ => "pill-crit",
        };

        html.push_str("<tr>\n");
        html.push_str(&format!("<td><strong>{}</strong></td>\n", z.zone_name));
        html.push_str(&format!("<td>{}</td>\n", z.plan_name));
        html.push_str(&format!("<td>{}</td>\n", ssl_pill));
        html.push_str(&format!("<td>{}</td>\n", tls_pill));
        html.push_str(&format!("<td>{}</td>\n", bool_pill(&z.settings_summary.always_https)));
        html.push_str(&format!("<td>{}</td>\n", bool_pill(&z.settings_summary.hsts_status)));
        html.push_str(&format!("<td>{}</td>\n", bool_pill(&z.settings_summary.waf_status)));
        html.push_str(&format!("<td>{}</td>\n", dnssec_pill));
        html.push_str(&format!("<td><strong>{}/100</strong></td>\n", z.score));
        html.push_str(&format!("<td><span class=\"pill {}\">{}</span></td>\n", zone_grade_class, z.grade));
        html.push_str("</tr>\n");
    }
    html.push_str("</tbody>\n</table>\n</section>\n");

    // Detailed Findings Accordion
    html.push_str("<section>\n<h2>🔍 Detailed Zone Findings & Remediation</h2>\n");

    for z in &report.zone_reports {
        let finding_count = z.findings.len();
        html.push_str("<div class=\"zone-accordion\">\n");
        html.push_str("<div class=\"zone-header\">\n");
        html.push_str("<div class=\"zone-info\">\n");
        html.push_str(&format!("<span class=\"zone-name\">{}</span>\n", z.zone_name));
        html.push_str(&format!("<span class=\"zone-meta\">Plan: {} | ID: {}</span>\n", z.plan_name, z.zone_id));
        html.push_str("</div>\n<div>\n");
        html.push_str(&format!("<span class=\"pill {}\">Score: {} ({})</span> ", match z.grade.as_str() {
            "A+" | "A" => "pill-pass",
            "B" => "pill-low",
            "C" => "pill-med",
            "D" => "pill-high",
            _ => "pill-crit",
        }, z.score, z.grade));
        html.push_str(&format!("<span class=\"zone-meta\">{} Findings</span>\n", finding_count));
        html.push_str("</div>\n</div>\n");

        if !z.findings.is_empty() {
            html.push_str("<div class=\"findings-list\">\n");
            for f in &z.findings {
                let sev_class = match f.risk_level {
                    RiskLevel::Critical => "pill-crit",
                    RiskLevel::High => "pill-high",
                    RiskLevel::Medium => "pill-med",
                    RiskLevel::Low => "pill-low",
                    RiskLevel::Info => "pill-info",
                };

                html.push_str("<div class=\"finding-item\">\n");
                html.push_str("<div class=\"finding-head\">\n");
                html.push_str(&format!("<div><span class=\"finding-title\">{}</span> <span class=\"zone-meta\">[{}]</span></div>\n", f.title, f.rule_id));
                html.push_str(&format!("<span class=\"pill {}\">{}</span>\n", sev_class, f.risk_level));
                html.push_str("</div>\n");
                html.push_str(&format!("<div class=\"finding-desc\">{}</div>\n", f.description));
                html.push_str("<div class=\"finding-grid\">\n");
                html.push_str(&format!("<div><strong>Current:</strong> {}</div>\n", f.actual_value));
                html.push_str(&format!("<div><strong>Recommended:</strong> {}</div>\n", f.expected_value));
                html.push_str("</div>\n");
                html.push_str("<div class=\"remediation-box\">\n");
                html.push_str("<div class=\"remediation-label\">🛠️ Remediation Guidance</div>\n");
                html.push_str(&format!("<div>{}</div>\n", f.remediation));
                if let Some(ref doc) = f.doc_url {
                    html.push_str(&format!("<div style=\"margin-top: 0.35rem;\"><a href=\"{}\" target=\"_blank\" style=\"color: var(--accent); font-size: 0.8rem;\">Cloudflare Documentation &rarr;</a></div>\n", doc));
                }
                html.push_str("</div>\n</div>\n");
            }
            html.push_str("</div>\n");
        }
        html.push_str("</div>\n");
    }

    html.push_str("</section>\n");

    // Footer
    html.push_str("<footer>\n");
    html.push_str("Generated by <strong>cf-zone-auditor</strong> • Cloudflare Zone Security Auditor & Compliance Gate\n");
    html.push_str("</footer>\n</div>\n</body>\n</html>\n");

    html
}
