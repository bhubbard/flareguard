use crate::bindings::types::{OutputFormat, ValidationReport};
use colored::Colorize;
use serde_json::json;
use std::io::{self, Write};

/// Render validation report according to requested OutputFormat.
pub fn render_report(report: &ValidationReport, format: OutputFormat) -> io::Result<()> {
    match format {
        OutputFormat::Text => render_text_report(report),
        OutputFormat::Json => render_json_report(report),
        OutputFormat::Sarif => render_sarif_report(report),
    }
}

/// Render rich human-readable terminal text output.
pub fn render_text_report(report: &ValidationReport) -> io::Result<()> {
    let mut stdout = io::stdout().lock();

    writeln!(stdout, "{}", "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".dimmed())?;
    writeln!(stdout, "{}", "  ⚡ Cloudflare Worker / Pages Binding Validator".bold().cyan())?;
    writeln!(stdout, "{}", "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".dimmed())?;

    if let Some(cfg) = &report.config_file {
        writeln!(stdout, "  {} {}", "Config:".bold(), cfg.white())?;
    } else {
        writeln!(stdout, "  {} {}", "Config:".bold(), "None found (all bindings treated as undeclared)".yellow())?;
    }
    writeln!(stdout, "  {} {}", "Environment:".bold(), report.environment.magenta())?;
    writeln!(stdout, "  {} {}", "Files Scanned:".bold(), report.total_files_scanned.to_string().white())?;
    writeln!(stdout)?;

    // 1. Undeclared Bindings (Errors)
    if !report.undeclared_accesses.is_empty() {
        writeln!(stdout, "{}", format!("  CRITICAL / ERROR: Undeclared Bindings ({} found)", report.undeclared_accesses.len()).bold().red())?;
        writeln!(stdout, "  {}", "These bindings are accessed in code but NOT declared in Wrangler config.".red().italic())?;
        writeln!(stdout, "  {}", "Risk: Runtime TypeError / crash when accessing undefined property at runtime.".red().italic())?;
        writeln!(stdout)?;

        for access in &report.undeclared_accesses {
            let loc = format!("{}:{}:{}", access.file_path, access.line, access.column);
            writeln!(
                stdout,
                "    {} {} in {}",
                "✖".bold().red(),
                access.name.bold().bright_red(),
                loc.underline().dimmed()
            )?;
            writeln!(
                stdout,
                "      {} `{}`",
                "Expression:".dimmed(),
                access.raw_expression.bright_yellow()
            )?;
            writeln!(
                stdout,
                "      {} Declare `{}` in your wrangler configuration (e.g. `vars`, `kv_namespaces`, `d1_databases`)",
                "Fix Hint:".bold().cyan(),
                access.name.bright_white()
            )?;
            writeln!(stdout)?;
        }
    }

    // 2. Ghost / Unused Bindings (Warnings)
    if !report.ghost_bindings.is_empty() {
        writeln!(stdout, "{}", format!("  WARNING: Ghost / Unused Bindings ({} found)", report.ghost_bindings.len()).bold().yellow())?;
        writeln!(stdout, "  {}", "These bindings are declared in Wrangler config but never referenced in code.".yellow().italic())?;
        writeln!(stdout, "  {}", "Recommendation: Remove unused bindings to keep infrastructure lean.".dimmed())?;
        writeln!(stdout)?;

        for ghost in &report.ghost_bindings {
            let details_str = ghost.details.as_deref().map(|d| format!(" ({})", d)).unwrap_or_default();
            writeln!(
                stdout,
                "    {} {} [{}{}] in {}",
                "▲".bold().yellow(),
                ghost.name.bold().bright_yellow(),
                ghost.binding_type,
                details_str.dimmed(),
                ghost.file.dimmed()
            )?;
        }
        writeln!(stdout)?;
    }

    // 3. Valid / Active Bindings Summary
    if !report.valid_bindings.is_empty() {
        writeln!(stdout, "{}", format!("  SYNCHRONIZED BINDINGS ({} active)", report.valid_bindings.len()).bold().green())?;
        for valid in &report.valid_bindings {
            writeln!(
                stdout,
                "    {} {} [{}] ({} reference{})",
                "✔".bold().green(),
                valid.binding.name.bold().bright_white(),
                valid.binding.binding_type.to_string().dimmed(),
                valid.access_count,
                if valid.access_count == 1 { "" } else { "s" }
            )?;
        }
        writeln!(stdout)?;
    }

    // Summary Box
    writeln!(stdout, "{}", "─────────────────────────────────────────────────────────────────────".dimmed())?;
    let status_str = if report.is_success {
        "✓ VALIDATION PASSED".bold().bright_green()
    } else {
        "✗ VALIDATION FAILED".bold().bright_red()
    };

    let errors_str = if report.undeclared_accesses.is_empty() {
        report.undeclared_accesses.len().to_string().green()
    } else {
        report.undeclared_accesses.len().to_string().red().bold()
    };

    let warnings_str = if report.ghost_bindings.is_empty() {
        report.ghost_bindings.len().to_string().green()
    } else {
        report.ghost_bindings.len().to_string().yellow().bold()
    };

    writeln!(
        stdout,
        "  Status: {}  |  Declared: {}  |  Scanned Accesses: {}  |  Errors: {}  |  Warnings: {}",
        status_str,
        report.total_declared.to_string().white(),
        report.total_accesses.to_string().white(),
        errors_str,
        warnings_str,
    )?;
    writeln!(stdout, "{}", "─────────────────────────────────────────────────────────────────────".dimmed())?;

    Ok(())
}

/// Render JSON format.
pub fn render_json_report(report: &ValidationReport) -> io::Result<()> {
    let json_str = serde_json::to_string_pretty(report)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    println!("{}", json_str);
    Ok(())
}

/// Render SARIF format (v2.1.0 standard for GitHub Actions / Code Scanning).
pub fn render_sarif_report(report: &ValidationReport) -> io::Result<()> {
    let mut results = Vec::new();

    // Undeclared binding errors
    for access in &report.undeclared_accesses {
        results.push(json!({
            "ruleId": "cf001-undeclared-binding",
            "level": "error",
            "message": {
                "text": format!("Binding '{}' accessed in code via `{}` is not declared in Wrangler config.", access.name, access.raw_expression)
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": access.file_path.replace("\\", "/")
                    },
                    "region": {
                        "startLine": access.line,
                        "startColumn": access.column
                    }
                }
            }]
        }));
    }

    // Ghost binding warnings
    for ghost in &report.ghost_bindings {
        results.push(json!({
            "ruleId": "cf002-ghost-binding",
            "level": "warning",
            "message": {
                "text": format!("Binding '{}' [{}] declared in '{}' is never referenced in source code.", ghost.name, ghost.binding_type, ghost.file)
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": ghost.file.replace("\\", "/")
                    },
                    "region": {
                        "startLine": 1,
                        "startColumn": 1
                    }
                }
            }]
        }));
    }

    let sarif = json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "cf-binding-validator",
                    "informationUri": "https://github.com/cloudflare/wrangler",
                    "version": env!("CARGO_PKG_VERSION"),
                    "rules": [
                        {
                            "id": "cf001-undeclared-binding",
                            "name": "UndeclaredBindingAccess",
                            "shortDescription": {
                                "text": "Binding is accessed in code without being declared in Wrangler config"
                            },
                            "fullDescription": {
                                "text": "Accessing undefined environment bindings at runtime causes TypeErrors and Worker crashes."
                            },
                            "defaultConfiguration": {
                                "level": "error"
                            }
                        },
                        {
                            "id": "cf002-ghost-binding",
                            "name": "GhostBindingDeclared",
                            "shortDescription": {
                                "text": "Binding is declared in Wrangler configuration but never referenced in code"
                            },
                            "fullDescription": {
                                "text": "Unused bindings add maintenance overhead and clutter configuration."
                            },
                            "defaultConfiguration": {
                                "level": "warning"
                            }
                        }
                    ]
                }
            },
            "results": results
        }]
    });

    println!("{}", serde_json::to_string_pretty(&sarif).unwrap());
    Ok(())
}
