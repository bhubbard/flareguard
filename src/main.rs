use anyhow::Result;
use clap::Parser;
use colored::Colorize;
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use std::process::exit;

use flareguard::cli::{Cli, Commands};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Secrets(args) => {
            run_secrets_command(args).await?;
        }
        Commands::Bindings(args) => {
            run_bindings_command(args)?;
        }
        Commands::Zone(args) => {
            run_zone_command(args).await?;
        }
        Commands::Origin(args) => {
            run_origin_command(args).await?;
        }
        Commands::Check(args) => {
            run_check_command(args).await?;
        }
    }

    Ok(())
}

async fn run_secrets_command(cli: flareguard::secrets::cli::Cli) -> Result<()> {
    if cli.list_rules {
        let rules = flareguard::secrets::rules::builtin::get_builtin_rules();
        println!("\n{}", "flareguard Built-in Secret Detection Rules:".bold());
        println!("================================================================================");
        for rule in rules {
            println!(
                "• [{}] {} (Severity: {})",
                rule.id.bright_yellow().bold(),
                rule.name.bold(),
                rule.severity
            );
            println!("  Description: {}", rule.description);
            println!("  Remediation: {}\n", rule.recommendation.dimmed());
        }
        return Ok(());
    }

    let mut ignore_filter = flareguard::secrets::ignore::IgnoreFilter::new();
    let ignore_file_path = cli
        .ignore_file
        .clone()
        .unwrap_or_else(|| PathBuf::from(".cfsecretignore"));
    if ignore_file_path.exists() {
        let _ = ignore_filter.load_from_file(&ignore_file_path);
    }

    for pat in &cli.excludes {
        let _ = ignore_filter.add_exclude_pattern(pat);
    }
    for rule_id in &cli.ignore_rules {
        ignore_filter.ignore_rule(rule_id);
    }
    for secret in &cli.ignore_secrets {
        ignore_filter.ignore_secret(secret);
    }

    let mut target_paths = cli.targets.clone();
    target_paths.extend(cli.additional_targets.clone());
    let current_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    if target_paths.is_empty() {
        target_paths = flareguard::secrets::scanner::discover_default_targets(&current_dir);
        if target_paths.is_empty() {
            target_paths.push(current_dir.clone());
        }
    }

    let mut rules = flareguard::secrets::rules::builtin::get_builtin_rules();
    if !cli.no_auto_env {
        let env_files = flareguard::secrets::env_parser::discover_env_files(&[current_dir]);
        for f in env_files {
            if let Ok(parsed) = flareguard::secrets::env_parser::parse_env_file(&f) {
                rules.extend(flareguard::secrets::env_parser::env_secrets_to_rules(&parsed));
            }
        }
    }

    for env_path in &cli.env_files {
        if let Ok(parsed) = flareguard::secrets::env_parser::parse_env_file(env_path) {
            rules.extend(flareguard::secrets::env_parser::env_secrets_to_rules(&parsed));
        }
    }

    let options = flareguard::secrets::scanner::ScannerOptions {
        max_file_size_bytes: cli.max_file_size_mb * 1024 * 1024,
        min_severity: cli.min_severity,
        follow_symlinks: false,
    };

    let result = flareguard::secrets::scanner::scan_targets(&target_paths, &rules, &ignore_filter, &options);

    let rendered = flareguard::secrets::report::render_report(
        cli.format,
        &result,
        &rules,
        env!("CARGO_PKG_VERSION"),
        cli.verbose,
    ).map_err(|e| anyhow::anyhow!("Error rendering report: {}", e))?;

    if let Some(ref out_path) = cli.output {
        fs::write(out_path, &rendered)?;
        if !cli.quiet {
            println!("Report successfully written to {}", out_path.display().to_string().cyan());
        }
    } else if !cli.quiet || !result.findings.is_empty() || cli.format != flareguard::secrets::report::OutputFormat::Text {
        println!("{}", rendered);
    }

    if cli.check && !result.findings.is_empty() {
        exit(1);
    }

    Ok(())
}

fn run_bindings_command(args: flareguard::bindings::cli::CliArgs) -> Result<()> {
    let config_path = if let Some(path) = args.config.clone() {
        if !path.exists() {
            eprintln!("Error: Wrangler config file not found at: {}", path.display());
            exit(1);
        }
        Some(path)
    } else {
        let search_dir = args.paths.first().cloned().unwrap_or_else(|| PathBuf::from("."));
        flareguard::bindings::wrangler::find_wrangler_config(&search_dir)
    };

    let wrangler_config = match config_path {
        Some(ref path) => match flareguard::bindings::wrangler::parse_wrangler_config(path) {
            Ok(cfg) => Some(cfg),
            Err(e) => {
                eprintln!("Error parsing wrangler configuration ({}): {}", path.display(), e);
                exit(1);
            }
        },
        None => None,
    };

    let options = flareguard::bindings::validator::ValidatorOptions {
        target_paths: args.paths.clone(),
        environment: args.environment.clone(),
        ignore_unused: args.ignore_unused.into_iter().collect::<HashSet<_>>(),
        ignore_undeclared: args.ignore_undeclared.into_iter().collect::<HashSet<_>>(),
        strict: args.strict,
    };

    let report = match flareguard::bindings::validator::validate_project(wrangler_config.as_ref(), &options) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Validation error: {}", e);
            exit(1);
        }
    };

    let format = match args.format {
        flareguard::bindings::cli::CliFormat::Text => flareguard::bindings::types::OutputFormat::Text,
        flareguard::bindings::cli::CliFormat::Json => flareguard::bindings::types::OutputFormat::Json,
        flareguard::bindings::cli::CliFormat::Sarif => flareguard::bindings::types::OutputFormat::Sarif,
    };

    if let Err(e) = flareguard::bindings::reporter::render_report(&report, format) {
        eprintln!("Error writing report: {}", e);
    }

    if args.check || args.strict {
        if !report.undeclared_accesses.is_empty() {
            exit(1);
        }
        if args.strict && !report.ghost_bindings.is_empty() {
            exit(2);
        }
    } else if !report.undeclared_accesses.is_empty() {
        exit(1);
    }

    Ok(())
}

async fn run_zone_command(args: flareguard::zone::cli::AuditArgs) -> Result<()> {
    let report = flareguard::zone::run_audit(&args).await?;
    let rendered = flareguard::zone::output_report(&report, &args)?;

    if args.output.is_none() && !args.quiet {
        println!("{}", rendered);
    }

    let (passed, failure_reasons) = flareguard::zone::evaluate_compliance_gates(&report, &args);
    if !passed {
        if !args.quiet {
            for reason in failure_reasons {
                eprintln!("{} {}", "✗".red().bold(), reason);
            }
        }
        exit(1);
    }

    Ok(())
}

async fn run_origin_command(cli: flareguard::origin::cli::Cli) -> Result<()> {
    let output_format = cli.get_output_format();
    let min_confidence = cli.get_min_confidence();

    let report_res = if cli.mock {
        let target = cli.target.as_deref().unwrap_or("example-corp.com");
        Ok(flareguard::origin::mock::run_mock_scan(target))
    } else {
        match cli.target.as_deref() {
            Some(domain) => {
                let options = flareguard::origin::scanner::ScanOptions {
                    concurrency: cli.concurrency,
                    timeout_secs: cli.timeout,
                    probe_ports: cli.get_probe_ports(),
                    enable_crtsh: !cli.no_crtsh,
                    enable_subdomains: !cli.no_subdomains,
                    enable_dns: !cli.no_dns,
                    wordlist_path: cli.wordlist.clone(),
                    min_confidence,
                    verbose: cli.verbose,
                };
                flareguard::origin::scanner::run_scan(domain, &options).await
            }
            None => {
                eprintln!(
                    "{} Please specify a target domain (e.g. `flareguard origin example.com`) or use `--mock`.",
                    "Error:".bright_red().bold()
                );
                exit(1);
            }
        }
    };

    let report = match report_res {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{} Failed to complete scan: {}", "Error:".bright_red().bold(), e);
            exit(1);
        }
    };

    let formatted_output = match flareguard::origin::report::render_report(&report, output_format) {
        Ok(out) => out,
        Err(e) => {
            eprintln!("{} Failed to format report: {}", "Error:".bright_red().bold(), e);
            exit(1);
        }
    };

    if let Some(ref path) = cli.output {
        if let Err(e) = fs::write(path, &formatted_output) {
            eprintln!("{} Failed to write report to {}: {}", "Error:".bright_red().bold(), path.display(), e);
            exit(1);
        }
        println!("{} Report successfully saved to {}", "Success:".bright_green().bold(), path.display().to_string().cyan());
    } else {
        println!("{}", formatted_output);
    }

    if cli.check {
        let check_threshold = if cli.min_confidence == "LOW" {
            flareguard::origin::models::ConfidenceLevel::High
        } else {
            min_confidence
        };

        let failing_findings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.confidence >= check_threshold)
            .collect();

        if !failing_findings.is_empty() {
            eprintln!(
                "\n{} CI Check Failed: {} unmasked origin IP(s) detected with confidence >= {}!",
                "FAIL:".bright_red().bold(),
                failing_findings.len(),
                check_threshold
            );
            exit(1);
        }
    }

    Ok(())
}

async fn run_check_command(args: flareguard::cli::CheckArgs) -> Result<()> {
    println!("{}", "🛡️ Running Flareguard Complete Workspace Audit...\n".bold());

    // 1. Secrets Scan
    println!("{}", "1. Scanning for Leaked Cloudflare Secrets & Credentials...".cyan().bold());
    let rules = flareguard::secrets::rules::builtin::get_builtin_rules();
    let ignore_filter = flareguard::secrets::ignore::IgnoreFilter::new();
    let options = flareguard::secrets::scanner::ScannerOptions {
        max_file_size_bytes: 50 * 1024 * 1024,
        min_severity: flareguard::secrets::rules::types::Severity::Low,
        follow_symlinks: false,
    };
    let scan_res = flareguard::secrets::scanner::scan_targets(&[args.path.clone()], &rules, &ignore_filter, &options);
    let has_secret_leaks = !scan_res.findings.is_empty();
    if let Ok(rendered) = flareguard::secrets::report::render_report(
        flareguard::secrets::report::OutputFormat::Text,
        &scan_res,
        &rules,
        env!("CARGO_PKG_VERSION"),
        false,
    ) {
        println!("{}", rendered);
    }

    // 2. Bindings Validation (if wrangler file found)
    let config_path = flareguard::bindings::wrangler::find_wrangler_config(&args.path);
    let mut has_binding_errors = false;

    if let Some(ref cfg) = config_path {
        println!("\n{}", "2. Validating Cloudflare Worker Bindings vs AST...".cyan().bold());
        if let Ok(wrangler_config) = flareguard::bindings::wrangler::parse_wrangler_config(cfg) {
            let options = flareguard::bindings::validator::ValidatorOptions {
                target_paths: vec![args.path.clone()],
                environment: None,
                ignore_unused: HashSet::new(),
                ignore_undeclared: HashSet::new(),
                strict: args.strict,
            };
            if let Ok(report) = flareguard::bindings::validator::validate_project(Some(&wrangler_config), &options) {
                let _ = flareguard::bindings::reporter::render_report(&report, flareguard::bindings::types::OutputFormat::Text);
                has_binding_errors = !report.undeclared_accesses.is_empty() || (args.strict && !report.ghost_bindings.is_empty());
            }
        }
    } else {
        println!("\n{} No wrangler configuration file detected in target path.", "ℹ".blue());
    }

    if args.strict && (has_secret_leaks || has_binding_errors) {
        println!("\n{} Workspace security check failed.", "✗".red().bold());
        exit(1);
    } else {
        println!("\n{} Workspace security check passed!", "✓".green().bold());
    }

    Ok(())
}
