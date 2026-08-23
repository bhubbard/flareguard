use clap::{Parser, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CliFormat {
    Text,
    Json,
    Sarif,
}

#[derive(Parser, Debug)]
#[command(
    name = "cf-binding-validator",
    about = "⚡ Validate Cloudflare Worker/Pages bindings against Wrangler configuration",
    version
)]
pub struct CliArgs {
    /// Target files or directories to scan (defaults to current directory)
    #[arg(default_value = ".")]
    pub paths: Vec<PathBuf>,

    /// Path to wrangler configuration (wrangler.jsonc, wrangler.json, or wrangler.toml)
    #[arg(short = 'c', long = "config")]
    pub config: Option<PathBuf>,

    /// Wrangler environment to validate against (e.g. 'production', 'staging')
    #[arg(short = 'e', long = "env")]
    pub environment: Option<String>,

    /// Check mode for CI/CD: exits with non-zero code if undeclared bindings exist
    #[arg(long = "check")]
    pub check: bool,

    /// Strict mode: also fail CI if unused/ghost bindings exist
    #[arg(long = "strict")]
    pub strict: bool,

    /// Output report format
    #[arg(short = 'f', long = "format", value_enum, default_value_t = CliFormat::Text)]
    pub format: CliFormat,

    /// Comma-separated binding names to ignore if unused
    #[arg(long = "ignore-unused", value_delimiter = ',')]
    pub ignore_unused: Vec<String>,

    /// Comma-separated binding names to ignore if undeclared
    #[arg(long = "ignore-undeclared", value_delimiter = ',')]
    pub ignore_undeclared: Vec<String>,
}
