use crate::origin::models::ConfidenceLevel;
use crate::origin::report::OutputFormat;
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "cf-origin-hunter",
    author = "Cloudflare Security Tools Team",
    version = "0.1.0",
    about = "Identify unmasked backend origin IP addresses behind Cloudflare edge proxies",
    long_about = "cf-origin-hunter is a high-performance Rust security auditing tool that discovers unmasked backend origin IPs behind Cloudflare reverse proxies using DNS SPF/MX parsing, subdomain wordlists, Certificate Transparency logs, and active HTTP/HTTPS signature verification."
)]
pub struct Cli {
    /// Target domain to audit (e.g. example.com)
    #[arg(value_name = "TARGET")]
    pub target: Option<String>,

    /// Run synthetic mock demonstration scan without making real network requests
    #[arg(long, default_value_t = false)]
    pub mock: bool,

    /// CI Gate mode: Exit with code 1 if an unmasked origin IP is found matching min-confidence
    #[arg(long, default_value_t = false)]
    pub check: bool,

    /// Minimum confidence level to report or fail on in CI gate (CONFIRMED, HIGH, MEDIUM, LOW)
    #[arg(long, value_name = "LEVEL", default_value = "LOW")]
    pub min_confidence: String,

    /// Output format (text, json, sarif, html)
    #[arg(long, short = 'f', value_name = "FORMAT", default_value = "text")]
    pub format: String,

    /// Save output report to specified file path
    #[arg(long, short = 'o', value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Custom subdomain wordlist file path
    #[arg(long, short = 'w', value_name = "FILE")]
    pub wordlist: Option<PathBuf>,

    /// Max concurrency for DNS resolution and HTTP probes
    #[arg(long, short = 'c', value_name = "NUM", default_value_t = 10)]
    pub concurrency: usize,

    /// Network timeout in seconds for DNS and HTTP requests
    #[arg(long, short = 't', value_name = "SECS", default_value_t = 5)]
    pub timeout: u64,

    /// Comma-separated list of ports to probe (default: 80,443,8080,8443)
    #[arg(long, short = 'p', value_name = "PORTS", default_value = "80,443,8080,8443")]
    pub ports: String,

    /// Disable Certificate Transparency (crt.sh) log queries
    #[arg(long, default_value_t = false)]
    pub no_crtsh: bool,

    /// Disable subdomain wordlist brute-force enumeration
    #[arg(long, default_value_t = false)]
    pub no_subdomains: bool,

    /// Disable MX and SPF DNS record parsing
    #[arg(long, default_value_t = false)]
    pub no_dns: bool,

    /// Enable verbose diagnostic messages
    #[arg(long, short = 'v', default_value_t = false)]
    pub verbose: bool,
}

impl Cli {
    pub fn get_output_format(&self) -> OutputFormat {
        self.format.parse().unwrap_or(OutputFormat::Text)
    }

    pub fn get_min_confidence(&self) -> ConfidenceLevel {
        self.min_confidence.parse().unwrap_or(ConfidenceLevel::Low)
    }

    pub fn get_probe_ports(&self) -> Vec<u16> {
        self.ports
            .split(',')
            .filter_map(|p| p.trim().parse::<u16>().ok())
            .collect()
    }
}
