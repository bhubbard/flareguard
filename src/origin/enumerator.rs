use crate::origin::cloudflare::{is_cloudflare_ip, partition_ips};
use crate::origin::crtsh::query_crtsh;
use crate::origin::dns::{
    extract_ips_from_spf, resolve_ips, resolve_mx_servers, resolve_ns_records, resolve_txt_records,
};
use crate::origin::error::Result;
use crate::origin::models::{CandidateIp, DiscoverySource};
use futures::stream::{self, StreamExt};
use hickory_resolver::TokioResolver;
use reqwest::Client;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;

pub const DEFAULT_SUBDOMAINS: &[&str] = &[
    "direct",
    "origin",
    "mail",
    "cpanel",
    "ftp",
    "dev",
    "staging",
    "portal",
    "admin",
    "api-origin",
    "backend",
    "internal",
    "vps",
    "server",
    "ssh",
    "mx",
    "autodiscover",
    "webmail",
    "test",
    "beta",
    "stage",
    "corp",
    "vpn",
    "ns1",
    "ns2",
    "smtp",
    "imap",
    "pop3",
    "git",
    "jenkins",
    "status",
    "monitor",
    "app-origin",
    "gateway",
    "remote",
    "intranet",
    "whm",
    "webdisk",
    "secure",
    "preview",
    "old",
    "legacy",
    "demo",
];

/// Options for configuring candidate origin enumeration
#[derive(Debug, Clone)]
pub struct EnumeratorOptions {
    pub concurrency: usize,
    pub enable_crtsh: bool,
    pub enable_subdomains: bool,
    pub enable_dns: bool,
    pub custom_wordlist: Option<Vec<String>>,
    pub timeout_secs: u64,
}

impl Default for EnumeratorOptions {
    fn default() -> Self {
        Self {
            concurrency: 10,
            enable_crtsh: true,
            enable_subdomains: true,
            enable_dns: true,
            custom_wordlist: None,
            timeout_secs: 5,
        }
    }
}

/// Reads a custom wordlist from file
pub fn load_wordlist_file(path: &Path) -> Result<Vec<String>> {
    let content = std::fs::read_to_string(path)?;
    let list: Vec<String> = content
        .lines()
        .map(|l| l.trim().to_lowercase())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    Ok(list)
}

/// Discovers candidate origin IPs for a target domain across subdomains, DNS, and Certificate Transparency
pub async fn enumerate_candidate_ips(
    domain: &str,
    resolver: &TokioResolver,
    http_client: &Client,
    options: &EnumeratorOptions,
) -> Result<Vec<CandidateIp>> {
    let mut candidate_map: HashMap<IpAddr, CandidateIp> = HashMap::new();
    let root = domain.trim().to_lowercase();

    // 1. Direct Domain Baseline Partitioning
    if let Ok(root_ips) = resolve_ips(resolver, &root).await {
        let (_cf_ips, non_cf) = partition_ips(&root_ips);
        for ip in non_cf {
            candidate_map.insert(
                ip,
                CandidateIp {
                    ip,
                    source: DiscoverySource::DirectDns(root.clone()),
                    hostname: Some(root.clone()),
                    is_cloudflare: false,
                    notes: vec![
                        "Apex / Root domain A/AAAA record points directly to non-Cloudflare IP"
                            .into(),
                    ],
                },
            );
        }
    }

    // 2. DNS Records Check (MX, SPF, TXT, NS)
    if options.enable_dns {
        // MX Records
        if let Ok(mx_list) = resolve_mx_servers(resolver, &root).await {
            for (exchange, ips) in mx_list {
                for ip in ips {
                    if !is_cloudflare_ip(&ip) {
                        candidate_map.entry(ip).or_insert_with(|| CandidateIp {
                            ip,
                            source: DiscoverySource::MxRecord(exchange.clone()),
                            hostname: Some(exchange.clone()),
                            is_cloudflare: false,
                            notes: vec![format!("Discovered via MX exchange {}", exchange)],
                        });
                    }
                }
            }
        }

        // TXT and SPF Records
        if let Ok(txt_records) = resolve_txt_records(resolver, &root).await {
            for txt in &txt_records {
                let spf_ips = extract_ips_from_spf(txt);
                for ip in spf_ips {
                    if !is_cloudflare_ip(&ip) {
                        candidate_map.entry(ip).or_insert_with(|| CandidateIp {
                            ip,
                            source: DiscoverySource::SpfRecord(txt.clone()),
                            hostname: None,
                            is_cloudflare: false,
                            notes: vec!["Extracted from SPF policy declaration".into()],
                        });
                    }
                }
            }
        }

        // NS Records
        if let Ok(ns_records) = resolve_ns_records(resolver, &root).await {
            for ns in ns_records {
                if let Ok(ips) = resolve_ips(resolver, &ns).await {
                    for ip in ips {
                        if !is_cloudflare_ip(&ip) {
                            candidate_map.entry(ip).or_insert_with(|| CandidateIp {
                                ip,
                                source: DiscoverySource::DirectDns(format!("NS: {}", ns)),
                                hostname: Some(ns.clone()),
                                is_cloudflare: false,
                                notes: vec![format!("Discovered via Nameserver {}", ns)],
                            });
                        }
                    }
                }
            }
        }
    }

    // 3. Subdomain Wordlist Enumeration
    if options.enable_subdomains {
        let subdomains_to_check: Vec<String> = match &options.custom_wordlist {
            Some(custom) => custom.clone(),
            None => DEFAULT_SUBDOMAINS.iter().map(|&s| s.to_string()).collect(),
        };

        let fqdns: Vec<String> = subdomains_to_check
            .into_iter()
            .map(|sub| {
                if sub.contains('.') {
                    sub
                } else {
                    format!("{}.{}", sub, root)
                }
            })
            .collect();

        let concurrency = options.concurrency.max(1);
        let stream = stream::iter(fqdns).map(|fqdn| {
            let res = resolver.clone();
            async move {
                let ips = resolve_ips(&res, &fqdn).await.unwrap_or_default();
                (fqdn, ips)
            }
        });

        let mut buffered = stream.buffer_unordered(concurrency);
        while let Some((fqdn, ips)) = buffered.next().await {
            for ip in ips {
                if !is_cloudflare_ip(&ip) {
                    candidate_map.entry(ip).or_insert_with(|| CandidateIp {
                        ip,
                        source: DiscoverySource::Subdomain(fqdn.clone()),
                        hostname: Some(fqdn.clone()),
                        is_cloudflare: false,
                        notes: vec![format!("Subdomain {} resolved to unmasked IP", fqdn)],
                    });
                }
            }
        }
    }

    // 4. Certificate Transparency Logs (crt.sh)
    if options.enable_crtsh
        && let Ok(sans) = query_crtsh(http_client, &root, options.timeout_secs).await {
            let stream = stream::iter(sans).map(|san| {
                let res = resolver.clone();
                async move {
                    let ips = resolve_ips(&res, &san).await.unwrap_or_default();
                    (san, ips)
                }
            });

            let mut buffered = stream.buffer_unordered(options.concurrency.max(1));
            while let Some((san, ips)) = buffered.next().await {
                for ip in ips {
                    if !is_cloudflare_ip(&ip) {
                        candidate_map.entry(ip).or_insert_with(|| CandidateIp {
                            ip,
                            source: DiscoverySource::CertificateTransparency(san.clone()),
                            hostname: Some(san.clone()),
                            is_cloudflare: false,
                            notes: vec![format!("crt.sh SAN {} resolved to unmasked IP", san)],
                        });
                    }
                }
            }
        }

    let mut result: Vec<CandidateIp> = candidate_map.into_values().collect();
    result.sort_by_key(|c| c.ip);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_subdomains_list() {
        assert!(DEFAULT_SUBDOMAINS.contains(&"origin"));
        assert!(DEFAULT_SUBDOMAINS.contains(&"direct"));
        assert!(DEFAULT_SUBDOMAINS.contains(&"cpanel"));
        assert!(DEFAULT_SUBDOMAINS.contains(&"mail"));
        assert!(DEFAULT_SUBDOMAINS.contains(&"dev"));
        assert!(DEFAULT_SUBDOMAINS.contains(&"staging"));
    }
}
