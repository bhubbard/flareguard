use crate::origin::error::{HunterError, Result};
use hickory_resolver::TokioResolver;
use hickory_resolver::proto::rr::{RData, RecordType};
use ipnet::Ipv4Net;
use regex::Regex;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::OnceLock;

/// Creates a new asynchronous DNS resolver configured with system resolver and fallback
pub fn create_resolver() -> Result<TokioResolver> {
    TokioResolver::builder_tokio()
        .map_err(|e| HunterError::Dns(e.to_string()))?
        .build()
        .map_err(|e| HunterError::Dns(e.to_string()))
}

/// Resolves A (IPv4) and AAAA (IPv6) records for a domain
pub async fn resolve_ips(resolver: &TokioResolver, domain: &str) -> Result<Vec<IpAddr>> {
    let mut results = Vec::new();

    if let Ok(response) = resolver.lookup_ip(domain).await {
        for ip in response.iter() {
            if !results.contains(&ip) {
                results.push(ip);
            }
        }
    }

    Ok(results)
}

/// Resolves MX records for a domain and looks up the IP addresses of the mail exchangers
pub async fn resolve_mx_servers(
    resolver: &TokioResolver,
    domain: &str,
) -> Result<Vec<(String, Vec<IpAddr>)>> {
    let mut servers = Vec::new();

    if let Ok(lookup) = resolver.lookup(domain, RecordType::MX).await {
        for record in lookup.answers() {
            if let RData::MX(ref mx) = record.data {
                let exchange = mx.exchange.to_utf8().trim_end_matches('.').to_string();
                let ips = resolve_ips(resolver, &exchange).await.unwrap_or_default();
                servers.push((exchange, ips));
            }
        }
    }

    Ok(servers)
}

/// Resolves TXT records for a domain
pub async fn resolve_txt_records(resolver: &TokioResolver, domain: &str) -> Result<Vec<String>> {
    let mut records = Vec::new();

    if let Ok(lookup) = resolver.lookup(domain, RecordType::TXT).await {
        for record in lookup.answers() {
            if let RData::TXT(ref txt) = record.data {
                let text = txt
                    .txt_data
                    .iter()
                    .map(|b| String::from_utf8_lossy(b).into_owned())
                    .collect::<Vec<_>>()
                    .join("");
                records.push(text);
            }
        }
    }

    Ok(records)
}

/// Resolves NS records for a domain
pub async fn resolve_ns_records(resolver: &TokioResolver, domain: &str) -> Result<Vec<String>> {
    let mut records = Vec::new();

    if let Ok(lookup) = resolver.lookup(domain, RecordType::NS).await {
        for record in lookup.answers() {
            if let RData::NS(ref ns) = record.data {
                let ns_str = ns.0.to_utf8().trim_end_matches('.').to_string();
                records.push(ns_str);
            }
        }
    }

    Ok(records)
}

static SPF_IP4_REGEX: OnceLock<Regex> = OnceLock::new();
static SPF_IP6_REGEX: OnceLock<Regex> = OnceLock::new();

fn get_spf_ip4_regex() -> &'static Regex {
    SPF_IP4_REGEX.get_or_init(|| Regex::new(r"(?i)ip4:([0-9\.\/]+)").unwrap())
}

fn get_spf_ip6_regex() -> &'static Regex {
    SPF_IP6_REGEX.get_or_init(|| Regex::new(r"(?i)ip6:([0-9a-fA-F:\/]+)").unwrap())
}

/// Extracts IPv4 and IPv6 addresses specified directly in an SPF record
pub fn extract_ips_from_spf(spf_text: &str) -> Vec<IpAddr> {
    let mut ips = Vec::new();

    if !spf_text.to_lowercase().contains("v=spf1") {
        return ips;
    }

    // Match ip4:
    let ip4_re = get_spf_ip4_regex();
    for cap in ip4_re.captures_iter(spf_text) {
        if let Some(matched) = cap.get(1) {
            let val = matched.as_str();
            if val.contains('/') {
                if let Ok(net) = Ipv4Net::from_str(val) {
                    let addr = IpAddr::V4(net.addr());
                    if !ips.contains(&addr) {
                        ips.push(addr);
                    }
                }
            } else if let Ok(ip) = Ipv4Addr::from_str(val) {
                let addr = IpAddr::V4(ip);
                if !ips.contains(&addr) {
                    ips.push(addr);
                }
            }
        }
    }

    // Match ip6:
    let ip6_re = get_spf_ip6_regex();
    for cap in ip6_re.captures_iter(spf_text) {
        if let Some(matched) = cap.get(1) {
            let val = matched.as_str();
            let cleaned = val.split('/').next().unwrap_or(val);
            if let Ok(ip) = Ipv6Addr::from_str(cleaned) {
                let addr = IpAddr::V6(ip);
                if !ips.contains(&addr) {
                    ips.push(addr);
                }
            }
        }
    }

    ips
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_ips_from_spf() {
        let spf = "v=spf1 ip4:198.51.100.42 ip4:203.0.113.0/24 ip6:2001:db8::1 include:_spf.google.com ~all";
        let ips = extract_ips_from_spf(spf);

        assert_eq!(ips.len(), 3);
        assert!(ips.contains(&"198.51.100.42".parse().unwrap()));
        assert!(ips.contains(&"203.0.113.0".parse().unwrap()));
        assert!(ips.contains(&"2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn test_extract_ips_from_non_spf() {
        let txt = "google-site-verification=abcdef123456";
        let ips = extract_ips_from_spf(txt);
        assert!(ips.is_empty());
    }

    #[test]
    fn test_extract_ips_single_ip4() {
        let spf = "v=spf1 a mx ip4:45.33.32.156 -all";
        let ips = extract_ips_from_spf(spf);
        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0], "45.33.32.156".parse::<IpAddr>().unwrap());
    }
}
