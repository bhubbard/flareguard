use crate::origin::models::{ConfidenceLevel, DiscoverySource, ProbeResult, TargetBaseline};

/// Calculates the overall confidence score (0-100) and confidence level for a candidate IP
pub fn calculate_confidence(
    baseline: &TargetBaseline,
    source: &DiscoverySource,
    successful_probes: &[ProbeResult],
    _failed_probes: &[ProbeResult],
) -> (ConfidenceLevel, u8, String) {
    // 1. Check for exact probe match (CONFIRMED - 100%)
    for probe in successful_probes {
        if let Some(ref match_details) = probe.match_details
            && match_details.exact_body_hash_match
        {
            return (
                ConfidenceLevel::Confirmed,
                100,
                format!(
                    "Exact SHA-256 body hash match on direct HTTP/HTTPS probe (port {}). Backend returned identical payload bypassing Cloudflare edge.",
                    probe.port
                ),
            );
        }
    }

    // 2. Check for title match and header similarities (HIGH - 85%)
    for probe in successful_probes {
        if let Some(ref match_details) = probe.match_details
            && match_details.title_match
            && !match_details.cf_ray_present
        {
            let baseline_title = baseline.html_title.as_deref().unwrap_or("N/A");
            return (
                ConfidenceLevel::High,
                85,
                format!(
                    "HTML title matches target baseline ('{}') without Cloudflare proxy headers on port {}.",
                    baseline_title, probe.port
                ),
            );
        }
    }

    // 3. Check for direct subdomain origin bypass (HIGH - 80-85%)
    match source {
        DiscoverySource::Subdomain(sub) if is_high_value_subdomain(sub) => {
            if !successful_probes.is_empty() {
                return (
                    ConfidenceLevel::High,
                    80,
                    format!(
                        "High-value origin subdomain ('{}') points directly to unmasked IP and responds to HTTP requests.",
                        sub
                    ),
                );
            }
        }
        DiscoverySource::CertificateTransparency(san)
            if is_high_value_subdomain(san) && !successful_probes.is_empty() =>
        {
            return (
                ConfidenceLevel::High,
                80,
                format!(
                    "Certificate Transparency SAN ('{}') points to unmasked IP with active web service.",
                    san
                ),
            );
        }
        _ => {}
    }

    // 4. Check for SPF direct IP declaration or MX server (MEDIUM - 60-70%)
    match source {
        DiscoverySource::SpfRecord(spf) => {
            if !successful_probes.is_empty() {
                return (
                    ConfidenceLevel::Medium,
                    70,
                    format!(
                        "IP explicitly authorized in target SPF record ('{}') and hosts active web service.",
                        spf
                    ),
                );
            } else {
                return (
                    ConfidenceLevel::Medium,
                    55,
                    format!(
                        "IP explicitly declared in SPF record ('{}'); server did not respond on standard HTTP/HTTPS ports.",
                        spf
                    ),
                );
            }
        }
        DiscoverySource::MxRecord(mx) => {
            if !successful_probes.is_empty() {
                return (
                    ConfidenceLevel::Medium,
                    65,
                    format!(
                        "Target MX server ('{}') resolves to unmasked IP and accepts HTTP traffic.",
                        mx
                    ),
                );
            } else {
                return (
                    ConfidenceLevel::Medium,
                    50,
                    format!(
                        "Target MX server ('{}') resolves to non-Cloudflare IP address.",
                        mx
                    ),
                );
            }
        }
        DiscoverySource::Subdomain(sub) => {
            if !successful_probes.is_empty() {
                return (
                    ConfidenceLevel::Medium,
                    60,
                    format!(
                        "Subdomain ('{}') resolves to non-Cloudflare IP with responsive HTTP port.",
                        sub
                    ),
                );
            }
        }
        DiscoverySource::CertificateTransparency(san) => {
            if !successful_probes.is_empty() {
                return (
                    ConfidenceLevel::Medium,
                    60,
                    format!(
                        "Historical crt.sh SAN ('{}') resolves to non-Cloudflare IP with responsive HTTP port.",
                        san
                    ),
                );
            }
        }
        DiscoverySource::HistoricalDns(src) if !successful_probes.is_empty() => {
            return (
                ConfidenceLevel::Medium,
                65,
                format!(
                    "Historical DNS record ('{}') resolves to active HTTP server.",
                    src
                ),
            );
        }
        _ => {}
    }

    // 5. Fallback for non-responsive candidate IPs (LOW - 25-35%)
    let reason = match source {
        DiscoverySource::Subdomain(sub) => {
            format!(
                "Subdomain ('{}') points to non-Cloudflare IP, but HTTP probes failed or timed out.",
                sub
            )
        }
        DiscoverySource::CertificateTransparency(san) => {
            format!(
                "Certificate SAN ('{}') points to non-Cloudflare IP, but HTTP probes failed or timed out.",
                san
            )
        }
        DiscoverySource::HistoricalDns(src) => {
            format!(
                "Historical record ('{}') points to non-Cloudflare IP, but host is currently unresponsive.",
                src
            )
        }
        _ => {
            format!(
                "Candidate discovered via {}, but no direct HTTP verification succeeded.",
                source
            )
        }
    };

    (ConfidenceLevel::Low, 30, reason)
}

fn is_high_value_subdomain(name: &str) -> bool {
    let lower = name.to_lowercase();
    let keywords = [
        "origin",
        "direct",
        "cpanel",
        "dev",
        "staging",
        "api-origin",
        "backend",
        "internal",
        "vps",
        "server",
        "admin",
        "portal",
        "ssh",
    ];
    keywords.iter().any(|&k| lower.contains(k))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::origin::models::ProbeMatchDetails;
    use std::collections::HashMap;

    fn mock_baseline() -> TargetBaseline {
        TargetBaseline {
            domain: "example.com".to_string(),
            resolved_ips: vec!["104.21.1.1".parse().unwrap()],
            is_behind_cloudflare: true,
            cloudflare_ips: vec!["104.21.1.1".parse().unwrap()],
            non_cloudflare_ips: vec![],
            http_status: Some(200),
            html_title: Some("Welcome to Example".to_string()),
            body_sha256: Some("abcdef1234567890".to_string()),
            body_length: 1200,
            server_header: Some("cloudflare".to_string()),
            headers: HashMap::new(),
        }
    }

    #[test]
    fn test_confidence_confirmed_on_hash_match() {
        let baseline = mock_baseline();
        let probe = ProbeResult {
            ip: "198.51.100.42".parse().unwrap(),
            port: 80,
            protocol: "http".to_string(),
            url: "http://198.51.100.42/".to_string(),
            success: true,
            status_code: Some(200),
            html_title: Some("Welcome to Example".to_string()),
            body_sha256: Some("abcdef1234567890".to_string()),
            body_length: 1200,
            server_header: Some("nginx".to_string()),
            headers: HashMap::new(),
            response_time_ms: 45,
            error: None,
            match_details: Some(ProbeMatchDetails {
                exact_body_hash_match: true,
                title_match: true,
                status_code_match: true,
                body_length_delta: 0,
                header_similarity_score: 0.9,
                cf_ray_present: false,
                direct_server_header: Some("nginx".to_string()),
                baseline_server_header: Some("cloudflare".to_string()),
            }),
        };

        let (level, score, reason) = calculate_confidence(
            &baseline,
            &DiscoverySource::Subdomain("origin.example.com".into()),
            &[probe],
            &[],
        );

        assert_eq!(level, ConfidenceLevel::Confirmed);
        assert_eq!(score, 100);
        assert!(reason.contains("Exact SHA-256"));
    }

    #[test]
    fn test_confidence_high_on_title_match() {
        let baseline = mock_baseline();
        let probe = ProbeResult {
            ip: "198.51.100.42".parse().unwrap(),
            port: 443,
            protocol: "https".to_string(),
            url: "https://198.51.100.42/".to_string(),
            success: true,
            status_code: Some(200),
            html_title: Some("Welcome to Example".to_string()),
            body_sha256: Some("different_hash".to_string()),
            body_length: 1250,
            server_header: Some("Apache/2.4".to_string()),
            headers: HashMap::new(),
            response_time_ms: 50,
            error: None,
            match_details: Some(ProbeMatchDetails {
                exact_body_hash_match: false,
                title_match: true,
                status_code_match: true,
                body_length_delta: 50,
                header_similarity_score: 0.8,
                cf_ray_present: false,
                direct_server_header: Some("Apache/2.4".to_string()),
                baseline_server_header: Some("cloudflare".to_string()),
            }),
        };

        let (level, score, reason) = calculate_confidence(
            &baseline,
            &DiscoverySource::Subdomain("dev.example.com".into()),
            &[probe],
            &[],
        );

        assert_eq!(level, ConfidenceLevel::High);
        assert_eq!(score, 85);
        assert!(reason.contains("HTML title matches"));
    }

    #[test]
    fn test_confidence_medium_on_spf() {
        let baseline = mock_baseline();
        let (level, score, reason) = calculate_confidence(
            &baseline,
            &DiscoverySource::SpfRecord("ip4:198.51.100.42".into()),
            &[],
            &[],
        );

        assert_eq!(level, ConfidenceLevel::Medium);
        assert_eq!(score, 55);
        assert!(reason.contains("SPF record"));
    }
}
