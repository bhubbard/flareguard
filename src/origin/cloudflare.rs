use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::OnceLock;

/// Official Cloudflare IPv4 IP ranges (https://www.cloudflare.com/ips-v4)
pub const CLOUDFLARE_IPV4_CIDRS: &[&str] = &[
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
];

/// Official Cloudflare IPv6 IP ranges (https://www.cloudflare.com/ips-v6)
pub const CLOUDFLARE_IPV6_CIDRS: &[&str] = &[
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
];

/// Cloudflare Autonomous System Numbers (ASN)
pub const CLOUDFLARE_ASNS: &[&str] = &[
    "AS13335",
    "AS209242",
    "CLOUDFLARENET",
    "CLOUDFLARE",
];

static CLOUDFLARE_NETWORKS: OnceLock<Vec<IpNet>> = OnceLock::new();

fn get_cloudflare_networks() -> &'static Vec<IpNet> {
    CLOUDFLARE_NETWORKS.get_or_init(|| {
        let mut nets = Vec::new();
        for cidr in CLOUDFLARE_IPV4_CIDRS {
            if let Ok(net) = Ipv4Net::from_str(cidr) {
                nets.push(IpNet::V4(net));
            }
        }
        for cidr in CLOUDFLARE_IPV6_CIDRS {
            if let Ok(net) = Ipv6Net::from_str(cidr) {
                nets.push(IpNet::V6(net));
            }
        }
        nets
    })
}

/// Checks if an IP address belongs to Cloudflare's public proxy edge network
pub fn is_cloudflare_ip(ip: &IpAddr) -> bool {
    let networks = get_cloudflare_networks();
    networks.iter().any(|net| net.contains(ip))
}

/// Checks if an ASN string represents Cloudflare
pub fn is_cloudflare_asn(asn: &str) -> bool {
    let upper = asn.to_uppercase();
    CLOUDFLARE_ASNS.iter().any(|&cf_asn| upper.contains(cf_asn))
}

/// Checks if HTTP headers contain Cloudflare edge proxy signatures
pub fn has_cloudflare_headers(headers: &std::collections::HashMap<String, String>) -> bool {
    for (k, v) in headers {
        let key = k.to_lowercase();
        let val = v.to_lowercase();
        if key == "server" && val.contains("cloudflare") {
            return true;
        }
        if key == "cf-ray" || key == "cf-cache-status" || key == "cf-mitigated" || key == "cf-request-id" {
            return true;
        }
    }
    false
}

/// Filters a slice of IP addresses into Cloudflare edge IPs and non-Cloudflare candidate IPs
pub fn partition_ips(ips: &[IpAddr]) -> (Vec<IpAddr>, Vec<IpAddr>) {
    let mut cf_ips = Vec::new();
    let mut non_cf_ips = Vec::new();

    for &ip in ips {
        if is_cloudflare_ip(&ip) {
            cf_ips.push(ip);
        } else {
            non_cf_ips.push(ip);
        }
    }

    (cf_ips, non_cf_ips)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cloudflare_ipv4_detection() {
        // Known Cloudflare IPs
        let cf_ip1: IpAddr = "104.21.45.12".parse().unwrap();
        let cf_ip2: IpAddr = "172.67.180.20".parse().unwrap();
        let cf_ip3: IpAddr = "162.158.5.99".parse().unwrap();
        let cf_ip4: IpAddr = "198.41.130.1".parse().unwrap();

        assert!(is_cloudflare_ip(&cf_ip1));
        assert!(is_cloudflare_ip(&cf_ip2));
        assert!(is_cloudflare_ip(&cf_ip3));
        assert!(is_cloudflare_ip(&cf_ip4));

        // Non-Cloudflare IPs
        let non_cf_ip1: IpAddr = "198.51.100.42".parse().unwrap();
        let non_cf_ip2: IpAddr = "8.8.8.8".parse().unwrap();
        let non_cf_ip3: IpAddr = "1.1.1.1".parse().unwrap(); // Note: 1.1.1.1 is CF DNS, but not in proxy CIDRs
        let non_cf_ip4: IpAddr = "140.82.121.3".parse().unwrap(); // GitHub

        assert!(!is_cloudflare_ip(&non_cf_ip1));
        assert!(!is_cloudflare_ip(&non_cf_ip2));
        assert!(!is_cloudflare_ip(&non_cf_ip3));
        assert!(!is_cloudflare_ip(&non_cf_ip4));
    }

    #[test]
    fn test_cloudflare_ipv6_detection() {
        let cf_ipv6: IpAddr = "2606:4700:3037::ac43:d236".parse().unwrap();
        assert!(is_cloudflare_ip(&cf_ipv6));

        let non_cf_ipv6: IpAddr = "2001:4860:4860::8888".parse().unwrap();
        assert!(!is_cloudflare_ip(&non_cf_ipv6));
    }

    #[test]
    fn test_partition_ips() {
        let ips = vec![
            "104.21.1.1".parse().unwrap(),
            "198.51.100.5".parse().unwrap(),
            "172.67.2.2".parse().unwrap(),
            "203.0.113.10".parse().unwrap(),
        ];
        let (cf, non_cf) = partition_ips(&ips);
        assert_eq!(cf.len(), 2);
        assert_eq!(non_cf.len(), 2);
        assert!(non_cf.contains(&"198.51.100.5".parse().unwrap()));
        assert!(non_cf.contains(&"203.0.113.10".parse().unwrap()));
    }

    #[test]
    fn test_has_cloudflare_headers() {
        let mut headers = std::collections::HashMap::new();
        headers.insert("server".to_string(), "cloudflare".to_string());
        headers.insert("cf-ray".to_string(), "8abc1234def-ORD".to_string());
        assert!(has_cloudflare_headers(&headers));

        let mut origin_headers = std::collections::HashMap::new();
        origin_headers.insert("server".to_string(), "nginx/1.24.0".to_string());
        origin_headers.insert("x-powered-by".to_string(), "PHP/8.2".to_string());
        assert!(!has_cloudflare_headers(&origin_headers));
    }
}
