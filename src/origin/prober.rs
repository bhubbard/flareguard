use crate::origin::cloudflare::has_cloudflare_headers;
use crate::origin::error::{HunterError, Result};
use crate::origin::models::{ProbeMatchDetails, ProbeResult, TargetBaseline};
use regex::Regex;
use reqwest::header::{HOST, USER_AGENT};
use reqwest::Client;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

static TITLE_REGEX: OnceLock<Regex> = OnceLock::new();

fn get_title_regex() -> &'static Regex {
    TITLE_REGEX.get_or_init(|| Regex::new(r"(?is)<title[^>]*>(.*?)</title>").unwrap())
}

/// Computes hex-encoded SHA-256 checksum of a byte slice
pub fn compute_sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Extracts HTML title from text
pub fn extract_html_title(html: &str) -> Option<String> {
    let re = get_title_regex();
    re.captures(html).and_then(|cap| {
        cap.get(1).map(|m| {
            m.as_str()
                .trim()
                .replace('\n', " ")
                .replace('\r', " ")
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        })
    })
}

/// Builds an HTTP client configured for origin probing
pub fn create_probe_client(timeout_secs: u64) -> Result<Client> {
    Client::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .timeout(Duration::from_secs(timeout_secs))
        .redirect(reqwest::redirect::Policy::limited(3))
        .build()
        .map_err(HunterError::from)
}

/// Fetches the target domain's HTTP/HTTPS response to establish comparison baseline
pub async fn fetch_target_baseline(
    client: &Client,
    domain: &str,
    resolved_ips: &[IpAddr],
    is_behind_cf: bool,
    cf_ips: &[IpAddr],
    non_cf_ips: &[IpAddr],
) -> TargetBaseline {
    let mut baseline = TargetBaseline {
        domain: domain.to_string(),
        resolved_ips: resolved_ips.to_vec(),
        is_behind_cloudflare: is_behind_cf,
        cloudflare_ips: cf_ips.to_vec(),
        non_cloudflare_ips: non_cf_ips.to_vec(),
        http_status: None,
        html_title: None,
        body_sha256: None,
        body_length: 0,
        server_header: None,
        headers: HashMap::new(),
    };

    let https_url = format!("https://{}/", domain);
    let http_url = format!("http://{}/", domain);

    let urls = [https_url, http_url];
    for url in &urls {
        let resp = client
            .get(url)
            .header(USER_AGENT, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
            .send()
            .await;

        if let Ok(response) = resp {
            baseline.http_status = Some(response.status().as_u16());

            let mut hdrs = HashMap::new();
            for (k, v) in response.headers() {
                if let Ok(val_str) = v.to_str() {
                    hdrs.insert(k.as_str().to_string(), val_str.to_string());
                }
            }

            if let Some(srv) = hdrs.get("server") {
                baseline.server_header = Some(srv.clone());
            }

            baseline.headers = hdrs;

            if let Ok(body_bytes) = response.bytes().await {
                baseline.body_length = body_bytes.len();
                baseline.body_sha256 = Some(compute_sha256(&body_bytes));
                let body_text = String::from_utf8_lossy(&body_bytes);
                baseline.html_title = extract_html_title(&body_text);
            }

            break;
        }
    }

    baseline
}

/// Probes a single IP on a given port and protocol with the Host header set to the target domain
pub async fn probe_candidate_ip(
    client: &Client,
    ip: IpAddr,
    port: u16,
    target_domain: &str,
    baseline: &TargetBaseline,
) -> ProbeResult {
    let protocol = if port == 443 || port == 8443 { "https" } else { "http" };
    let formatted_ip = match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format!("[{}]", v6),
    };
    let url = format!("{}://{}:{}/", protocol, formatted_ip, port);

    let start = Instant::now();

    let req = client
        .get(&url)
        .header(HOST, target_domain)
        .header(USER_AGENT, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 cf-origin-hunter/0.1.0");

    match req.send().await {
        Ok(response) => {
            let elapsed = start.elapsed().as_millis() as u64;
            let status = response.status().as_u16();

            let mut hdrs = HashMap::new();
            for (k, v) in response.headers() {
                if let Ok(val_str) = v.to_str() {
                    hdrs.insert(k.as_str().to_string(), val_str.to_string());
                }
            }

            let srv = hdrs.get("server").cloned();
            let cf_ray_present = has_cloudflare_headers(&hdrs);

            let (body_len, sha256_hash, title) = match response.bytes().await {
                Ok(bytes) => {
                    let len = bytes.len();
                    let hash = compute_sha256(&bytes);
                    let body_text = String::from_utf8_lossy(&bytes);
                    let t = extract_html_title(&body_text);
                    (len, Some(hash), t)
                }
                Err(_) => (0, None, None),
            };

            // Compare match details against baseline
            let exact_body_hash = match (&sha256_hash, &baseline.body_sha256) {
                (Some(probe_hash), Some(base_hash)) => probe_hash == base_hash,
                _ => false,
            };

            let title_match = match (&title, &baseline.html_title) {
                (Some(pt), Some(bt)) => !pt.is_empty() && pt.to_lowercase() == bt.to_lowercase(),
                _ => false,
            };

            let status_match = match baseline.http_status {
                Some(base_status) => base_status == status,
                None => false,
            };

            let body_length_delta = (body_len as i64) - (baseline.body_length as i64);

            let match_details = ProbeMatchDetails {
                exact_body_hash_match: exact_body_hash,
                title_match,
                status_code_match: status_match,
                body_length_delta,
                header_similarity_score: if cf_ray_present { 0.1 } else { 0.8 },
                cf_ray_present,
                direct_server_header: srv.clone(),
                baseline_server_header: baseline.server_header.clone(),
            };

            ProbeResult {
                ip,
                port,
                protocol: protocol.to_string(),
                url,
                success: true,
                status_code: Some(status),
                html_title: title,
                body_sha256: sha256_hash,
                body_length: body_len,
                server_header: srv,
                headers: hdrs,
                response_time_ms: elapsed,
                error: None,
                match_details: Some(match_details),
            }
        }
        Err(err) => {
            let elapsed = start.elapsed().as_millis() as u64;
            ProbeResult {
                ip,
                port,
                protocol: protocol.to_string(),
                url,
                success: false,
                status_code: None,
                html_title: None,
                body_sha256: None,
                body_length: 0,
                server_header: None,
                headers: HashMap::new(),
                response_time_ms: elapsed,
                error: Some(err.to_string()),
                match_details: None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_sha256() {
        let text = b"Hello Cloudflare Hunter";
        let hash = compute_sha256(text);
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_extract_html_title() {
        let html = "<html><head><title>Acme Corp | Security Portal</title></head><body><h1>Hi</h1></body></html>";
        let title = extract_html_title(html);
        assert_eq!(title, Some("Acme Corp | Security Portal".to_string()));

        let multiline = "<html><head><title>\n  Dashboard &bull; Login  \n</title></head></html>";
        let title2 = extract_html_title(multiline);
        assert_eq!(title2, Some("Dashboard &bull; Login".to_string()));

        let no_title = "<html><body><h1>No title</h1></body></html>";
        assert_eq!(extract_html_title(no_title), None);
    }
}
