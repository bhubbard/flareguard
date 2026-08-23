use crate::origin::models::RemediationStep;

/// Generates actionable remediation steps based on detected origin leak exposures
pub fn generate_remediation_plan() -> Vec<RemediationStep> {
    vec![
        RemediationStep {
            id: "REM-001".to_string(),
            title: "Configure Cloudflare Authenticated Origin Pulls (AOP)".to_string(),
            priority: "CRITICAL".to_string(),
            description: "Enforce TLS client certificate validation on origin web servers (Nginx/Apache/Envoy). Direct requests from attackers to origin IP will be rejected at TLS handshake unless routed through Cloudflare edge.".to_string(),
            commands: vec![
                "# Download Cloudflare Origin CA root certificate".to_string(),
                "curl -s https://developers.cloudflare.com/ssl/static/authenticated_origin_pull_ca.pem -o /etc/ssl/certs/cloudflare_aop_ca.pem".to_string(),
                "# In Nginx server block:".to_string(),
                "ssl_client_certificate /etc/ssl/certs/cloudflare_aop_ca.pem;".to_string(),
                "ssl_verify_client on;".to_string(),
            ],
            doc_url: "https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/".to_string(),
        },
        RemediationStep {
            id: "REM-002".to_string(),
            title: "Restrict Origin Firewall / Security Groups to Cloudflare IPs Only".to_string(),
            priority: "CRITICAL".to_string(),
            description: "Block all direct ingress traffic on HTTP (80) and HTTPS (443) ports except from Cloudflare's published IP ranges. Ensure no unauthorized hosts can reach the backend.".to_string(),
            commands: vec![
                "# Cloudflare IPv4 ranges: 173.245.48.0/20, 103.21.244.0/22, 103.22.200.0/22, 103.31.4.0/22, 141.101.64.0/18, 108.162.192.0/18, 190.93.240.0/20, 188.114.96.0/20, 197.234.240.0/22, 198.41.128.0/17, 162.158.0.0/15, 104.16.0.0/13, 104.24.0.0/14, 172.64.0.0/13, 131.0.72.0/22".to_string(),
                "# Example UFW setup:".to_string(),
                "for ip in $(curl -s https://www.cloudflare.com/ips-v4); do ufw allow from $ip to any port 443 proto tcp; done".to_string(),
                "ufw default deny incoming".to_string(),
            ],
            doc_url: "https://www.cloudflare.com/ips/".to_string(),
        },
        RemediationStep {
            id: "REM-003".to_string(),
            title: "Deploy Cloudflare Tunnel (cloudflared) for Zero Public Ingress".to_string(),
            priority: "HIGH".to_string(),
            description: "Replace public DNS A/AAAA records with Cloudflare Tunnel (CNAME to *.cfargotunnel.com). The origin creates outbound-only connections to Cloudflare edge with no open inbound firewall ports.".to_string(),
            commands: vec![
                "# Install cloudflared daemon".to_string(),
                "cloudflared tunnel create prod-origin-tunnel".to_string(),
                "cloudflared tunnel route dns prod-origin-tunnel app.example.com".to_string(),
                "cloudflared tunnel run --token <TOKEN>".to_string(),
            ],
            doc_url: "https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/".to_string(),
        },
        RemediationStep {
            id: "REM-004".to_string(),
            title: "Rotate Exposed Origin IP & Separate Mail/DNS Infrastructure".to_string(),
            priority: "HIGH".to_string(),
            description: "Once an origin IP is discovered in historical DNS, certificate transparency logs, or SPF records, rotate the server's public IP address. Separate MX mail servers onto dedicated external relays (e.g. Fastmail, Google Workspace, AWS SES).".to_string(),
            commands: vec![
                "# Disassociate leaked Elastic/Cloud IP and allocate new origin IP address".to_string(),
                "# Verify MX records point to third-party hosted mail servers rather than web origin".to_string(),
                "# Delete unused DNS records (e.g., direct.domain.com, cpanel.domain.com, origin.domain.com)".to_string(),
            ],
            doc_url: "https://developers.cloudflare.com/fundamentals/setup/protect-your-origin-server/".to_string(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_remediation_steps_generation() {
        let plan = generate_remediation_plan();
        assert_eq!(plan.len(), 4);
        assert_eq!(plan[0].id, "REM-001");
        assert!(plan[0].title.contains("Authenticated Origin Pulls"));
        assert!(plan[1].title.contains("Firewall"));
    }
}
