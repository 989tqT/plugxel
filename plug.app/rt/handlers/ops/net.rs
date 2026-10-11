use std::time::Duration;
use ureq;
use serde_json::Value;
use url::Url;

/// default timeout for net request
const DEFAULT_TIMEOUT: u64 = 30;
const USER_AGENT: &str = "plugxel-runtime/1.0.0";
/// maximum response body size (1 MiB)
const MAX_RESPONSE_SIZE: usize = 1024 * 1024;

fn is_private_ip(host: &str) -> bool {
    // block localhost hostnames
    let lower_host = host.to_lowercase();
    if lower_host == "localhost" || lower_host == "localhost.localdomain" || 
       lower_host.starts_with("127.") || lower_host == "::1" {
        return true;
    }
    
    // block private/reserved IP ranges (RFC 1918, RFC 3927, RFC 6598, etc.)
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(v4) => {
                let octets = v4.octets();
                // 10.0.0.0/8
                if octets[0] == 10 { return true; }
                // 172.16.0.0/12
                if octets[0] == 172 && (16..=31).contains(&octets[1]) { return true; }
                // 192.168.0.0/16
                if octets[0] == 192 && octets[1] == 168 { return true; }
                // 127.0.0.0/8 (loopback)
                if octets[0] == 127 { return true; }
                // 169.254.0.0/16 (link-local)
                if octets[0] == 169 && octets[1] == 254 { return true; }
                // 0.0.0.0/8
                if octets[0] == 0 { return true; }
                // 224.0.0.0/4 (multicast)
                if octets[0] >= 224 { return true; }
                // 240.0.0.0/4 (reserved)
                if octets[0] >= 240 { return true; }
            }
            std::net::IpAddr::V6(v6) => {
                let segments = v6.segments();
                // ::1/128 (loopback)
                if v6.is_loopback() { return true; }
                // fe80::/10 (link-local)
                if segments[0] & 0xffc0 == 0xfe80 { return true; }
                // fc00::/7 (unique local)
                if segments[0] & 0xfe00 == 0xfc00 { return true; }
                // ::/128 (unspecified)
                if v6.is_unspecified() { return true; }
                // ff00::/8 (multicast)
                if segments[0] & 0xff00 == 0xff00 { return true; }
            }
        }
    }
    false
}

/// execute post request with json body (SSRF protected)
pub fn http_post_json(url: &str, json_payload: &str) -> Result<String, String> {
    // validate URL
    let parsed_url = Url::parse(url).map_err(|e| format!("Invalid URL: {}", e))?;
    
    // enforce HTTPS only
    if parsed_url.scheme() != "https" {
        return Err("Only HTTPS scheme is allowed".into());
    }
    
    // block private/reserved IPs (SSRF protection)
    if let Some(host) = parsed_url.host_str() {
        if is_private_ip(host) {
            return Err("Access to private IP addresses is blocked".into());
        }
    }
    
    // check input json format validity
    let body: Value = serde_json::from_str(json_payload)
        .map_err(|e| format!("Invalid JSON input: {}", e))?;

    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(DEFAULT_TIMEOUT))
        .build();

    let response = agent.post(url)
        .set("User-Agent", USER_AGENT)
        .set("Content-Type", "application/json")
        .send_json(body)
        .map_err(|e| format!("POST failed: {}", e))?;

    // limit response size
    let resp_str = response.into_string()
        .map_err(|e| format!("Failed to read response body: {}", e))?;
    
    if resp_str.len() > MAX_RESPONSE_SIZE {
        return Err(format!("Response too large (max {} bytes)", MAX_RESPONSE_SIZE));
    }
    
    Ok(resp_str)
}
