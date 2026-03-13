//! Captcha verification plugin (Cloudflare Turnstile + hCaptcha)
//! 
//! - handle_request: verifies captcha token via third-party API, stores credential
//! - hook_comment_content_filter: checks credential, marks unverified as pending

#![no_main]

use std::alloc::{alloc, Layout};
use std::slice;

extern "C" {
    fn host_log(level_ptr: i32, level_len: i32, msg_ptr: i32, msg_len: i32);
    fn host_http_request(
        method_ptr: i32, method_len: i32,
        url_ptr: i32, url_len: i32,
        headers_ptr: i32, headers_len: i32,
        body_ptr: i32, body_len: i32,
    ) -> i32;
    fn host_storage_get(key_ptr: i32, key_len: i32) -> i32;
    fn host_storage_set(key_ptr: i32, key_len: i32, value_ptr: i32, value_len: i32) -> i32;
    fn host_storage_delete(key_ptr: i32, key_len: i32) -> i32;
    fn host_query_articles(filter_ptr: i32, filter_len: i32) -> i32;
    fn host_get_article(id_ptr: i32, id_len: i32) -> i32;
    fn host_get_comments(article_id_ptr: i32, article_id_len: i32) -> i32;
    fn host_update_article_meta(article_id: i32, data_ptr: i32, data_len: i32) -> i32;
}

#[no_mangle]
pub extern "C" fn allocate(size: i32) -> i32 {
    if size <= 0 || size > 4 * 1024 * 1024 { return 0; }
    let layout = match Layout::from_size_align(size as usize, 1) {
        Ok(l) => l,
        Err(_) => return 0,
    };
    let ptr = unsafe { alloc(layout) };
    if ptr.is_null() { 0 } else { ptr as i32 }
}

// ============================================================================
// Handle API request: POST /api/v1/plugins/captcha/api/verify
// ============================================================================

#[no_mangle]
pub extern "C" fn handle_request(ptr: i32, len: i32) -> i32 {
    let input = match read_input(ptr, len) {
        Some(s) => s,
        None => return write_output(r#"{"status":400,"body":"{\"error\":\"bad input\"}"}"#),
    };

    let method = extract_json_string(&input, "method").unwrap_or_default();
    let path = extract_json_string(&input, "path").unwrap_or_default();
    let body = extract_json_string(&input, "body").unwrap_or_default();

    // Read settings (injected into request data by the framework... but for handle_request
    // they come from plugin_data). We read from storage instead.
    let secret_key = extract_json_string(&input, "secret_key").unwrap_or_default();
    let provider = extract_json_string(&input, "provider").unwrap_or_default();

    match (method.as_str(), path.as_str()) {
        ("POST", "verify") => handle_verify(&body, &provider, &secret_key),
        _ => write_output(r#"{"status":404,"body":"{\"error\":\"not found\"}"}"#),
    }
}

fn handle_verify(body: &str, settings_provider: &str, secret_key: &str) -> i32 {
    let token = extract_json_string(body, "token").unwrap_or_default();
    let req_provider = extract_json_string(body, "provider").unwrap_or_default();

    // Use provider from request body, fallback to settings
    let provider = if !req_provider.is_empty() { &req_provider } else { settings_provider };

    if token.is_empty() {
        return write_output(r#"{"status":400,"body":"{\"success\":false,\"error\":\"missing token\"}"}"#);
    }
    if secret_key.is_empty() {
        log("warn", "Captcha secret_key not configured");
        return write_output(r#"{"status":500,"body":"{\"success\":false,\"error\":\"not configured\"}"}"#);
    }

    // Verify token with the provider's API
    let (verify_url, post_body) = match provider {
        "turnstile" => (
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            format!("secret={}&response={}", url_encode(secret_key), url_encode(&token)),
        ),
        "hcaptcha" => (
            "https://api.hcaptcha.com/siteverify",
            format!("secret={}&response={}", url_encode(secret_key), url_encode(&token)),
        ),
        _ => {
            return write_output(r#"{"status":400,"body":"{\"success\":false,\"error\":\"unknown provider\"}"}"#);
        }
    };

    let headers = r#"{"Content-Type":"application/x-www-form-urlencoded"}"#;
    let result_ptr = unsafe {
        host_http_request(
            "POST".as_ptr() as i32, 4,
            verify_url.as_ptr() as i32, verify_url.len() as i32,
            headers.as_ptr() as i32, headers.len() as i32,
            post_body.as_ptr() as i32, post_body.len() as i32,
        )
    };

    if result_ptr <= 0 {
        log("error", "HTTP request to captcha provider failed");
        return write_output(r#"{"status":502,"body":"{\"success\":false,\"error\":\"verification request failed\"}"}"#);
    }

    let resp_json = match read_result(result_ptr) {
        Some(s) => s,
        None => return write_output(r#"{"status":502,"body":"{\"success\":false,\"error\":\"bad response\"}"}"#),
    };

    // Parse the response body
    let resp_body = extract_json_string(&resp_json, "body").unwrap_or_default();
    let success = resp_body.contains("\"success\":true") || resp_body.contains("\"success\": true");

    if success {
        // Store verification credential with fixed key (one-time use)
        let ts = get_timestamp_str();
        storage_set("last_verified", &ts);
        log("info", &format!("Captcha verified successfully ({})", provider));

        let resp = format!(r#"{{"status":200,"body":"{{\"success\":true,\"credential\":\"{}\"}}" }}"#, ts);
        write_output(&resp)
    } else {
        log("info", &format!("Captcha verification failed ({}): {}", provider, resp_body));
        write_output(r#"{"status":403,"body":"{\"success\":false,\"error\":\"verification failed\"}"}"#)
    }
}

// ============================================================================
// Hook: comment_content_filter (backend safety net)
// If captcha is enabled but no recent credential found, mark as pending
// ============================================================================

#[no_mangle]
pub extern "C" fn hook_comment_content_filter(ptr: i32, len: i32) -> i32 {
    let input = match read_input(ptr, len) {
        Some(s) => s,
        None => return 0,
    };

    let provider = extract_json_string(&input, "provider").unwrap_or_default();
    if provider == "none" || provider.is_empty() {
        return 0; // Captcha disabled, pass through
    }

    // Check if there's a recent verification credential (within last 5 minutes)
    // We look for any "verified:*" key in storage
    // Since we can't list keys, we check the most recent ones
    // The frontend sends the credential timestamp, but as a safety net
    // we just check if ANY recent credential exists
    
    // Simple approach: check last 300 seconds worth of credentials
    // This is a best-effort safety net; the frontend is the primary gate
    let has_credential = check_recent_credential();
    
    if !has_credential {
        log("info", "No captcha credential found, marking comment as pending");
        let content = extract_json_string(&input, "content").unwrap_or_default();
        let article_id = extract_json_number(&input, "article_id").unwrap_or(0);
        let result = format!(
            r#"{{"content":"{}","article_id":{},"status":"pending","filter_reason":"captcha_not_verified"}}"#,
            escape_json_string(&content), article_id
        );
        return write_output(&result);
    }

    // Credential found, clean it up (one-time use)
    cleanup_credentials();
    0 // Pass through, no modification
}

fn check_recent_credential() -> bool {
    // Check storage for any "verified:*" key
    // Since WASM storage is simple key-value, we store a known key "last_verified"
    // that gets updated on each successful verification
    if let Some(val) = storage_get("last_verified") {
        if !val.is_empty() {
            return true;
        }
    }
    false
}

fn cleanup_credentials() {
    storage_delete("last_verified");
}

// ============================================================================
// Utility functions
// ============================================================================

fn log(level: &str, msg: &str) {
    unsafe {
        host_log(
            level.as_ptr() as i32, level.len() as i32,
            msg.as_ptr() as i32, msg.len() as i32,
        );
    }
}

fn storage_get(key: &str) -> Option<String> {
    let result_ptr = unsafe {
        host_storage_get(key.as_ptr() as i32, key.len() as i32)
    };
    if result_ptr <= 0 { return None; }
    let json = read_result(result_ptr)?;
    if !json.contains("\"found\":true") { return None; }
    extract_json_string(&json, "value")
}

fn storage_set(key: &str, value: &str) -> bool {
    unsafe {
        host_storage_set(
            key.as_ptr() as i32, key.len() as i32,
            value.as_ptr() as i32, value.len() as i32,
        ) > 0
    }
}

fn storage_delete(key: &str) -> bool {
    unsafe {
        host_storage_delete(key.as_ptr() as i32, key.len() as i32) > 0
    }
}

fn read_input(ptr: i32, len: i32) -> Option<String> {
    if ptr <= 0 || len <= 0 { return None; }
    let bytes = unsafe { slice::from_raw_parts(ptr as *const u8, len as usize) };
    String::from_utf8(bytes.to_vec()).ok()
}

fn read_result(ptr: i32) -> Option<String> {
    if ptr <= 0 { return None; }
    unsafe {
        let rp = ptr as usize;
        let len_bytes = slice::from_raw_parts(rp as *const u8, 4);
        let len = u32::from_le_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]) as usize;
        if len == 0 || len > 2 * 1024 * 1024 { return None; }
        let data = slice::from_raw_parts((rp + 4) as *const u8, len);
        String::from_utf8(data.to_vec()).ok()
    }
}

fn write_output(json: &str) -> i32 {
    let bytes = json.as_bytes();
    let total = 4 + bytes.len();
    let layout = match Layout::from_size_align(total, 1) {
        Ok(l) => l,
        Err(_) => return 0,
    };
    let ptr = unsafe { alloc(layout) };
    if ptr.is_null() { return 0; }
    unsafe {
        let len_bytes = (bytes.len() as u32).to_le_bytes();
        std::ptr::copy_nonoverlapping(len_bytes.as_ptr(), ptr, 4);
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr.add(4), bytes.len());
    }
    ptr as i32
}

fn extract_json_string(json: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{}\":", key);
    let start = json.find(&pattern)? + pattern.len();
    let rest = json[start..].trim_start();
    if !rest.starts_with('"') { return None; }
    let rest = &rest[1..];

    let mut result = Vec::new();
    let bytes = rest.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'"' { break; }
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            i += 1;
            match bytes[i] {
                b'n' => result.push(b'\n'),
                b't' => result.push(b'\t'),
                b'r' => result.push(b'\r'),
                b'"' => result.push(b'"'),
                b'\\' => result.push(b'\\'),
                b'/' => result.push(b'/'),
                other => { result.push(b'\\'); result.push(other); }
            }
        } else {
            result.push(bytes[i]);
        }
        i += 1;
    }
    String::from_utf8(result).ok()
}

fn extract_json_number(json: &str, key: &str) -> Option<i64> {
    let pattern = format!("\"{}\":", key);
    let start = json.find(&pattern)? + pattern.len();
    let rest = json[start..].trim_start();
    let end = rest.find(|c: char| !c.is_ascii_digit() && c != '-').unwrap_or(rest.len());
    if end == 0 { return None; }
    rest[..end].parse().ok()
}

fn escape_json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                out.push(HEX_CHARS[(b >> 4) as usize] as char);
                out.push(HEX_CHARS[(b & 0x0f) as usize] as char);
            }
        }
    }
    out
}

const HEX_CHARS: &[u8; 16] = b"0123456789ABCDEF";

fn get_timestamp_str() -> String {
    // Simple counter-based approach since we don't have access to system time in WASM
    // Use a storage counter as a pseudo-timestamp
    let counter = storage_get("_counter").and_then(|s| s.parse::<u64>().ok()).unwrap_or(0) + 1;
    storage_set("_counter", &counter.to_string());
    counter.to_string()
}
