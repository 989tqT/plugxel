use std::fs::File;
use std::io::{Read, Write};
use std::time::{Instant, Duration};
use crate::ops::host::{print_info, print_error};

// re-export enforce_https to avoid circular dep with check/mod.rs
// both download_file_hr and download_with_progress must enforce HTTPS
fn enforce_https(url: &str) -> Result<(), String> {
    use url::Url;
    let parsed = Url::parse(url).map_err(|e| format!("Invalid URL: {}", e))?;
    if parsed.scheme() != "https" {
        // allow http on loopback for local test servers
        let host = parsed.host_str().unwrap_or("");
        if host == "127.0.0.1" || host == "::1" || host == "localhost" {
            return Ok(());
        }
        return Err("Only HTTPS downloads are allowed".into());
    }
    Ok(())
}

pub fn download_with_progress(url: &str, dest_path: &str, silent: bool) -> bool {
    // enforce HTTPS for all external downloads
    if let Err(e) = enforce_https(url) {
        if !silent {
            print_error(&format!("[SECURITY] {}", e));
        }
        return false;
    }
    let agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
    let req = ureq::get(url).set("User-Agent", agent);
    let response = match req.call() {
        Ok(res) => res,
        Err(_) => return false,
    };

    let content_len = response.header("Content-Length").and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
    
    let mut file = match File::create(dest_path) {
        Ok(f) => f,
        Err(_) => return false,
    };

    let mut reader = response.into_reader();
    let mut buffer = [0u8; 8192];
    let mut total_read = 0;
    let start_time = Instant::now();
    let mut last_ui_update = Instant::now();
    let spinner = ['|', '/', '-', '\\'];
    let mut spinner_idx = 0;

    if !silent {
        print_info("Starting download...");
    }

    loop {
        let bytes_read = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => return false,
        };

        total_read += bytes_read as u64;
        if let Err(_) = file.write_all(&buffer[..bytes_read]) { return false; }

        if !silent && last_ui_update.elapsed() >= Duration::from_millis(100) {
            spinner_idx = (spinner_idx + 1) % spinner.len();
            let pct = if content_len > 0 { (total_read as f64 / content_len as f64) * 100.0 } else { 0.0 };
            let elapsed = start_time.elapsed().as_secs_f64();
            let speed = if elapsed > 0.0 { total_read as f64 / elapsed } else { 0.0 };
            let eta = if speed > 0.0 && content_len > 0 { 
                let remaining = (content_len as f64 - total_read as f64) / speed;
                format!("{:.1}s", remaining)
            } else { 
                "Unknown".to_string() 
            };

            let progress_msg = format!(
                "  {} Downloading... [{:>3.0}%] ETA: {:>8} ({:>6.1} KB/s)",
                spinner[spinner_idx], pct, eta, speed / 1024.0
            );
            print_info(&progress_msg);
            last_ui_update = Instant::now();
        }
    }

    if !silent {
        let final_msg = format!("  [+] Download complete: {} bytes", total_read);
        print_info(&final_msg);
    }

    total_read > 0 && (content_len == 0 || total_read == content_len)
}
