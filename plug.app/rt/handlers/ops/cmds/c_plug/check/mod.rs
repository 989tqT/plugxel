use std::fs;
use std::env;
use crate::ops::cmds::SESSION_PLUGINS;
use crate::ops::host::{print_info, print_error};
use minisign_verify::PublicKey;
use url::Url;

// minisign public key for registry signature verification (baked in at build time)
// generated with: minisign -G -p pubkey_new.txt -s passkey_new.txt
const REGISTRY_PUBKEY: &str = "RWQZFvnyykSobBmh4FOLeHNPnxqM+nHHWuVa4aOnwmQ6CLoE1Yh995wf";

/// enforce HTTPS scheme for registry/WASM downloads (defense in depth)
/// allows HTTP only for loopback addresses (127.0.0.1/localhost) for test infra
fn enforce_https(url: &str) -> Result<(), String> {
    let parsed = Url::parse(url).map_err(|e| format!("Invalid URL: {}", e))?;
    if parsed.scheme() != "https" {
        // allow http on loopback for local test servers
        let host = parsed.host_str().unwrap_or("");
        if host == "127.0.0.1" || host == "::1" || host == "localhost" {
            return Ok(());
        }
        return Err("Registry/WASM downloads require HTTPS".into());
    }
    Ok(())
}

fn verify_registry_signature(registry_path: &std::path::Path) -> Result<(), String> {
    use std::fs;
    
    let registry_url = std::env::var("PLUGXEL_REGISTRY_URL").or_else(|_| std::env::var("PLUG_REGISTRY_URL")).unwrap_or_else(|_| {
        "https://raw.githubusercontent.com/989tqT/plugxel/trunk/pluglists.json".to_string()
    });

    // Skip verification for local loopback test server (matching enforce_https)
    if let Ok(parsed) = Url::parse(&registry_url) {
        let host = parsed.host_str().unwrap_or("");
        if host == "127.0.0.1" || host == "::1" || host == "localhost" {
            return Ok(());
        }
    }

    let sig_path = registry_path.with_extension("json.minisig");
    
    // download signature file if not present
    if !sig_path.exists() {
        let sig_url = format!("{}.minisig", registry_url);

        // enforce HTTPS for signature download too (same transport channel as registry)
        if let Err(e) = enforce_https(&sig_url) {
            return Err(e);
        }

        let sig_path_str = sig_path.to_str().unwrap();
        let hr = download_file_hr(&sig_url, sig_path_str);
        if hr != 0 {
            return Err("Failed to download registry signature file".into());
        }
    }
    
    let registry_content = fs::read(registry_path)
        .map_err(|e| format!("Failed to read registry: {}", e))?;
    let sig_content = fs::read(&sig_path)
        .map_err(|e| format!("Failed to read signature: {}", e))?;
    
    let pubkey = PublicKey::from_base64(REGISTRY_PUBKEY)
        .map_err(|e| format!("Invalid public key: {}", e))?;

    let signature = minisign_verify::Signature::decode(&String::from_utf8_lossy(&sig_content))
        .map_err(|e| format!("Invalid signature format: {}", e))?;

    pubkey.verify(&registry_content, &signature, true)
        .map_err(|e| format!("Registry signature verification failed: {}", e))?;
    
    Ok(())
}

#[derive(serde::Deserialize)]
pub struct CloudPlugin {
    pub name: String,
    pub version: String,
    pub author: String,
    pub description: String,
    pub official: bool,
    #[serde(default)]
    pub sha256: Option<String>,
    #[serde(default)]
    pub permissions_hash: Option<String>,
}

#[derive(serde::Deserialize)]
pub struct CloudRepo {
    pub repo_version: String,
    pub plugins: Vec<CloudPlugin>,
}



fn compare_versions(registry: &str, local: &str) -> bool {
    let parse_ver = |s: &str| -> Vec<u32> {
        let clean_s: String = s.chars().filter(|c| c.is_digit(10) || *c == '.').collect();
        clean_s.split('.')
            .filter_map(|x| x.parse::<u32>().ok())
            .collect()
    };
    parse_ver(registry) > parse_ver(local)
}

pub fn download_file_hr(url: &str, dest: &str) -> i32 {
    // enforce HTTPS for all external downloads
    if let Err(e) = enforce_https(url) {
        print_error(&format!("[SECURITY] {}", e));
        return -1;
    }
    let req = ureq::get(url)
        .set("Cache-Control", "no-cache")
        .set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
    match req.call() {
        Ok(res) => {
            if let Ok(mut file) = fs::File::create(dest) {
                if let Ok(_) = std::io::copy(&mut res.into_reader(), &mut file) {
                    return 0; // Success
                }
            }
        }
        Err(_) => {}
    }
    -1 // Generic error
}

pub fn c_check(_args: *const i8) -> i32 {
    let _ = crate::ops::utils::safe_cstr_to_string(_args).unwrap_or_default();
    print_info("\n--- SYSTEM STATUS ---");
    let loaded = crate::ops::plugin_mgr::get_loaded_plugins();
    if loaded.is_empty() {
        print_info("No plugins running.");
    } else {
        print_info("Running plugins:");
        for (p, h) in loaded {
            print_info(&format!("  [{}] {}", h, p));
        }
    }

    print_info("\n--- PLUGIN REGISTRY ---");
    print_info("Connecting to official repository...");

    let registry_url = std::env::var("PLUGXEL_REGISTRY_URL").or_else(|_| std::env::var("PLUG_REGISTRY_URL")).unwrap_or_else(|_| {
        "https://raw.githubusercontent.com/989tqT/plugxel/trunk/pluglists.json".to_string()
    });
    let temp_dir = env::temp_dir();
    let temp_file = temp_dir.join("pluglists.json");
    let temp_path = temp_file.to_str().unwrap();
    let last_hr = download_file_hr(&registry_url, temp_path);
    let mut ok = last_hr == 0;
    if !ok {
        // local fallback copy registry from pluglists.json if download fail
        if let Some(local_registry) = find_local_file("pluglists.json") {
            if let Ok(_) = fs::copy(&local_registry, temp_path) {
                ok = true;
            }
        }
    }
    if !ok {
        print_info(&format!(
            "  [WARN] Download failed (HRESULT=0x{:08X})", last_hr as u32
        ));
    }

    if ok {
        // verify registry signature before trusting any content
        let registry_path = std::path::Path::new(temp_path);
        if let Err(e) = verify_registry_signature(registry_path) {
            print_error(&format!("[SECURITY] Registry verification failed: {}", e));
            let _ = fs::remove_file(temp_path);
            return -1;
        }
        
        if let Ok(content) = fs::read_to_string(temp_path) {
            let mut session = SESSION_PLUGINS.lock().unwrap();
            session.clear();

            match serde_json::from_str::<CloudRepo>(&content) {
                Ok(repo) => {
                    print_info(&format!("Plug Registry v{} [VERIFIED]", repo.repo_version));
                    let loaded_info = crate::ops::plugin_mgr::get_loaded_plugins_info();
                    for p in repo.plugins {
                        let hash = crate::ops::utils::rand_hash(&p.name);
                        session.insert(hash.clone(), (p.name.clone(), p.sha256.clone().unwrap_or_default(), p.permissions_hash.clone()));
                        let off_tag = if p.official { "[Official]" } else { "" };
                        let mut status_tag = String::new();
                        if let Some((_, _, local_ver)) = loaded_info.iter().find(|(n, _, _)| *n == p.name) {
                            if compare_versions(&p.version, local_ver) {
                                status_tag = format!(" [OUTDATED: Local v{} -> Registry v{}]", local_ver, p.version);
                            } else {
                                status_tag = " [Installed]".to_string();
                            }
                        }
                        print_info(&format!("  [{}] {} v{} (author: {}) {}{}", hash, p.name, p.version, p.author, off_tag, status_tag));
                        print_info(&format!("         -> {}", p.description));
                    }
                }
                Err(e) => {
                    print_error(&format!("Failed to parse JSON registry: {}", e));
                }
            }
            if session.is_empty() {
                print_info("Plugin list is empty.");
            } else {
                print_info("\nUse /plug [hash] to download and install a plugin.");
            }
        } else {
            print_info("Failed to read plugin list from temp storage.");
        }
        let _ = fs::remove_file(temp_path);
    } else {
        print_info(&format!("Network Error: Could not fetch plugin list from Github. Last HRESULT=0x{:08X}", last_hr as u32));
    }
    0
}

fn find_local_file(filename: &str) -> Option<std::path::PathBuf> {
    // scan upwards from executable path to find target file
    if let Ok(exe) = std::env::current_exe() {
        let mut parent = exe.parent();
        while let Some(p) = parent {
            let path = p.join(filename);
            if path.exists() && path.is_file() {
                return Some(path);
            }
            parent = p.parent();
        }
    }
    // scan upwards from current directory
    if let Ok(cur) = std::env::current_dir() {
        let mut parent = Some(cur.as_path());
        while let Some(p) = parent {
            let path = p.join(filename);
            if path.exists() && path.is_file() {
                return Some(path);
            }
            parent = p.parent();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_registry_with_sha256() {
        let json_data = r#"{
            "repo_version": "1.0.0",
            "plugins": [
                {
                    "name": "pTerm",
                    "author": "plugxel",
                    "version": "1.0.1",
                    "description": "Terminal environment",
                    "official": true,
                    "sha256": "0c36f35332eada4fd8dd6e5d3e6678bf637d3be6176d6ef638bffbe4a643e044"
                }
            ]
        }"#;

        let parsed: Result<CloudRepo, _> = serde_json::from_str(json_data);
        assert!(parsed.is_ok(), "Registry with sha256 should parse successfully");
        let repo = parsed.unwrap();
        assert_eq!(repo.plugins[0].name, "pTerm");
        assert_eq!(repo.plugins[0].sha256, Some("0c36f35332eada4fd8dd6e5d3e6678bf637d3be6176d6ef638bffbe4a643e044".to_string()));
    }

    #[test]
    fn test_deserialize_registry_missing_sha256() {
        let json_data = r#"{
            "repo_version": "1.0.0",
            "plugins": [
                {
                    "name": "pTerm",
                    "author": "plugxel",
                    "version": "1.0.1",
                    "description": "Terminal environment",
                    "official": true
                }
            ]
        }"#;

        let parsed: Result<CloudRepo, _> = serde_json::from_str(json_data);
        assert!(parsed.is_ok(), "Registry without sha256 should parse successfully (backwards compatible)");
        let repo = parsed.unwrap();
        assert_eq!(repo.plugins[0].name, "pTerm");
        assert_eq!(repo.plugins[0].sha256, None, "Missing sha256 field should deserialize to None");
    }
}
