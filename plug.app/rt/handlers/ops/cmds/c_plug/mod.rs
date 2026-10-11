use std::path::PathBuf;
use std::fs;
use toml;
use crate::ops::cmds::SESSION_PLUGINS;
use crate::ops::host::{print_info, print_error};

pub mod check;
pub mod progress;
pub mod del;

pub fn c_plug(args: *const i8) -> i32 {
    let hash = match crate::ops::utils::safe_cstr_to_string(args) {
        Some(val) => val.trim().to_string(),
        None => return -1,
    };

    if hash.is_empty() {
        print_error("Usage: /plug [hash]");
        return -1;
    }

    let (plugin_name, registry_sha256, registry_permissions_hash) = {
        let session = SESSION_PLUGINS.lock().unwrap();
        match session.get(&hash) {
            Some((name, sha, perm_hash)) => (name.clone(), sha.clone(), perm_hash.clone()),
            None => {
                print_error("Invalid or expired hash. Run /plug* to get a fresh list.");
                return -1;
            }
        }
    };

    let clean_name = plugin_name
        .trim_end_matches(".plug")
        .trim_end_matches(".wasm")
        .to_string();

    install_plugin_manually(&clean_name, &hash, &registry_sha256, registry_permissions_hash.as_deref(), false)
}

pub fn install_plugin_manually(clean_name: &str, session_hash: &str, registry_sha256: &str, registry_permissions_hash: Option<&str>, silent: bool) -> i32 {
    if !silent {
        print_info(&format!("Downloading: {}.plug...", clean_name));
    }

    let dest_root = match crate::ops::utils::get_plugins_dir() {
        Some(path) => path,
        None => {
            print_error("Failed to resolve plugins directory.");
            return -1;
        }
    };

    if !dest_root.exists() {
        let _ = fs::create_dir_all(&dest_root);
    }

    let mut dest_dir = dest_root.clone();
    dest_dir.push(clean_name);
    
    if !dest_dir.exists() {
        let _ = fs::create_dir_all(&dest_dir);
    }

    let mut dest_wasm = dest_dir.clone();
    dest_wasm.push(format!("{}.{}", clean_name, session_hash));
    let mut tmp_wasm = dest_wasm.clone();
    let mut tmp_wasm_name = tmp_wasm.file_name().unwrap_or_default().to_os_string();
    tmp_wasm_name.push(".tmp");
    tmp_wasm.set_file_name(tmp_wasm_name);
    
    let base_url = std::env::var("PLUGXEL_WASM_BASE_URL").or_else(|_| std::env::var("PLUG_WASM_BASE_URL")).unwrap_or_else(|_| {
        "https://raw.githubusercontent.com/989tqT/plugxel/trunk/plugins/".to_string()
    });
    let base_url = if base_url.is_empty() || base_url.ends_with('/') {
        base_url
    } else {
        format!("{}/", base_url)
    };

    let url_wasm = format!("{}{}/{}", base_url, clean_name, clean_name);
    let url_toml = format!("{}plugin.toml", base_url);
    let mut dest_toml = dest_root.clone();
    dest_toml.push("plugin.toml");
    let mut tmp_toml = dest_toml.clone();
    let mut tmp_toml_name = tmp_toml.file_name().unwrap_or_default().to_os_string();
    tmp_toml_name.push(".tmp");
    tmp_toml.set_file_name(tmp_toml_name);

    let mut success = false;

    let mut downloaded_wasm = progress::download_with_progress(&url_wasm, tmp_wasm.to_str().unwrap(), silent);
    if !downloaded_wasm {
        // local fallback copy plugin from local path if download fail
        if let Some(plugins_dir) = find_local_plugins_dir() {
            let local_wasm = plugins_dir.join(clean_name).join(clean_name);
            if local_wasm.exists() {
                if let Ok(_) = fs::copy(&local_wasm, &tmp_wasm) {
                    downloaded_wasm = true;
                    if !silent {
                        print_info(&format!("local fallback copy plugin: {}", clean_name));
                    }
                }
            }
        }
    }

    if downloaded_wasm {
        if !silent {
            print_info("Downloading unified manifest file...");
        }
        let mut downloaded_toml = progress::download_with_progress(&url_toml, tmp_toml.to_str().unwrap(), true);
        if !downloaded_toml {
            // local fallback copy manifest if download fail
            if let Some(plugins_dir) = find_local_plugins_dir() {
                let local_toml = plugins_dir.join("plugin.toml");
                if local_toml.exists() {
                    if let Ok(_) = fs::copy(&local_toml, &tmp_toml) {
                        downloaded_toml = true;
                        if !silent {
                            print_info("local fallback: copy manifest");
                        }
                    }
                }
            }
        }

        if downloaded_toml {
            let wasm_bytes = match fs::read(&tmp_wasm) {
                Ok(bytes) => bytes,
                Err(e) => {
                    print_error(&format!("Failed to read downloaded WASM: {}", e));
                    let _ = fs::remove_file(&tmp_wasm);
                    let _ = fs::remove_file(&tmp_toml);
                    return -1;
                }
            };

            let sha256_hex = crate::ops::utils::calculate_buffer_sha256(&wasm_bytes);

            // verify against registry-pinned hash (fail-closed on missing or mismatch)
            if registry_sha256.is_empty() {
                print_error(&format!("[SECURITY] Missing pinned hash in registry for plugin: {}. Aborting installation.", clean_name));
                let _ = fs::remove_file(&tmp_wasm);
                let _ = fs::remove_file(&tmp_toml);
                return -1;
            }

            if sha256_hex != registry_sha256 {
                print_error(&format!("[SECURITY] Pinned registry hash mismatch for plugin: {} (Expected: {}, Found: {})", clean_name, registry_sha256, sha256_hex));
                let _ = fs::remove_file(&tmp_wasm);
                let _ = fs::remove_file(&tmp_toml);
                return -1;
            }
            
            // rename files atomically
            if let Err(e) = fs::rename(&tmp_wasm, &dest_wasm) {
                print_error(&format!("Failed to finalize WASM file: {}", e));
                let _ = fs::remove_file(&tmp_wasm);
                let _ = fs::remove_file(&tmp_toml);
                return -1;
            }

            if let Err(e) = fs::rename(&tmp_toml, &dest_toml) {
                print_error(&format!("Failed to finalize manifest file: {}", e));
                let _ = fs::remove_file(&dest_wasm);
                let _ = fs::remove_file(&tmp_toml);
                return -1;
            }

            // generate integrity data in TOML format: wasm_sha256 + permissions_hash
            let mut dest_integrity = dest_dir.clone();
            dest_integrity.push(format!("{}.integrity", clean_name));

            // parse the downloaded manifest to compute permissions hash
            let computed_perms_hash = if let Ok(content) = fs::read_to_string(&dest_toml) {
                if let Ok(pm) = toml::from_str::<crate::ops::plugin_mgr::PluginManifest>(&content) {
                    if let Some(manifest) = pm.plugin.iter().find(|m| m.name == clean_name) {
                        Some(crate::ops::utils::calculate_permissions_hash(manifest))
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            };

            let perms_hash_valid = match (computed_perms_hash.as_deref(), registry_permissions_hash) {
                (Some(computed), Some(registry)) => {
                    if computed != registry {
                        print_error(&format!("[SECURITY] Registry permissions hash mismatch for plugin: {} (Expected: {}, Found: {})", clean_name, registry, computed));
                        let _ = fs::remove_file(&dest_wasm);
                        let _ = fs::remove_file(&dest_toml);
                        return -1;
                    }
                    Some(registry.to_string())
                }
                (Some(_), None) => {
                    print_info(&format!("[WARN] Registry missing permissions_hash for plugin: {}. Permissions not pinned.", clean_name));
                    None
                }
                (None, Some(_)) => {
                    print_error(&format!("[SECURITY] Failed to compute permissions hash from manifest for: {}", clean_name));
                    let _ = fs::remove_file(&dest_wasm);
                    let _ = fs::remove_file(&dest_toml);
                    return -1;
                }
                (None, None) => None,
            };

            // write integrity TOML
            let integrity_content = if let Some(ref ph) = perms_hash_valid {
                format!("wasm_sha256 = \"{}\"\npermissions_hash = \"{}\"\n", sha256_hex, ph)
            } else {
                format!("wasm_sha256 = \"{}\"\n", sha256_hex)
            };
            if let Err(e) = crate::ops::utils::write_atomic(&dest_integrity, integrity_content.as_bytes()) {
                print_error(&format!("Failed to write integrity file: {}", e));
            }

            let mut dest_hash = dest_dir.clone();
            dest_hash.push(format!("{}.hash", clean_name));
            if let Err(e) = crate::ops::utils::write_atomic(&dest_hash, session_hash.as_bytes()) {
                print_error(&format!("Failed to write selection hash: {}", e));
            }

            if !silent {
                print_info("Files downloaded.");
                print_info(&format!("Plugin '{}' successfully installed.", clean_name));
                print_info(&format!("  Hash   : {}", session_hash));
                print_info("  Status : Installation complete. Plugin is ready to use.");
            }

            crate::ops::plugin_mgr::init_plugins(dest_root.to_str().unwrap());
            success = true;
        } else {
            print_error("Failed to download the plugin manifest. Installation aborted.");
            let _ = fs::remove_file(&tmp_wasm);
            let _ = fs::remove_file(&tmp_toml);
        }
    } else {
        print_error("Failed to download the plugin. Check your network or the plugin name.");
        let _ = fs::remove_file(&tmp_wasm);
    }

    if success { 0 } else { -1 }
}

fn find_local_plugins_dir() -> Option<PathBuf> {
    // scan upwards from executable path to find plugins folder
    if let Ok(exe) = std::env::current_exe() {
        let mut parent = exe.parent();
        while let Some(p) = parent {
            let path = p.join("plugins");
            if path.exists() && path.is_dir() {
                return Some(path);
            }
            parent = p.parent();
        }
    }
    // scan upwards from current directory
    if let Ok(cur) = std::env::current_dir() {
        let mut parent = Some(cur.as_path());
        while let Some(p) = parent {
            let path = p.join("plugins");
            if path.exists() && path.is_dir() {
                return Some(path);
            }
            parent = p.parent();
        }
    }
    None
}
