use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::PathBuf;
use rand::RngCore;
use hex;

pub fn get_plugins_dir() -> Option<PathBuf> {
    let mut sys_path = PathBuf::new();
    if cfg!(windows) {
        let mut sys_drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
        if sys_drive.ends_with(':') {
            sys_drive.push('\\');
        }
        sys_path.push(sys_drive);
        sys_path.push(".plugxel");
    } else if let Ok(home) = std::env::var("HOME") {
        sys_path.push(home);
        sys_path.push(".plugxel");
    }
    if sys_path.as_os_str().is_empty() {
        return None;
    }
    sys_path.push("plugins");
    Some(sys_path)
}


pub fn get_data_dir() -> Option<PathBuf> {
    let mut sys_path = PathBuf::new();
    if cfg!(windows) {
        let mut sys_drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
        if sys_drive.ends_with(':') {
            sys_drive.push('\\');
        }
        sys_path.push(sys_drive);
        sys_path.push(".plugxel");
    } else if let Ok(home) = std::env::var("HOME") {
        sys_path.push(home);
        sys_path.push(".plugxel");
    }
    if sys_path.as_os_str().is_empty() {
        return None;
    }
    sys_path.push("data");
    Some(sys_path)
}

pub fn to_c_string(input: &str) -> CString {
    let sanitized: String = input.chars().filter(|&c| c != '\0').collect();
    CString::new(sanitized).unwrap_or_else(|_| CString::new("").unwrap())
}

pub fn safe_cstr_to_string(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    unsafe {
        let cstr = CStr::from_ptr(ptr);
        Some(cstr.to_string_lossy().into_owned())
    }
}
pub fn rand_hash(seed: &str) -> String {
    let mut bytes = [0u8; 8];
    let mut rng = rand::rng();
    rng.fill_bytes(&mut bytes);
    let mut s = hex::encode(bytes);
    s.push_str(&seed[..seed.len().min(4)]);
    s
}

pub fn calculate_buffer_sha256(bytes: &[u8]) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

/// compute SHA256 of canonical manifest permissions + allowed_commands
/// used for permission pinning
pub fn calculate_permissions_hash(manifest: &crate::ops::plugin_mgr::Manifest) -> String {
    use sha2::{Sha256, Digest};
    use serde::Serialize;

    // canonical representation: permissions sorted + allowed_commands sorted by path then args_pattern
    #[derive(Serialize)]
    struct PermissionsSnapshot {
        permissions: Vec<String>,
        allowed_commands: Vec<crate::ops::plugin_mgr::AllowedCommand>,
    }

    let mut perms = manifest.permissions.clone();
    perms.sort();

    let mut cmds = manifest.allowed_commands.clone().unwrap_or_default();
    cmds.sort_by(|a, b| a.path.cmp(&b.path).then(a.args_pattern.cmp(&b.args_pattern)));

    let snapshot = PermissionsSnapshot {
        permissions: perms,
        allowed_commands: cmds,
    };

    // serialize as JSON for canonical form
    let json = serde_json::to_vec(&snapshot).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(&json);
    format!("{:x}", hasher.finalize())
}

pub fn write_atomic(path: &std::path::Path, content: &[u8]) -> Result<(), std::io::Error> {
    use std::fs;
    use std::io::Write;

    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "No parent directory")
    })?;
    let file_name = path.file_name().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "No file name")
    })?;

    // randomized temp name to avoid races
    let rand_suffix: u64 = rand::random();
    let tmp_name = format!("{}.tmp.{:016x}", file_name.to_string_lossy(), rand_suffix);
    let tmp_path = parent.join(tmp_name);

    // write temp file
    {
        let mut file = fs::File::create(&tmp_path)?;
        file.write_all(content)?;
        file.sync_all()?;
    }

    // try atomic rename; on cross-device error, fail closed (no copy fallback)
    match fs::rename(&tmp_path, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            // clean up temp file on any error
            let _ = fs::remove_file(&tmp_path);

            // cross-device: not atomic, reject
            #[cfg(unix)]
            {
                use libc;
                if e.raw_os_error() == Some(libc::EXDEV) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "Atomic write requires same filesystem (cross-device not supported)",
                    ));
                }
            }

            #[cfg(windows)]
            if e.raw_os_error() == Some(17) { // ERROR_NOT_SAME_DEVICE
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Atomic write requires same volume (cross-device not supported)",
                ));
            }

            Err(e)
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn test_to_c_string_strips_null_bytes() {
        let cstr = to_c_string("hello\0world");
        assert_eq!(cstr.to_str().unwrap(), "helloworld");
    }

    #[test]
    fn test_get_plugins_dir_returns_plugins_suffix() {
        if let Some(path) = get_plugins_dir() {
            assert_eq!(path.file_name().and_then(|n| n.to_str()), Some("plugins"));
        }
    }

    #[test]
    fn test_safe_cstr_to_string_valid() {
        let input = CString::new("hello world").unwrap();
        let result = safe_cstr_to_string(input.as_ptr());
        assert_eq!(result, Some("hello world".to_string()));
    }

    #[test]
    fn test_safe_cstr_to_string_null() {
        let result = safe_cstr_to_string(std::ptr::null());
        assert_eq!(result, None);
    }

    #[test]
    fn test_rand_hash_uniqueness() {
        let hash1 = rand_hash("test");
        let hash2 = rand_hash("test");
        // 16 hex chars (8 bytes) + 4 seed chars = 20
        assert_eq!(hash1.len(), 20);
        assert_eq!(hash2.len(), 20);
        assert!(u64::from_str_radix(&hash1[..16], 16).is_ok());
        assert!(u64::from_str_radix(&hash2[..16], 16).is_ok());
    }
}
