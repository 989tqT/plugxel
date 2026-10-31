use wasmer::{Instance, Module, Store, Function, imports, Memory, FunctionEnv, FunctionEnvMut};
use wasmer_compiler_cranelift::Cranelift;
use std::path::{Path, PathBuf};
use std::fs;
use std::cell::RefCell;
use once_cell::sync::Lazy;
use std::sync::{Mutex, Arc, mpsc};
use std::process::{Command, Stdio};
use std::io::{BufRead, BufReader};
#[cfg(windows)]
use std::os::windows::process::CommandExt;
use serde::{Deserialize, Serialize};
use toml;
use crate::ops::host::{
    print_info, print_error,
    add_tab, set_tab_cwd, set_tab_owner,
    get_current_print_tab, set_prompt_visibility
};
use crate::ops::net::http_post_json;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;
const HOST_API_VERSION: &str = "0.1.2a";
// maximum allowed lengths for FFI string reads (prevent OOB/alloc DoS)
const MAX_FFI_STRING_LEN: usize = 64 * 1024;      // 64 KiB general
const MAX_ARGS_LEN: usize = 4096;                  // command args
const MAX_ENV_NAME_LEN: usize = 256;               // env var name
const MAX_URL_LEN: usize = 2048;                   // URL
const MAX_JSON_PAYLOAD_LEN: usize = 16 * 1024;     // JSON body
const MAX_RESPONSE_BUF_LEN: usize = 1024 * 1024;   // 1 MiB response buffer
const MAX_TAB_LABEL_LEN: usize = 256;              // tab label

// thread-local storage for current command args (avoids race between plugins)
thread_local! {
    static CURRENT_ARGS: RefCell<String> = RefCell::new(String::new());
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct AllowedCommand {
    pub path: String,
    pub args_pattern: String,
}

#[derive(Deserialize, Clone, Debug)]
pub struct Manifest {
    pub name: String,
    pub version: String,
    pub author: String,
    pub api_version: String,
    pub permissions: Vec<String>,
    pub allowed_commands: Option<Vec<AllowedCommand>>,
}

fn resolve_binary_path(exe: &str) -> Option<PathBuf> {
    let path = Path::new(exe);
    if path.is_absolute() {
        return fs::canonicalize(path).ok();
    }
    
    if let Ok(cur) = std::env::current_dir() {
        let p = cur.join(exe);
        if p.exists() {
            return fs::canonicalize(p).ok();
        }
    }
    
    if let Ok(paths) = std::env::var("PATH") {
        for p in std::env::split_paths(&paths) {
            let bin_path = p.join(exe);
            if bin_path.exists() {
                return fs::canonicalize(bin_path).ok();
            }
            if cfg!(windows) {
                for ext in &[".exe", ".bat", ".cmd", ".com"] {
                    let bin_path_ext = p.join(format!("{}{}", exe, ext));
                    if bin_path_ext.exists() {
                        return fs::canonicalize(bin_path_ext).ok();
                    }
                }
            }
        }
    }
    None
}

static TRUSTED_PLUGIN_HASHES: &[&str] = &[
    include_str!("../../pterm_hash.txt")
];

#[derive(Deserialize, Clone, Debug)]
pub struct PluginManifest {
    pub plugin: Vec<Manifest>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct SinglePluginManifest {
    pub plugin: Manifest,
}

// TOML format for .integrity sidecar
#[derive(Deserialize)]
struct IntegrityToml {
    wasm_sha256: String,
    permissions_hash: Option<String>,
}

pub struct Plugin {
    pub name: String,
    pub hash: String,
    pub manifest: Manifest,
    pub is_trusted: bool,
    store: Store,
    instance: Instance,
}


struct Env {
    memory: Option<Memory>,
    permissions: Vec<String>,
    allowed_commands: Vec<AllowedCommand>,
    is_trusted: bool,
    scoped_dir: Option<PathBuf>,
    fd_table: Arc<crate::ops::fs_containment::DescriptorTable>,
    // fd 0 1 2 owned outside fd_table so stdio never alias filesystem capability
    stdio: crate::ops::fs_containment::StdioDescriptors,
}

static PLUGINS: Lazy<Mutex<Vec<Plugin>>> = Lazy::new(|| Mutex::new(Vec::new()));
static PLUGIN_EXEC_LOCKS: Lazy<Mutex<std::collections::HashMap<String, Arc<Mutex<()>>>>> =
    Lazy::new(|| Mutex::new(std::collections::HashMap::new()));
static TAB_CWDS: Lazy<Mutex<std::collections::HashMap<i32, String>>> = Lazy::new(|| Mutex::new(std::collections::HashMap::new()));
static TAB_LABELS: Lazy<Mutex<std::collections::HashMap<i32, String>>> = Lazy::new(|| Mutex::new(std::collections::HashMap::new()));

type Job = Box<dyn FnOnce() + Send + 'static>;

struct SimpleThreadPool {
    sender: mpsc::Sender<Job>,
}

impl SimpleThreadPool {
    fn new(size: usize) -> Self {
        let (sender, receiver) = mpsc::channel::<Job>();
        let receiver = Arc::new(Mutex::new(receiver));

        for _ in 0..size {
            let receiver = Arc::clone(&receiver);
            std::thread::spawn(move || {
                loop {
                    let job = {
                        let Ok(lock) = receiver.lock() else { break };
                        match lock.recv() {
                            Ok(j) => j,
                            Err(_) => break,
                        }
                    };

                    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        job();
                    }));
                }
            });
        }
        Self { sender }
    }

    fn execute<F>(&self, f: F)
    where
        F: FnOnce() + Send + 'static,
    {
        let job = Box::new(f);
        let _ = self.sender.send(job);
    }
}

static POOL: Lazy<SimpleThreadPool> = Lazy::new(|| SimpleThreadPool::new(4));

fn plugin_exec_lock(name: &str) -> Arc<Mutex<()>> {
    let mut locks = PLUGIN_EXEC_LOCKS.lock().unwrap();
    locks
        .entry(name.to_string())
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone()
}

fn import_requires_permission(name: &str) -> Option<&'static str> {
    match name {
        "host_exec" => Some("host_exec"),
        "host_add_tab" => Some("host_add_tab"),
        "host_set_tab_owner" => Some("host_set_tab_owner"),
        "host_get_tab_label" => Some("host_get_tab_label"),
        "get_env" => Some("get_env"),
        "net_post" => Some("net_post"),
        "host_get_platform" => Some("host_get_platform"),
        _ => None,
    }
}

fn has_permission(permissions: &[String], required: &str) -> bool {
    permissions.iter().any(|p| p == required)
}

pub fn init_plugins(plugins_dir: &str) {
    let path = Path::new(plugins_dir);
    
    {
        let mut plugins = PLUGINS.lock().unwrap();
        plugins.clear();
    }

    if !path.exists() {
        let _ = fs::create_dir_all(path);
        return;
    }

    let mut plug_files = Vec::new();

    fn walk_dir(dir: &Path, files: &mut Vec<PathBuf>) {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_dir() {
                    walk_dir(&p, files);
                } else if p.extension().map_or(false, |ext| ext == "hash") {
                    files.push(p);
                }
            }
        }
    }
    walk_dir(path, &mut plug_files);

    let dest_root = path.parent().unwrap_or(path);
    let marker_path = dest_root.join(".integrity_migration_v1_done");

    // phase 1.5 one-time global migration check
    if !marker_path.exists() {
        print_info("[SECURITY-WARNING] Global integrity migration started. Backfilling plugin .integrity files...");
        for p in &plug_files {
            if let Some(stem) = p.file_stem().and_then(|s| s.to_str()) {
                let name = stem.split('.').next().unwrap_or(stem);
                let mut integrity_path = p.parent().unwrap().to_path_buf();
                integrity_path.push(format!("{}.integrity", name));
                if !integrity_path.exists() {
                    let hash_val = fs::read_to_string(p).unwrap_or_default().trim().to_string();
                    if !hash_val.is_empty() {
                        let wasm_path = p.with_extension(&hash_val);
                        if wasm_path.exists() {
                            if let Ok(bytes) = fs::read(&wasm_path) {
                                let sha256_hex = crate::ops::utils::calculate_buffer_sha256(&bytes);
                                // write in TOML format with wasm_sha256 only (permissions_hash comes
                                // from registry install, not from migration)
                                let integrity_content = format!("wasm_sha256 = \"{}\"\n", sha256_hex);
                                if let Err(e) = crate::ops::utils::write_atomic(&integrity_path, integrity_content.as_bytes()) {
                                    print_error(&format!("Migration failed to write integrity file for {}: {}", name, e));
                                } else {
                                    print_info(&format!("[SECURITY-WARNING] Generated integrity file for pre-existing plugin: {}", name));
                                }
                            }
                        }
                    }
                }
            }
        }

        // write marker atomically
        if let Err(e) = crate::ops::utils::write_atomic(&marker_path, b"v1_done") {
            print_error(&format!("Failed to write global migration marker: {}", e));
        } else {
            print_info("[SECURITY] Global integrity migration complete. Marker written.");
        }
    }

    let unified_manifest_path = path.join("plugin.toml");
    let mut manifest_map = std::collections::HashMap::new();
    if unified_manifest_path.exists() {
        if let Ok(content) = fs::read_to_string(&unified_manifest_path) {
            if let Ok(p_manifest) = toml::from_str::<PluginManifest>(&content) {
                for m in p_manifest.plugin {
                    manifest_map.insert(m.name.clone(), m);
                }
            } else {
                print_error(&format!("[SECURITY] Failed to parse unified manifest: {}", unified_manifest_path.display()));
            }
        }
    } else {
         print_error(&format!("[SECURITY] Missing unified manifest: {}", unified_manifest_path.display()));
    }

    for p in plug_files {
        let stem_opt = p.file_stem().and_then(|s| s.to_str());
        if let Some(stem) = stem_opt {
            if let Some(manifest) = manifest_map.get(stem) {
                let hash_val = fs::read_to_string(&p).unwrap_or_default().trim().to_string();
                let wasm_path = p.with_extension(&hash_val);
                if let Err(e) = load_plugin(&wasm_path, manifest, &hash_val) {
                     print_error(&format!("[WASM] Failed to load {}: {}", wasm_path.display(), e));
                }
            } else {
                let individual_toml = p.with_extension("toml");
                if individual_toml.exists() {
                    if let Ok(content) = fs::read_to_string(&individual_toml) {
                        if let Ok(single) = toml::from_str::<SinglePluginManifest>(&content) {
                            let hash_val = fs::read_to_string(&p).unwrap_or_default().trim().to_string();
                            let wasm_path = p.with_extension(&hash_val);
                            if let Err(e) = load_plugin(&wasm_path, &single.plugin, &hash_val) {
                                 print_error(&format!("[WASM] Failed to load {}: {}", wasm_path.display(), e));
                            }
                        } else {
                            print_error(&format!("[SECURITY] Invalid manifest format: {}", individual_toml.display()));
                        }
                    }
                } else {
                    print_error(&format!("[SECURITY] Missing manifest entry for {}", p.display()));
                }
            }
        }
    }
}


// normalize path for capability boundary compare
fn normalize_for_comparison(path: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        let s = path.to_string_lossy().to_lowercase();
        let stripped = if let Some(rest) = s.strip_prefix(r"\\?\\") {
            rest
        } else {
            &s
        };
        PathBuf::from(stripped.replace('/', "\\"))
    }
    #[cfg(not(windows))]
    {
        path.to_path_buf()
    }
}

// check if path is symlink or reparse point (junction / mount point)
fn is_reparse_or_symlink(path: &Path) -> bool {
    if path.is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if let Ok(meta) = path.symlink_metadata() {
            if meta.file_attributes() & 0x400 != 0 {
                return true;
            }
        }
    }
    false
}

// retrieve canonical path from open file handle via kernel
fn get_file_canonical_path(file: &fs::File) -> Option<PathBuf> {
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use std::os::windows::ffi::OsStringExt;
        extern "system" {
            fn GetFinalPathNameByHandleW(
                h_file: *mut std::ffi::c_void,
                file_path: *mut u16,
                max_path_len: u32,
                flags: u32,
            ) -> u32;
        }
        let handle = file.as_raw_handle();
        let mut buf = vec![0u16; 1024];
        let len = unsafe {
            GetFinalPathNameByHandleW(
                handle as *mut _,
                buf.as_mut_ptr(),
                buf.len() as u32,
                0,
            )
        };
        if len == 0 || len >= buf.len() as u32 {
            return None;
        }
        let os_str = std::ffi::OsString::from_wide(&buf[..len as usize]);
        Some(PathBuf::from(os_str))
    }
    #[cfg(not(windows))]
    {
        use std::os::unix::io::AsRawFd;
        let fd = file.as_raw_fd();
        std::fs::read_link(format!("/proc/self/fd/{}", fd)).ok()
    }
}

// capability-based path resolution rooted at capability base_dir
// enforces wasi capability boundary: path must not escape base_dir
fn resolve_capability_path(base_dir: &Path, raw_path: &str, follow_symlinks: bool) -> Result<PathBuf, i32> {
    // 1. directory-relative capability lookup rejects rooted paths
    // guest path must be resolved relative to directory handle capability
    if raw_path.starts_with('/') || raw_path.starts_with('\\') || raw_path.contains(':') {
        return Err(76); // ENOTCAPABLE
    }

    let canonical_root = match base_dir.canonicalize() {
        Ok(c) => c,
        Err(_) => return Err(44), // ENOENT
    };
    let norm_root = normalize_for_comparison(&canonical_root);

    let mut current = canonical_root.clone();

    // 2. iterate path components relative to directory capability handle
    for comp in raw_path.split(|c| c == '/' || c == '\\') {
        if comp.is_empty() || comp == "." {
            continue;
        }
        if comp == ".." {
            let norm_curr = normalize_for_comparison(&current);
            if norm_curr == norm_root {
                // capability boundary exceeded: cannot traverse above preopen root
                return Err(76); // ENOTCAPABLE
            }
            if !current.pop() {
                return Err(76); // ENOTCAPABLE
            }
            let norm_popped = normalize_for_comparison(&current);
            if !norm_popped.starts_with(&norm_root) {
                return Err(76); // ENOTCAPABLE
            }
            continue;
        }

        current.push(comp);

        // 3. check symlink / junction boundary during traversal
        if is_reparse_or_symlink(&current) {
            if !follow_symlinks {
                return Err(76); // ENOTCAPABLE
            }
            let target = match current.canonicalize() {
                Ok(t) => t,
                Err(_) => return Err(44),
            };
            let norm_target = normalize_for_comparison(&target);
            if !norm_target.starts_with(&norm_root) {
                // symlink target escapes capability root
                return Err(76); // ENOTCAPABLE
            }
            current = target;
        }
    }

    // 4. final capability boundary verification
    if current.exists() {
        let canon = match current.canonicalize() {
            Ok(c) => c,
            Err(_) => return Err(44),
        };
        let norm_canon = normalize_for_comparison(&canon);
        if !norm_canon.starts_with(&norm_root) {
            return Err(76); // ENOTCAPABLE
        }
        Ok(canon)
    } else {
        // path does not exist yet (e.g. O_CREAT)
        // ensure its parent exists and is within capability root
        if let Some(parent) = current.parent() {
            if parent.exists() {
                let canon_parent = match parent.canonicalize() {
                    Ok(cp) => cp,
                    Err(_) => return Err(44),
                };
                let norm_parent = normalize_for_comparison(&canon_parent);
                if !norm_parent.starts_with(&norm_root) {
                    return Err(76); // ENOTCAPABLE
                }
            } else {
                return Err(44);
            }
        }
        Ok(current)
    }
}

// resolve directory path from descriptor handle during b3.1 transition
fn resolve_dir_descriptor_path(
    desc: &crate::ops::fs_containment::DescriptorState,
    scoped_dir: &Option<PathBuf>,
) -> Result<PathBuf, i32> {
    use crate::ops::fs_containment::{DescriptorKind, WASI_EBADF};
    match desc.kind() {
        DescriptorKind::PreopenDir { dir_file, .. } => {
            if let Some(dir) = scoped_dir {
                Ok(dir.clone())
            } else {
                get_file_canonical_path(dir_file).ok_or(WASI_EBADF)
            }
        }
        DescriptorKind::Directory { dir_file } => {
            get_file_canonical_path(dir_file).ok_or(WASI_EBADF)
        }
        DescriptorKind::RegularFile { .. } => Err(WASI_EBADF),
    }
}

// sanitize guest stdio buffer for host ui console sink
// convert invalid utf8 lossy escape embedded nul to literal \0 and trim trailing newline
pub(crate) fn sanitize_host_stdio_message(buf: &[u8]) -> String {
    let lossy = String::from_utf8_lossy(buf);
    let escaped = if lossy.contains('\0') {
        lossy.replace('\0', "\\0")
    } else {
        lossy.into_owned()
    };
    let cleaned = escaped.trim_end_matches(|c| c == '\n' || c == '\r');
    cleaned.to_string()
}

// host stdout sink routing guest fd 1 write to print_info
struct HostStdoutSink;

impl std::io::Write for HostStdoutSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let msg = sanitize_host_stdio_message(buf);
        if !msg.is_empty() {
            print_info(&msg);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// host stderr sink routing guest fd 2 write to print_error
struct HostStderrSink;

impl std::io::Write for HostStderrSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let msg = sanitize_host_stdio_message(buf);
        if !msg.is_empty() {
            print_error(&msg);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// execute stdio write across guest ciovec array and store nwritten into guest linear memory
fn wasm_stdio_write(
    stdio: &crate::ops::fs_containment::StdioDescriptors,
    stream: crate::ops::fs_containment::StdioStream,
    view: &wasmer::MemoryView,
    iovs_ptr: i32,
    iovs_len: i32,
    nwritten_ptr: i32,
) -> i32 {
    if let Err(errno) = stdio.require(stream, crate::ops::fs_containment::WasiRights::FD_WRITE) {
        return errno;
    }
    if iovs_len < 0 {
        return crate::ops::fs_containment::WASI_EINVAL;
    }
    let Ok(iovs_base) = u64::try_from(iovs_ptr) else {
        return crate::ops::fs_containment::WASI_EINVAL;
    };
    let Ok(nwritten_u64) = u64::try_from(nwritten_ptr) else {
        return crate::ops::fs_containment::WASI_EINVAL;
    };
    let mut buffers: Vec<Vec<u8>> = Vec::with_capacity(iovs_len as usize);
    for i in 0..(iovs_len as u64) {
        let Some(entry_offset) = i.checked_mul(8).and_then(|off| iovs_base.checked_add(off)) else {
            return crate::ops::fs_containment::WASI_EINVAL;
        };
        let mut iov_buf = [0u8; 8];
        if view.read(entry_offset, &mut iov_buf).is_err() {
            return crate::ops::fs_containment::WASI_EINVAL;
        }
        let ptr = u32::from_le_bytes([iov_buf[0], iov_buf[1], iov_buf[2], iov_buf[3]]) as u64;
        let len = u32::from_le_bytes([iov_buf[4], iov_buf[5], iov_buf[6], iov_buf[7]]) as usize;
        let mut chunk = vec![0u8; len];
        if len > 0 && view.read(ptr, &mut chunk).is_err() {
            return crate::ops::fs_containment::WASI_EINVAL;
        }
        buffers.push(chunk);
    }
    let slice_refs: Vec<&[u8]> = buffers.iter().map(|b| b.as_slice()).collect();
    let total_written = match stdio.write_stream(stream, &slice_refs) {
        Ok(n) => n,
        Err(errno) => return errno,
    };
    let Ok(total_u32) = u32::try_from(total_written) else {
        return crate::ops::fs_containment::WASI_EINVAL;
    };
    if view.write(nwritten_u64, &total_u32.to_le_bytes()).is_err() {
        return crate::ops::fs_containment::WASI_EINVAL;
    };
    crate::ops::fs_containment::WASI_ESUCCESS
}

// execute stdio read across guest iovec array where stdin return eof zero byte
fn wasm_stdio_read(
    stdio: &crate::ops::fs_containment::StdioDescriptors,
    stream: crate::ops::fs_containment::StdioStream,
    view: &wasmer::MemoryView,
    iovs_ptr: i32,
    iovs_len: i32,
    nread_ptr: i32,
) -> i32 {
    let nread_bytes = match stdio.read_stream(stream) {
        Ok(n) => n,
        Err(errno) => return errno,
    };
    if iovs_len < 0 {
        return crate::ops::fs_containment::WASI_EINVAL;
    }
    let Ok(iovs_base) = u64::try_from(iovs_ptr) else {
        return crate::ops::fs_containment::WASI_EINVAL;
    };
    let Ok(nread_u64) = u64::try_from(nread_ptr) else {
        return crate::ops::fs_containment::WASI_EINVAL;
    };
    for i in 0..(iovs_len as u64) {
        let Some(entry_offset) = i.checked_mul(8).and_then(|off| iovs_base.checked_add(off)) else {
            return crate::ops::fs_containment::WASI_EINVAL;
        };
        let mut iov_buf = [0u8; 8];
        if view.read(entry_offset, &mut iov_buf).is_err() {
            return crate::ops::fs_containment::WASI_EINVAL;
        }
    }
    let Ok(total_u32) = u32::try_from(nread_bytes) else {
        return crate::ops::fs_containment::WASI_EINVAL;
    };
    if view.write(nread_u64, &total_u32.to_le_bytes()).is_err() {
        return crate::ops::fs_containment::WASI_EINVAL;
    };
    crate::ops::fs_containment::WASI_ESUCCESS
}

// poll_oneoff stub return wasi_enosys until readiness polling is supported
// fail closed without subscription processing event emission or nevents update
pub(crate) fn wasi_poll_oneoff(_in_ptr: i32, _out_ptr: i32, _nsubscriptions: i32, _nevents_ptr: i32) -> i32 {
    crate::ops::fs_containment::WASI_ENOSYS
}

fn load_plugin(wasm_path: &Path, manifest: &Manifest, hash: &str) -> Result<(), Box<dyn std::error::Error>> {
    let wasm_bytes = fs::read(wasm_path)?;
    let sha256_hex = crate::ops::utils::calculate_buffer_sha256(&wasm_bytes);

    let mut is_trusted = false;
    if TRUSTED_PLUGIN_HASHES.iter().any(|h| h.trim() == sha256_hex) {
        is_trusted = true;
    }

    if !is_trusted {
        let stem_opt = wasm_path.file_stem().and_then(|s| s.to_str());
        let name = if let Some(stem) = stem_opt {
            stem.split('.').next().unwrap_or(stem)
        } else {
            manifest.name.as_str()
        };
        let integrity_path = wasm_path.parent().unwrap().join(format!("{}.integrity", name));
        if !integrity_path.exists() {
            return Err(format!("[SECURITY] Missing integrity sidecar for {}", name).into());
        }

        // parse integrity file — support TOML format (wasm_sha256 + permissions_hash)
        // fall back to legacy single-line SHA256 hex
        let integrity_raw = fs::read_to_string(&integrity_path)?.trim().to_string();
        let (expected_wasm_hash, expected_perms_hash) = if integrity_raw.starts_with("wasm_sha256") {
            // TOML format
            match toml::from_str::<IntegrityToml>(&integrity_raw) {
                Ok(t) => (t.wasm_sha256, t.permissions_hash),
                Err(_) => return Err(format!("[SECURITY] Corrupt integrity file for {}", name).into()),
            }
        } else {
            // legacy single-line SHA256
            (integrity_raw, None)
        };

        if expected_wasm_hash != sha256_hex {
            return Err(format!("[SECURITY] Integrity mismatch for {}", name).into());
        }

        // if integrity pins permissions_hash, compute current manifest permissions hash
        // and compare. fail-closed on mismatch — manifest may have been tampered.
        if let Some(ref pinned_perms_hash) = expected_perms_hash {
            let current_perms_hash = crate::ops::utils::calculate_permissions_hash(manifest);
            if current_perms_hash != *pinned_perms_hash {
                return Err(format!("[SECURITY] Permissions hash mismatch for {} (manifest may have been tampered)", name).into());
            }
        }
    }

    if !manifest.api_version.starts_with("0.1") {
        return Err(format!("Incompatible API version: {} (Host: {})", manifest.api_version, HOST_API_VERSION).into());
    }

    let mut store = Store::new(Cranelift::default());
    let module = Module::new(&store, &wasm_bytes)?;

    // verify imported function against manifest permission declaration
    for import in module.imports() {
        if import.module() == "env" {
            let name = import.name();
            if let Some(required) = import_requires_permission(name) {
                if !has_permission(&manifest.permissions, required) {
                    return Err(format!("[SECURITY] Unauthorized import: {}", name).into());
                }
            }
        } else if import.module() == "wasi_snapshot_preview1" {
            // SECURITY: wasi_snapshot_preview1 imports MUST be explicitly allowed
            let name = import.name();
            const SCOPED_FS_WASI: &[&str] = &[
                "path_open",
                "path_create_directory",
                "path_remove_directory",
                "path_unlink_file",
                "path_readlink",
                "path_symlink",
                "path_filestat_get",
                "path_filestat_set_times",
                "path_rename",
            ];
            const ALLOWED_WASI: &[&str] = &[
                // process / exit
                "proc_exit",
                // file descriptor ops
                "fd_write", "fd_read", "fd_close", "fd_seek", "fd_fdstat_get",
                "fd_fdstat_set_flags", "fd_fdstat_set_rights", "fd_prestat_get",
                "fd_prestat_dir_name", "fd_advise", "fd_allocate", "fd_datasync",
                "fd_filestat_get", "fd_filestat_set_size", "fd_filestat_set_times",
                "fd_pread", "fd_pwrite", "fd_readdir", "fd_renumber", "fd_sync",
                "fd_tell",
                // clocks / args / env (read-only stubs)
                "clock_res_get", "clock_time_get",
                "args_sizes_get", "args_get", "environ_sizes_get", "environ_get",
                // poll / sched (stubs returning ENOSYS)
                "poll_oneoff", "sched_yield",
            ];
            if SCOPED_FS_WASI.contains(&name) {
                if !manifest.permissions.contains(&"fs_scoped".to_string()) {
                    return Err(format!("[SECURITY] Unauthorized WASI import: {}", name).into());
                }
            } else if !ALLOWED_WASI.contains(&name) {
                return Err(format!("[SECURITY] Unauthorized WASI import: {}", name).into());
            }
        }
    }

    let has_fs_scoped = manifest.permissions.contains(&"fs_scoped".to_string());
    let (scoped_dir, fd_table) = if has_fs_scoped {
        let dir = crate::ops::utils::get_data_dir()
            .unwrap_or_else(|| PathBuf::from(".plugxel").join("data"))
            .join(hash);
        let _ = fs::create_dir_all(&dir);
        let root_file = crate::ops::fs_containment::open_directory_handle(&dir).map_err(|e| {
            format!(
                "[SECURITY] Failed to open preopen capability directory {}: errno {}",
                dir.display(),
                e
            )
        })?;
        // initialize descriptor table with preopen capability directory at fd 3
        let table = crate::ops::fs_containment::DescriptorTable::new_with_preopen(root_file, "/data");
        (Some(dir), Arc::new(table))
    } else {
        (None, Arc::new(crate::ops::fs_containment::DescriptorTable::new()))
    };

    let env = FunctionEnv::new(&mut store, Env { 
        memory: None, 
        permissions: manifest.permissions.clone(),
        allowed_commands: manifest.allowed_commands.clone().unwrap_or_default(),
        is_trusted,
        scoped_dir,
        fd_table,
        stdio: crate::ops::fs_containment::StdioDescriptors::with_sinks(
            Box::new(HostStdoutSink),
            Box::new(HostStderrSink),
        ),
    });

    let import_object = imports! {
        "env" => {
            "print_info" => Function::new_typed_with_env(&mut store, &env, |mut env: FunctionEnvMut<Env>, ptr: i32, len: i32| {
                let (env_data, store) = env.data_and_store_mut();
                if len <= 0 || len as usize > MAX_FFI_STRING_LEN { return; }
                if let Some(memory) = &env_data.memory {
                    let view = memory.view(&store);
                    let mut buffer = vec![0u8; len as usize];
                    if view.read(ptr as u64, &mut buffer).is_ok() {
                        if let Ok(s) = std::str::from_utf8(&buffer) {
                             print_info(&format!("[PLUGIN] {}", s));
                        }
                    }
                }
            }),
            "print_error" => Function::new_typed_with_env(&mut store, &env, |mut env: FunctionEnvMut<Env>, ptr: i32, len: i32| {
                let (env_data, store) = env.data_and_store_mut();
                if len <= 0 || len as usize > MAX_FFI_STRING_LEN { return; }
                if let Some(memory) = &env_data.memory {
                    let view = memory.view(&store);
                    let mut buffer = vec![0u8; len as usize];
                    if view.read(ptr as u64, &mut buffer).is_ok() {
                        if let Ok(s) = std::str::from_utf8(&buffer) {
                             print_error(&format!("[PLUGIN ERROR] {}", s));
                        }
                    }
                }
            }),

            "get_args" => Function::new_typed_with_env(&mut store, &env, |mut env: FunctionEnvMut<Env>, ptr: i32, max_len: i32| {
                let (env_data, store) = env.data_and_store_mut();
                if max_len <= 0 || max_len as usize > MAX_ARGS_LEN { return; }
                if let Some(memory) = &env_data.memory {
                    let view = memory.view(&store);
                    CURRENT_ARGS.with(|args| {
                        let args = args.borrow();
                        let bytes = args.as_bytes();
                        let cap = (max_len as usize).saturating_sub(1);
                        let n = std::cmp::min(bytes.len(), cap);
                        if view.write(ptr as u64, &bytes[..n]).is_ok() {
                            let _ = view.write((ptr as u64) + n as u64, &[0u8]);
                        }
                    });
                }
            }),

            "host_exec" => Function::new_typed_with_env(&mut store, &env, |mut env: FunctionEnvMut<Env>, ptr: i32, len: i32| {
                let (env_data, store) = env.data_and_store_mut();
                if !env_data.permissions.iter().any(|p| p == "host_exec") {
                    print_error("[SECURITY] Plugin attempted to call host_exec without permission");
                    return;
                }
                if len <= 0 || len as usize > MAX_FFI_STRING_LEN { return; }
                if let Some(memory) = &env_data.memory {
                    let view = memory.view(&store);
                    let mut buf = vec![0u8; len as usize];
                    if view.read(ptr as u64, &mut buf).is_ok() {
                        let full_cmd_line = std::str::from_utf8(&buf).unwrap_or("").trim();
                        if full_cmd_line.is_empty() { return; }
                        


                        let tab_idx = get_current_print_tab();
                        
                        if full_cmd_line.to_lowercase().starts_with("cd ") || full_cmd_line.to_lowercase() == "cd" {
                            let mut target_dir = full_cmd_line[2..].trim().to_string();
                            if target_dir.is_empty() { return; }
                            if target_dir.starts_with('"') && target_dir.ends_with('"') {
                                target_dir = target_dir[1..target_dir.len()-1].to_string();
                            }
                            let base_dir = {
                                let cwds = TAB_CWDS.lock().unwrap();
                                cwds.get(&tab_idx).cloned().unwrap_or_else(|| {
                                    std::env::current_dir().unwrap_or_default().to_string_lossy().to_string()
                                })
                            };
                            let new_path = Path::new(&base_dir).join(target_dir);
                            if let Ok(abs_path) = fs::canonicalize(new_path) {
                                let path_str = abs_path.to_string_lossy().replace("\\\\?\\", "").to_string();
                                // security: enforce path containment within fixed jail root
                                // use the tab's original working directory as the jail root
                                // (not the dynamic CWD which can be changed via cd)
                                let jail_root = {
                                    let cwds = TAB_CWDS.lock().unwrap();
                                    cwds.get(&tab_idx).cloned().unwrap_or_else(|| {
                                        std::env::current_dir().unwrap_or_default().to_string_lossy().replace("\\\\?\\", "").to_string()
                                    })
                                };
                                if !path_str.starts_with(&jail_root) {
                                    print_error("Access denied: path escapes allowed directory");
                                    return;
                                };
                                {
                                    let mut cwds = TAB_CWDS.lock().unwrap();
                                    cwds.insert(tab_idx, path_str.clone());
                                }
                                set_tab_cwd(tab_idx, &path_str);
                            } else {
                                print_error("The system cannot find the path specified.");
                            }
                            return;
                        }

                        let mut parsed_args = parse_args(full_cmd_line);
                        if parsed_args.is_empty() { return; }
                        let exe = parsed_args.remove(0);

                        let canonical_exe = if env_data.is_trusted {
                            resolve_binary_path(&exe).unwrap_or_else(|| std::path::PathBuf::from(&exe))
                        } else {
                            // b1. resolve absolute canonical path
                            match resolve_binary_path(&exe) {
                                Some(p) => p,
                                None => {
                                    print_error(&format!("[SECURITY] Blocked execution: binary not found: {}", exe));
                                    return;
                                }
                            }
                        };

                        if !env_data.is_trusted {
                            // allowlist-only execution: no blacklist (blacklists are bypassable)
                            // only binaries explicitly declared in manifest allowed_commands with matching
                            // canonical path and args regex are permitted
                            let mut allowed = false;
                            let args_string = parsed_args.join(" ");
                            for entry in &env_data.allowed_commands {
                                if let Ok(entry_canonical) = fs::canonicalize(&entry.path) {
                                    if entry_canonical == canonical_exe {
                                        if let Ok(re) = regex::Regex::new(&entry.args_pattern) {
                                            if re.is_match(&args_string) {
                                                allowed = true;
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                            
                            if !allowed {
                                // test coupling: this message is asserted in tests/integration/test_sandbox_rules.py
                                // (has_unauth_block check). rename here → must update assertion string there
                                print_error(&format!("[SECURITY] Blocked execution of unauthorized binary: {}", canonical_exe.display()));
                                return;
                            }
                        }

                        let sub_cwd = {
                            let cwds = TAB_CWDS.lock().unwrap();
                            cwds.get(&tab_idx).cloned().unwrap_or_else(|| {
                                std::env::current_dir().unwrap_or_default().to_string_lossy().to_string()
                            })
                        };
                        let mut cmd = Command::new(&canonical_exe);
                        cmd.args(&parsed_args)
                           .current_dir(sub_cwd)
                           .stdout(Stdio::piped())
                           .stderr(Stdio::piped());
                        
                        #[cfg(windows)]
                        cmd.creation_flags(CREATE_NO_WINDOW);
                        
                        match cmd.spawn() {
                            Ok(mut child) => {
                                if let Some(stdout) = child.stdout.take() {
                                    let reader = BufReader::new(stdout);
                                    for line in reader.lines().flatten() { print_info(&line); }
                                }
                                if let Some(stderr) = child.stderr.take() {
                                    let reader = BufReader::new(stderr);
                                    for line in reader.lines().flatten() { print_error(&format!("[STDERR] {}", line)); }
                                }
                                let _ = child.wait();
                            }
                            Err(e) => {
                                if e.kind() == std::io::ErrorKind::NotFound { print_error("Unknown command."); }
                                else { print_error(&format!("[EXEC FAILED] '{}': {}", exe, e)); }
                            }
                        }
                    }
                }
            }),
            "get_env" => Function::new_typed_with_env(&mut store, &env, |mut env: FunctionEnvMut<Env>, name_ptr: i32, name_len: i32, resp_ptr: i32, resp_max_len: i32| {
                let (env_data, store) = env.data_and_store_mut();
                if !has_permission(&env_data.permissions, "get_env") {
                    print_error("[SECURITY] Plugin attempted to call get_env without permission");
                    return;
                }
                if name_len <= 0 || name_len as usize > MAX_ENV_NAME_LEN { return; }
                if resp_max_len <= 0 || resp_max_len as usize > MAX_FFI_STRING_LEN { return; }
                if let Some(memory) = &env_data.memory {
                    let view = memory.view(&store);
                    let mut name_buf = vec![0u8; name_len as usize];
                    if view.read(name_ptr as u64, &mut name_buf).is_ok() {
                        let name = std::str::from_utf8(&name_buf).unwrap_or("");
                        let val = std::env::var(name).unwrap_or_default();
                        let val_bytes = val.as_bytes();
                        let len = std::cmp::min(val_bytes.len(), resp_max_len as usize);
                        let _ = view.write(resp_ptr as u64, &val_bytes[..len]);
                    }
                }
            }),
            "host_get_platform" => Function::new_typed_with_env(&mut store, &env, |mut _env: FunctionEnvMut<Env>| -> i32 {
                if cfg!(windows) { 0 } else { 1 }
            }),
            "host_add_tab" => Function::new_typed_with_env(&mut store, &env, |mut env: FunctionEnvMut<Env>, ptr: i32, len: i32| {
                let (env_data, store) = env.data_and_store_mut();
                if let Some(memory) = &env_data.memory {
                    let view = memory.view(&store);
                    let mut buffer = vec![0u8; len as usize];
                    if view.read(ptr as u64, &mut buffer).is_ok() {
                        if let Ok(name) = std::str::from_utf8(&buffer) {
                             add_tab(name);
                             let tab_idx = get_current_print_tab();
                             let mut labels = TAB_LABELS.lock().unwrap();
                             labels.insert(tab_idx, name.to_string());
                             return;
                        }
                    }
                }
                add_tab("");
            }),
            "host_set_tab_owner" => Function::new_typed_with_env(&mut store, &env, |mut env: FunctionEnvMut<Env>, ptr: i32, len: i32| {
                let (env_data, store) = env.data_and_store_mut();
                if let Some(memory) = &env_data.memory {
                    let view = memory.view(&store);
                    let mut buffer = vec![0u8; len as usize];
                    if view.read(ptr as u64, &mut buffer).is_ok() {
                        if let Ok(name) = std::str::from_utf8(&buffer) {
                             let tab_idx = get_current_print_tab();
                             set_tab_owner(tab_idx, name);
                        }
                    }
                }
            }),
            "host_get_tab_label" => Function::new_typed_with_env(&mut store, &env, |mut env: FunctionEnvMut<Env>, ptr: i32, max_len: i32| {
                let (env_data, store) = env.data_and_store_mut();
                if max_len <= 0 || max_len as usize > MAX_TAB_LABEL_LEN { return 0; }
                if let Some(memory) = &env_data.memory {
                    let view = memory.view(&store);
                    let tab_idx = get_current_print_tab();
                    let labels = TAB_LABELS.lock().unwrap();
                    if let Some(label) = labels.get(&tab_idx) {
                        let bytes = label.as_bytes();
                        let n = std::cmp::min(bytes.len(), max_len as usize);
                        let _ = view.write(ptr as u64, &bytes[..n]);
                        return n as i32;
                    }
                }
                0
            }),
            "net_post" => Function::new_typed_with_env(&mut store, &env, |mut env: FunctionEnvMut<Env>, url_ptr: i32, url_len: i32, body_ptr: i32, body_len: i32, resp_ptr: i32, resp_max_len: i32| {
                let (env_data, store) = env.data_and_store_mut();
                if !has_permission(&env_data.permissions, "net_post") {
                    print_error("[SECURITY] Plugin attempted to call net_post without permission");
                    return;
                }
                if url_len <= 0 || url_len as usize > MAX_URL_LEN { return; }
                if body_len <= 0 || body_len as usize > MAX_JSON_PAYLOAD_LEN { return; }
                if resp_max_len <= 0 || resp_max_len as usize > MAX_RESPONSE_BUF_LEN { return; }
                if let Some(memory) = &env_data.memory {
                    let view = memory.view(&store);
                    let mut url_buf = vec![0u8; url_len as usize];
                    let mut body_buf = vec![0u8; body_len as usize];
                    if view.read(url_ptr as u64, &mut url_buf).is_ok() && view.read(body_ptr as u64, &mut body_buf).is_ok() {
                        let url = std::str::from_utf8(&url_buf).unwrap_or("");
                        let body = std::str::from_utf8(&body_buf).unwrap_or("");
                        match http_post_json(url, body) {
                            Ok(resp) => {
                                let resp_bytes = resp.as_bytes();
                                let len = std::cmp::min(resp_bytes.len(), resp_max_len as usize);
                                let _ = view.write(resp_ptr as u64, &resp_bytes[..len]);
                            }
                            Err(e) => {
                                print_error(&format!("[NET ERROR] {}", e));
                                let _ = view.write(resp_ptr as u64, b"{}");
                            }
                        }
                    }
                }
            }),
        },
        "wasi_snapshot_preview1" => {
            "args_sizes_get" => Function::new_typed_with_env(&mut store, &env, |mut env: FunctionEnvMut<Env>, argc_ptr: i32, argv_buf_size_ptr: i32| -> i32 {
                let (env_data, store) = env.data_and_store_mut();
                if let Some(memory) = &env_data.memory {
                    let view = memory.view(&store);
                    CURRENT_ARGS.with(|args| {
                        let args = args.borrow();
                        let parsed = parse_args(&args);
                        let mut argc = 1;
                        let mut size = "plugin\0".len();
                        for arg in parsed.iter() { argc += 1; size += arg.len() + 1; }
                        let _ = view.write(argc_ptr as u64, &(argc as u32).to_le_bytes());
                        let _ = view.write(argv_buf_size_ptr as u64, &(size as u32).to_le_bytes());
                    });
                }
                0
            }),
            "args_get" => Function::new_typed_with_env(&mut store, &env, |mut env: FunctionEnvMut<Env>, mut argv_ptr: i32, mut argv_buf_ptr: i32| -> i32 {
                let (env_data, store) = env.data_and_store_mut();
                if let Some(memory) = &env_data.memory {
                    let view = memory.view(&store);
                    CURRENT_ARGS.with(|args| {
                        let args = args.borrow();
                        let parsed = parse_args(&args);
                        let mut write_arg = |arg: &str| {
                            let _ = view.write(argv_ptr as u64, &(argv_buf_ptr as u32).to_le_bytes());
                            argv_ptr += 4;
                            let bytes = arg.as_bytes();
                            let _ = view.write(argv_buf_ptr as u64, bytes);
                            argv_buf_ptr += bytes.len() as i32;
                            let _ = view.write(argv_buf_ptr as u64, &[0u8]);
                            argv_buf_ptr += 1;
                        };
                        write_arg("plugin");
                        for arg in parsed.iter() { write_arg(arg); }
                    });
                }
                0
            }),
            "environ_sizes_get" => Function::new_typed_with_env(&mut store, &env, |mut env: FunctionEnvMut<Env>, count: i32, buf_size: i32| -> i32 {
                let (env_data, store) = env.data_and_store_mut();
                if let Some(memory) = &env_data.memory {
                    let view = memory.view(&store);
                    let _ = view.write(count as u64, &0u32.to_le_bytes());
                    let _ = view.write(buf_size as u64, &0u32.to_le_bytes());
                }
                0
            }),
            "environ_get" => Function::new_typed(&mut store, |_: i32, _: i32| -> i32 { 0 }),
            "proc_exit" => Function::new_typed(&mut store, |_: i32| {}),
            "fd_write" => Function::new_typed_with_env(&mut store, &env, |mut env: FunctionEnvMut<Env>, fd: i32, iovs_ptr: i32, iovs_len: i32, nwritten: i32| -> i32 {
                let (env_data, store) = env.data_and_store_mut();
                if let Some(stream) = crate::ops::fs_containment::StdioStream::from_fd(fd) {
                    let Some(memory) = &env_data.memory else {
                        return crate::ops::fs_containment::WASI_EINVAL;
                    };
                    let view = memory.view(&store);
                    return wasm_stdio_write(&env_data.stdio, stream, &view, iovs_ptr, iovs_len, nwritten);
                }
                // file descriptor write
                if let Some(memory) = &env_data.memory {
                    let view = memory.view(&store);
                    if let Ok(desc) = env_data.fd_table.get(fd) {
                        if let crate::ops::fs_containment::DescriptorKind::RegularFile { file, .. } = desc.kind() {
                            use std::io::Write;
                            let mut file_guard = file.lock().unwrap_or_else(|e| e.into_inner());
                            let mut total_written = 0usize;
                            for i in 0..iovs_len {
                                let mut iov_buf = [0u8; 8];
                                if view.read((iovs_ptr + i * 8) as u64, &mut iov_buf).is_ok() {
                                    let ptr = u32::from_le_bytes(iov_buf[0..4].try_into().unwrap()) as u64;
                                    let len = u32::from_le_bytes(iov_buf[4..8].try_into().unwrap()) as usize;
                                    let mut data = vec![0u8; len];
                                    if view.read(ptr, &mut data).is_ok() {
                                        if file_guard.write_all(&data).is_ok() {
                                            total_written += len;
                                        } else {
                                            return 5;
                                        }
                                    }
                                }
                            }
                            let _ = view.write(nwritten as u64, &(total_written as u32).to_le_bytes());
                            return 0;
                        }
                    }
                }
                8
            }),
            "fd_read" => Function::new_typed_with_env(&mut store, &env, |mut env: FunctionEnvMut<Env>, fd: i32, iovs_ptr: i32, iovs_len: i32, nread: i32| -> i32 {
                let (env_data, store) = env.data_and_store_mut();
                if let Some(stream) = crate::ops::fs_containment::StdioStream::from_fd(fd) {
                    let Some(memory) = &env_data.memory else {
                        return crate::ops::fs_containment::WASI_EINVAL;
                    };
                    let view = memory.view(&store);
                    return wasm_stdio_read(&env_data.stdio, stream, &view, iovs_ptr, iovs_len, nread);
                }
                if let Some(memory) = &env_data.memory {
                    let view = memory.view(&store);
                    if let Ok(desc) = env_data.fd_table.get(fd) {
                        if let crate::ops::fs_containment::DescriptorKind::RegularFile { file, .. } = desc.kind() {
                            use std::io::Read;
                            let mut file_guard = file.lock().unwrap_or_else(|e| e.into_inner());
                            let mut total_read = 0usize;
                            for i in 0..iovs_len {
                                let mut iov_buf = [0u8; 8];
                                if view.read((iovs_ptr + i * 8) as u64, &mut iov_buf).is_ok() {
                                    let ptr = u32::from_le_bytes(iov_buf[0..4].try_into().unwrap()) as u64;
                                    let len = u32::from_le_bytes(iov_buf[4..8].try_into().unwrap()) as usize;
                                    let mut data = vec![0u8; len];
                                    match file_guard.read(&mut data) {
                                        Ok(n) => {
                                            if view.write(ptr, &data[..n]).is_ok() {
                                                total_read += n;
                                            }
                                            if n < len { break; }
                                        }
                                        Err(_) => return 5,
                                    }
                                }
                            }
                            let _ = view.write(nread as u64, &(total_read as u32).to_le_bytes());
                            return 0;
                        }
                    }
                }
                8
            }),
            "fd_close" => Function::new_typed_with_env(&mut store, &env, |mut env: FunctionEnvMut<Env>, fd: i32| -> i32 {
                let (env_data, _) = env.data_and_store_mut();
                if let Some(stream) = crate::ops::fs_containment::StdioStream::from_fd(fd) {
                    return match env_data.stdio.close(stream) {
                        Ok(()) => crate::ops::fs_containment::WASI_ESUCCESS,
                        Err(errno) => errno,
                    };
                }
                match env_data.fd_table.close(fd) {
                    Ok(()) => crate::ops::fs_containment::WASI_ESUCCESS,
                    Err(errno) => errno,
                }
            }),
            "fd_seek" => Function::new_typed_with_env(&mut store, &env, |mut env: FunctionEnvMut<Env>, fd: i32, offset: i64, whence: i32, newoffset_ptr: i32| -> i32 {
                let (env_data, store) = env.data_and_store_mut();
                let Some(memory) = &env_data.memory else {
                    return crate::ops::fs_containment::WASI_EINVAL;
                };
                let Ok(newoffset_u64) = u64::try_from(newoffset_ptr) else {
                    return crate::ops::fs_containment::WASI_EINVAL;
                };
                let Ok(whence_u8) = u8::try_from(whence) else {
                    return crate::ops::fs_containment::WASI_EINVAL;
                };
                if let Some(stream) = crate::ops::fs_containment::StdioStream::from_fd(fd) {
                    if let Err(errno) = env_data.stdio.rights(stream) {
                        return errno;
                    }
                    return crate::ops::fs_containment::WASI_ENOTCAPABLE;
                }
                let desc = match env_data.fd_table.get(fd) {
                    Ok(d) => d,
                    Err(errno) => return errno,
                };
                match desc.fd_seek(offset, whence_u8) {
                    Ok(pos) => {
                        let view = memory.view(&store);
                        if view.write(newoffset_u64, &pos.to_le_bytes()).is_err() {
                            return crate::ops::fs_containment::WASI_EINVAL;
                        }
                        crate::ops::fs_containment::WASI_ESUCCESS
                    }
                    Err(errno) => errno,
                }
            }),
            "fd_fdstat_get" => Function::new_typed_with_env(&mut store, &env, |mut env: FunctionEnvMut<Env>, fd: i32, stat_ptr: i32| -> i32 {
                let (env_data, store) = env.data_and_store_mut();
                let Some(memory) = &env_data.memory else {
                    return crate::ops::fs_containment::WASI_EINVAL;
                };
                let Ok(stat_u64) = u64::try_from(stat_ptr) else {
                    return crate::ops::fs_containment::WASI_EINVAL;
                };
                let raw_bytes = if let Some(stream) = crate::ops::fs_containment::StdioStream::from_fd(fd) {
                    match env_data.stdio.fd_fdstat_get(stream) {
                        Ok(stat) => stat.to_wasi_bytes(),
                        Err(errno) => return errno,
                    }
                } else {
                    let desc = match env_data.fd_table.get(fd) {
                        Ok(d) => d,
                        Err(errno) => return errno,
                    };
                    desc.fd_fdstat_get().to_wasi_bytes()
                };
                let view = memory.view(&store);
                if view.write(stat_u64, &raw_bytes).is_err() {
                    return crate::ops::fs_containment::WASI_EINVAL;
                }
                crate::ops::fs_containment::WASI_ESUCCESS
            }),
            "fd_fdstat_set_flags" => Function::new_typed_with_env(&mut store, &env, |mut env: FunctionEnvMut<Env>, fd: i32, flags: i32| -> i32 {
                let (env_data, _) = env.data_and_store_mut();
                let Ok(raw_flags) = u16::try_from(flags) else {
                    return crate::ops::fs_containment::WASI_EINVAL;
                };
                if let Some(stream) = crate::ops::fs_containment::StdioStream::from_fd(fd) {
                    return match env_data.stdio.set_fd_flags(stream, raw_flags) {
                        Ok(()) => crate::ops::fs_containment::WASI_ESUCCESS,
                        Err(errno) => errno,
                    };
                }
                let desc = match env_data.fd_table.get(fd) {
                    Ok(d) => d,
                    Err(errno) => return errno,
                };
                match desc.set_fd_flags(raw_flags) {
                    Ok(()) => crate::ops::fs_containment::WASI_ESUCCESS,
                    Err(errno) => errno,
                }
            }),
            "fd_fdstat_set_rights" => Function::new_typed_with_env(&mut store, &env, |mut env: FunctionEnvMut<Env>, fd: i32, fs_rights_base: i64, fs_rights_inheriting: i64| -> i32 {
                let (env_data, _) = env.data_and_store_mut();
                if let Some(stream) = crate::ops::fs_containment::StdioStream::from_fd(fd) {
                    return match env_data.stdio.set_rights(stream, fs_rights_base as u64, fs_rights_inheriting as u64) {
                        Ok(()) => crate::ops::fs_containment::WASI_ESUCCESS,
                        Err(errno) => errno,
                    };
                }
                let desc = match env_data.fd_table.get(fd) {
                    Ok(d) => d,
                    Err(errno) => return errno,
                };
                match desc.set_rights(fs_rights_base as u64, fs_rights_inheriting as u64) {
                    Ok(()) => crate::ops::fs_containment::WASI_ESUCCESS,
                    Err(errno) => errno,
                }
            }),
            "fd_prestat_get" => Function::new_typed_with_env(&mut store, &env, |mut env: FunctionEnvMut<Env>, fd: i32, prestat_ptr: i32| -> i32 {
                let (env_data, store) = env.data_and_store_mut();
                let Some(memory) = &env_data.memory else {
                    return crate::ops::fs_containment::WASI_EINVAL;
                };
                let Ok(prestat_u64) = u64::try_from(prestat_ptr) else {
                    return crate::ops::fs_containment::WASI_EINVAL;
                };
                let Ok(desc) = env_data.fd_table.get(fd) else {
                    return crate::ops::fs_containment::WASI_EBADF;
                };
                if let crate::ops::fs_containment::DescriptorKind::PreopenDir { guest_path, .. } = desc.kind() {
                    let view = memory.view(&store);
                    let mut buf = [0u8; 8];
                    buf[0] = 0;
                    let name_len = guest_path.len() as u32;
                    buf[4..8].copy_from_slice(&name_len.to_le_bytes());
                    if view.write(prestat_u64, &buf).is_ok() {
                        return crate::ops::fs_containment::WASI_ESUCCESS;
                    }
                    return crate::ops::fs_containment::WASI_EINVAL;
                }
                crate::ops::fs_containment::WASI_EBADF
            }),
            "fd_prestat_dir_name" => Function::new_typed_with_env(&mut store, &env, |mut env: FunctionEnvMut<Env>, fd: i32, path_ptr: i32, path_len: i32| -> i32 {
                let (env_data, store) = env.data_and_store_mut();
                let Some(memory) = &env_data.memory else {
                    return crate::ops::fs_containment::WASI_EINVAL;
                };
                if path_len < 0 {
                    return crate::ops::fs_containment::WASI_EINVAL;
                }
                let Ok(path_u64) = u64::try_from(path_ptr) else {
                    return crate::ops::fs_containment::WASI_EINVAL;
                };
                let Ok(desc) = env_data.fd_table.get(fd) else {
                    return crate::ops::fs_containment::WASI_EBADF;
                };
                if let crate::ops::fs_containment::DescriptorKind::PreopenDir { guest_path, .. } = desc.kind() {
                    let view = memory.view(&store);
                    let name = guest_path.as_bytes();
                    let to_write = std::cmp::min(path_len as usize, name.len());
                    if view.write(path_u64, &name[..to_write]).is_ok() {
                        return crate::ops::fs_containment::WASI_ESUCCESS;
                    }
                    return crate::ops::fs_containment::WASI_EINVAL;
                }
                crate::ops::fs_containment::WASI_EBADF
            }),
            "path_open" => Function::new_typed_with_env(&mut store, &env, |mut env: FunctionEnvMut<Env>, dirfd: i32, dirflags: i32, path_ptr: i32, path_len: i32, oflags: i32, fs_rights_base: i64, fs_rights_inheriting: i64, fdflags: i32, opened_fd_ptr: i32| -> i32 {
                let (env_data, store) = env.data_and_store_mut();
                if env_data.scoped_dir.is_none() {
                    return 76;
                }
                let Ok(opened_fd_u64) = u64::try_from(opened_fd_ptr) else {
                    return 28;
                };
                let Ok(raw_fdflags) = u16::try_from(fdflags) else {
                    return 28;
                };
                let validated_flags = match crate::ops::fs_containment::DescriptorFlags::from_raw_validated(raw_fdflags) {
                    Ok(f) => f,
                    Err(errno) => return errno,
                };
                if let Some(stream) = crate::ops::fs_containment::StdioStream::from_fd(dirfd) {
                    if let Err(errno) = env_data.stdio.rights(stream) {
                        return errno;
                    }
                    return crate::ops::fs_containment::WASI_ENOTCAPABLE;
                }
                let parent_desc = match env_data.fd_table.get(dirfd) {
                    Ok(d) => d,
                    Err(errno) => return errno,
                };
                let base_dir = match resolve_dir_descriptor_path(&parent_desc, &env_data.scoped_dir) {
                    Ok(p) => p,
                    Err(errno) => return errno,
                };
                if let Some(memory) = &env_data.memory {
                    let view = memory.view(&store);
                    if path_len < 0 {
                        return 28;
                    }
                    let mut path_bytes = vec![0u8; path_len as usize];
                    if view.read(path_ptr as u64, &mut path_bytes).is_err() {
                        return 28;
                    }
                    let raw_path = match std::str::from_utf8(&path_bytes) {
                        Ok(s) => s,
                        Err(_) => return 28,
                    };

                    let follow_symlinks = (dirflags & 1) != 0;
                    let target_path = match resolve_capability_path(&base_dir, raw_path, follow_symlinks) {
                        Ok(p) => p,
                        Err(errno) => return errno,
                    };

                    if oflags & 2 != 0 {
                        // open directory descriptor and allocate id via descriptor table
                        let child_rights = match parent_desc.rights().derive_child_rights(
                            false,
                            false,
                            true,
                            validated_flags,
                            fs_rights_base as u64,
                            fs_rights_inheriting as u64,
                        ) {
                            Ok(r) => r,
                            Err(errno) => return errno,
                        };
                        let runtime_flags = match crate::ops::fs_containment::DescriptorFlags::from_raw_runtime_supported(raw_fdflags) {
                            Ok(f) => f,
                            Err(errno) => return errno,
                        };
                        if target_path.is_dir() {
                            let canon_dir = match target_path.canonicalize() {
                                Ok(c) => c,
                                Err(_) => return 44,
                            };
                            let norm_dir = normalize_for_comparison(&canon_dir);
                            let norm_root = match base_dir.canonicalize() {
                                Ok(c) => normalize_for_comparison(&c),
                                Err(_) => return 44,
                            };
                            if !norm_dir.starts_with(&norm_root) {
                                return 76;
                            }
                            let dir_file = match crate::ops::fs_containment::open_directory_handle(&target_path) {
                                Ok(f) => f,
                                Err(errno) => return errno,
                            };
                            let dir_state = match crate::ops::fs_containment::DescriptorState::new_directory(
                                dir_file,
                                child_rights,
                                runtime_flags,
                            ) {
                                Ok(s) => s,
                                Err(errno) => return errno,
                            };
                            let next_fd = match env_data.fd_table.insert(dir_state) {
                                Ok(id) => id,
                                Err(errno) => return errno,
                            };
                            let Ok(fd_bytes) = crate::ops::fs_containment::encode_abi_fd(next_fd) else {
                                return 8;
                            };
                            if view.write(opened_fd_u64, &fd_bytes).is_err() {
                                return 28;
                            }
                            return 0;
                        } else {
                            return 44;
                        }
                    }

                    let child_rights = match parent_desc.rights().derive_child_rights(
                        (oflags & 1) != 0,
                        (oflags & 8) != 0,
                        false,
                        validated_flags,
                        fs_rights_base as u64,
                        fs_rights_inheriting as u64,
                    ) {
                        Ok(r) => r,
                        Err(errno) => return errno,
                    };
                    let runtime_flags = match crate::ops::fs_containment::DescriptorFlags::from_raw_runtime_supported(raw_fdflags) {
                        Ok(f) => f,
                        Err(errno) => return errno,
                    };

                    let mut opts = fs::OpenOptions::new();
                    opts.read(true);
                    if oflags & 1 != 0 {
                        opts.write(true);
                        opts.create(true);
                    } else {
                        opts.write(true);
                    }
                    // deferred truncate: never truncate before handle verification
                    // prevents host file corruption on namespace race

                    #[cfg(windows)]
                    {
                        use std::os::windows::fs::OpenOptionsExt;
                        // FILE_FLAG_OPEN_REPARSE_POINT (0x00200000)
                        // prevents kernel CreateFileW from following reparse points / symlinks
                        opts.custom_flags(0x00200000);
                    }
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::OpenOptionsExt;
                        if !follow_symlinks {
                            opts.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
                        }
                    }

                    match opts.open(&target_path) {
                        Ok(file) => {
                            // post-open kernel handle verification
                            let norm_root = match base_dir.canonicalize() {
                                Ok(c) => normalize_for_comparison(&c),
                                Err(_) => return 44,
                            };
                            if let Some(opened_path) = get_file_canonical_path(&file) {
                                let norm_opened = normalize_for_comparison(&opened_path);
                                if !norm_opened.starts_with(&norm_root) {
                                    drop(file);
                                    // fail-closed: never touch or delete out-of-boundary objects
                                    return 76;
                                }
                            } else {
                                drop(file);
                                return 76;
                            }

                            // reject reparse points (symlinks, junctions) on opened handle
                            #[cfg(windows)]
                            {
                                use std::os::windows::fs::MetadataExt;
                                if let Ok(meta) = file.metadata() {
                                    if meta.file_attributes() & 0x400 != 0 {
                                        drop(file);
                                        return 76;
                                    }
                                }
                            }
                            #[cfg(not(windows))]
                            {
                                if !follow_symlinks {
                                    if let Ok(meta) = target_path.symlink_metadata() {
                                        if meta.file_type().is_symlink() {
                                            drop(file);
                                            return 76;
                                        }
                                    }
                                }
                            }

                            // deferred atomic truncate: executed strictly on verified handle
                            if oflags & 8 != 0 {
                                if file.set_len(0).is_err() {
                                    drop(file);
                                    return 5;
                                }
                            }

                            let file_state = match crate::ops::fs_containment::DescriptorState::new_regular_file(
                                file,
                                child_rights,
                                runtime_flags,
                            ) {
                                Ok(s) => s,
                                Err(errno) => return errno,
                            };
                            let next_fd = match env_data.fd_table.insert(file_state) {
                                Ok(id) => id,
                                Err(errno) => return errno,
                            };
                            let Ok(fd_bytes) = crate::ops::fs_containment::encode_abi_fd(next_fd) else {
                                return 8;
                            };
                            if view.write(opened_fd_u64, &fd_bytes).is_err() {
                                return 28;
                            }
                            0
                        }
                        Err(e) => match e.kind() {
                            std::io::ErrorKind::NotFound => 44,
                            std::io::ErrorKind::PermissionDenied => 2,
                            std::io::ErrorKind::AlreadyExists => 20,
                            _ => 28,
                        },
                    }
                } else {
                    28
                }
            }),
            "path_create_directory" => Function::new_typed_with_env(&mut store, &env, |mut env: FunctionEnvMut<Env>, dirfd: i32, path_ptr: i32, path_len: i32| -> i32 {
                let (env_data, store) = env.data_and_store_mut();
                if env_data.scoped_dir.is_none() { return 76; }
                let parent_desc = match env_data.fd_table.get(dirfd) {
                    Ok(d) => d,
                    Err(errno) => return errno,
                };
                let base_dir = match resolve_dir_descriptor_path(&parent_desc, &env_data.scoped_dir) {
                    Ok(p) => p,
                    Err(errno) => return errno,
                };
                if let Some(memory) = &env_data.memory {
                    let view = memory.view(&store);
                    let mut path_bytes = vec![0u8; path_len as usize];
                    if view.read(path_ptr as u64, &mut path_bytes).is_err() { return 28; }
                    let raw_path = match std::str::from_utf8(&path_bytes) {
                        Ok(s) => s,
                        Err(_) => return 28,
                    };
                    let target_path = match resolve_capability_path(&base_dir, raw_path, false) {
                        Ok(p) => p,
                        Err(errno) => return errno,
                    };
                    let res = if target_path.exists() {
                        0
                    } else if std::fs::create_dir(&target_path).is_ok() {
                        0
                    } else {
                        28
                    };
                    if res == 0 {
                        let norm_root = match base_dir.canonicalize() {
                            Ok(c) => normalize_for_comparison(&c),
                            Err(_) => return 44,
                        };
                        if let Ok(canon) = target_path.canonicalize() {
                            let norm_canon = normalize_for_comparison(&canon);
                            if !norm_canon.starts_with(&norm_root) {
                                // fail-closed: do not remove foreign directory
                                return 76;
                            }
                            0
                        } else {
                            28
                        }
                    } else {
                        res
                    }
                } else {
                    28
                }
            }),
            "path_remove_directory" => Function::new_typed_with_env(&mut store, &env, |mut env: FunctionEnvMut<Env>, dirfd: i32, path_ptr: i32, path_len: i32| -> i32 {
                let (env_data, store) = env.data_and_store_mut();
                if env_data.scoped_dir.is_none() { return 76; }
                let parent_desc = match env_data.fd_table.get(dirfd) {
                    Ok(d) => d,
                    Err(errno) => return errno,
                };
                let base_dir = match resolve_dir_descriptor_path(&parent_desc, &env_data.scoped_dir) {
                    Ok(p) => p,
                    Err(errno) => return errno,
                };
                if let Some(memory) = &env_data.memory {
                    let view = memory.view(&store);
                    let mut path_bytes = vec![0u8; path_len as usize];
                    if view.read(path_ptr as u64, &mut path_bytes).is_err() { return 28; }
                    let raw_path = match std::str::from_utf8(&path_bytes) {
                        Ok(s) => s,
                        Err(_) => return 28,
                    };
                    let target_path = match resolve_capability_path(&base_dir, raw_path, false) {
                        Ok(p) => p,
                        Err(errno) => return errno,
                    };
                    let norm_root = match base_dir.canonicalize() {
                        Ok(c) => normalize_for_comparison(&c),
                        Err(_) => return 44,
                    };
                    let canon = match target_path.canonicalize() {
                        Ok(c) => c,
                        Err(_) => return 44,
                    };
                    let norm_canon = normalize_for_comparison(&canon);
                    if !norm_canon.starts_with(&norm_root) || norm_canon == norm_root {
                        return 76;
                    }
                    if std::fs::remove_dir(&target_path).is_ok() { 0 } else { 44 }
                } else {
                    28
                }
            }),
            "path_unlink_file" => Function::new_typed_with_env(&mut store, &env, |mut env: FunctionEnvMut<Env>, dirfd: i32, path_ptr: i32, path_len: i32| -> i32 {
                let (env_data, store) = env.data_and_store_mut();
                if env_data.scoped_dir.is_none() { return 76; }
                let parent_desc = match env_data.fd_table.get(dirfd) {
                    Ok(d) => d,
                    Err(errno) => return errno,
                };
                let base_dir = match resolve_dir_descriptor_path(&parent_desc, &env_data.scoped_dir) {
                    Ok(p) => p,
                    Err(errno) => return errno,
                };
                if let Some(memory) = &env_data.memory {
                    let view = memory.view(&store);
                    let mut path_bytes = vec![0u8; path_len as usize];
                    if view.read(path_ptr as u64, &mut path_bytes).is_err() { return 28; }
                    let raw_path = match std::str::from_utf8(&path_bytes) {
                        Ok(s) => s,
                        Err(_) => return 28,
                    };
                    let target_path = match resolve_capability_path(&base_dir, raw_path, false) {
                        Ok(p) => p,
                        Err(errno) => return errno,
                    };
                    let norm_root = match base_dir.canonicalize() {
                        Ok(c) => normalize_for_comparison(&c),
                        Err(_) => return 44,
                    };
                    let canon = match target_path.canonicalize() {
                        Ok(c) => c,
                        Err(_) => return 44,
                    };
                    let norm_canon = normalize_for_comparison(&canon);
                    if !norm_canon.starts_with(&norm_root) || norm_canon == norm_root {
                        return 76;
                    }
                    if std::fs::remove_file(&target_path).is_ok() { 0 } else { 44 }
                } else {
                    28
                }
            }),
            "path_readlink" => Function::new_typed(&mut store, |_: i32, _: i32, _: i32, _: i32, _: i32, _: i32| -> i32 { 76 }),
            "path_symlink" => Function::new_typed(&mut store, |_: i32, _: i32, _: i32, _: i32, _: i32| -> i32 { 76 }),
            "path_filestat_get" => Function::new_typed(&mut store, |_: i32, _: i32, _: i32, _: i32, _: i32| -> i32 { 76 }),
            "path_filestat_set_times" => Function::new_typed(&mut store, |_: i32, _: i32, _: i32, _: i32, _: i64, _: i64, _: i32| -> i32 { 76 }),
            "path_rename" => Function::new_typed(&mut store, |_: i32, _: i32, _: i32, _: i32, _: i32, _: i32| -> i32 { 76 }),
            "fd_advise" => Function::new_typed(&mut store, |_: i32, _: i64, _: i64, _: i32| -> i32 { 0 }),
            "fd_allocate" => Function::new_typed(&mut store, |_: i32, _: i64, _: i64| -> i32 { 0 }),
            "fd_datasync" => Function::new_typed(&mut store, |_: i32| -> i32 { 0 }),
            "fd_filestat_get" => Function::new_typed_with_env(&mut store, &env, |mut env: FunctionEnvMut<Env>, fd: i32, buf_ptr: i32| -> i32 {
                let (env_data, store) = env.data_and_store_mut();
                if let Some(memory) = &env_data.memory {
                    let view = memory.view(&store);
                    if let Ok(desc) = env_data.fd_table.get(fd) {
                        let metadata = match desc.kind() {
                            crate::ops::fs_containment::DescriptorKind::RegularFile { file, .. } => {
                                file.lock().unwrap_or_else(|e| e.into_inner()).metadata().ok()
                            }
                            crate::ops::fs_containment::DescriptorKind::PreopenDir { dir_file, .. }
                            | crate::ops::fs_containment::DescriptorKind::Directory { dir_file } => {
                                dir_file.metadata().ok()
                            }
                        };
                        if let Some(meta) = metadata {
                            let mut buf = [0u8; 64];
                            let filetype: u8 = if meta.is_dir() { 4 } else { 3 };
                            buf[16] = filetype;
                            buf[32..40].copy_from_slice(&meta.len().to_le_bytes());
                            let _ = view.write(buf_ptr as u64, &buf);
                            return 0;
                        }
                    }
                }
                8
            }),
            // unimplemented stub return wasi_enosys until wired to filelocktable
            "fd_filestat_set_size" => Function::new_typed(&mut store, |_: i32, _: i64| -> i32 { crate::ops::fs_containment::WASI_ENOSYS }),
            "fd_filestat_set_times" => Function::new_typed(&mut store, |_: i32, _: i64, _: i64, _: i32| -> i32 { 0 }),
            "fd_pread" => Function::new_typed(&mut store, |_: i32, _: i32, _: i32, _: i64, _: i32| -> i32 { crate::ops::fs_containment::WASI_ENOSYS }),
            "fd_pwrite" => Function::new_typed(&mut store, |_: i32, _: i32, _: i32, _: i64, _: i32| -> i32 { crate::ops::fs_containment::WASI_ENOSYS }),
            "fd_readdir" => Function::new_typed(&mut store, |_: i32, _: i32, _: i32, _: i64, _: i32| -> i32 { 0 }),
            "fd_renumber" => Function::new_typed(&mut store, |_: i32, _: i32| -> i32 { 0 }),
            "fd_sync" => Function::new_typed(&mut store, |_: i32| -> i32 { 0 }),
            "fd_tell" => Function::new_typed_with_env(&mut store, &env, |mut env: FunctionEnvMut<Env>, fd: i32, offset_ptr: i32| -> i32 {
                let (env_data, store) = env.data_and_store_mut();
                let Some(memory) = &env_data.memory else {
                    return crate::ops::fs_containment::WASI_EINVAL;
                };
                let Ok(offset_u64) = u64::try_from(offset_ptr) else {
                    return crate::ops::fs_containment::WASI_EINVAL;
                };
                if let Some(stream) = crate::ops::fs_containment::StdioStream::from_fd(fd) {
                    if let Err(errno) = env_data.stdio.rights(stream) {
                        return errno;
                    }
                    return crate::ops::fs_containment::WASI_ENOTCAPABLE;
                }
                let desc = match env_data.fd_table.get(fd) {
                    Ok(d) => d,
                    Err(errno) => return errno,
                };
                match desc.fd_tell() {
                    Ok(pos) => {
                        let view = memory.view(&store);
                        if view.write(offset_u64, &pos.to_le_bytes()).is_err() {
                            return crate::ops::fs_containment::WASI_EINVAL;
                        }
                        crate::ops::fs_containment::WASI_ESUCCESS
                    }
                    Err(errno) => errno,
                }
            }),
            // unimplemented stub return wasi_enosys until readiness polling is supported
            "poll_oneoff" => Function::new_typed(&mut store, wasi_poll_oneoff),
            "sched_yield" => Function::new_typed(&mut store, || -> i32 { 0 }),
        }
    };

    let instance = Instance::new(&mut store, &module, &import_object)?;
    let memory = instance.exports.get_memory("memory")?.clone();
    env.as_mut(&mut store).memory = Some(memory);

    if let Ok(ctors) = instance.exports.get_typed_function::<(), ()>(&store, "__wasm_call_ctors") {
        let _ = ctors.call(&mut store);
    }

    let mut plugins = PLUGINS.lock().unwrap();
    plugins.push(Plugin {
        name: manifest.name.clone(),
        hash: hash.to_string(),
        manifest: manifest.clone(),
        is_trusted,
        store,
        instance,
    });
    Ok(())
}

fn parse_args(s: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current_arg = String::new();
    let mut in_quotes = false;
    for c in s.trim().chars() {
        match c {
            '"' => in_quotes = !in_quotes,
            ' ' if !in_quotes => {
                if !current_arg.is_empty() { args.push(current_arg.clone()); current_arg.clear(); }
            }
            _ => current_arg.push(c),
        }
    }
    if !current_arg.is_empty() { args.push(current_arg); }
    args
}

pub fn get_loaded_plugins() -> Vec<(String, String)> {
    let plugins = PLUGINS.lock().unwrap();
    plugins.iter().filter(|p| p.name != "api").map(|p| (p.name.clone(), p.hash.clone())).collect()
}

pub fn get_loaded_plugins_info() -> Vec<(String, String, String)> {
    let plugins = PLUGINS.lock().unwrap();
    plugins.iter().filter(|p| p.name != "api").map(|p| (p.name.clone(), p.hash.clone(), p.manifest.version.clone())).collect()
}

/// called when ui tab is closed. drops any plugin instance that was
/// running inside that tab so we don't leak wasm memory or get stale
/// callback firing into now-deleted tab index
pub fn unload_plugin_by_tab(tab_idx: i32) {
    use crate::ops::host::get_tab_owner;
    let owner = match get_tab_owner(tab_idx) {
        Some(o) if !o.is_empty() => o,
        _ => return, // Tab had no plugin owner — nothing to do
    };
    let mut plugins = PLUGINS.lock().unwrap();
    let before = plugins.len();
    plugins.retain(|p| p.name != owner);
    let removed = before - plugins.len();
    if removed > 0 {
        drop(plugins); // Release lock before calling back into UI
        crate::ops::host::print_info(&format!("[PLUGXEL] Plugin '{}' unloaded (tab closed).", owner));
    }
}


fn dispatch_call_plugin_entry(plugin: &mut Plugin) -> bool {
    if let Ok(f) = plugin.instance.exports.get_typed_function::<(), i32>(&plugin.store, "main_plugin") {
        let _ = f.call(&mut plugin.store); return true;
    }
    if let Ok(f) = plugin.instance.exports.get_typed_function::<(), i32>(&plugin.store, "run") {
        let _ = f.call(&mut plugin.store); return true;
    }
    if let Ok(f) = plugin.instance.exports.get_typed_function::<(), ()>(&plugin.store, "run") {
        let _ = f.call(&mut plugin.store); return true;
    }
    if let Ok(f) = plugin.instance.exports.get_typed_function::<(), ()>(&plugin.store, "_start") {
        let _ = f.call(&mut plugin.store); return true;
    }
    if let Ok(f) = plugin.instance.exports.get_typed_function::<(), i32>(&plugin.store, "main") {
        let _ = f.call(&mut plugin.store); return true;
    }
    print_error(&format!("[WASM] Plugin '{}' is loaded but has no callable export.", plugin.name));
    false
}

pub fn dispatch_plugin_cmd(cmd: &str, args: &str) -> bool {
    let args_str = args.to_string();
    let cmd_str = cmd.to_string();
    {
        let plugins = PLUGINS.lock().unwrap();
        if !plugins.iter().any(|p| p.name == cmd_str) {
            return false;
        }
    }

    let exec_lock = plugin_exec_lock(&cmd_str);
    set_prompt_visibility(false);

    POOL.execute(move || {
        let _guard = exec_lock.lock().unwrap();
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let start_time = std::time::Instant::now();
            let label = cmd_str.to_uppercase();
            // set thread-local args for this plugin execution
            CURRENT_ARGS.with(|args| {
                *args.borrow_mut() = args_str;
            });

            let dispatched = {
                let mut plugins = PLUGINS.lock().unwrap();
                if let Some(plugin) = plugins.iter_mut().find(|p| p.name == cmd_str) {
                    dispatch_call_plugin_entry(plugin)
                } else {
                    false
                }
            };

            if dispatched {
                let elapsed = start_time.elapsed().as_secs_f32();
                print_info(&format!("<~> {} responded in {:.1}s.", label, elapsed));
            }
        }));

        if let Err(e) = res {
            print_error(&format!("[RUST PANIC] Plugin task failed! {:?}", e));
        }
        set_prompt_visibility(true);
    });
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_import_requires_permission_mapping() {
        assert_eq!(import_requires_permission("host_exec"), Some("host_exec"));
        assert_eq!(import_requires_permission("get_env"), Some("get_env"));
        assert_eq!(import_requires_permission("net_post"), Some("net_post"));
        assert_eq!(import_requires_permission("print_info"), None);
        assert_eq!(import_requires_permission("host_get_platform"), Some("host_get_platform"));
    }

    #[test]
    fn test_has_permission() {
        let perms = vec!["host_exec".to_string(), "get_env".to_string()];
        assert!(has_permission(&perms, "host_exec"));
        assert!(has_permission(&perms, "get_env"));
        assert!(!has_permission(&perms, "net_post"));
    }

    #[test]
    fn test_parse_args_empty() {
        let args = parse_args("");
        assert!(args.is_empty(), "Empty input should return empty vector");
    }

    #[test]
    fn test_parse_args_simple() {
        let args = parse_args("command arg1 arg2");
        assert_eq!(args, vec!["command", "arg1", "arg2"]);
    }

    #[test]
    fn test_parse_args_with_quotes() {
        let args = parse_args("command \"quoted argument\" regular_arg");
        assert_eq!(args, vec!["command", "quoted argument", "regular_arg"]);
    }

    #[test]
    fn test_parse_args_multiple_spaces() {
        let args = parse_args("   command    arg1   \"arg  with  spaces\"  ");
        assert_eq!(args, vec!["command", "arg1", "arg  with  spaces"]);
    }

    #[test]
    fn test_b3_1_plugin_mgr_descriptor_management_lifecycle() {
        use crate::ops::fs_containment::{
            encode_abi_fd, open_directory_handle, DescriptorFlags, DescriptorKind,
            DescriptorState, DescriptorTable, StdioDescriptors, StdioStream, WasiRights,
            WASI_EBADF, WASI_EINVAL, WASI_ENOTCAPABLE, WASI_ENOSYS, WASI_ENOTSUP,
            WASI_FILETYPE_CHARACTER_DEVICE,
        };

        assert_eq!(WASI_ENOSYS, 52);
        assert_eq!(WASI_ENOTSUP, 58);

        let stdio = StdioDescriptors::new();
        let stdin_stat = stdio.fd_fdstat_get(StdioStream::Stdin).unwrap();
        assert_eq!(stdin_stat.fs_filetype, WASI_FILETYPE_CHARACTER_DEVICE);
        assert_eq!(stdin_stat.fs_rights_base.0, WasiRights::FD_READ);
        assert!(!stdin_stat.fs_rights_base.contains(WasiRights::POLL_FD_READWRITE));
        assert_eq!(stdio.require(StdioStream::Stdin, WasiRights::FD_WRITE), Err(WASI_ENOTCAPABLE));
        assert_eq!(stdio.require(StdioStream::Stdout, WasiRights::FD_WRITE), Ok(()));
        assert_eq!(stdio.close(StdioStream::Stdout), Ok(()));
        assert_eq!(stdio.require(StdioStream::Stdout, WasiRights::FD_WRITE), Err(WASI_EBADF));

        let temp_dir =
            std::env::temp_dir().join(format!("plug_b31_mgr_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).unwrap();

        let root_file = open_directory_handle(&temp_dir).unwrap();
        let table = DescriptorTable::new_with_preopen(root_file, "/data");

        // verify preopen descriptor at fd 3 and prestat identity
        let preopen = table.get(3).unwrap();
        match preopen.kind() {
            DescriptorKind::PreopenDir { guest_path, .. } => assert_eq!(*guest_path, "/data"),
            _ => panic!("expected preopen directory at fd 3"),
        }

        let scoped_opt = Some(temp_dir.clone());
        let resolved_root = resolve_dir_descriptor_path(&preopen, &scoped_opt).unwrap();
        assert_eq!(resolved_root, temp_dir);

        // open regular file descriptor beneath preopen root
        let file_path = temp_dir.join("b31_state.bin");
        std::fs::write(&file_path, b"0123456789abcdef").unwrap();
        let reg_file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&file_path)
            .unwrap();
        let child_rights = preopen
            .rights()
            .derive_child_rights(
                false,
                false,
                false,
                DescriptorFlags::EMPTY,
                WasiRights::PLUGXEL_COMPAT_MAX_RIGHTS,
                WasiRights::PLUGXEL_COMPAT_MAX_RIGHTS,
            )
            .unwrap();
        assert!(!child_rights.base.contains(WasiRights::POLL_FD_READWRITE));
        let reg_state =
            DescriptorState::new_regular_file(reg_file, child_rights, DescriptorFlags::EMPTY)
                .unwrap();
        let fd4 = table.insert(reg_state).unwrap();
        assert_eq!(fd4, 4);
        assert_eq!(encode_abi_fd(fd4), Ok(4u32.to_le_bytes()));

        // verify seek tell fdstat_get fdstat_set_flags and fdstat_set_rights
        let desc4 = table.get(fd4).unwrap();
        assert_eq!(desc4.fd_seek(6, 0), Ok(6));
        assert_eq!(desc4.fd_tell(), Ok(6));
        assert_eq!(desc4.set_fd_flags(0), Ok(()));
        assert_eq!(desc4.set_fd_flags(DescriptorFlags::APPEND), Err(WASI_ENOTSUP));
        assert_eq!(desc4.set_fd_flags(1 << 12), Err(WASI_EINVAL));

        let fdstat_bytes = desc4.fd_fdstat_get().to_wasi_bytes();
        assert_eq!(fdstat_bytes[0], 4);
        assert_eq!(u16::from_le_bytes([fdstat_bytes[2], fdstat_bytes[3]]), 0);

        // attenuate to fd_read and fd_tell only then verify cur zero seek still work
        let tell_only_mask = WasiRights::FD_READ | WasiRights::FD_TELL;
        assert_eq!(desc4.set_rights(tell_only_mask, 0), Ok(()));
        assert_eq!(desc4.fd_seek(0, 1), Ok(6));
        assert_eq!(desc4.fd_seek(2, 1), Err(WASI_ENOTCAPABLE));
        assert_eq!(desc4.fd_seek(0, 0), Err(WASI_ENOTCAPABLE));
        assert_eq!(desc4.fd_tell(), Ok(6));

        // attenuate seek and tell right then verify fd_seek and fd_tell reject with enotcapable
        let read_only_mask = WasiRights::FD_READ;
        assert_eq!(desc4.set_rights(read_only_mask, 0), Ok(()));
        assert_eq!(desc4.fd_seek(0, 1), Err(WASI_ENOTCAPABLE));
        assert_eq!(desc4.fd_tell(), Err(WASI_ENOTCAPABLE));

        // close preopen fd 3 and fd 4 then verify table lookup return ebadf without id reuse
        assert_eq!(table.close(3), Ok(()));
        assert_eq!(table.get(3).err(), Some(WASI_EBADF));
        assert_eq!(table.close(fd4), Ok(()));
        assert_eq!(table.get(fd4).err(), Some(WASI_EBADF));
        assert_eq!(desc4.fd_fdstat_get().fs_rights_base, WasiRights(read_only_mask));

        drop(desc4);
        drop(preopen);
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_b3_1_plugin_mgr_wasm_stdio_dispatch_and_instance_isolation() {
        use crate::ops::fs_containment::{
            StdioDescriptors, StdioStream, WASI_EBADF, WASI_EIO, WASI_ENOTCAPABLE, WASI_ESUCCESS,
        };
        use wasmer::{Memory, MemoryType};

        #[derive(Clone)]
        struct VecSink {
            buf: Arc<Mutex<Vec<u8>>>,
            limit: Option<usize>,
            fail: bool,
        }

        impl VecSink {
            fn new() -> (Self, Arc<Mutex<Vec<u8>>>) {
                let buf = Arc::new(Mutex::new(Vec::new()));
                (
                    Self {
                        buf: Arc::clone(&buf),
                        limit: None,
                        fail: false,
                    },
                    buf,
                )
            }
        }

        impl std::io::Write for VecSink {
            fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
                if self.fail {
                    return Err(std::io::Error::new(std::io::ErrorKind::Other, "sink fail"));
                }
                let n = self.limit.map_or(data.len(), |l| data.len().min(l));
                self.buf.lock().unwrap().extend_from_slice(&data[..n]);
                Ok(n)
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let mut store = Store::new(Cranelift::default());
        let memory = Memory::new(&mut store, MemoryType::new(1, None, false)).unwrap();
        let view = memory.view(&store);

        // write guest payload and ciovec table into linear memory
        let stdout_msg = b"plugin-stdout-payload";
        let stderr_msg = b"plugin-stderr-payload";
        view.write(0x100, stdout_msg).unwrap();
        view.write(0x200, stderr_msg).unwrap();

        // ciovec 0 at 0x40 -> (0x100, len)
        view.write(0x40, &0x100u32.to_le_bytes()).unwrap();
        view.write(0x44, &(stdout_msg.len() as u32).to_le_bytes()).unwrap();
        // ciovec 1 at 0x50 -> (0x200, len)
        view.write(0x50, &0x200u32.to_le_bytes()).unwrap();
        view.write(0x54, &(stderr_msg.len() as u32).to_le_bytes()).unwrap();

        let (out1_sink, out1_buf) = VecSink::new();
        let (err1_sink, err1_buf) = VecSink::new();
        let stdio_inst1 = StdioDescriptors::with_sinks(Box::new(out1_sink), Box::new(err1_sink));

        let (out2_sink, out2_buf) = VecSink::new();
        let (err2_sink, err2_buf) = VecSink::new();
        let stdio_inst2 = StdioDescriptors::with_sinks(Box::new(out2_sink), Box::new(err2_sink));

        // 1. fd_write(1) and fd_write(2) write exact bytes to distinct sinks and update nwritten
        assert_eq!(
            wasm_stdio_write(&stdio_inst1, StdioStream::Stdout, &view, 0x40, 1, 0x80),
            WASI_ESUCCESS
        );
        let mut nwritten_bytes = [0u8; 4];
        view.read(0x80, &mut nwritten_bytes).unwrap();
        assert_eq!(u32::from_le_bytes(nwritten_bytes) as usize, stdout_msg.len());
        assert_eq!(out1_buf.lock().unwrap().as_slice(), stdout_msg);
        assert!(err1_buf.lock().unwrap().is_empty());

        assert_eq!(
            wasm_stdio_write(&stdio_inst1, StdioStream::Stderr, &view, 0x50, 1, 0x84),
            WASI_ESUCCESS
        );
        view.read(0x84, &mut nwritten_bytes).unwrap();
        assert_eq!(u32::from_le_bytes(nwritten_bytes) as usize, stderr_msg.len());
        assert_eq!(err1_buf.lock().unwrap().as_slice(), stderr_msg);

        // 2. fd_read(0) return eof zero byte while fd_write(0) and fd_read(1|2) return enotcapable
        view.write(0x88, &99u32.to_le_bytes()).unwrap();
        assert_eq!(
            wasm_stdio_read(&stdio_inst1, StdioStream::Stdin, &view, 0x40, 1, 0x88),
            WASI_ESUCCESS
        );
        view.read(0x88, &mut nwritten_bytes).unwrap();
        assert_eq!(u32::from_le_bytes(nwritten_bytes), 0);
        assert_eq!(
            wasm_stdio_write(&stdio_inst1, StdioStream::Stdin, &view, 0x40, 1, 0x80),
            WASI_ENOTCAPABLE
        );
        assert_eq!(
            wasm_stdio_read(&stdio_inst1, StdioStream::Stdout, &view, 0x40, 1, 0x88),
            WASI_ENOTCAPABLE
        );

        // 3. close fd 0 1 2 in instance 1 -> instance 1 return ebadf while instance 2 stay active
        assert_eq!(stdio_inst1.close(StdioStream::Stdin), Ok(()));
        assert_eq!(stdio_inst1.close(StdioStream::Stdout), Ok(()));
        assert_eq!(stdio_inst1.close(StdioStream::Stderr), Ok(()));
        assert_eq!(
            wasm_stdio_read(&stdio_inst1, StdioStream::Stdin, &view, 0x40, 1, 0x88),
            WASI_EBADF
        );
        assert_eq!(
            wasm_stdio_write(&stdio_inst1, StdioStream::Stdout, &view, 0x40, 1, 0x80),
            WASI_EBADF
        );
        assert_eq!(
            wasm_stdio_write(&stdio_inst1, StdioStream::Stderr, &view, 0x50, 1, 0x84),
            WASI_EBADF
        );

        assert_eq!(
            wasm_stdio_write(&stdio_inst2, StdioStream::Stdout, &view, 0x40, 1, 0x80),
            WASI_ESUCCESS
        );
        assert_eq!(
            wasm_stdio_write(&stdio_inst2, StdioStream::Stderr, &view, 0x50, 1, 0x84),
            WASI_ESUCCESS
        );
        assert_eq!(out2_buf.lock().unwrap().as_slice(), stdout_msg);
        assert_eq!(err2_buf.lock().unwrap().as_slice(), stderr_msg);

        // 4. partial write and sink error propagation through wasm_stdio_write
        let (mut partial_sink, partial_buf) = VecSink::new();
        partial_sink.limit = Some(6);
        let mut err_sink = VecSink::new().0;
        err_sink.fail = true;
        let stdio_partial_err =
            StdioDescriptors::with_sinks(Box::new(partial_sink), Box::new(err_sink));

        assert_eq!(
            wasm_stdio_write(&stdio_partial_err, StdioStream::Stdout, &view, 0x40, 1, 0x90),
            WASI_ESUCCESS
        );
        view.read(0x90, &mut nwritten_bytes).unwrap();
        assert_eq!(u32::from_le_bytes(nwritten_bytes), 6);
        assert_eq!(partial_buf.lock().unwrap().as_slice(), &stdout_msg[..6]);

        assert_eq!(
            wasm_stdio_write(&stdio_partial_err, StdioStream::Stderr, &view, 0x50, 1, 0x94),
            WASI_EIO
        );
    }

    #[test]
    fn test_b3_1_poll_oneoff_unimplemented_stub_returns_enosys() {
        use crate::ops::fs_containment::{WasiRights, WASI_ENOSYS, WASI_ENOTCAPABLE};
        use wasmer::{Memory, MemoryType};

        // verify poll_oneoff stub return wasi_enosys without fake success
        let in_ptr = 0x100;
        let out_ptr = 0x200;
        let nsubscriptions = 2;
        let nevents_ptr = 0x300;
        let ret = wasi_poll_oneoff(in_ptr, out_ptr, nsubscriptions, nevents_ptr);
        assert_eq!(ret, WASI_ENOSYS);
        assert_eq!(WASI_ENOSYS, 52);

        // verify guest memory canary buffer remain untouched and no fake nevents written
        let mut store = Store::new(Cranelift::default());
        let memory = Memory::new(&mut store, MemoryType::new(1, None, false)).unwrap();
        let view = memory.view(&store);

        let canary_out = [0xAAu8; 64];
        let canary_nevents = 0xDEADBEEFu32.to_le_bytes();
        view.write(out_ptr as u64, &canary_out).unwrap();
        view.write(nevents_ptr as u64, &canary_nevents).unwrap();

        // invoke stub with canary in memory
        let ret2 = wasi_poll_oneoff(in_ptr, out_ptr, nsubscriptions, nevents_ptr);
        assert_eq!(ret2, WASI_ENOSYS);

        let mut read_out = [0u8; 64];
        let mut read_nevents = [0u8; 4];
        view.read(out_ptr as u64, &mut read_out).unwrap();
        view.read(nevents_ptr as u64, &mut read_nevents).unwrap();

        assert_eq!(read_out, canary_out);
        assert_eq!(read_nevents, canary_nevents);

        // verify poll_fd_readwrite capability remain reject across regular file and stdio
        assert!(!WasiRights::SUPPORTED_REGULAR_FILE_BASE.contains(WasiRights::POLL_FD_READWRITE));
        assert!(!WasiRights::SUPPORTED_DIRECTORY_INHERITING.contains(WasiRights::POLL_FD_READWRITE));

        let stdio = crate::ops::fs_containment::StdioDescriptors::new();
        assert_eq!(
            stdio.require(crate::ops::fs_containment::StdioStream::Stdin, WasiRights::POLL_FD_READWRITE),
            Err(WASI_ENOTCAPABLE)
        );
        assert_eq!(
            stdio.require(crate::ops::fs_containment::StdioStream::Stdout, WasiRights::POLL_FD_READWRITE),
            Err(WASI_ENOTCAPABLE)
        );
        assert_eq!(
            stdio.require(crate::ops::fs_containment::StdioStream::Stderr, WasiRights::POLL_FD_READWRITE),
            Err(WASI_ENOTCAPABLE)
        );
    }

    #[test]
    fn test_b3_1_host_stdio_embedded_nul_escaping_and_lossy_utf8() {
        use std::ffi::CString;

        // verify embedded nul byte escaped to literal \0 instead of drop message
        let raw = b"hello\0world\n";
        let sanitized = sanitize_host_stdio_message(raw);
        assert_eq!(sanitized, "hello\\0world");

        // verify cstring creation always succeed on sanitized string
        let c_res = CString::new(sanitized.clone());
        assert!(c_res.is_ok(), "sanitized message must not contain embedded nul");

        // verify multiple embedded nuls and carriage return trimming
        let raw_multi = b"\0start\0middle\0end\r\n";
        let sanitized_multi = sanitize_host_stdio_message(raw_multi);
        assert_eq!(sanitized_multi, "\\0start\\0middle\\0end");
        assert!(CString::new(sanitized_multi).is_ok());

        // verify invalid utf8 byte replaced with unicode replacement character
        let invalid_utf8 = b"bad\xffbyte\0\n";
        let sanitized_invalid = sanitize_host_stdio_message(invalid_utf8);
        assert!(sanitized_invalid.contains('\u{FFFD}'));
        assert!(sanitized_invalid.ends_with("\\0"));
        assert!(CString::new(sanitized_invalid).is_ok());
    }
}
