# Plugin Development

Plugins are WebAssembly (`wasm32-unknown-unknown`) binaries.

## 1. Rust Template

Create a library project (`cargo new my_plugin --lib`) with `crate-type = ["cdylib"]` in `Cargo.toml`.

### `src/lib.rs`
```rust
extern "C" {
    fn get_args(ptr: *mut u8, max_len: usize);
    fn print_info(ptr: *const u8, len: usize);
}

#[no_mangle]
pub extern "C" fn run() {
    let mut buf = [0u8; 256];
    unsafe { get_args(buf.as_mut_ptr(), buf.len()); }
    
    let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let args = std::str::from_utf8(&buf[..len]).unwrap_or("").trim();

    let msg = format!("Args received: {}", args);
    unsafe { print_info(msg.as_ptr(), msg.len()); }
}
```

---

## 2. Permissions Manifest (`plugin.toml`)

Permissions must be explicitly requested to call sensitive host FFI imports:

```toml
[[plugin]]
name = "my_plugin"
version = "1.0.0"
author = "Dev"
api_version = "xxx"
permissions = [
  "host_exec",           # Spawning local commands (allowlist-only, no shell)
  "host_add_tab",        # Spawning new tabs
  "host_set_tab_owner",  # Taking tab ownership
  "host_get_tab_label",  # Reading active tab label
  "host_get_platform",   # Detecting host OS (0=Windows, 1=Linux)
  "get_env",             # Reading host environment variables
  "net_post",            # HTTP POST requests (HTTPS only, no private IPs)
  "fs_scoped"            # Scoped filesystem capability (preopened /data storage)
]
```

---

## 3. Compilation

Compile and optimize the WASM binary:

```bash
# Add target
rustup target add wasm32-unknown-unknown

# Compile optimized WASM
rustc --target wasm32-unknown-unknown \
      --crate-type cdylib src/lib.rs \
      -o plugins/my_plugin/my_plugin.wasm \
      -C opt-level=z \
      -C lto=true \
      -C strip=symbols \
      -C link-arg=--allow-undefined
```
---

## Security Notes

### WASI Imports
The runtime **does not** expose the full WASI preview1 API. Only a safe subset is available (stdin/stdout/stderr, clocks, args, env stubs). Attempting to import blocked WASI functions (`path_open`, `sock_connect`, `proc_raise`, etc.) will cause plugin load failure.

### Command Execution (`host_exec`)
- No shell interpretation: commands run via `execvp`/`CreateProcess` with argv array directly
- Allowlist-only: manifest must declare `allowed_commands` with canonical path + args regex
- Example:
```toml
[[plugin]]
# ... other fields ...
allowed_commands = [
  { path = "/usr/bin/git", args_pattern = "^(status|log|diff)" },
  { path = "C:\\Program Files\\Git\\bin\\git.exe", args_pattern = "^(status|log|diff)" }
]
```

### Network (`net_post`)
- HTTPS only (HTTP rejected)
- Private IPs blocked (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16, link-local, multicast)
- Response capped at 1 MiB
- 30 second timeout

### Filesystem (`fs_scoped`)
- `cd` command restricted to current working directory jail
- With `fs_scoped` permission, plugins access persistent sandbox storage via the preopened `/data` capability descriptor
- Strict capability boundary: path traversals (`..`), rooted paths, symlink creation, and symlink escapes outside `/data` return `ENOTCAPABLE` (76)
- Without `fs_scoped`, zero filesystem preopens are provisioned and `path_*` WASI imports are rejected at load time
