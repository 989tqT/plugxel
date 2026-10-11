# Architecture

## Subsystem Layers

The framework splits operations into two layers connected via C FFI:
- **UI Host (C++17)**: Manages native window loops (Win32 GDI on Windows, GTK4/Cairo on Linux). Renders UI elements (carets, scrollbars, text selection) and forwards keyboard input to the core.
- **Core Runtime (Rust)**: Instantiates Wasmer 4.3 (Cranelift compilation), processes shell commands, maps active tab contexts, and enforces sandboxing.

---

## FFI Boundary (`cmn/inc/sys/c.h`)

### Rust Functions (Called by C++)
- `c_init()` / `c_cleanup()`: Lifecycle initialization and shutdown.
- `c_is_running()`: Returns runtime status.
- `c_parse(input_str)`: Parses and executes keyboard inputs.
- `c_on_tab_close(idx)`: Unloads plugins running inside the closed tab.

### C++ Functions (Called by Rust / Plugins)
- `main_*_print_info(str)` / `main_*_print_error(str)`: Output logs to active text buffers.
- `main_*_add_tab(name)`: Spawns a new tab context. Note that the WASM FFI layer exposes a platform-neutral import named `host_add_tab` which the host runtime routes to these platform-specific functions.
- `main_*_set_prompt_visibility(visible)`: Controls standard input prompt fields.
- `main_*_get_tab_owner(idx, buf, max_len)` / `main_*_set_tab_owner(idx, name)`: Syncs tab ownership state. The `get` function writes the owner string into `buf` up to `max_len` to ensure buffer safety and avoid ABI crashes.

---

## Command Routing & Permissions

Inputs starting with `/` invoke built-in commands (e.g., `/tab` or `/plug`). Other inputs are dispatched to the WASM plugin owning the active tab.

If a plugin requests access to sensitive FFI imports (such as `host_exec` to run local shell subprocesses, `get_env` to read environment variables, `net_post` for outbound HTTP, or `host_get_platform` to detect host OS), the runtime validates its manifest permissions list (`plugin.toml`) at load time (import validation) and again at call time (runtime gate) before delegating to the host OS.

### WASI Sandbox Enforcement
The `wasi_snapshot_preview1` import namespace is **not** automatically exposed. Only an explicit allowlist of safe WASI functions is provided (see `plugin_mgr.rs:ALLOWED_WASI`). Dangerous syscalls (`path_open`, `sock_connect`, `proc_raise`, `random_get`, etc.) are blocked at module load time regardless of manifest.

### Supply Chain Security
Plugin registry (`pluglists.json`) is verified via minisign/Ed25519 signature (public key baked in binary) before any plugin metadata or hashes are trusted. Downloaded WASM is verified against registry-pinned SHA256.

### Network Hardening
`net_post` enforces: HTTPS-only scheme, private/reserved IP blocking (RFC1918, loopback, link-local, multicast), 1 MiB response size limit, 30s timeout.

### Filesystem Containment
`cd` command handler resolves target via `canonicalize` then verifies result stays within process CWD jail. Traversal attempts (`../../etc`) are rejected.
