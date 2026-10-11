# Security Model & Threat Analysis

## Threat Model

### Assets
- Host filesystem (read/write/execute)
- Host network (internal/external)
- Host process execution
- Plugin integrity (supply chain)
- User data in plugin tabs

### Actors
- **Malicious plugin author**: Publishes plugin to registry
- **Compromised registry**: GitHub repo / CDN hijacked
- **Local attacker**: Code execution on host machine
- **Network attacker**: MITM on plugin download

## Security Controls

### 1. WASM Sandbox (Wasmer 4.3 Cranelift)
- Linear memory isolation (no host pointer access)
- No direct syscall instruction execution
- All host interaction via explicit FFI imports

### 2. Import Validation (Load Time)
**Env namespace** (`env.*`):
- Every import checked against manifest `permissions[]`
- Missing permission → load failure
- Imports: `host_exec`, `host_add_tab`, `host_set_tab_owner`, `host_get_tab_label`, `host_get_platform`, `get_env`, `net_post`, `print_info`, `print_error`, `get_args`

**WASI namespace** (`wasi_snapshot_preview1.*`):
- **Explicit allowlist only** (see `plugin_mgr.rs:ALLOWED_WASI`)
- Capability-Gated (`fs_scoped` manifest permission required): `path_open`, `path_create_directory`, `path_remove_directory`, `path_unlink_file`, `path_readlink`, `path_filestat_get`, `path_filestat_set_times`, `path_rename`
- Blocked / Denied: Arbitrary `path_symlink`, `path_link`, `sock_connect`, `sock_bind`, `sock_listen`, `sock_accept`, `proc_raise`, `random_get` (stubbed), etc.
- Allowed: `fd_write`/`fd_read` (stdout/stderr only), `proc_exit`, `clock_time_get`, `args_*`, `environ_*` (stubs), `poll_oneoff`, `sched_yield`, `sock_*` (stubs returning ENOSYS)

### 3. Runtime Gates (Call Time)
Each sensitive import re-checks permission before executing:
```rust
if !env_data.permissions.iter().any(|p| p == "host_exec") {
    print_error("[SECURITY] Plugin attempted to call host_exec without permission");
    return;
}
```

### 4. Command Execution Hardening (`host_exec`)
- **No shell**: Direct `Command::new(exe).args(args)` — no `cmd /c`, `sh -c`
- **Allowlist-only**: Manifest `allowed_commands` with canonical path + args regex
- **Path canonicalization**: `resolve_binary_path()` → `fs::canonicalize()`
- **No blacklist**: Blacklists are bypassable; removed entirely

### 5. Network Hardening (`net_post`)
- HTTPS only (scheme validation via `url::Url`)
- Private IP blocking (RFC1918, RFC3927, RFC6598, loopback, multicast, reserved)
- Hostname blocking: `localhost`, `localhost.localdomain`
- Response size limit: 1 MiB
- Timeout: 30s (configurable via `DEFAULT_TIMEOUT`)

### 6. Filesystem Containment & Scoped Sandbox
- `cd` command: `canonicalize()` + prefix check against process CWD
- WASI Scoped Filesystem Sandbox (`fs_scoped`):
  - Scoped Filesystem Capability: **ENFORCED** (mapped to isolated `/data` virtual descriptor per plugin).
  - Preopen Directory Policy (Plug Invariant): In Plugxel's sandbox model, exactly one preopened directory descriptor mapped to virtual path `/data` is provisioned per plugin. (Note: while WASI Preview 1 permits arbitrary preopen sets, restricting to exactly one isolated `/data` preopen is a deliberate Plugxel security invariant for zero-trust storage isolation).
  - Capability Isolation: **ENFORCED**. Each plugin maps `/data` to an opaque host path (`~/.plugxel/data/<plugin_hash>/`). Cross-plugin sibling traversals (`../sibling`) are strictly denied at the capability boundary.
  - Traversal Containment: **ENFORCED**. Lexical lookup strictly rejects rooted paths (`/`, `\`, drive syntax) and ascending traversals (`..`) exceeding the capability root, returning `ENOTCAPABLE` (76).
  - Unauthorized Import / Permission Gate: **ENFORCED**. Plugins without `fs_scoped` receive zero preopen capabilities (`EBADF`) and any `path_*` imports are rejected at load time.
  - Surface Minimization: **ENFORCED**. Non-essential filesystem primitives (`path_symlink`, `path_readlink`, `path_rename`, `path_filestat_*`) are locked down as fail-closed stubs returning `ENOTCAPABLE` (76). Operational surface restricted strictly to CRUD on regular files/directories.
  - Post-Open Object Verification: **ENFORCED**. File handles opened via `path_open` are interrogated at the kernel level (`GetFinalPathNameByHandleW` on Windows, `/proc/self/fd/` on Linux) to verify that the backing file object strictly resides within the capability root. Reparse points on opened handles trigger immediate descriptor revocation (`drop`) and return `ENOTCAPABLE` (76).
  - Pre-Verification Truncation Side Effects: **ELIMINATED**. Truncation (`O_TRUNC`) is deferred exclusively to verified handles via `file.set_len(0)` — eliminating premature truncation of out-of-boundary host files during namespace races.
  - Foreign Deletion Elimination: **ENFORCED**. Foreign deletion logic is completely purged — escape detection drops descriptors fail-closed with zero host modification or deletion.
  - Final-Object Reparse Dereference Inhibition: **ENFORCED**. Windows open passes `FILE_FLAG_OPEN_REPARSE_POINT` (0x00200000) to inhibit kernel reparse dereferencing for the target object during `CreateFileW`; Linux open enforces `O_NOFOLLOW | O_CLOEXEC`.
  - Path Mutation Namespace Races: **RESIDUAL RISK (P1.5 Atomic Containment Target)**. Pathname-based mutating operations (`path_create_directory`, `path_unlink_file`, `path_remove_directory`, and `O_CREAT` race window) rely on multi-pass lexical inspection + post-action validation. Without descriptor-relative atomic kernel primitives, concurrent namespace mutation between check and operation remains a theoretical host race.
  - Atomic Kernel-Level Path Containment: **P1.5 ENGINEERING ROADMAP (PENDING)**.
    - Linux target architecture: `openat2(dirfd, relative_path, { RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS })` with kernel-enforced `EAGAIN` race backoff. Directory mutations via descriptor-relative `*at()` syscalls (`mkdirat`, `unlinkat`).
    - Windows target architecture: Handle-relative directory walking/pinning (`NtOpenFile` with `RootDirectory` or recursive verified handle binding) to eliminate intermediate reparse hopping.
    - Concurrent namespace race fuzzing test suite (verifying host file preservation during continuous race swapping).
- Plugin working directory tracked per-tab (`TAB_CWDS`)

### 7. Supply Chain Integrity
- Registry (`pluglists.json`) signed with minisign/Ed25519
- Public key baked into binary (`REGISTRY_PUBKEY`)
- Signature verified before parsing any registry content
- Plugin WASM verified against registry-pinned SHA256
- Atomic write with same-FS verification (`write_atomic`)

### 8. Input Validation
- All FFI string reads bounded by constants:
  - `MAX_FFI_STRING_LEN = 64 KiB`
  - `MAX_URL_LEN = 2 KiB`
  - `MAX_JSON_PAYLOAD_LEN = 16 KiB`
  - `MAX_RESPONSE_BUF_LEN = 1 MiB`
  - `MAX_TAB_LABEL_LEN = 256 B`
- Prevents OOB reads and allocation DoS

## Known Limitations / Residual Risk

| Risk | Mitigation | Residual |
|------|-----------|----------|
| WASI stubs return ENOSYS | Plugins expecting real syscalls fail gracefully | Low (breaks compat, not security) |
| Allowlist regex ReDoS | `regex` crate is linear-time (no backtracking) | Low |
| Registry key rotation | Not implemented; requires binary rebuild | Medium |
| Side-channel via `host_get_platform` | Now permission-gated | Low |
| TOCTOU in `write_atomic` cross-FS | Same-FS check + randomized temp name | Low |
| Intermediate namespace race (pre-P1.5) | Reparse inhibit + post-open handle verification + deferred truncate | Low-Medium (mitigated against destruction; full atomic containment targeted in P1.5) |
| Malicious plugin DoS (infinite loop) | No fuel metering / epoch interruption | Medium |
| Memory exhaustion via large allocations | `MAX_FFI_STRING_LEN` bounds; Wasmer memory limit not set | Medium |

## Security Checklist for Plugin Review

- [ ] Manifest declares minimal permissions
- [ ] `allowed_commands` uses canonical paths, restrictive regex
- [ ] No WASI imports beyond allowlist (verify with `wasm-objdump -x plugin.wasm | grep wasi_snapshot_preview1`)
- [ ] `net_post` URLs are HTTPS, external domains only
- [ ] Plugin does not attempt `cd` traversal
- [ ] SHA256 in registry matches published WASM

## Incident Response

1. **Malicious plugin detected**: Revoke registry entry, rotate minisign key, rebuild host
2. **Registry compromise**: Rotate minisign key immediately, audit all plugins
3. **Sandbox escape**: Isolate host, analyze WASM module, patch Wasmer/import gate
