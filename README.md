# Plugxel: A WebAssembly Plugin Framework

<p align="left">
  <img src="plug.res/ast/ico/p-1.png" alt="logo" width="500"/>
</p>

<p align="center">
  <a href="https://github.com/989tqT/plugxel/actions/workflows/ci.yml"><img src="https://github.com/989tqT/plugxel/actions/workflows/ci.yml/badge.svg" alt="CI Build" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT" /></a>
</p>

## Features

- **Sandboxed WASM Runtime**: Isolated memory execution using Wasmer 4.3 (Cranelift). WASI preview1 imports are strictly gated — capability-based scoped filesystem (`/data`) confined to opaque isolated per-plugin storage under manifest permission; arbitrary host access blocked.
- **Granular Permissions Model**: Enforces manifest-declared permissions at load time (import validation) AND call time (runtime gate) for host imports including `host_get_platform` and scoped filesystem capability (`fs_scoped`).
- **SSRF Protection**: `net_post` enforces HTTPS-only, blocks private/reserved IPs (RFC1918, loopback, link-local), limits response to 1 MiB.
- **Multitab**: Launch and run multiple independent plugins concurrently in separate workspace tabs.
- **Cross-Platform Native UI**: Compiles to Windows (Win32 GDI) and Linux (GTK4) with zero browser engine footprint.

---

## Overview

```mermaid
graph TD
    A[C++ UI Subsystem] -- Input Commands --> B(FFI Interface)
    B -- Parse / Process --> C[Rust Runtime Core]
    C -- Load / Run --> D[Wasmer Sandbox Engine]
    D -- Host Imports / Callbacks --> C
    C -- Control UI --> B
    B -- UI Updates --> A
```

---

## Getting Started

Refer to [docs/BUILD.md](docs/BUILD.md) for full toolchain setup.

### Quick Build
```bash
# Windows
cd plug.cross\windows && .\make.bat

# Linux
cd plug.cross/linux && ./make.sh
```

---

## Console Commands

| Command | Args | Description |
|---|---|---|
| `/?` | None | Displays help details. |
| `/a` | None | Displays system environment and memory statistics. |
| `/tab` | None | Spawns a new workspace tab. |
| `/plug*` | None | Lists available online registry plugins and hashes. |
| `/plug` | `[hash]` | Downloads and initializes a plugin. |
| `/plug-` | `[hash]` | Unloads the specified plugin. |
| `/e` | None | Exits the application. |

> See [All plugins command reference](docs/PLUGINS/README.md) for details.

---

## Plugin Development

Plugins are compiled targeting `wasm32-unknown-unknown`.

```rust
extern "C" {
    fn get_args(ptr: *mut u8, max_len: usize);
    fn print_info(ptr: *const u8, len: usize);
}

#[no_mangle]
pub extern "C" fn run() {
    let mut buf = [0u8; 128];
    unsafe { get_args(buf.as_mut_ptr(), buf.len()); }
    let msg = "Hello from WASM plugin!";
    unsafe { print_info(msg.as_ptr(), msg.len()); }
}
```

Refer to [docs/PLUGIN_DEVELOPMENT.md](docs/PLUGIN_DEVELOPMENT.md) for details on permissions configuration (`plugin.toml`) and FFI imports.

---

## Security

See [docs/SECURITY.md](docs/SECURITY.md) for the complete threat model, sandbox architecture, and security controls summary.