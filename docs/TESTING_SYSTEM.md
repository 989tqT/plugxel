# Plugxel Testing System

This document details the restructured and scaled testing system for the **plugxel** framework. It establishes a multi-layered automated test suite validating FFI boundaries, sandbox permission enforcement, unit logic, and E2E lifecycles.

---

## 1. Directory Architecture

```text
tests/
├── preflight.py                 # Environment verification, path-based orphan cleanup, context generation
├── run.py                       # Parallelized test orchestrator and CI reporter
├── unit/                        # Subsystem isolated unit checks
│   ├── rust_core/               # Cargo tests wrapper with JSON format parsing
│   └── cpp_ui/                  # Headless C++ unit tests (C++17, custom assert framework)
├── integration/                 # Boundary and multi-module validation
│   ├── test_ffi_boundary.py     # FFI memory, multi-byte UTF-8, double-free verification
│   └── test_sandbox_rules.py    # Wasmer constraints check (load-time, runtime, baseline checks)
├── e2e/                         # Process-level End-to-End checks
│   └── test_cli_lifecycle.py    # Deadlock-free stream reading CLI lifecycle loops
└── fixtures/                    # Mock binaries, manifests, and plugin templates
    ├── manifests/               # Test plugin.toml manifests (valid/invalid permissions)
    └── mock_plugins/            # WASM templates (ok_plugin, rogue_plugin, rogue_plugin_runtime)
```

---

## 2. Preflight & Environment Validation (`tests/preflight.py`)

To distinguish target environment mismatches from code failures, `preflight.py` executes before the orchestrator to verify requirements:
- **Rust Target**: Verifies `wasm32-unknown-unknown` target is installed via `rustup target list --installed`. If missing, installs it or halts with setup instructions.
- **Version Ranges**: Checks that `cargo` is present and reports the configured minimum cargo version from `preflight.py`.
- **Zero-Dependency Path-Based Orphan Cleanup**:
  - To avoid installing third-party Python modules like `psutil` in CI/dev setups, path lookup uses native command utilities.
  - **Windows**: Invokes `powershell "Get-Process plugxelxel -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path"` to retrieve the executable path of matching active processes.
  - **Linux**: Reads `/proc/<pid>/exe` using `os.readlink()` for processes owned by the current user.
  - If a process matches the exact absolute target path of our compiled build binary in the workspace, it is terminated.
- **OS Mapping**: Detects hosting environment parameters (`platform.system()`) to assign OS-specific configurations:
  - Binary names: `plugxel-{arch}.exe` (Windows) vs `plugxel-{arch}` (Linux).
  - Release directories: `plug.cross/release/{arch}` on Windows and `plug.cross/release/x86_64` for Linux x64.
  - Path separator configurations.
- **Output**: Generates a unified `EnvContext` JSON object containing all pathing and platform context, which is forwarded to subsequent test scripts.

---

## 3. Subsystem Breakdown & Implementation Specs

### 3.1 Unified Test Orchestrator (`tests/run.py`)
- **CI vs Local execution modes**:
  - **Local Mode (interactive)**: If the compiled host binary is missing, prompts `Build now? [y/N]`.
  - **CI Mode (non-interactive, via `--ci` or `CI=true`)**: Automatically triggers compilation steps and fails immediately with log details if compilation fails.
- **Indirect Dependency Cache Tracking**: Compares the modification times (`mtime`) of not only the `.rs` source files of mock plugins, but also all associated dependencies:
  - `Cargo.toml` and `Cargo.lock` in the plugin directory.
  - Manifest configurations (`plugin.toml`) located in `fixtures/manifests/`.
  - Rebuilds the plugins if any of these direct or indirect configuration files have changed.
- **Parallelization & Merge**:
  - Parallelizes C++ and Rust unit test runs.
  - Output results are compiled into separate files (`results-rust.xml`, `results-cpp.xml`) to prevent write collisions.
  - The orchestrator parses and merges these intermediate results along with integration and E2E results into the final `tests/.artifacts/results.xml` (JUnit format).
- **Global Timeouts**: Sets a strict 10-minute timeout for the entire execution to prevent CI pipelines hanging indefinitely due to deadlocks.

### 3.2 Fixture & Manifest Specifications (`tests/fixtures/`)
Manifest configurations (`plugin.toml`) define the permission scope of the WASM plugins:
- **`ok_plugin` Manifest**:
  ```toml
  [[plugin]]
  name = "ok_plugin"
  permissions = ["host_add_tab", "host_exec"]
  ```
- **`rogue_plugin` Manifest (Load-time)**:
  ```toml
  [[plugin]]
  name = "rogue_plugin"
  permissions = [] # Missing required imports declarations, fails load-time validation
  ```

WASM files check:
- **`ok_plugin.rs`**: Baseline plugin using permitted FFI calls. Verifies normal operations and prevents false-positive test results.
- **`rogue_plugin.rs`** (Load-time check): A plugin containing host imports not declared in its `plugin.toml` manifest permissions (e.g. `host_add_tab`, `get_env`, `net_post`). Verifies that the Wasmer runtime successfully rejects module initialization.
- **`rogue_plugin_runtime.rs`** (Runtime check): A plugin with valid import declarations that calls `host_exec` with arguments exceeding its permission scope (or attempts prohibited actions). Verifies that the runtime correctly catches and traps the thread during runtime execution.

### 3.3 Unit Tests (`tests/unit/`)
- **`rust_core/`**: Executes `cargo test` and parses the output format (using `--format json` or stdout parsing) to translate unit test status into the unified JUnit report.
- **`cpp_ui/`**: Headless runner compiling C++ files (e.g. testing text wrapping, selections, caret limits) without creating window frames. Implements a lightweight `assert` helper that logs status directly to stdout (`[PASS] test_case` / `[FAIL] test_case`), which the Python orchestrator parses to build its JUnit report.

### 3.4 Integration Tests (`tests/integration/`)
- **`test_ffi_boundary.py`**:
  - Tests multi-byte UTF-8 character marshalling across the C++/Rust boundaries.
  - Asserts safe handling of double-free and use-after-free scenarios on cleanup.
  - Asserts that null pointers and empty buffers do not crash host routing.
- **`test_sandbox_rules.py`**:
  - `ok_plugin baseline check` (positive baseline verification).
  - `rogue_plugin load-time imports rejection check` (rejects unauthorized imports at compile/link).
  - `rogue_plugin_runtime sandbox trap check` (runtime execution containment).
  - `ok_plugin integrity mismatch check` (tampered WASM with stale `.integrity` sidecar is blocked).
  - `Global migration and post-migration bypass checks` (**Plan Cases A & B**: one-time global migration backfill validation and post-migration missing sidecar blocking).
  - `Trusted plugin bypass integrity file check`
  - `Tampered trusted plugin block check`

### 3.5 End-to-End Tests (`tests/e2e/`)
- **`test_cli_lifecycle.py`**: Spawns the production compiled `plugxel` executable under test scenarios using `subprocess.Popen` with `HIDE_CONSOLE=ON` (the standard production build configuration to ensure we test the identical binary shipped).
- **Console Redirection Prevention**: To prevent visual console windows flashing and cướp focus during E2E checks, Windows runs will launch Popen with the `subprocess.CREATE_NO_WINDOW` creation flag. Standard pipes redirection operates normally.
- **Deadlock Avoidance**:
  - Forces `encoding='utf-8'` and `text=True` on process pipes to avoid encoding mismatches.
  - Implements thread-based non-blocking readers. Standard output streams are read in separate threads and pushed to queues to prevent pipe blockages.
  - Applies a strict 5-second timeout per command sequence.
  - Ensures clean teardown in `finally` blocks, using `proc.terminate()`, awaiting process exits, and falling back to `proc.kill()` if necessary to avoid orphaned background processes.

---

## 4. CI Workflow Integration
- **Matrix configurations**: Configures builds on `ubuntu-latest` and `windows-latest` runners to verify cross-platform compiler and path operations.
- **Toolchain Cache**: Caches the cargo registry and WASM compiler targets to speed up workflow execution.
- **JUnit Reporter**: Publishes `results.xml` results using a standard reporter action to show failing test details in PR comments.
