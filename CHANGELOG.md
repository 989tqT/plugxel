# Changelog

---

## [Unreleased]

### Added

- Added an experimental P1.5 Linux filesystem-containment spike using `openat2()` with `RESOLVE_BENEATH`, `RESOLVE_NO_MAGICLINKS`, and `RESOLVE_NO_SYMLINKS`; directory mutations use safely opened parent descriptors with single-component `mkdirat()` and `unlinkat()`. The spike remains isolated from the production runtime.
- Added a reproducible standalone Linux containment runner and acceptance tests covering scoped access, traversal and symlink rejection, pinned-parent mutations, outside-sentinel integrity, concurrent namespace mutation, retry exhaustion, and fail-closed behavior when `openat2` is unavailable.
- Added an experimental P1.5 Windows filesystem-containment feasibility spike using native `NtCreateFile` with parent `RootDirectory` handle walking, single-component lexical validation, `FILE_OPEN_REPARSE_POINT` junction rejection, fail-closed hard-link policy (`NumberOfLinks > 1`), deterministic truncate positioning, and handle-directed atomic deletions via `SetFileInformationByHandle`. The spike remains isolated from the production runtime.
- Implemented native per-directory case-sensitivity gating in the isolated Windows containment spike via `NtQueryInformationFile` with `FileCaseSensitiveInformation` (class 71, flag `0x00000001`). Enforced pre-open parent inspection before resolving each child, strict fail-closed policy (`WASI_ENOTCAPABLE = 76`) on query failures or case-sensitive directories, directory-boundary-aware exact ordinal canonical comparison, and zero mutation side-effects across real NTFS fixtures.
- Prototyped experimental per-file exclusive truncate/write synchronization (`FileLockTable`) in the isolated Windows containment spike (`windows.rs`), keyed by verified NTFS file identity `(VolumeSerialNumber, FileIndexHigh, FileIndexLow)` with two-level locking, unwind-safe RAII lock-entry cleanup (`LockEntryReleaseGuard`), `SetFileInformationByHandle(FileEndOfFileInfo)` (`EndOfFile = 0`) truncation, and native descriptor file-pointer preservation. Added two-handle NTFS concurrency, lock-lifecycle, and `catch_unwind` recovery tests; the production runtime (`plugin_mgr.rs`) remains untouched and the production concurrency acceptance gate remains open.

### Fixed

- Corrected WASI Preview 1 errno constants and Linux-to-WASI error mappings, including `EIO = 29` and `EISDIR = 31`.
- Added deterministic regression tests for `EAGAIN` retry exhaustion (one initial attempt plus three retries) and `ENOSYS` fail-closed behavior.

---

## [0.1.2a] - 2026-10-08

### Fixed
* Compiler error in `main_w.cpp`: resolved duplicate switch case value `32778` (`WM_APP + 10` and `WM_APP_REQUEST_CLOSE`) by consolidating window close requests into a single canonical `WM_APP_REQUEST_CLOSE` handler.
* Headless stdin worker exit deadlock: replaced blocking `fclose(stdin); thread.join();` in `main_w.cpp` and `main_l.cpp` cleanup routines with `g_headless_stdin_thread.detach()`, eliminating application freezes on shutdown when stdin is held open by external parent processes.
* Headless stdin EOF termination: updated `headless_stdin_worker` in `main_w.cpp` and `main_l.cpp` to explicitly dispatch close requests (`WM_APP_REQUEST_CLOSE` via `PostMessageW` on Windows, `main_l_request_close()` on Linux) when stdin reaches EOF, preventing headless processes from hanging indefinitely in UI message loops.
* Test suite manifest format & trusted binary selection (`test_sandbox_rules.py`): updated Test Case 6 to select canonical `pTerm` WASM matching compile-time trust hash (`9ada6ad...`) and corrected unified manifest `plugin.toml` format to array-of-tables `[[plugin]]`.

---

## [0.1.2a] - 2026-07-13

### Security
* Registry downloads now enforce HTTPS (prevents MITM on plugin/registry transport)
* Plugin permissions are now cryptographically pinned to the registry at install-time and re-verified at every load, preventing local manifest tampering from silently escalating a plugin's capabilities
* Fixed TOCTOU race in atomic file writes on cross-device filesystems (fail-closed instead of non-atomic copy fallback)
* Removed unauthorized shell interpreter (`dash`) from the untrusted plugin execution allowlist
* Registry trust validation check by trimming whitespace inside compile-time `TRUSTED_PLUGIN_HASHES` array comparisons

### Added
* Headless GTK stdin loop on Linux (`main_l.cpp`) enabling CI integration and E2E testing without a display server.
* Shared WASM compilation module `tests/build_utils.py` to enforce `--allow-undefined` linker flags globally across all plugin builds.
* Automated target binary copying and caching for Linux production builds.
* Custom structured issue templates (Bug Report, Feature Request, Plugin Submission) and a Pull Request template in `.github/`.
* Platform-agnostic OS detection FFI `host_get_platform` returning compile-time host platform evaluation (0 for Windows, 1 for Linux) to eliminate brittle environment variable parsing.
* Linux shell executor backend (`sh.rs`) executing `/bin/sh -c` queries for the `pTerm` plugin.
* Shell blacklisting security reinforcement: added `dash` shell to the banned executable list in the sandbox to block unauthorized access by untrusted plugins.
* Shared `get_plugins_dir()` utility in `utils.rs` for consistent cross-platform plugin storage path resolution (`$HOME/.plugxel/plugins` on Linux, `%SystemDrive%\.plugxel\plugins` on Windows).
* Permission gates for `get_env` and `net_post` WASM host imports — load-time import validation and runtime call-time enforcement against `plugin.toml` declarations.

### Fixed
* Linux CI cross-compilation failure (`x86_64-pc-windows-gnu` target) — removed orphaned `.cargo/config.toml` that forced incorrect target resolution on Linux runners.
* Stale host binary cache build errors: old binaries are unlinked when `pterm_hash.txt` has changed.
* Registry trust validation check by trimming whitespace inside compile-time `TRUSTED_PLUGIN_HASHES` array comparisons.
* Error reporting inside `verify_production_binary_clean` to distinguish missing binaries from forbidden-symbol leaks.
* Unused Windows-only `CommandExt` import in `plugin_mgr.rs` correctly scoped under `#[cfg(windows)]` to prevent cross-platform compiler warnings.
* Removed unsafe dynamic code evaluation in plugin initialization
* Fixed Linux CI build errors caused by MSVC-specific `/DELAYLOAD` pragmas in linker commands.
* Linux production linker `undefined reference to 'g_headless_mode'` — guarded `extern "C"` declaration in `main_l.cpp` under `#ifdef PLUG_ENABLE_HEADLESS_MODE`; production builds now use `static constexpr bool g_headless_mode = false` with zero runtime cost.
* GCC `-Wextern-initializer` warning in `main.cpp` — changed `extern "C" bool g_headless_mode = false` to block-form `extern "C" { bool g_headless_mode = false; }`.
* Process hang on `/e` exit in headless mode — `g_cmd_thread` was blocking indefinitely on `g_cmd_cv.wait()`; `main_l_cleanup()` now sets `g_cmd_thread_running = false`, notifies the CV, and joins the thread before returning so the process exits cleanly within the test timeout window.
* Headless CI broken pipe (`test_cli_lifecycle`) — moved `g_cmd_thread` and `g_headless_stdin_thread` startup from `on_tick()` frame-clock callback to `on_activate()` so stdin reader is live before any test data arrives; frame-clock callbacks are not guaranteed to fire before GApplication idle-hold expires under `xvfb-run`.
* Linux `test_sandbox_rules` 120s timeout — plugin directory was hardcoded to `C:\.plugxel\plugins` (Windows-only); corrected to `$HOME/.plugxel/plugins` matching `proc.rs` `c_init()` runtime logic.
* FFI Windows-centric symbol leakage — renamed `main_w_add_tab` to platform-neutral `host_add_tab` across `plugin_mgr.rs`, pTerm manifests, source plugin files, and test mocks (`ok_plugin.rs`, `rogue_plugin.rs`, `rogue_plugin_runtime.rs`) to prevent load-time link failures.
* `pTerm` Linux shell execution compatibility — resolved execution errors on Linux hosts by adding `/sh` routing to the command parser, introducing the Linux shell backend, defaulting shell mode dynamically on Unix targets, and mapping E2E test assertions to platform-specific outputs.
* Linux plugin install/delete path mismatch — `/plug` and `/plug-` handlers in `c_plug/mod.rs` and `c_plug/del/mod.rs` were hardcoded to `%SystemDrive%\.plugxel\plugins` (Windows-only); aligned with `c_init()` using shared `get_plugins_dir()` so Linux installs to `$HOME/.plugxel/plugins`.
* Plugin dispatch race condition — `dispatch_plugin_cmd()` no longer removes the plugin instance from the in-memory registry during async execution; per-plugin execution locks serialize concurrent invocations instead.
* README and startup banner exit command typo — corrected `/e-` references to `/e` in `main.cpp` and `main_l.cpp`.
* FFI input sanitization — `c_parse()` routes command arguments through `to_c_string()` to strip embedded null bytes before CString conversion.
* Tab-close deadlock: resolved application hang ("not responding") when closing tabs by releasing `g_mutex` before executing `c_on_tab_close` FFI call. This prevents recursive lock acquisition on non-recursive C++ `std::mutex` from re-entrant calls (`get_tab_owner` / `print_info`) originating from Rust runtime.
* Linux compilation: resolved `conflicting declaration of print_info_idle with C linkage` linkage conflict by scoping GTK static C++ callbacks outside of `extern "C"` blocks in `main_l.cpp`.
* Integration testing registry lockup: updated regex pattern to match 20-character session hashes in `test_sandbox_rules.py`, preventing infinite read blocking on `p.stdout.readline()`.
* Local registry HTTP downloads: added loopback exceptions (allowing `127.0.0.1`, `::1`, `localhost`) to `enforce_https` and `verify_registry_signature` checks inside `check/mod.rs` and `progress.rs` to allow testing E2E registry downloads without local HTTPS configuration or signature keys.
* Mock manifests: synchronized `pTerm` mock manifests in `test_sandbox_rules.py` to request the required `host_get_platform` permission, matching production FFI requirements.

---

## [0.1.1a] - 2026-07-05

### Added
* End-to-end interactive mock HTTP server registry download tests (Test Case 8, 9, and 10) in `test_sandbox_rules.py`.

### Fixed
* MSVC Windows entrypoint linker failures (`WinMain` unresolved) in `CMakeLists.txt` using `/ENTRY:mainCRTStartup`.
* Linux CI Rust library detection failures by introducing auto-scanning inside the orchestrator.
* GHA Windows runners multi-line backslash parsing errors.
* GHA `cargo-audit` workflow check permissions and updated deprecated Node configurations.

---

## [0.1.0a] - 2026-07-04

### Added
* **Native/FFI Interface**: C++ application shell linked to a Rust runtime staticlib (`tm_main`).
* **WASM Plugin Runtime**: Built-in integration with the Wasmer 4.3 runtime using the Cranelift compiler.
* **Multitab Layout Subsystem**: High-fidelity terminal emulator window manager supporting multiple tab contexts, carets, scrollbars, text highlighting, clipboard manipulation, and custom hover transitions.
* **Unified Plugins Manifest**: Added `plugin.toml` tracking configurations, authors, and security permissions.
* **`pTerm` Plugin**: Compiled terminal tool supporting shell delegation (CMD and PowerShell) inside sandboxed tabs.
* **CLI Commands Support**: Added command parser supporting `/a`, `/?`, `/e`, `/tab`, `/plug*`, `/plug`, and `/plug-`.
* **CI/CD Workflows**: Added test runners, document formatting validators, and release builder templates.
* **Comprehensive Docs Suite**: Added Architecture, Build, and Plugin Development specifications.
