import os
import sys
import shutil
import platform
import subprocess
import json
import hashlib
import time
from pathlib import Path

def setup_plugin_sandbox(plugin_name: str, src_wasm: Path, src_toml: Path, dest_dir: Path):
    dest_dir.mkdir(parents=True, exist_ok=True)
    hash_val = f"test_{plugin_name}_hash"
    hash_file = dest_dir / f"{plugin_name}.hash"
    wasm_file = dest_dir / f"{plugin_name}.{hash_val}"
    toml_file = dest_dir / f"{plugin_name}.toml"
    integrity_file = dest_dir / f"{plugin_name}.integrity"

    with open(hash_file, "w", encoding="utf-8") as f:
        f.write(hash_val)

    shutil.copy2(src_wasm, wasm_file)
    if src_toml.resolve() != toml_file.resolve():
        shutil.copy2(src_toml, toml_file)

    wasm_bytes = wasm_file.read_bytes()
    sha = hashlib.sha256(wasm_bytes).hexdigest()
    with open(integrity_file, "w", encoding="utf-8") as f:
        f.write(sha)

def run_plugin(target_bin: str, plugin_name: str, startupinfo, creationflags, timeout=10):
    proc = subprocess.Popen(
        [target_bin],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        startupinfo=startupinfo,
        creationflags=creationflags,
        env={**os.environ, "PLUGXEL_HEADLESS": "1", "PLUG_HEADLESS": "1"}
    )
    time.sleep(0.5)
    proc.stdin.write(f"{plugin_name}\n")
    proc.stdin.flush()
    time.sleep(1.0)
    proc.stdin.write("/e\n")
    proc.stdin.flush()
    stdout, stderr = proc.communicate(timeout=timeout)
    return proc.returncode, stdout, stderr

def create_outside_link(target_dir: Path, link_path: Path):
    """Create directory junction on Windows or symlink on Linux pointing outside."""
    if link_path.exists() or os.path.lexists(str(link_path)):
        try:
            os.rmdir(str(link_path))
        except Exception:
            try:
                os.unlink(str(link_path))
            except Exception:
                shutil.rmtree(link_path, ignore_errors=True)
    if platform.system() == "Windows":
        try:
            import _winapi
            _winapi.CreateJunction(str(target_dir), str(link_path))
            return True
        except Exception as e:
            print(f"[WARN] Failed to create junction: {e}")
            return False
    else:
        try:
            os.symlink(str(target_dir), str(link_path))
            return True
        except Exception as e:
            print(f"[WARN] Failed to create symlink: {e}")
            return False

def main():
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except AttributeError:
        pass

    print("[SCOPED_FS] Running Scoped Filesystem Security Contract tests...")

    env_ctx = {}
    if "ENV_CONTEXT" in os.environ:
        try:
            env_ctx = json.loads(os.environ["ENV_CONTEXT"])
        except Exception:
            pass

    project_root = Path(__file__).parent.parent.parent.resolve()
    target_bin = env_ctx.get("target_bin")

    if not target_bin or not Path(target_bin).exists():
        system = platform.system()
        arch = "x64"
        if system == "Windows":
            target_bin = str(project_root / "plug.cross" / "release" / arch / f"plugxel-test-{arch}.exe")
        else:
            target_bin = str(project_root / "plug.cross" / "release" / "x86_64" / f"plugxel-test-{arch}")

    if not Path(target_bin).exists():
        print(f"[FAIL] Target test binary not found: {target_bin}")
        sys.exit(1)

    fixtures_build = project_root / "tests" / "fixtures" / "build"
    manifests_dir = project_root / "tests" / "fixtures" / "manifests"

    system = platform.system()
    if system == "Windows":
        sys_drive = os.environ.get("SystemDrive", "C:")
        if not sys_drive.endswith("\\"):
            sys_drive += "\\"
        plug_root = Path(sys_drive) / ".plugxel"
    else:
        plug_root = Path.home() / ".plugxel"

    plug_dir = plug_root / "plugins"
    plug_data_dir = plug_root / "data"

    # Backup existing plugin folder
    backup_dir = plug_root / "plugins_backup"
    if plug_dir.exists():
        if backup_dir.exists():
            shutil.rmtree(backup_dir)
        shutil.move(plug_dir, backup_dir)
    plug_dir.mkdir(parents=True, exist_ok=True)

    startupinfo = None
    creationflags = 0
    if system == "Windows":
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE
        creationflags = subprocess.CREATE_NO_WINDOW

    failed = False

    try:
        # -------------------------------------------------------------
        # Test Case 1: Preopen Identity & Capability Operations (ALLOW)
        # -------------------------------------------------------------
        print("\n[SCOPED_FS] Test Case 1: Capability identity (/data) and valid CRUD inside scope...")
        shutil.rmtree(plug_dir, ignore_errors=True)
        plug_dir.mkdir(parents=True, exist_ok=True)

        setup_plugin_sandbox(
            "fs_scoped_ok_plugin",
            fixtures_build / "fs_scoped_ok_plugin.wasm",
            manifests_dir / "fs_scoped_ok_plugin.toml",
            plug_dir
        )

        code, stdout, stderr = run_plugin(target_bin, "fs_scoped_ok_plugin", startupinfo, creationflags)
        if "SCOPED_OK: PASS" in stdout:
            print("[PASS] Scoped filesystem preopen identity (/data) and CRUD operations verified successfully.")
        else:
            print("[FAIL] Scoped filesystem valid operations failed!")
            print(f"Stdout:\n{stdout}\nStderr:\n{stderr}")
            failed = True

        plugin_scoped_dir = plug_data_dir / "test_fs_scoped_ok_plugin_hash"
        ok_file = plugin_scoped_dir / "ok.txt"
        if not ok_file.exists():
            print(f"[FAIL] Host scoped file not found at: {ok_file}")
            failed = True
        else:
            content = ok_file.read_bytes()
            if content != b"scoped_payload_data":
                print(f"[FAIL] Host scoped file content mismatch: {content}")
                failed = True
            else:
                print(f"[PASS] Host scoped file confirmed at: {ok_file}")

        # -------------------------------------------------------------
        # Test Case 2: Adversarial Escapes & Host Symlink Escape (DENY)
        # -------------------------------------------------------------
        print("\n[SCOPED_FS] Test Case 2: Path traversal and host symlink escape rejection...")
        shutil.rmtree(plug_dir, ignore_errors=True)
        plug_dir.mkdir(parents=True, exist_ok=True)

        # Create host secret outside sandbox
        host_secret_dir = plug_root / "host_secrets"
        host_secret_dir.mkdir(parents=True, exist_ok=True)
        host_secret_file = host_secret_dir / "host_secret.txt"
        host_secret_file.write_text("HOST_SUPER_SECRET_TOKEN", encoding="utf-8")

        # Prepare plugin data directory and link to outside secret
        escape_plugin_data = plug_data_dir / "test_fs_scoped_escape_plugin_hash"
        escape_plugin_data.mkdir(parents=True, exist_ok=True)
        link_path = escape_plugin_data / "link_outside"
        has_outside_link = create_outside_link(host_secret_dir, link_path)

        setup_plugin_sandbox(
            "fs_scoped_escape_plugin",
            fixtures_build / "fs_scoped_escape_plugin.wasm",
            manifests_dir / "fs_scoped_escape_plugin.toml",
            plug_dir
        )

        code, stdout, stderr = run_plugin(target_bin, "fs_scoped_escape_plugin", startupinfo, creationflags)
        if "BREACH" in stdout:
            print("[FAIL] Escape breach occurred!")
            print(f"Stdout:\n{stdout}\nStderr:\n{stderr}")
            failed = True
        elif "SCOPED_ESCAPE: ALL_BLOCKED" in stdout:
            print("[PASS] Path traversal and symlink/junction escape correctly denied.")
        else:
            print("[FAIL] Expected SCOPED_ESCAPE: ALL_BLOCKED not found in stdout!")
            print(f"Stdout:\n{stdout}\nStderr:\n{stderr}")
            failed = True

        # Gate 5: Verify host secret file integrity was never compromised or deleted
        if not host_secret_file.exists():
            print("[FAIL] Host secret file was deleted during adversarial open!")
            failed = True
        elif host_secret_file.read_text(encoding="utf-8") != "HOST_SUPER_SECRET_TOKEN":
            print("[FAIL] Host secret file was modified or truncated during adversarial open!")
            failed = True
        else:
            print("[PASS] Host secret file integrity strictly preserved (content and existence intact).")

        # Clean up host secret dir
        shutil.rmtree(host_secret_dir, ignore_errors=True)

        # -------------------------------------------------------------
        # Test Case 3: Missing Permission Zero Preopens (RUNTIME GATE)
        # -------------------------------------------------------------
        print("\n[SCOPED_FS] Test Case 3: Missing fs_scoped permission yields zero preopen capabilities...")
        shutil.rmtree(plug_dir, ignore_errors=True)
        plug_dir.mkdir(parents=True, exist_ok=True)

        setup_plugin_sandbox(
            "fs_scoped_no_perm_plugin",
            fixtures_build / "fs_scoped_no_perm_plugin.wasm",
            manifests_dir / "fs_scoped_no_perm_plugin.toml",
            plug_dir
        )

        code, stdout, stderr = run_plugin(target_bin, "fs_scoped_no_perm_plugin", startupinfo, creationflags)
        if "PREOPEN_LEAKED" in stdout:
            print("[FAIL] Preopen capability leaked to plugin without fs_scoped permission!")
            print(f"Stdout:\n{stdout}\nStderr:\n{stderr}")
            failed = True
        elif "SCOPED_NO_PERM: ZERO_PREOPENS" in stdout:
            print("[PASS] Plugin without fs_scoped permission granted exactly zero preopen capabilities.")
        else:
            print("[FAIL] Expected SCOPED_NO_PERM: ZERO_PREOPENS not found in stdout!")
            print(f"Stdout:\n{stdout}\nStderr:\n{stderr}")
            failed = True

        # -------------------------------------------------------------
        # Test Case 4: Unauthorized WASI Import Rejected (LOAD-TIME GATE)
        # -------------------------------------------------------------
        print("\n[SCOPED_FS] Test Case 4: Unauthorized WASI import rejected at load time...")
        shutil.rmtree(plug_dir, ignore_errors=True)
        plug_dir.mkdir(parents=True, exist_ok=True)

        setup_plugin_sandbox(
            "fs_scoped_unauthorized_import_plugin",
            fixtures_build / "fs_scoped_unauthorized_import_plugin.wasm",
            manifests_dir / "fs_scoped_unauthorized_import_plugin.toml",
            plug_dir
        )

        code, stdout, stderr = run_plugin(target_bin, "fs_scoped_unauthorized_import_plugin", startupinfo, creationflags)
        if "Unauthorized WASI import: path_open" in stderr or "Unauthorized WASI import: path_open" in stdout:
            print("[PASS] Unauthorized WASI import path_open rejected at load-time successfully.")
        else:
            print("[FAIL] Unauthorized WASI import was not rejected at load-time!")
            print(f"Stdout:\n{stdout}\nStderr:\n{stderr}")
            failed = True

        # -------------------------------------------------------------
        # Test Case 5: Cross-Plugin Isolation & Sibling Traversal (DENY)
        # -------------------------------------------------------------
        print("\n[SCOPED_FS] Test Case 5: Cross-plugin isolation and adversarial sibling escape...")
        shutil.rmtree(plug_dir, ignore_errors=True)
        plug_dir.mkdir(parents=True, exist_ok=True)

        setup_plugin_sandbox(
            "fs_isolated_a",
            fixtures_build / "fs_isolated_a.wasm",
            manifests_dir / "fs_isolated_a.toml",
            plug_dir
        )
        setup_plugin_sandbox(
            "fs_isolated_b",
            fixtures_build / "fs_isolated_b.wasm",
            manifests_dir / "fs_isolated_b.toml",
            plug_dir
        )

        code_a, stdout_a, stderr_a = run_plugin(target_bin, "fs_isolated_a", startupinfo, creationflags)
        if "ISOLATED_A: WROTE_SECRET" not in stdout_a:
            print("[FAIL] Plugin A failed to write secret!")
            print(f"Stdout:\n{stdout_a}\nStderr:\n{stderr_a}")
            failed = True
        else:
            print("[PASS] Plugin A successfully created scoped secret.")

        code_b, stdout_b, stderr_b = run_plugin(target_bin, "fs_isolated_b", startupinfo, creationflags)
        if "BREACH" in stdout_b:
            print("[FAIL] Isolation breach! Plugin B was able to access Plugin A file or sibling path!")
            print(f"Stdout:\n{stdout_b}\nStderr:\n{stderr_b}")
            failed = True
        elif "ISOLATED_B: ISOLATION_VERIFIED" in stdout_b:
            print("[PASS] Sibling traversal and cross-plugin access denied — isolation verified.")
        else:
            print("[FAIL] Expected ISOLATED_B: ISOLATION_VERIFIED not found in stdout!")
            print(f"Stdout:\n{stdout_b}\nStderr:\n{stderr_b}")
            failed = True

        # Verify host paths are opaque and separate
        dir_a = plug_data_dir / "test_fs_isolated_a_hash"
        dir_b = plug_data_dir / "test_fs_isolated_b_hash"
        if not (dir_a / "secret.txt").exists():
            print(f"[FAIL] Plugin A file missing at {dir_a / 'secret.txt'}")
            failed = True
        if (dir_b / "secret.txt").exists():
            print(f"[FAIL] Plugin A file leaked into Plugin B directory: {dir_b / 'secret.txt'}")
            failed = True
        if not (dir_b / "secret_b.txt").exists():
            print(f"[FAIL] Plugin B file missing at {dir_b / 'secret_b.txt'}")
            failed = True

    finally:
        # Restore backup
        if plug_dir.exists():
            shutil.rmtree(plug_dir, ignore_errors=True)
        if backup_dir.exists():
            shutil.move(backup_dir, plug_dir)

    if failed:
        print("\n[SCOPED_FS] FAILED — One or more security contract tests failed.")
        sys.exit(1)
    else:
        print("\n[SCOPED_FS] SUCCESS — All Scoped Filesystem Security Contract tests passed.")
        sys.exit(0)

if __name__ == "__main__":
    main()
