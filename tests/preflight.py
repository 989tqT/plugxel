import os
import sys
import subprocess
import platform
import json
import re
from pathlib import Path

# minimum required versions
MIN_CARGO_VERSION = "1.70.0"

def get_cargo_version():
    try:
        output = subprocess.check_output(["cargo", "--version"], text=True)
        match = re.search(r"cargo\s+(\d+\.\d+\.\d+)", output)
        if match:
            return match.group(1)
    except Exception:
        pass
    return None

def check_wasm_target():
    try:
        output = subprocess.check_output(["rustup", "target", "list", "--installed"], text=True)
        if "wasm32-unknown-unknown" in output:
            return True
        print("[PREFLIGHT] wasm32-unknown-unknown target not found. Attempting to install...")
        subprocess.check_call(["rustup", "target", "add", "wasm32-unknown-unknown"])
        return True
    except Exception as e:
        print(f"[PREFLIGHT-WARNING] Failed to verify/install wasm32 target: {e}")
        return False

def clean_orphans(target_bin_path: Path):
    system = platform.system()
    target_abs = str(target_bin_path.resolve()).replace("\\", "/").lower()
    
    if system == "Windows":
        # powershell script with try/catch to safely get path and pids
        ps_script = (
            "Get-Process -Name @('plug', 'plugxel') -ErrorAction SilentlyContinue | ForEach-Object { "
            "  try { "
            "    if ($_.Path) { $_.Path + '|' + $_.Id } "
            "  } catch {} "
            "}; exit 0"
        )
        try:
            output = subprocess.check_output(
                ["powershell", "-NoProfile", "-Command", ps_script],
                text=True,
                stderr=subprocess.DEVNULL
            )
            for line in output.splitlines():
                if "|" in line:
                    path_str, pid_str = line.split("|", 1)
                    path_str = path_str.strip().replace("\\", "/").lower()
                    if path_str == target_abs:
                        pid = int(pid_str.strip())
                        print(f"[PREFLIGHT] Terminating orphaned process {pid} ({path_str})")
                        subprocess.run(["taskkill", "/F", "/PID", str(pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            print(f"[PREFLIGHT-WARNING] Error querying Windows processes: {e}")
            
    elif system == "Linux":
        for pid_dir in Path("/proc").glob("[0-9]*"):
            try:
                exe_link = pid_dir / "exe"
                if exe_link.is_symlink():
                    exe_path = str(exe_link.resolve()).replace("\\", "/").lower()
                    if exe_path == target_abs:
                        pid = int(pid_dir.name)
                        print(f"[PREFLIGHT] Terminating orphaned process {pid} ({exe_path})")
                        os.kill(pid, 15) # sigterm
            except Exception:
                pass

def run_preflight(project_root: Path) -> dict:
    print("==================================================")
    print("Running Preflight Environment Validation...")
    print("==================================================")
    
    system = platform.system()

    # resolve binary name dynamically from toolchains.json active arch
    toolchains_cfg = project_root / "plug.cross" / "windows" / "config" / "toolchains.json"
    arch = "x64"  # safe default
    if toolchains_cfg.exists():
        try:
            with open(toolchains_cfg, "r", encoding="utf-8") as f:
                tc_data = json.load(f)
            active_tc = tc_data.get("active_toolchain", "clang-x64")
            arch = tc_data["toolchains"][active_tc].get("arch", "x64")
        except Exception as e:
            print(f"[PREFLIGHT-WARNING] Could not read toolchains.json: {e}. Defaulting arch=x64.")

    if system == "Windows":
        binary_name = f"plugxel-{arch}.exe"
        release_subdir = arch
    else:
        # linux uses arch from toolchains.json; map x64→x86_64 for directory convention
        dir_arch = "x86_64" if arch == "x64" else arch
        binary_name = f"plugxel-{arch}"
        release_subdir = dir_arch

    # resolve target build binary path in release directory
    release_dir = project_root / "plug.cross" / "release" / release_subdir
    target_bin = release_dir / binary_name

    
    # 1. clean orphans
    clean_orphans(target_bin)
    
    # 2. check cargo version
    cargo_ver = get_cargo_version()
    if not cargo_ver:
        print("[PREFLIGHT-ERROR] Cargo compiler is not installed or not in PATH.")
        sys.exit(1)
        
    print(f"[PREFLIGHT] Cargo version: {cargo_ver} (Min required: {MIN_CARGO_VERSION})")
    
    # 3. check wasm target
    check_wasm_target()
    
    # 4. generate environment context
    context = {
        "os": system,
        "binary_name": binary_name,
        "release_dir": str(release_dir.resolve()),
        "target_bin": str(target_bin.resolve()),
        "project_root": str(project_root.resolve()),
        "cargo_version": cargo_ver,
    }
    
    artifacts_dir = project_root / "tests" / ".artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    
    with open(artifacts_dir / "env_context.json", "w", encoding="utf-8") as f:
        json.dump(context, f, indent=2)
        
    print("[PREFLIGHT] Environment Context generated successfully.")
    print("==================================================\n")
    return context

if __name__ == "__main__":
    root = Path(__file__).parent.parent.resolve()
    run_preflight(root)
