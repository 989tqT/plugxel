import os
import sys
import subprocess
import platform
import json
import time
from pathlib import Path

def main():
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except AttributeError:
        pass # ignore in older python versions where reconfigure is not available
        
    print("[INTEGRATION] Running FFI boundary tests...")
    
    # load environment context
    env_ctx = {}
    if "ENV_CONTEXT" in os.environ:
        try:
            env_ctx = json.loads(os.environ["ENV_CONTEXT"])
        except Exception:
            pass
            
    project_root = Path(__file__).parent.parent.parent.resolve()
    target_bin = env_ctx.get("target_bin")
    
    if not target_bin or not Path(target_bin).exists():
        # fallback: resolve binary name from toolchains.json active arch
        system = platform.system()
        tc_cfg = project_root / "plug.cross" / "windows" / "config" / "toolchains.json"
        arch = "x64"
        if tc_cfg.exists():
            try:
                import json as _json
                tc_data = _json.loads(tc_cfg.read_text(encoding="utf-8"))
                active_tc = tc_data.get("active_toolchain", "clang-x64")
                arch = tc_data["toolchains"][active_tc].get("arch", "x64")
            except Exception:
                pass
        binary_name = f"plugxel-{arch}.exe" if system == "Windows" else f"plugxel-{arch}"
        release_dir = project_root / "plug.cross" / "release" / (arch if system == "Windows" else ("x86_64" if arch == "x64" else arch))
        target_bin = str((release_dir / binary_name).resolve())
        
    if not Path(target_bin).exists():
        print(f"[INTEGRATION-ERROR] Compiled executable not found at: {target_bin}")
        sys.exit(1)

    failed = False
    
    # test case 1: multi-byte utf-8 boundary marshalling
    # launch process, pipe tab creation with unicode chars, exit, verify return code is 0
    print("[INTEGRATION] Test Case 1: Multi-byte UTF-8 inputs (/tab Chào thế giới)...")
    try:
        startupinfo = None
        if platform.system() == "Windows":
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            # using creation flag to prevent console window popup
            creationflags = subprocess.CREATE_NO_WINDOW
        else:
            creationflags = 0
            
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
        
        # write unicode string to create tab, then exit
        input_data = "/tab Chào thế giới\n/e\n"
        stdout, stderr = proc.communicate(input=input_data, timeout=10)
        
        if proc.returncode != 0:
            print(f"[FAIL] UTF-8 test failed. Exit code: {proc.returncode}")
            print(f"Stderr: {stderr}")
            failed = True
        else:
            print("[PASS] UTF-8 test passed successfully.")
            
    except Exception as e:
        print(f"[FAIL] UTF-8 test encountered error: {e}")
        failed = True

    # test case 2: null / empty input buffer handling
    print("[INTEGRATION] Test Case 2: Empty string input...")
    try:
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
        
        # write multiple empty lines and spaces, then exit
        input_data = "   \n\n  \n/e\n"
        stdout, stderr = proc.communicate(input=input_data, timeout=10)
        
        if proc.returncode != 0:
            print(f"[FAIL] Empty input test failed. Exit code: {proc.returncode}")
            failed = True
        else:
            print("[PASS] Empty input test passed successfully.")
            
    except Exception as e:
        print(f"[FAIL] Empty input test encountered error: {e}")
        failed = True

    sys.exit(1 if failed else 0)

if __name__ == "__main__":
    main()
