import os
import sys
import subprocess
import platform
import json
import time
import queue
import threading
from pathlib import Path

def enqueue_output(out, q):
    try:
        for line in iter(out.readline, ''):
            q.put(line)
        out.close()
    except Exception:
        pass

def main():
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except AttributeError:
        pass
        
    print("[E2E] Running CLI Lifecycle E2E tests against headless production-grade target...")
    
    # 1. load env context
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
        binary_name = f"plugxel-test-{arch}.exe" if system == "Windows" else f"plugxel-test-{arch}"
        release_dir = project_root / "plug.cross" / "release" / (arch if system == "Windows" else ("x86_64" if arch == "x64" else arch))
        target_bin = str((release_dir / binary_name).resolve())
        
    if not Path(target_bin).exists():
        print(f"[E2E-ERROR] Compiled test executable not found at: {target_bin}")
        sys.exit(1)

    # spawn process with pipes and plug_headless=1 env variable set
    startupinfo = None
    if platform.system() == "Windows":
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        creationflags = subprocess.CREATE_NO_WINDOW
    else:
        creationflags = 0
        
    print(f"[E2E] Spawning: {target_bin}")
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
    
    # set up thread-safe queue readers
    stdout_queue = queue.Queue()
    stderr_queue = queue.Queue()
    
    t_out = threading.Thread(target=enqueue_output, args=(proc.stdout, stdout_queue), daemon=True)
    t_err = threading.Thread(target=enqueue_output, args=(proc.stderr, stderr_queue), daemon=True)
    
    t_out.start()
    t_err.start()
    
    failed = False
    
    try:
        # step 1: write about command /
        print("[E2E] Step 1: Sending about command /a...")
        proc.stdin.write("/a\n")
        proc.stdin.flush()
        time.sleep(0.5)
            
        # step 2: write tab command /tab
        print("[E2E] Step 2: Sending tab creation command (/tab)...")
        proc.stdin.write("/tab\n")
        proc.stdin.flush()
        time.sleep(0.5)
            
        # step 3: trigger thread-safe ui state dump
        print("[E2E] Step 3: Requesting thread-safe state dump via magic token...")
        proc.stdin.write("__dump_state__\n")
        proc.stdin.flush()
        time.sleep(1.0)
        
        # read stdout queue for output
        stdout_output = []
        while not stdout_queue.empty():
            stdout_output.append(stdout_queue.get_nowait())
        full_stdout = "".join(stdout_output)
        
        # extract json block between delimiters
        dump_start = "---STATE_DUMP_START---"
        dump_end = "---STATE_DUMP_END---"
        
        if dump_start in full_stdout and dump_end in full_stdout:
            try:
                json_part = full_stdout.split(dump_start)[1].split(dump_end)[0].strip()
                state = json.loads(json_part)
                print("[E2E] Dump State parsed successfully:")
                print(json.dumps(state, indent=2))
                
                # assertion
                # 1. we expect active tab index to be 1 since tab was created
                if state.get("active_tab") != 1:
                    print(f"[FAIL] Expected active_tab to be 1, got: {state.get('active_tab')}")
                    failed = True
                else:
                    print("[PASS] Active tab index matches expectation.")
                    
                # 2. we expect at least 2 tabs in list
                tabs = state.get("tabs", [])
                if len(tabs) < 2:
                    print(f"[FAIL] Expected at least 2 tabs, got: {len(tabs)}")
                    failed = True
                else:
                    print("[PASS] Tab list count matches expectation.")
            except Exception as ex:
                print(f"[FAIL] Failed to parse UI state JSON dump: {ex}")
                print(f"Stdout was:\n{full_stdout}")
                failed = True
        else:
            print("[FAIL] Magic state dump token did not return demarcated block!")
            print(f"Stdout was:\n{full_stdout}")
            failed = True
            
        # step 4: write exit command /e
        print("[E2E] Step 4: Sending exit command /e...")
        proc.stdin.write("/e\n")
        proc.stdin.flush()
        
        # wait for process exit
        proc.wait(timeout=5)
        
        if proc.returncode != 0:
            print(f"[FAIL] Process exited with non-zero exit code: {proc.returncode}")
            failed = True
        else:
            print("[PASS] Process exited cleanly.")
            
    except subprocess.TimeoutExpired:
        print("[FAIL] Process timed out during execution!")
        proc.kill()
        failed = True
    except Exception as e:
        print(f"[FAIL] Unexpected error: {e}")
        failed = True
        
    sys.exit(1 if failed else 0)

if __name__ == "__main__":
    main()
