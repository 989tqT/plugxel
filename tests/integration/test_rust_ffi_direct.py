import os
import sys
import subprocess
from pathlib import Path

def main():
    print("[INTEGRATION] Running direct Rust FFI integration tests via cargo test...")
    project_root = Path(__file__).parent.parent.parent.resolve()
    rt_dir = project_root / "plug.app" / "rt"
    
    try:
        # run cargo test for integration_tests
        res = subprocess.run(
            ["cargo", "test", "--test", "integration_tests"],
            cwd=str(rt_dir),
            capture_output=True,
            text=True
        )
        print(res.stdout)
        if res.returncode != 0:
            print(f"[FAIL] Rust FFI direct integration tests failed. Stderr:\n{res.stderr}")
            sys.exit(res.returncode)
        else:
            print("[PASS] Rust FFI direct integration tests passed successfully.")
            sys.exit(0)
    except Exception as e:
        print(f"[FAIL] Failed to execute cargo test: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
