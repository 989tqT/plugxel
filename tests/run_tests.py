import subprocess
import sys
from pathlib import Path

def run_tests():
    project_root = Path(__file__).parent.parent.resolve()
    rust_rt_dir = project_root / "plug.app" / "rt"

    print("==================================================")
    # 1. run cargo test
    print("Running Rust Runtime Unit Tests via Cargo...")
    print("Directory: ", rust_rt_dir)
    print("==================================================")
    
    try:
        result = subprocess.run(
            ["cargo", "test"],
            cwd=str(rust_rt_dir),
            capture_output=False,
            text=True
        )
        if result.returncode == 0:
            print("\n[SUCCESS] All Rust runtime unit tests passed successfully!")
            return True
        else:
            print(f"\n[FAILURE] Cargo test exited with non-zero code: {result.returncode}")
            return False
    except FileNotFoundError:
        print("\n[ERROR] 'cargo' executable not found in system PATH. Ensure Rust and Cargo are installed.")
        return False
    except Exception as e:
        print(f"\n[ERROR] Exception encountered during test execution: {e}")
        return False

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
