import subprocess
import sys
from pathlib import Path

def main():
    project_root = Path(__file__).parent.parent.parent.parent.resolve()
    rust_dir = project_root / "plug.app" / "rt"
    
    print("[RUST UNIT] Running Cargo tests...")
    res = subprocess.run(["cargo", "test"], cwd=str(rust_dir))
    sys.exit(res.returncode)

if __name__ == "__main__":
    main()
