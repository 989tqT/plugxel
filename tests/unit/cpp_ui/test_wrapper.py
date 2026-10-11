import subprocess
import sys
import platform
import json
from pathlib import Path

def main():
    script_dir = Path(__file__).parent.resolve()
    build_dir = script_dir / "build"
    build_dir.mkdir(parents=True, exist_ok=True)
    
    # check env context
    env_ctx = {}
    if "ENV_CONTEXT" in os.environ:
        try:
            env_ctx = json.loads(os.environ["ENV_CONTEXT"])
        except Exception:
            pass
            
    system = env_ctx.get("os", platform.system())
    
    # configure and compile using cmake
    print("[CPP UNIT] Configuring CMake...")
    try:
        # use ninja if available, otherwise default generator
        generator_args = []
        if system == "Windows":
            # for windows, check if ninja is in tool path
            generator_args = ["-G", "Ninja"]
            
        subprocess.check_call(["cmake", "-S", str(script_dir), "-B", str(build_dir)] + generator_args, stdout=subprocess.DEVNULL)
        print("[CPP UNIT] Building test executable...")
        subprocess.check_call(["cmake", "--build", str(build_dir)], stdout=subprocess.DEVNULL)
    except Exception as e:
        print(f"[CPP UNIT-ERROR] Failed to compile C++ unit tests: {e}")
        sys.exit(1)
        
    # run compiled test binary
    binary_name = "test_runner.exe" if system == "Windows" else "test_runner"
    exe_path = build_dir / binary_name
    
    if not exe_path.exists():
        # check alternative release folders
        alt_paths = [build_dir / "Release" / binary_name, build_dir / "Debug" / binary_name]
        for alt in alt_paths:
            if alt.exists():
                exe_path = alt
                break
                
    if not exe_path.exists():
        print(f"[CPP UNIT-ERROR] Compiled executable not found at {exe_path}")
        sys.exit(1)
        
    print(f"[CPP UNIT] Running test binary: {exe_path.name}...")
    res = subprocess.run([str(exe_path)], capture_output=False)
    sys.exit(res.returncode)

if __name__ == "__main__":
    import os
    main()
