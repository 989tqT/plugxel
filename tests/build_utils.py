import subprocess
import sys
from pathlib import Path

def compile_wasm_plugin(src_file: Path, dest_wasm: Path) -> bool:
    """Compile a Rust source file into a WebAssembly plugin targeting wasm32-unknown-unknown with proper link args."""
    try:
        # we enforce standard optimization and allow-undefined link args to link ffi imports correctly
        cmd = [
            "rustc",
            "--target", "wasm32-unknown-unknown",
            "--crate-type", "cdylib",
            "-C", "opt-level=z",
            "-C", "lto=true",
            "-C", "link-arg=--allow-undefined",
            str(src_file),
            "-o", str(dest_wasm)
        ]
        
        # output compiling step
        print(f"[EXEC] {' '.join(cmd)}")
        subprocess.check_call(cmd)
        return True
    except Exception as e:
        print(f"[BUILD-ERROR] Failed to compile WASM plugin {src_file.name}: {e}")
        return False
