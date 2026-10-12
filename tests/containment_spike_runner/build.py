#!/usr/bin/env python3
# build script for linux containment spike runner
# compile standalone runner targeting x86_64 unknown linux musl

import os
import sys
import platform
import subprocess
from pathlib import Path

def build():
    script_dir = Path(__file__).resolve().parent
    cargo_toml = script_dir / "Cargo.toml"

    print("[BUILD] building containment_spike_runner...")

    env = os.environ.copy()
    if platform.system() == "Windows":
        # cross compile for musl using clang and lld
        env["CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER"] = "clang"
        env["CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS"] = "-C link-arg=-fuse-ld=lld -C link-arg=--target=x86_64-unknown-linux-musl"
        cmd = ["cargo", "build", "--manifest-path", str(cargo_toml), "--target", "x86_64-unknown-linux-musl"]
    else:
        # native linux build
        cmd = ["cargo", "build", "--manifest-path", str(cargo_toml)]

    res = subprocess.run(cmd, env=env)
    if res.returncode != 0:
        print("[FAIL] failed to build containment_spike_runner")
        sys.exit(res.returncode)
    print("[SUCCESS] containment_spike_runner build complete")

if __name__ == "__main__":
    build()
