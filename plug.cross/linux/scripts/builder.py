import os
import sys
import json
import subprocess
import shutil

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CROSS_DIR = os.path.dirname(SCRIPT_DIR)
ROOT_DIR = os.path.dirname(os.path.dirname(CROSS_DIR))
RUST_APP_DIR = os.path.join(ROOT_DIR, "plug.app", "rt")

sys.path.append(os.path.join(ROOT_DIR, "tests"))
from build_utils import compile_wasm_plugin

def load_config():
    config_path = os.path.join(CROSS_DIR, "config", "toolchains.json")
    with open(config_path, "r") as f:
        return json.load(f)

def run_command(cmd, cwd, env=None):
    try:
        subprocess.run(cmd, cwd=cwd, env=env, check=True)
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Command failed with exit code {e.returncode}")
        sys.exit(1)

def build(toolchain_name=None, headless_test=False):
    import time
    start_time = time.time()
    config = load_config()

    if toolchain_name is None:
        toolchain_name = config.get("active_toolchain", "gcc-x64")

    toolchains = config.get("toolchains", {})
    if toolchain_name not in toolchains:
        print(f"[ERROR] Toolchain '{toolchain_name}' not found.")
        sys.exit(1)

    tc = toolchains[toolchain_name]
    tools = config.get("tools", {})
    build_options = config.get("build_options", {})

    if headless_test:
        build_options["headless_test"] = True

    arch = tc.get("arch", "x64")
    
    release_subdir = "x86_64" if arch == "x64" else arch
    release_dir = os.path.join(os.path.dirname(CROSS_DIR), "release", release_subdir)
    build_dir = os.path.join(CROSS_DIR, "build", toolchain_name)
    if os.path.exists(build_dir):
        shutil.rmtree(build_dir, ignore_errors=True)
    os.makedirs(release_dir, exist_ok=True)
    os.makedirs(build_dir, exist_ok=True)
    
    cargo_cmd = tools.get("cargo", "cargo")
    cmake_cmd_bin = tools.get("cmake", "cmake")
    ninja_cmd = tools.get("ninja", "ninja")
    upx_cmd = tools.get("upx", "upx")
    
    env = os.environ.copy()
    
    # add cargo bin path if missing
    cargo_home_bin = os.path.expanduser("~/.cargo/bin")
    if os.path.exists(cargo_home_bin) and cargo_home_bin not in env.get("PATH", ""):
        env["PATH"] = f"{cargo_home_bin}:{env.get('PATH', '')}"

    # set c and c++ compiler
    if tc.get("c_compiler"):
        resolved_cc = shutil.which(tc["c_compiler"], path=env.get("PATH"))
        if not resolved_cc:
            print(f"[ERROR] C compiler '{tc['c_compiler']}' is not found. Please install build-essential or gcc/clang.")
            sys.exit(1)
        env["CC"] = resolved_cc
        
        # force rust use selected linker
        rust_target_env = tc["rust_target"].upper().replace("-", "_")
        env[f"CARGO_TARGET_{rust_target_env}_LINKER"] = resolved_cc
        
    if tc.get("cxx_compiler"):
        resolved_cxx = shutil.which(tc["cxx_compiler"], path=env.get("PATH"))
        if not resolved_cxx:
            print(f"[ERROR] C++ compiler '{tc['cxx_compiler']}' is not found. Please install g++ or clang++.")
            sys.exit(1)
        env["CXX"] = resolved_cxx
    
    # resolve cargo path avoid filenotfounderror
    resolved_cargo = shutil.which(cargo_cmd, path=env.get("PATH"))
    if not resolved_cargo:
        print("[ERROR] 'cargo' is not found. Please install Rust (https://rustup.rs/)")
        sys.exit(1)

    print("\n[0] Building WASM Plugins...")
    plugins_dir = os.path.join(ROOT_DIR, "plugins")
    os.makedirs(plugins_dir, exist_ok=True)
    src_plugins_dir = os.path.join(RUST_APP_DIR, "src_plugins")
    rustc_exe = tools.get("rustc", "rustc")
    resolved_rustc = shutil.which(rustc_exe, path=env.get("PATH"))
    if resolved_rustc:
        import hashlib
        for root, dirs, files in os.walk(src_plugins_dir):
            for filename in files:
                if not filename.endswith(".rs") or filename.startswith("."):
                    continue

                name = os.path.splitext(filename)[0]
                hash_val = hashlib.md5(name.encode()).hexdigest()[:8]
                plugin_out_dir = os.path.join(plugins_dir, name)
                if os.path.exists(plugin_out_dir) and not os.path.isdir(plugin_out_dir):
                    os.remove(plugin_out_dir)
                os.makedirs(plugin_out_dir, exist_ok=True)
                out_wasm = os.path.join(plugin_out_dir, f"{name}.{hash_val}")
                out_hash = os.path.join(plugin_out_dir, f"{name}.hash")

                print(f"[WASM] Compiling {name}...")
                from pathlib import Path
                compile_wasm_plugin(Path(os.path.join(root, filename)), Path(out_wasm))
                
                with open(out_hash, "w") as hf:
                    hf.write(hash_val)

                if name == "pTerm":
                    with open(out_wasm, "rb") as wf:
                        wasm_bytes = wf.read()
                    pterm_sha = hashlib.sha256(wasm_bytes).hexdigest()
                    hash_file_path = os.path.join(RUST_APP_DIR, "pterm_hash.txt")
                    with open(hash_file_path, "w") as hf:
                        hf.write(pterm_sha)
                    print(f"[WASM] Updated pTerm hardcoded trust hash: {pterm_sha}")
        
        src_toml = os.path.join(src_plugins_dir, "plugin.toml")
        dst_toml = os.path.join(plugins_dir, "plugin.toml")
        if os.path.exists(src_toml):
            shutil.copy2(src_toml, dst_toml)

    print(f"\n[1] Building Rust Runtime ({toolchain_name})...")
    
    hash_file = os.path.join(RUST_APP_DIR, "pterm_hash.txt")
    if not os.path.exists(hash_file):
        print("[ERROR] pterm_hash.txt not found. Build WASM plugins first to generate the trust hash.")
        sys.exit(1)
        
    if os.path.getmtime(hash_file) < start_time - 2:
        print("[ERROR] pterm_hash.txt is stale (not rebuilt in this run). Force rebuilding plugins first.")
        sys.exit(1)

    rust_target = tc["rust_target"]
    run_command([resolved_cargo, "build", "--release", "--target", rust_target], cwd=RUST_APP_DIR, env=env)
    rust_lib_path = os.path.join(RUST_APP_DIR, "target", rust_target, "release", "libtm_main.a")
    
    print(f"\n[2] Configuring C/C++ Engine ({toolchain_name})...")
    
    # gtk4 need pkg-config resolve library path
    if not shutil.which("pkg-config", path=env.get("PATH")):
        print("[ERROR] 'pkg-config' is not found. Please install it (e.g. sudo apt install pkg-config libgtk-4-dev).")
        sys.exit(1)

    resolved_cmake = shutil.which(cmake_cmd_bin, path=env.get("PATH"))
    if not resolved_cmake:
        print("[ERROR] 'cmake' is not found. Please install CMake.")
        sys.exit(1)

    cmake_cmd = [
        resolved_cmake,
        "-G", "Ninja",
        f"-DRUST_LIB_PATH={rust_lib_path}",
        "-DCMAKE_BUILD_TYPE=Release"
    ]

    if tc.get("extra_flags"):
        cmake_cmd.append(f"-DCMAKE_C_FLAGS={tc['extra_flags']}")
        cmake_cmd.append(f"-DCMAKE_CXX_FLAGS={tc['extra_flags']}")

    if build_options.get("hide_console", False):
        # linux hide console need detached launch or stdout avoid
        pass

    if build_options.get("headless_test", False):
        cmake_cmd.extend(["-DPLUGXEL_ENABLE_HEADLESS_MODE=ON", "-DPLUG_ENABLE_HEADLESS_MODE=ON"])

    cmake_cmd.append(CROSS_DIR)
    run_command(cmake_cmd, cwd=build_dir, env=env)
    
    print(f"\n[3] Compiling Binary ({toolchain_name})...")
    resolved_ninja = shutil.which(ninja_cmd, path=env.get("PATH"))
    if not resolved_ninja:
        print("[ERROR] 'ninja' is not found. Please install Ninja build system.")
        sys.exit(1)
    run_command([resolved_ninja], cwd=build_dir, env=env)
    
    exe_name = "plugxel"
    exe_path = os.path.join(build_dir, exe_name)
    release_exe = os.path.join(release_dir, f"plugxel-{arch}")
    
    print("\n[4] Stripping debug symbols...")
    run_command(["strip", exe_path], cwd=build_dir)
    
    if build_options.get("upx_compress", False):
        print("\n[5] Compressing with UPX...")
        resolved_upx = shutil.which(upx_cmd, path=env.get("PATH"))
        if resolved_upx:
            upx_level = build_options.get("upx_level", "--best").split()
            run_command([resolved_upx] + upx_level + [exe_path], cwd=build_dir)
        else:
            print("[WARNING] UPX not found. Skipping compression.")
        
    shutil.copy(exe_path, release_exe)
    print(f"\n[OK] Build completed! Output: {release_exe}")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("toolchain", nargs="?", help="Toolchain name")
    parser.add_argument("--headless-test", action="store_true", help="Build with headless test mode")
    args = parser.parse_args()

    if args.toolchain:
        build(args.toolchain, headless_test=args.headless_test)
    elif args.headless_test:
        build(headless_test=True)
    else:
        build()
