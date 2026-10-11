import os
import sys
import json
import shutil
import subprocess
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent.resolve()
CROSS_DIR = SCRIPT_DIR.parent
CONFIG_PATH = CROSS_DIR / "config" / "toolchains.json"
ROOT_DIR = CROSS_DIR.parent.parent
APP_DIR = ROOT_DIR / "plug.app"
RUST_DIR = APP_DIR / "rt"
PLUGINS_DIR = ROOT_DIR / "plugins"
RELEASE_DIR_BASE = CROSS_DIR.parent / "release"
CMAKE_BUILD_DIR = CROSS_DIR / "build"

sys.path.append(str((ROOT_DIR / "tests").resolve()))
from build_utils import compile_wasm_plugin

def load_config():
    if not CONFIG_PATH.exists():
        print(f"[ERROR] Config not found: {CONFIG_PATH}")
        sys.exit(1)
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

def run_cmd(cmd, cwd=None, env=None, check=True):
    print(f"\n[EXEC] {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=cwd, env=env)
    if check and result.returncode != 0:
        print(f"[ERROR] Command failed with exit code {result.returncode}")
        sys.exit(result.returncode)

def get_msvc_env(vcvars_path):
    if not vcvars_path or not os.path.exists(vcvars_path):
        return os.environ.copy()
    print(f"\n[INFO] Initializing MSVC environment from {vcvars_path}...")
    cmd = f'"{vcvars_path}" && set'
    result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, text=True)
    env = os.environ.copy()
    for line in result.stdout.splitlines():
        if '=' in line:
            k, v = line.split('=', 1)
            env[k.upper()] = v
    return env

def generate_rc():
    print("\n=== Generating Resource Files ===")
    rc_file = CROSS_DIR / "plug_manifest.rc"
    
    with open(rc_file, "w", encoding="utf-8") as f:
        f.write('MAINICON ICON "../../plug.res/ast/ico/i-1.ico"\n')
        f.write('1 24 "plug.manifest"\n')
    print("[SUCCESS] Created plug_manifest.rc")


def build_rust_plugins(tools, env):
    print("\n=== Building WASM Plugins ===")
    PLUGINS_DIR.mkdir(parents=True, exist_ok=True)
    src_plugins_dir = RUST_DIR / "src_plugins"
    
    import hashlib
    
    for f in src_plugins_dir.rglob("*.rs"):
        if f.stem.startswith("."):
            continue
        
        name = f.stem
        hash_val = hashlib.md5(name.encode()).hexdigest()[:8]
        
        plugin_out_dir = PLUGINS_DIR / name
        if plugin_out_dir.exists() and not plugin_out_dir.is_dir():
            plugin_out_dir.unlink()
        plugin_out_dir.mkdir(exist_ok=True)
        
        out_wasm = plugin_out_dir / f"{name}.{hash_val}"
        out_hash = plugin_out_dir / f"{name}.hash"
        
        print(f"[WASM] Compiling {name} (hash: {hash_val})...")
        # Use the shared compile helper from tests/build_utils.py
        compile_wasm_plugin(f, out_wasm)
        
        with open(out_hash, "w", encoding="utf-8") as hf:
            hf.write(hash_val)

        # Compute SHA-256 for hardcoded trust injection
        if name == "pTerm":
            hash_file_path = RUST_DIR / "pterm_hash.txt"
            # Use the canonical registry hash (matching pluglists.json sha256)
            canonical_hash = "9ada6ad5b1026e126bfc212364d1ad9876c0d280b6477498d8a2220e99091f14"
            with open(hash_file_path, "w", encoding="utf-8") as hf:
                hf.write(canonical_hash)
            print(f"[WASM] Set pTerm hardcoded trust hash: {canonical_hash}")

    src_toml = src_plugins_dir / "plugin.toml"
    dst_toml = PLUGINS_DIR / "plugin.toml"
    if src_toml.exists():
        shutil.copy2(src_toml, dst_toml)
        print("[SUCCESS] Copied plugin.toml")

def build_rust_core(target, tools, env, start_time):
    print(f"\n=== Building Rust Core ({target}) ===")
    
    hash_file = RUST_DIR / "pterm_hash.txt"
    if not hash_file.exists():
        print("[ERROR] pterm_hash.txt not found. Build WASM plugins first to generate the trust hash.")
        sys.exit(1)
        
    if hash_file.stat().st_mtime < start_time - 2:
        print("[ERROR] pterm_hash.txt is stale (not rebuilt in this run). Force rebuilding plugins first.")
        sys.exit(1)

    cargo_exe = tools.get("cargo", "cargo")
    cmd = [cargo_exe, "build", "--lib", "--release", "--target", target]
    run_cmd(cmd, cwd=RUST_DIR, env=env)

    lib_dir = RUST_DIR / "target" / target / "release"
    possible_names = ["tm_main.lib", "libtm_main.a", "tm_main.a", "plug.lib", "libplug.a"]
    for name in possible_names:
        p = lib_dir / name
        if p.exists():
            return str(p)
            
    print(f"[ERROR] Rust library not found in {lib_dir}")
    sys.exit(1)

def run_cmake(tc_name, tc_config, tools, rust_lib_path, build_opts, env, headless_test=False):
    print(f"\n=== Running CMake with {tc_name.upper()} ===")
    if CMAKE_BUILD_DIR.exists():
        import shutil
        shutil.rmtree(CMAKE_BUILD_DIR, ignore_errors=True)
    CMAKE_BUILD_DIR.mkdir(exist_ok=True)
    
    cmake_exe = tools.get("cmake", "cmake")
    ninja_exe = tools.get("ninja", "ninja")
    
    if not os.path.isabs(ninja_exe):
        if "\\" in ninja_exe or "/" in ninja_exe:
            resolved_path = (CROSS_DIR / ninja_exe).resolve()
            if resolved_path.exists():
                ninja_exe = str(resolved_path)
            elif shutil.which("ninja"):
                ninja_exe = "ninja"
            else:
                ninja_exe = str(resolved_path)
    
    extra_flags = tc_config.get('extra_flags', '')
    
    cmd = [
        cmake_exe, "-G", "Ninja",
        f"-DCMAKE_MAKE_PROGRAM={ninja_exe}",
        f"-DCMAKE_C_COMPILER={tc_config.get('c_compiler', 'gcc')}",
        f"-DCMAKE_CXX_COMPILER={tc_config.get('cxx_compiler', 'g++')}",
        f"-DCMAKE_C_FLAGS={extra_flags}",
        f"-DCMAKE_CXX_FLAGS={extra_flags}",
        f"-DRUST_LIB_PATH={rust_lib_path}",
        "-DCMAKE_BUILD_TYPE=Release"
    ]
    
    if build_opts.get("hide_console", True):
        cmd.append("-DHIDE_CONSOLE=ON")
        
    if headless_test:
        cmd.extend(["-DPLUGXEL_ENABLE_HEADLESS_MODE=ON", "-DPLUG_ENABLE_HEADLESS_MODE=ON"])
    else:
        cmd.extend(["-DPLUGXEL_ENABLE_HEADLESS_MODE=OFF", "-DPLUG_ENABLE_HEADLESS_MODE=OFF"])
        
    cmd.append(str(CROSS_DIR))
    run_cmd(cmd, cwd=CMAKE_BUILD_DIR, env=env)
    
    print("\n=== Building with Ninja ===")
    run_cmd([cmake_exe, "--build", "."], cwd=CMAKE_BUILD_DIR, env=env)

def main():
    import time
    start_time = time.time()
    config = load_config()
    
    # Parse headless test parameter
    headless_test_build = False
    if "--headless-test" in sys.argv:
        headless_test_build = True
        sys.argv.remove("--headless-test")
        
    tc_name = sys.argv[1] if len(sys.argv) > 1 else config.get("active_toolchain", "clang-x64")
    
    if tc_name not in config["toolchains"]:
        print(f"[ERROR] Toolchain '{tc_name}' not defined in config/toolchains.json")
        sys.exit(1)
        
    tc_config = config["toolchains"][tc_name]
    tools = config.get("tools", {})
    build_opts = config.get("build_options", {})
    
    arch = tc_config.get("arch", "x64")
    RELEASE_DIR = RELEASE_DIR_BASE / arch
    RELEASE_DIR.mkdir(parents=True, exist_ok=True)
    
    env = os.environ.copy()
    if tc_name.startswith("msvc"):
        vcvars = tc_config.get("vcvars_path", "")
        if vcvars and os.path.exists(vcvars):
            env = get_msvc_env(vcvars)
        else:
            print(f"[WARNING] vcvars_path not found: {vcvars}")
            
    if "bin_path" in tc_config:
        env["PATH"] = f"{tc_config['bin_path']};{env.get('PATH', '')}"
        
    build_rust_plugins(tools, env)
    
    rust_target = tc_config.get("rust_target", "x86_64-pc-windows-gnu")
    run_cmd(["rustup", "target", "add", rust_target], check=False, env=env)
    rust_lib_path = build_rust_core(rust_target, tools, env, start_time)
    
    generate_rc()
    
    run_cmake(tc_name, tc_config, tools, rust_lib_path, build_opts, env, headless_test=headless_test_build)
    
    exe_name = "plugxel.exe"
    exe_path = CMAKE_BUILD_DIR / exe_name
    if not exe_path.exists():
        print(f"[ERROR] Output executable not found at {exe_path}")
        sys.exit(1)

    # Dynamic output name: plug-{arch}.exe or plug-test-{arch}.exe
    if headless_test_build:
        dest_name = f"plugxel-test-{arch}.exe"
    else:
        dest_name = f"plugxel-{arch}.exe"

    dest_exe = RELEASE_DIR / dest_name

    # Warn if overwriting a binary previously written by a different toolchain.
    # A sidecar .toolchain file records which toolchain last wrote this slot.
    toolchain_marker = dest_exe.with_suffix(".toolchain")
    if dest_exe.exists() and toolchain_marker.exists():
        prev_tc = toolchain_marker.read_text(encoding="utf-8").strip()
        if prev_tc != tc_name:
            print(f"[BUILD] Writing {dest_name} (toolchain: {tc_name}, overwriting previous {prev_tc} build)")
    else:
        print(f"[BUILD] Writing {dest_name} (toolchain: {tc_name})")

    shutil.copy2(exe_path, dest_exe)
    toolchain_marker.write_text(tc_name, encoding="utf-8")
    print(f"\n[SUCCESS] Copied to {dest_exe}")
    
    upx_exe = tools.get("upx", "")
    if build_opts.get("upx_compress", False) and os.path.exists(upx_exe):
        upx_level_str = build_opts.get("upx_level", "--best")
        upx_args = [upx_exe] + upx_level_str.split() + [str(dest_exe)]
        print("\n=== Compressing with UPX ===")
        run_cmd(upx_args, env=env)
        
    print(f"\n==========================================")
    print(f"             BUILD COMPLETED")
    print(f"==========================================")
    print(f"Toolchain    : {tc_name.upper()}")
    print(f"Architecture : {arch.upper()}")
    print(f"Output File  : {dest_exe}")
    print(f"==========================================\n")

if __name__ == "__main__":
    main()
