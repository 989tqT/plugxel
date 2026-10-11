import os
import sys
import subprocess
import time
import platform
import json
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import xml.etree.ElementTree as ET
import shutil

# import preflight
from preflight import run_preflight

sys.path.append(str(Path(__file__).parent.resolve()))
from build_utils import compile_wasm_plugin as compile_wasm_shared

def compile_wasm_plugin(src_file: Path, dest_dir: Path, manifest_file: Path) -> bool:
    plugin_name = src_file.stem
    dest_wasm = dest_dir / f"{plugin_name}.wasm"
    
    # cache check: if dest_wasm exists and is newer than source and configs, skip compilation
    if dest_wasm.exists():
        dest_mtime = dest_wasm.stat().st_mtime
        src_mtime = src_file.stat().st_mtime
        manifest_mtime = manifest_file.stat().st_mtime if manifest_file.exists() else 0
        cargo_lock = src_file.parent.parent.parent / "Cargo.lock"
        cargo_lock_mtime = cargo_lock.stat().st_mtime if cargo_lock.exists() else 0
        
        if dest_mtime > max(src_mtime, manifest_mtime, cargo_lock_mtime):
            # up to date
            return True
            
    print(f"[BUILD] Compiling mock plugin: {plugin_name}...")
    success = compile_wasm_shared(src_file, dest_wasm)
    if success:
        print(f"[BUILD] Mock plugin {plugin_name} compiled successfully.")
    return success
# strings that must not appear in production binary
# any of these appearing means compile-time guard failed
PRODUCTION_BINARY_FORBIDDEN_STRINGS = [
    "PLUGXEL_HEADLESS",
    "PLUG_HEADLESS",
    "headless_stdin_worker",
    "__dump_state__",
]

def verify_production_binary_clean(bin_path: Path) -> dict:
    """Scan the production binary for forbidden test-code strings.
    Returns a result dict compatible with run_test_script output."""
    import time
    start = time.time()
    name = "verify_production_binary_clean"
    print(f"[TEST] Starting {name}...")

    if not bin_path.exists():
        return {
            "name": name, "success": False, "duration": 0.0,
            "stdout": "",
            "stderr": f"[FAIL] Production binary not found: {bin_path}\n",
        }

    data = bin_path.read_bytes()
    failures = []
    for s in PRODUCTION_BINARY_FORBIDDEN_STRINGS:
        count = data.count(s.encode("utf-8"))
        if count > 0:
            failures.append(f"'{s}' found {count} time(s) — compile-time guard may have failed")

    duration = time.time() - start
    if failures:
        report = "[FAIL] Production binary contains forbidden test-code strings:\n"
        report += "\n".join(f"  - {f}" for f in failures)
        report += f"\n  Binary: {bin_path}"
        return {"name": name, "success": False, "duration": duration,
                "stdout": report, "stderr": ""}

    report = f"[PASS] Production binary clean. Scanned {len(PRODUCTION_BINARY_FORBIDDEN_STRINGS)} forbidden string(s), all 0 occurrences.\n"
    report += f"  Binary: {bin_path}"
    print(f"[TEST] {name} PASSED")
    return {"name": name, "success": True, "duration": duration,
            "stdout": report, "stderr": ""}

def find_rust_lib(project_root: Path) -> str:
    search_paths = [
        project_root / "plug.app" / "rt" / "target" / "x86_64-pc-windows-gnu" / "release" / "libtm_main.a",
        project_root / "plug.app" / "rt" / "target" / "x86_64-pc-windows-msvc" / "release" / "tm_main.lib",
        project_root / "plug.app" / "rt" / "target" / "x86_64-unknown-linux-gnu" / "release" / "libtm_main.a",
        project_root / "plug.app" / "rt" / "target" / "release" / "libtm_main.a",
        project_root / "plug.app" / "rt" / "target" / "release" / "tm_main.lib",
    ]
    for p in search_paths:
        if p.exists():
            return str(p.resolve())
    return ""



def build_project(project_root: Path, os_name: str, headless_test: bool = False) -> bool:
    print(f"[BUILD] Compiling host application (headless_test={headless_test})...")
    try:
        script_path = project_root / "plug.cross" / "windows" / "scripts" / "builder.py"
        if os_name == "Windows" and script_path.exists():
            args = [sys.executable, str(script_path)]
            if headless_test:
                args.append("--headless-test")
            res = subprocess.run(args, cwd=str(project_root))
            return res.returncode == 0
        else:
            build_dir = project_root / "plug.cross" / ("windows" if os_name == "Windows" else "linux") / "build"
            if build_dir.exists():
                shutil.rmtree(build_dir, ignore_errors=True)
            build_dir.mkdir(parents=True, exist_ok=True)
            rust_lib = find_rust_lib(project_root)
            if not rust_lib:
                print("[BUILD-ERROR] Rust static library not found! Please build the rust core first.")
                return False
            cmake_args = [
                "cmake",
                "-S", str(build_dir.parent),
                "-B", str(build_dir),
                f"-DRUST_LIB_PATH={rust_lib}"
            ]
            if os_name == "Windows":
                cmake_args.append("-DHIDE_CONSOLE=ON")
            if headless_test:
                cmake_args.extend(["-DPLUGXEL_ENABLE_HEADLESS_MODE=ON", "-DPLUG_ENABLE_HEADLESS_MODE=ON"])
            else:
                cmake_args.extend(["-DPLUGXEL_ENABLE_HEADLESS_MODE=OFF", "-DPLUG_ENABLE_HEADLESS_MODE=OFF"])
            subprocess.check_call(cmake_args)
            subprocess.check_call(["cmake", "--build", str(build_dir)])

            # copy compiled binary to release directory for linux target
            release_subdir = "x86_64"
            target_name = "plugxel-test-x64" if headless_test else "plugxel-x64"
            dest_bin = project_root / "plug.cross" / "release" / release_subdir / target_name
            dest_bin.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(build_dir / "plugxel", dest_bin)
            print(f"[BUILD] Copied compiled binary to {dest_bin}")
            return True
    except Exception as e:
        print(f"[BUILD-ERROR] Build failed: {e}")
        return False

def run_test_script(script_path: Path, env_ctx: dict) -> dict:
    name = script_path.stem
    print(f"[TEST] Starting {name}...")
    start_time = time.time()
    
    try:
        # run process
        res = subprocess.run(
            [sys.executable, str(script_path)],
            cwd=str(script_path.parent),
            env={**os.environ, "ENV_CONTEXT": json.dumps(env_ctx)},
            capture_output=True,
            text=True,
            timeout=120 # 2 minutes per sub-script timeout
        )
        duration = time.time() - start_time
        success = res.returncode == 0
        return {
            "name": name,
            "success": success,
            "stdout": res.stdout,
            "stderr": res.stderr,
            "duration": duration,
        }
    except subprocess.TimeoutExpired as e:
        duration = time.time() - start_time
        return {
            "name": name,
            "success": False,
            "stdout": e.stdout or "",
            "stderr": (e.stderr or "") + "\n[TIMEOUT] Test timed out after 120s",
            "duration": duration,
        }
    except Exception as e:
        duration = time.time() - start_time
        return {
            "name": name,
            "success": False,
            "stdout": "",
            "stderr": f"Execution error: {e}",
            "duration": duration,
        }

def generate_junit_xml(results: list, output_file: Path):
    root = ET.Element("testsuites", name="PlugxelTestSuite")
    total_tests = len(results)
    total_failures = sum(1 for r in results if not r["success"])
    total_time = sum(r["duration"] for r in results)
    
    root.set("tests", str(total_tests))
    root.set("failures", str(total_failures))
    root.set("time", f"{total_time:.3f}")
    
    suite = ET.SubElement(root, "testsuite", name="AllTests", tests=str(total_tests), failures=str(total_failures), time=f"{total_time:.3f}")
    
    for r in results:
        tc = ET.SubElement(suite, "testcase", name=r["name"], classname="tests", time=f"{r['duration']:.3f}")
        if not r["success"]:
            msg = "Test failed"
            if "[FAIL]" in r["stdout"]:
                msg = "Assertions failed"
            elif "TIMEOUT" in r["stderr"]:
                msg = "Timed out"
            
            fail = ET.SubElement(tc, "failure", message=msg)
            fail.text = f"--- STDOUT ---\n{r['stdout']}\n--- STDERR ---\n{r['stderr']}"
            
    output_file.parent.mkdir(parents=True, exist_ok=True)
    tree = ET.ElementTree(root)
    tree.write(output_file, encoding="UTF-8", xml_declaration=True)
    print(f"[REPORTER] JUnit XML generated: {output_file}")

def main():
    start_time = time.time()
    project_root = Path(__file__).parent.parent.resolve()
    
    # 1. run preflight
    env_ctx = run_preflight(project_root)
    os_name = env_ctx["os"]
    
    # check build requirements
    ci_mode = "--ci" in sys.argv or os.environ.get("CI") == "true"
    
    # 1. compile host production binary first to check compile integrity
    target_bin_path = Path(env_ctx["target_bin"])
    pterm_hash_file = project_root / "plug.app" / "rt" / "pterm_hash.txt"
    if target_bin_path.exists() and pterm_hash_file.exists():
        if pterm_hash_file.stat().st_mtime > target_bin_path.stat().st_mtime:
            print("[ORCHESTRATOR] pterm_hash.txt updated. Forcing rebuild of production binary.")
            try:
                target_bin_path.unlink()
            except Exception:
                pass
                
    if not target_bin_path.exists():
        if ci_mode:
            print("[ORCHESTRATOR] Build binary missing in CI. Compiling production host...")
            if not build_project(project_root, os_name):
                print("[ORCHESTRATOR-ERROR] Host build compilation failed.")
                sys.exit(1)
        else:
            answer = input("Production host executable not found. Build now? [y/N]: ").strip().lower()
            if answer in ["y", "yes"]:
                if not build_project(project_root, os_name):
                    print("[ORCHESTRATOR-ERROR] Host build compilation failed.")
                    sys.exit(1)
            else:
                print("[ORCHESTRATOR-WARNING] Proceeding without production host binary.")

    # 2. find and build rust core and e2e headless test binary
    rust_lib = find_rust_lib(project_root)
    if not rust_lib:
        print("[ORCHESTRATOR] Rust core library missing. Compiling static library...")
        # compile rust library core
        is_msvc = (os.environ.get("VCINSTALLDIR") is not None) or shutil.which("cl") is not None
        if os_name == "Windows":
            target_tri = "x86_64-pc-windows-msvc" if is_msvc else "x86_64-pc-windows-gnu"
        else:
            target_tri = "x86_64-unknown-linux-gnu"
        subprocess.check_call(["cargo", "build", "--release", "--lib", "--target", target_tri], cwd=str(project_root / "plug.app" / "rt"))
        rust_lib = find_rust_lib(project_root)
        if not rust_lib:
            print("[ORCHESTRATOR-ERROR] Failed to compile or locate Rust core library.")
            sys.exit(1)
            
    # locate/compile headless-test variant plugxel-test-{arch}.exe
    tc_cfg = project_root / "plug.cross" / "windows" / "config" / "toolchains.json"
    arch = "x64"
    if tc_cfg.exists():
        try:
            tc_data = json.loads(tc_cfg.read_text(encoding="utf-8"))
            active_tc = tc_data.get("active_toolchain", "clang-x64")
            arch = tc_data["toolchains"][active_tc].get("arch", "x64")
        except Exception:
            pass
    if os_name == "Windows":
        test_bin_name = f"plugxel-test-{arch}.exe"
        release_subdir = arch
    else:
        release_subdir = "x86_64" if arch == "x64" else arch
        test_bin_name = f"plugxel-test-{arch}"
    test_bin_path = project_root / "plug.cross" / "release" / release_subdir / test_bin_name
    if test_bin_path.exists() and pterm_hash_file.exists():
        if pterm_hash_file.stat().st_mtime > test_bin_path.stat().st_mtime:
            print("[ORCHESTRATOR] pterm_hash.txt updated. Forcing rebuild of testing binary.")
            try:
                test_bin_path.unlink()
            except Exception:
                pass
                
    if not test_bin_path.exists():
        print(f"[ORCHESTRATOR] Testing binary {test_bin_name} missing. Compiling...")
        if not build_project(project_root, os_name, headless_test=True):
            print("[ORCHESTRATOR-ERROR] Failed to compile headless-test binary.")
            sys.exit(1)

    env_ctx["target_bin"] = str(test_bin_path.resolve())



    # 2. compile wasm fixtures
    fixtures_dir = project_root / "tests" / "fixtures"
    mock_plugins_dir = fixtures_dir / "mock_plugins"
    manifests_dir = fixtures_dir / "manifests"
    
    # create build destination dir
    wasm_dest_dir = fixtures_dir / "build"
    wasm_dest_dir.mkdir(parents=True, exist_ok=True)
    
    # compile each mock plugin
    plugins_to_build = [
        "ok_plugin", "rogue_plugin", "rogue_plugin_runtime",
        "fs_scoped_ok_plugin", "fs_scoped_escape_plugin", "fs_scoped_no_perm_plugin",
        "fs_isolated_a", "fs_scoped_unauthorized_import_plugin",
        "fs_isolated_b"
    ]
    for p in plugins_to_build:
        src = mock_plugins_dir / f"{p}.rs"
        manifest = manifests_dir / f"{p}.toml"
        if src.exists():
            if not compile_wasm_plugin(src, wasm_dest_dir, manifest):
                print(f"[ORCHESTRATOR-ERROR] Failed to compile fixture {p}.")
                sys.exit(1)

    # 3. queue test scripts
    unit_tests = [
        project_root / "tests" / "unit" / "rust_core" / "test_wrapper.py",
        project_root / "tests" / "unit" / "cpp_ui" / "test_wrapper.py" # c++ unit test python wrapper
    ]
    
    integration_tests = [
        project_root / "tests" / "integration" / "test_ffi_boundary.py",
        project_root / "tests" / "integration" / "test_sandbox_rules.py",
        project_root / "tests" / "integration" / "test_rust_ffi_direct.py",
        project_root / "tests" / "integration" / "test_scoped_fs.py"
    ]
    
    e2e_tests = [
        project_root / "tests" / "e2e" / "test_cli_lifecycle.py"
    ]
    
    results = []

    # security gate: verify production binary has no test-code leaks before running test
    # this run against plugxel.exe (plug_enable_headless_mode=off build), not plug_test.exe
    prod_bin_path = Path(env_ctx["release_dir"]) / env_ctx["binary_name"]
    leak_result = verify_production_binary_clean(prod_bin_path)
    results.append(leak_result)
    if not leak_result["success"]:
        if leak_result.get("stderr"):
            print(f"[ORCHESTRATOR-ERROR] Production binary check failed: {leak_result['stderr'].strip()}")
        else:
            print(f"[ORCHESTRATOR-ERROR] Production binary symbol leak detected. Aborting test run.")
            print(leak_result["stdout"])
        results_xml = project_root / "tests" / ".artifacts" / "results.xml"
        generate_junit_xml(results, results_xml)
        sys.exit(1)

    # run unit test in parallel
    print("[ORCHESTRATOR] Executing Unit Tests in parallel...")
    with ThreadPoolExecutor(max_workers=len(unit_tests)) as executor:
        futures = [executor.submit(run_test_script, ut, env_ctx) for ut in unit_tests if ut.exists()]
        for f in futures:
            res = f.result()
            results.append(res)
            status = "PASSED" if res["success"] else "FAILED"
            print(f"[TEST] {res['name']} {status}")
            if not res["success"]:
                print(f"--- STDOUT ({res['name']}) ---\n{res['stdout']}")
                print(f"--- STDERR ({res['name']}) ---\n{res['stderr']}")
            
    # run integration and e2e test sequentially to prevent locking collisions
    print("[ORCHESTRATOR] Executing Integration and E2E Tests sequentially...")
    sequential_tests = integration_tests + e2e_tests
    for t in sequential_tests:
        if t.exists():
            res = run_test_script(t, env_ctx)
            results.append(res)
            status = "PASSED" if res["success"] else "FAILED"
            print(f"[TEST] {res['name']} {status}")
            if not res["success"]:
                print(f"--- STDOUT ({res['name']}) ---\n{res['stdout']}")
                print(f"--- STDERR ({res['name']}) ---\n{res['stderr']}")
            
    # 4. generate reports
    results_xml = project_root / "tests" / ".artifacts" / "results.xml"
    generate_junit_xml(results, results_xml)
    
    total_failures = sum(1 for r in results if not r["success"])
    print(f"\n==================================================")
    print("                 TEST RUN SUMMARY")
    print(f"==================================================")
    print(f"Total executed : {len(results)}")
    print(f"Passed         : {len(results) - total_failures}")
    print(f"Failed         : {total_failures}")
    print(f"Elapsed Time   : {time.time() - start_time:.2f}s")
    print(f"==================================================")
    
    sys.exit(1 if total_failures > 0 else 0)

if __name__ == "__main__":
    main()
