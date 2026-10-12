// p1.5 linux atomic containment runner
// verify 8 acceptance gate via rust linux containment engine

#[path = "../../../plug.app/rt/handlers/ops/fs_containment/mod.rs"]
pub mod fs_containment;

use fs_containment::*;
use fs_containment::linux::*;

use std::ffi::CString;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

fn main() {
    println!("[SPIKE-RUST] running p1.5 linux containment acceptance suite");
    let mut failed = false;

    // create temporary test sandbox
    let base_dir_str = format!("/tmp/plug_spike_{}", std::process::id());
    let base_dir = Path::new(&base_dir_str);
    if base_dir.exists() {
        let _ = fs::remove_dir_all(base_dir);
    }
    fs::create_dir_all(base_dir).expect("create base tmp dir");

    let sandbox_root = base_dir.join("sandbox_data");
    fs::create_dir_all(&sandbox_root).expect("create sandbox root");

    let outside_dir = base_dir.join("host_outside");
    fs::create_dir_all(&outside_dir).expect("create outside dir");

    let sentinel_file = outside_dir.join("sentinel.txt");
    fs::write(&sentinel_file, b"HOST_SACRED_SENTINEL_DATA").expect("write sentinel");

    let c_sandbox_root = CString::new(sandbox_root.to_str().unwrap()).unwrap();
    let root_fd = unsafe {
        libc::open(
            c_sandbox_root.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    assert!(root_fd >= 0, "failed open root fd");

    let engine = LinuxContainmentEngine::new();

    // gate 1: standard in capability io
    let inside_path = sandbox_root.join("inside.txt");
    fs::write(&inside_path, b"inside_payload").expect("write inside");
    let res1 = engine.open_beneath(root_fd, "inside.txt", OpenFlags {
        read: true,
        ..Default::default()
    });
    match res1 {
        Ok(fd) => {
            unsafe { libc::close(fd); }
            println!("[PASS] Gate 1: standard in capability io PASS");
        }
        Err(e) => {
            println!("[FAIL] Gate 1: failed with errno {}", e);
            failed = true;
        }
    }

    // gate 2: rooted and traversal rejection
    let res2_root = engine.open_beneath(root_fd, "/etc/passwd", OpenFlags::default());
    let res2_traversal = engine.open_beneath(root_fd, "../host_outside/sentinel.txt", OpenFlags::default());
    if res2_root == Err(WASI_ENOTCAPABLE) && res2_traversal == Err(WASI_ENOTCAPABLE) {
        println!("[PASS] Gate 2: rooted and traversal rejection DENY");
    } else {
        println!("[FAIL] Gate 2: traversal allowed! root={:?}, trav={:?}", res2_root, res2_traversal);
        failed = true;
    }

    // gate 3: symlink and magiclink invalidation
    let link_out = sandbox_root.join("link_out");
    symlink(&sentinel_file, &link_out).expect("create symlink");
    let res3 = engine.open_beneath(root_fd, "link_out", OpenFlags {
        follow_symlinks: false,
        ..Default::default()
    });
    if res3 == Err(WASI_ENOTCAPABLE) {
        println!("[PASS] Gate 3: symlink and magiclink invalidation DENY");
    } else {
        println!("[FAIL] Gate 3: symlink escape allowed! res={:?}", res3);
        failed = true;
    }

    // gate 4: safe parent open and leaf unlink
    let sub_dir = sandbox_root.join("subdir");
    fs::create_dir_all(&sub_dir).expect("create subdir");
    let sub_leaf = sub_dir.join("leaf.txt");
    fs::write(&sub_leaf, b"leaf_payload").expect("write leaf");

    let res4 = engine.unlink_file_beneath(root_fd, "subdir/leaf.txt");
    if res4 == Ok(()) && !sub_leaf.exists() {
        println!("[PASS] Gate 4: safe parent open and leaf unlink PASS");
    } else {
        println!("[FAIL] Gate 4: unlink leaf failed! res={:?}", res4);
        failed = true;
    }

    // gate 5: multi component outside traversal
    let res5 = engine.mkdir_beneath(root_fd, "link_out/newdir");
    if res5 == Err(WASI_ENOTCAPABLE) {
        println!("[PASS] Gate 5: multi component outside traversal DENY");
    } else {
        println!("[FAIL] Gate 5: mkdir outside allowed! res={:?}", res5);
        failed = true;
    }

    // gate 6: destructive mutation confinement
    let res6 = engine.open_beneath(root_fd, "link_out", OpenFlags {
        write: true,
        create: true,
        truncate: true,
        follow_symlinks: false,
        ..Default::default()
    });
    let sentinel_data = fs::read(&sentinel_file).unwrap();
    if res6 == Err(WASI_ENOTCAPABLE) && sentinel_data == b"HOST_SACRED_SENTINEL_DATA" {
        println!("[PASS] Gate 6: destructive mutation confinement PASS");
    } else {
        println!("[FAIL] Gate 6: sentinel damaged or call succeeded! res={:?}", res6);
        failed = true;
    }

    // gate 7: concurrent namespace mutation integrity with metrics logging
    let stop_race = Arc::new(AtomicBool::new(false));
    let stop_clone = stop_race.clone();
    let mutation_count = Arc::new(AtomicU64::new(0));
    let mutation_clone = mutation_count.clone();
    let race_link = sandbox_root.join("race_target");
    let sentinel_target = sentinel_file.clone();

    let handle = thread::spawn(move || {
        let mut toggle = true;
        while !stop_clone.load(Ordering::Relaxed) {
            let _ = fs::remove_file(&race_link);
            if toggle {
                let _ = symlink(&sentinel_target, &race_link);
            } else {
                let _ = fs::write(&race_link, b"local_safe");
            }
            mutation_clone.fetch_add(1, Ordering::Relaxed);
            toggle = !toggle;
            thread::sleep(Duration::from_micros(50));
        }
    });

    let mut allowed_safe = 0u64;
    let mut denied_confined = 0u64;
    let mut eagain_observed = 0u64;
    let mut total_attempts = 0u64;

    for _ in 0..500 {
        total_attempts += 1;
        let res = engine.open_beneath(root_fd, "race_target", OpenFlags {
            write: true,
            create: true,
            truncate: true,
            follow_symlinks: false,
            ..Default::default()
        });
        match res {
            Ok(fd) => {
                allowed_safe += 1;
                unsafe { libc::close(fd); }
            }
            Err(e) => {
                if e == WASI_EAGAIN {
                    eagain_observed += 1;
                } else if e == WASI_ENOTCAPABLE || e == WASI_ENOENT {
                    denied_confined += 1;
                } else {
                    println!("[WARN] Gate 7 unexpected errno during race: {}", e);
                }
            }
        }
        let data = fs::read(&sentinel_file).unwrap();
        if data != b"HOST_SACRED_SENTINEL_DATA" {
            println!("[FAIL] Gate 7: sentinel damaged during race!");
            failed = true;
            break;
        }
    }

    stop_race.store(true, Ordering::Relaxed);
    let _ = handle.join();
    let total_mutations = mutation_count.load(Ordering::Relaxed);

    if !failed {
        let final_sentinel = fs::read(&sentinel_file).unwrap();
        assert_eq!(final_sentinel, b"HOST_SACRED_SENTINEL_DATA");
        println!(
            "[PASS] Gate 7: concurrent namespace mutation integrity PASS (attempts: {}, safe: {}, denied: {}, eagain: {}, mutations: {}, sentinel: intact)",
            total_attempts, allowed_safe, denied_confined, eagain_observed, total_mutations
        );
    }

    // gate 7b: deterministic eagain retry exhaustion test
    let c_dummy = CString::new("test_target").unwrap();
    let dummy_how = OpenHow::default();
    let mut eagain_calls = 0;
    let res_eagain = LinuxContainmentEngine::openat2_syscall_with_runner(root_fd, &c_dummy, &dummy_how, |_, _, _| {
        eagain_calls += 1;
        (-1, libc::EAGAIN)
    });
    if res_eagain == Err(WASI_EAGAIN) && eagain_calls == 4 {
        println!("[PASS] Gate 7b: deterministic eagain retry exhaustion PASS (attempts: 4 [1 initial + 3 retries] -> WASI_EAGAIN)");
    } else {
        println!("[FAIL] Gate 7b: eagain exhaustion failed! res={:?}, calls={}", res_eagain, eagain_calls);
        failed = true;
    }

    // gate 8: primitive unavailability fail closed (deterministic enosys injection)
    let mut enosys_calls = 0;
    let res_enosys = LinuxContainmentEngine::openat2_syscall_with_runner(root_fd, &c_dummy, &dummy_how, |_, _, _| {
        enosys_calls += 1;
        (-1, libc::ENOSYS)
    });
    if res_enosys == Err(WASI_ENOTCAPABLE) && enosys_calls == 1 {
        println!("[PASS] Gate 8: primitive unavailability fail closed PASS (injected ENOSYS -> ENOTCAPABLE, 0 fallback)");
    } else {
        println!("[FAIL] Gate 8: enosys injection failed! res={:?}, calls={}", res_enosys, enosys_calls);
        failed = true;
    }

    unsafe { libc::close(root_fd); }
    let _ = fs::remove_dir_all(base_dir);

    if failed {
        println!("[SPIKE-RUST] suite failed");
        std::process::exit(1);
    } else {
        println!("[SPIKE-RUST] 8/8 gates verified natively via LinuxContainmentEngine");
    }
}
