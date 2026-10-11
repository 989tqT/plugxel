#!/usr/bin/env python3
import os
import sys
from pathlib import Path

REPO_ROOT = Path(r"c:\lab\prj\plugxel")
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures"
MOCK_DIR = FIXTURES_DIR / "mock_plugins"
MANIFEST_DIR = FIXTURES_DIR / "manifests"

COMMON_HEADER = """// wasi scoped filesystem test plugin
#![allow(dead_code)]

#[repr(C)]
struct Ciovec {
    buf: *const u8,
    buf_len: usize,
}

#[repr(C)]
struct Iovec {
    buf: *mut u8,
    buf_len: usize,
}

extern "C" {
    fn print_info(ptr: *const u8, len: usize);
}

#[link(wasm_import_module = "wasi_snapshot_preview1")]
extern "C" {
    fn fd_prestat_get(fd: i32, buf: *mut u8) -> i32;
    fn fd_prestat_dir_name(fd: i32, path: *mut u8, path_len: i32) -> i32;
    fn path_open(
        dirfd: i32,
        dirflags: i32,
        path: *const u8,
        path_len: i32,
        oflags: i32,
        fs_rights_base: u64,
        fs_rights_inheriting: u64,
        fdflags: i32,
        opened_fd: *mut i32,
    ) -> i32;
    fn fd_write(fd: i32, iovs: *const Ciovec, iovs_len: i32, nwritten: *mut i32) -> i32;
    fn fd_read(fd: i32, iovs: *const Iovec, iovs_len: i32, nread: *mut i32) -> i32;
    fn fd_close(fd: i32) -> i32;
    fn path_create_directory(dirfd: i32, path: *const u8, path_len: i32) -> i32;
    fn path_symlink(old_path: *const u8, old_len: i32, dirfd: i32, new_path: *const u8, new_len: i32) -> i32;
}

// discover preopened capability fd dynamically and verify virtual identity "/data"
unsafe fn find_and_verify_data_capability() -> (i32, i32) {
    let mut data_fd = -1;
    let mut preopen_count = 0;
    let mut prestat = [0u8; 8];

    for fd in 0..64 {
        let ret = fd_prestat_get(fd, prestat.as_mut_ptr());
        if ret == 0 {
            preopen_count += 1;
            let tag = prestat[0];
            if tag == 0 {
                let mut name_buf = [0u8; 32];
                let d_ret = fd_prestat_dir_name(fd, name_buf.as_mut_ptr(), name_buf.len() as i32);
                if d_ret == 0 && (&name_buf[..5] == b"/data" || &name_buf[..4] == b"data") {
                    data_fd = fd;
                }
            }
        }
    }
    (data_fd, preopen_count)
}
"""

PLUGINS = {
    "fs_scoped_ok_plugin": {
        "rs": COMMON_HEADER + """
#[no_mangle]
pub extern "C" fn run() {
    unsafe {
        let (dir_fd, preopen_count) = find_and_verify_data_capability();
        if dir_fd < 0 || preopen_count != 1 {
            let msg = "SCOPED_OK: FAIL_PREOPEN_IDENTITY";
            print_info(msg.as_ptr(), msg.len());
            return;
        }

        let path = "ok.txt";
        let mut file_fd: i32 = -1;
        let res = path_open(
            dir_fd,
            0,
            path.as_ptr(),
            path.len() as i32,
            9,
            !0u64,
            !0u64,
            0,
            &mut file_fd,
        );
        if res != 0 || file_fd < 0 {
            let msg = "SCOPED_OK: FAIL_OPEN_WRITE";
            print_info(msg.as_ptr(), msg.len());
            return;
        }

        let write_data = b"scoped_payload_data";
        let ciovec = Ciovec {
            buf: write_data.as_ptr(),
            buf_len: write_data.len(),
        };
        let mut written: i32 = 0;
        let w_res = fd_write(file_fd, &ciovec, 1, &mut written);
        fd_close(file_fd);
        if w_res != 0 || written != write_data.len() as i32 {
            let msg = "SCOPED_OK: FAIL_WRITE";
            print_info(msg.as_ptr(), msg.len());
            return;
        }

        let mut read_fd: i32 = -1;
        let o_res = path_open(
            dir_fd,
            0,
            path.as_ptr(),
            path.len() as i32,
            0,
            !0u64,
            !0u64,
            0,
            &mut read_fd,
        );
        if o_res != 0 || read_fd < 0 {
            let msg = "SCOPED_OK: FAIL_OPEN_READ";
            print_info(msg.as_ptr(), msg.len());
            return;
        }

        let mut read_buf = [0u8; 64];
        let iovec = Iovec {
            buf: read_buf.as_mut_ptr(),
            buf_len: read_buf.len(),
        };
        let mut nread: i32 = 0;
        let r_res = fd_read(read_fd, &iovec, 1, &mut nread);
        fd_close(read_fd);
        if r_res != 0 || nread != write_data.len() as i32 || &read_buf[..nread as usize] != write_data {
            let msg = "SCOPED_OK: FAIL_READ_VERIFY";
            print_info(msg.as_ptr(), msg.len());
            return;
        }

        let sub_dir = "subdir";
        let _ = path_create_directory(dir_fd, sub_dir.as_ptr(), sub_dir.len() as i32);
        let sub_file = "subdir/nested.txt";
        let mut sub_fd: i32 = -1;
        let s_res = path_open(
            dir_fd,
            0,
            sub_file.as_ptr(),
            sub_file.len() as i32,
            9,
            !0u64,
            !0u64,
            0,
            &mut sub_fd,
        );
        if s_res != 0 || sub_fd < 0 {
            let msg = "SCOPED_OK: FAIL_SUBDIR";
            print_info(msg.as_ptr(), msg.len());
            return;
        }
        fd_close(sub_fd);

        let msg = "SCOPED_OK: PASS";
        print_info(msg.as_ptr(), msg.len());
    }
}
""",
        "manifest": """[plugin]
name = "fs_scoped_ok_plugin"
version = "1.0.0"
author = "test"
api_version = "0.1.2a"
permissions = ["fs_scoped"]
"""
    },
    "fs_scoped_escape_plugin": {
        "rs": COMMON_HEADER + """
#[no_mangle]
pub extern "C" fn run() {
    unsafe {
        let (dir_fd, _) = find_and_verify_data_capability();
        if dir_fd < 0 {
            let msg = "SCOPED_ESCAPE: FAIL_NO_PREOPEN";
            print_info(msg.as_ptr(), msg.len());
            return;
        }

        let mut fd: i32 = -1;

        // attack 1: parent traversal
        let p1 = "../escape.txt";
        let r1 = path_open(dir_fd, 0, p1.as_ptr(), p1.len() as i32, 0, !0u64, !0u64, 0, &mut fd);
        if r1 == 0 {
            fd_close(fd);
            let msg = "SCOPED_ESCAPE: BREACH_PARENT";
            print_info(msg.as_ptr(), msg.len());
            return;
        }

        // attack 2: nested traversal
        let p2 = "subdir/../../escape.txt";
        let r2 = path_open(dir_fd, 0, p2.as_ptr(), p2.len() as i32, 0, !0u64, !0u64, 0, &mut fd);
        if r2 == 0 {
            fd_close(fd);
            let msg = "SCOPED_ESCAPE: BREACH_NESTED";
            print_info(msg.as_ptr(), msg.len());
            return;
        }

        // attack 3: rooted absolute path
        let p3 = "/etc/passwd";
        let r3 = path_open(dir_fd, 0, p3.as_ptr(), p3.len() as i32, 0, !0u64, !0u64, 0, &mut fd);
        if r3 == 0 {
            fd_close(fd);
            let msg = "SCOPED_ESCAPE: BREACH_ROOT";
            print_info(msg.as_ptr(), msg.len());
            return;
        }

        // attack 4: leading slash path
        let p4 = "/escape.txt";
        let r4 = path_open(dir_fd, 0, p4.as_ptr(), p4.len() as i32, 0, !0u64, !0u64, 0, &mut fd);
        if r4 == 0 {
            fd_close(fd);
            let msg = "SCOPED_ESCAPE: BREACH_SLASH";
            print_info(msg.as_ptr(), msg.len());
            return;
        }

        // attack 5: windows drive path syntax
        let p5 = "C:\\\\Windows\\\\System32\\\\notepad.exe";
        let r5 = path_open(dir_fd, 0, p5.as_ptr(), p5.len() as i32, 0, !0u64, !0u64, 0, &mut fd);
        if r5 == 0 {
            fd_close(fd);
            let msg = "SCOPED_ESCAPE: BREACH_DRIVE";
            print_info(msg.as_ptr(), msg.len());
            return;
        }

        // attack 6: symlink / junction outside escape
        let p6 = "link_outside/host_secret.txt";
        // dirflag 1 = LOOKUPFLAG_SYMLINK_FOLLOW
        let r6 = path_open(dir_fd, 1, p6.as_ptr(), p6.len() as i32, 0, !0u64, !0u64, 0, &mut fd);
        if r6 == 0 {
            fd_close(fd);
            let msg = "SCOPED_ESCAPE: BREACH_SYMLINK";
            print_info(msg.as_ptr(), msg.len());
            return;
        }

        // attack 7: attempt to create symlink pointing outside
        let target = "../../host_secret.txt";
        let sym_name = "malicious_link";
        let r7 = path_symlink(target.as_ptr(), target.len() as i32, dir_fd, sym_name.as_ptr(), sym_name.len() as i32);
        if r7 == 0 {
            let msg = "SCOPED_ESCAPE: BREACH_SYMLINK_CREATION";
            print_info(msg.as_ptr(), msg.len());
            return;
        }

        let msg = "SCOPED_ESCAPE: ALL_BLOCKED";
        print_info(msg.as_ptr(), msg.len());
    }
}
""",
        "manifest": """[plugin]
name = "fs_scoped_escape_plugin"
version = "1.0.0"
author = "test"
api_version = "0.1.2a"
permissions = ["fs_scoped"]
"""
    },
    "fs_scoped_no_perm_plugin": {
        "rs": """// plugin without fs_scoped permission verifying zero preopens
extern "C" {
    fn print_info(ptr: *const u8, len: usize);
}

#[link(wasm_import_module = "wasi_snapshot_preview1")]
extern "C" {
    fn fd_prestat_get(fd: i32, buf: *mut u8) -> i32;
}

#[no_mangle]
pub extern "C" fn run() {
    unsafe {
        let mut preopen_count = 0;
        let mut prestat = [0u8; 8];
        for fd in 0..64 {
            let ret = fd_prestat_get(fd, prestat.as_mut_ptr());
            if ret == 0 {
                preopen_count += 1;
            }
        }
        if preopen_count == 0 {
            let msg = "SCOPED_NO_PERM: ZERO_PREOPENS";
            print_info(msg.as_ptr(), msg.len());
        } else {
            let msg = "SCOPED_NO_PERM: PREOPEN_LEAKED";
            print_info(msg.as_ptr(), msg.len());
        }
    }
}
""",
        "manifest": """[plugin]
name = "fs_scoped_no_perm_plugin"
version = "1.0.0"
author = "test"
api_version = "0.1.2a"
permissions = []
"""
    },
    "fs_scoped_unauthorized_import_plugin": {
        "rs": """// plugin attempting unauthorized wasi import path_open
extern "C" {
    fn print_info(ptr: *const u8, len: usize);
}

#[link(wasm_import_module = "wasi_snapshot_preview1")]
extern "C" {
    fn path_open(
        dirfd: i32,
        dirflags: i32,
        path: *const u8,
        path_len: i32,
        oflags: i32,
        fs_rights_base: u64,
        fs_rights_inheriting: u64,
        fdflags: i32,
        opened_fd: *mut i32,
    ) -> i32;
}

#[no_mangle]
pub extern "C" fn run() {
    let msg = "UNAUTHORIZED_WASI_SHOULD_NEVER_RUN";
    unsafe { print_info(msg.as_ptr(), msg.len()); }
}
""",
        "manifest": """[plugin]
name = "fs_scoped_unauthorized_import_plugin"
version = "1.0.0"
author = "test"
api_version = "0.1.2a"
permissions = []
"""
    },
    "fs_isolated_a": {
        "rs": COMMON_HEADER + """
#[no_mangle]
pub extern "C" fn run() {
    unsafe {
        let (dir_fd, _) = find_and_verify_data_capability();
        if dir_fd < 0 {
            let msg = "ISOLATED_A: FAIL_NO_PREOPEN";
            print_info(msg.as_ptr(), msg.len());
            return;
        }

        let path = "secret.txt";
        let mut file_fd: i32 = -1;
        let res = path_open(dir_fd, 0, path.as_ptr(), path.len() as i32, 9, !0u64, !0u64, 0, &mut file_fd);
        if res != 0 || file_fd < 0 {
            let msg = "ISOLATED_A: FAIL_OPEN";
            print_info(msg.as_ptr(), msg.len());
            return;
        }
        let data = b"SECRET_A_TOKEN_12345";
        let ciovec = Ciovec { buf: data.as_ptr(), buf_len: data.len() };
        let mut written: i32 = 0;
        fd_write(file_fd, &ciovec, 1, &mut written);
        fd_close(file_fd);

        let msg = "ISOLATED_A: WROTE_SECRET";
        print_info(msg.as_ptr(), msg.len());
    }
}
""",
        "manifest": """[plugin]
name = "fs_isolated_a"
version = "1.0.0"
author = "test"
api_version = "0.1.2a"
permissions = ["fs_scoped"]
"""
    },
    "fs_isolated_b": {
        "rs": COMMON_HEADER + """
#[no_mangle]
pub extern "C" fn run() {
    unsafe {
        let (dir_fd, _) = find_and_verify_data_capability();
        if dir_fd < 0 {
            let msg = "ISOLATED_B: FAIL_NO_PREOPEN";
            print_info(msg.as_ptr(), msg.len());
            return;
        }

        // direct secret read attempt
        let path = "secret.txt";
        let mut file_fd: i32 = -1;
        let res = path_open(dir_fd, 0, path.as_ptr(), path.len() as i32, 0, !0u64, !0u64, 0, &mut file_fd);
        if res == 0 && file_fd >= 0 {
            fd_close(file_fd);
            let msg = "ISOLATED_B: BREACH_A_VISIBLE";
            print_info(msg.as_ptr(), msg.len());
            return;
        }

        // adversarial sibling escape attempt 1: ../test_fs_isolated_a_hash/secret.txt
        let sibling_p1 = "../test_fs_isolated_a_hash/secret.txt";
        let mut s1_fd: i32 = -1;
        let r1 = path_open(dir_fd, 0, sibling_p1.as_ptr(), sibling_p1.len() as i32, 0, !0u64, !0u64, 0, &mut s1_fd);
        if r1 == 0 && s1_fd >= 0 {
            fd_close(s1_fd);
            let msg = "ISOLATED_B: BREACH_SIBLING_PARENT";
            print_info(msg.as_ptr(), msg.len());
            return;
        }

        // adversarial sibling escape attempt 2: ../../data/test_fs_isolated_a_hash/secret.txt
        let sibling_p2 = "../../data/test_fs_isolated_a_hash/secret.txt";
        let mut s2_fd: i32 = -1;
        let r2 = path_open(dir_fd, 0, sibling_p2.as_ptr(), sibling_p2.len() as i32, 0, !0u64, !0u64, 0, &mut s2_fd);
        if r2 == 0 && s2_fd >= 0 {
            fd_close(s2_fd);
            let msg = "ISOLATED_B: BREACH_SIBLING_ROOT";
            print_info(msg.as_ptr(), msg.len());
            return;
        }

        // write plugin B secret
        let mut b_fd: i32 = -1;
        let b_path = "secret_b.txt";
        let b_res = path_open(dir_fd, 0, b_path.as_ptr(), b_path.len() as i32, 9, !0u64, !0u64, 0, &mut b_fd);
        if b_res == 0 && b_fd >= 0 {
            let b_data = b"SECRET_B_PAYLOAD";
            let ciovec = Ciovec { buf: b_data.as_ptr(), buf_len: b_data.len() };
            let mut written: i32 = 0;
            fd_write(b_fd, &ciovec, 1, &mut written);
            fd_close(b_fd);
        }

        let msg = "ISOLATED_B: ISOLATION_VERIFIED";
        print_info(msg.as_ptr(), msg.len());
    }
}
""",
        "manifest": """[plugin]
name = "fs_isolated_b"
version = "1.0.0"
author = "test"
api_version = "0.1.2a"
permissions = ["fs_scoped"]
"""
    }
}

def main():
    MOCK_DIR.mkdir(parents=True, exist_ok=True)
    MANIFEST_DIR.mkdir(parents=True, exist_ok=True)

    for name, data in PLUGINS.items():
        rs_path = MOCK_DIR / f"{name}.rs"
        toml_path = MANIFEST_DIR / f"{name}.toml"
        rs_path.write_text(data["rs"].strip() + "\n", encoding="utf-8")
        toml_path.write_text(data["manifest"].strip() + "\n", encoding="utf-8")
        print(f"Generated {rs_path.name} and {toml_path.name}")

if __name__ == "__main__":
    main()
