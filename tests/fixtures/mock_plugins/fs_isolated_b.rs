// wasi scoped filesystem test plugin
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
