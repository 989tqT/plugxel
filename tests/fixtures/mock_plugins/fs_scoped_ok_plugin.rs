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
