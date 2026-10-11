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
