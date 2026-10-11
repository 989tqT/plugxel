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
        let p5 = "C:\\Windows\\System32\\notepad.exe";
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

        // attack 6b: adversarial truncate/create through symlink to outside secret
        // oflags 9 = O_CREAT (1) | O_TRUNC (8)
        let r6b = path_open(dir_fd, 1, p6.as_ptr(), p6.len() as i32, 9, !0u64, !0u64, 0, &mut fd);
        if r6b == 0 {
            fd_close(fd);
            let msg = "SCOPED_ESCAPE: BREACH_TRUNCATE_OUTSIDE";
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
