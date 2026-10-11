// plugin attempting unauthorized wasi import path_open
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
    let mut fd = -1;
    let path = b"test.txt";
    // calling path_open ensures LLVM does not dead-strip the import
    unsafe {
        path_open(3, 0, path.as_ptr(), path.len() as i32, 0, 0, 0, 0, &mut fd);
    }
    let msg = "UNAUTHORIZED_WASI_SHOULD_NEVER_RUN";
    unsafe { print_info(msg.as_ptr(), msg.len()); }
}
