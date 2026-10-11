// plugin without fs_scoped permission verifying zero preopens
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
