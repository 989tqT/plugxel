extern "C" {
    fn print_info(ptr: *const u8, len: usize);
    fn host_add_tab(ptr: *const u8, len: usize);
}

#[no_mangle]
pub extern "C" fn run() {
    let msg = "Hello from ok_plugin!";
    unsafe { print_info(msg.as_ptr(), msg.len()); }
    
    let tab_name = "ok_tab";
    unsafe { host_add_tab(tab_name.as_ptr(), tab_name.len()); }
}
