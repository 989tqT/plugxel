use std::ffi::CString;
use tm_main::ops::proc::c_init;
use tm_main::ops::proc::c_cleanup;
use tm_main::ops::proc::c_is_running;
use tm_main::ops::proc::c_parse;

#[cfg(target_os = "linux")]
#[no_mangle]
pub extern "C" fn __rust_probestack() {}

#[cfg(windows)]
mod mocks {
    use std::os::raw::c_char;
    #[no_mangle] pub extern "C" fn main_w_print_info(_msg: *const c_char) {}
    #[no_mangle] pub extern "C" fn main_w_print_error(_msg: *const c_char) {}
    #[no_mangle] pub extern "C" fn main_w_add_tab(_owner: *const c_char) {}
    #[no_mangle] pub extern "C" fn main_w_request_close() {}
    #[no_mangle] pub extern "C" fn main_w_replace_last_line(_msg: *const c_char) {}
    #[no_mangle] pub extern "C" fn main_w_set_prompt_visibility(_visible: i32) {}
    #[no_mangle] pub extern "C" fn main_w_set_tab_owner(_tab_idx: i32, _owner_name: *const c_char) {}
    #[no_mangle] pub extern "C" fn main_w_get_tab_owner(_tab_idx: i32, _buf: *mut u8, _max_len: i32) -> i32 { 0 }
    #[no_mangle] pub extern "C" fn main_w_set_tab_cwd(_tab_idx: i32, _path: *const c_char) {}
    #[no_mangle] pub extern "C" fn main_w_get_current_print_tab() -> i32 { 0 }
}

#[cfg(not(windows))]
mod mocks {
    use std::os::raw::c_char;
    #[no_mangle] pub extern "C" fn main_l_print_info(_msg: *const c_char) {}
    #[no_mangle] pub extern "C" fn main_l_print_error(_msg: *const c_char) {}
    #[no_mangle] pub extern "C" fn main_l_add_tab(_owner: *const c_char) {}
    #[no_mangle] pub extern "C" fn main_l_request_close() {}
    #[no_mangle] pub extern "C" fn main_l_replace_last_line(_msg: *const c_char) {}
    #[no_mangle] pub extern "C" fn main_l_set_prompt_visibility(_visible: i32) {}
    #[no_mangle] pub extern "C" fn main_l_set_tab_owner(_tab_idx: i32, _owner_name: *const c_char) {}
    #[no_mangle] pub extern "C" fn main_l_get_tab_owner(_tab_idx: i32, _buf: *mut u8, _max_len: i32) -> i32 { 0 }
    #[no_mangle] pub extern "C" fn main_l_set_tab_cwd(_tab_idx: i32, _path: *const c_char) {}
    #[no_mangle] pub extern "C" fn main_l_get_current_print_tab() -> i32 { 0 }
}

#[test]
fn test_runtime_lifecycle_and_parsing() {
    c_cleanup();
    assert_eq!(c_is_running(), 0);

    let init_res = c_init();
    assert_eq!(init_res, 0);
    assert_eq!(c_is_running(), 1);

    // Empty command should return -1
    let cmd_empty = CString::new("").unwrap();
    assert_eq!(c_parse(cmd_empty.as_ptr() as *mut i8), -1);

    // Invalid command should return -1
    let cmd_invalid = CString::new("/unknown_cmd").unwrap();
    assert_eq!(c_parse(cmd_invalid.as_ptr() as *mut i8), -1);

    // Valid help command should return 0
    let cmd_help = CString::new("/?").unwrap();
    assert_eq!(c_parse(cmd_help.as_ptr() as *mut i8), 0);

    c_cleanup();
    assert_eq!(c_is_running(), 0);
}
