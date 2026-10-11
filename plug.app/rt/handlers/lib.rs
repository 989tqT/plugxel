pub mod ops {
    pub mod cmds;
    pub mod proc;
    pub mod plugin_mgr;
    pub mod utils;
    pub mod host;
    pub mod net;
}

#[cfg(test)]
#[cfg(windows)]
mod test_mocks {
    use std::os::raw::c_char;

    #[no_mangle]
    pub extern "C" fn main_w_print_info(_msg: *const c_char) {}

    #[no_mangle]
    pub extern "C" fn main_w_print_error(_msg: *const c_char) {}

    #[no_mangle]
    pub extern "C" fn main_w_add_tab(_owner: *const c_char) {}

    #[no_mangle]
    pub extern "C" fn main_w_request_close() {}

    #[no_mangle]
    pub extern "C" fn main_w_replace_last_line(_msg: *const c_char) {}

    #[no_mangle]
    pub extern "C" fn main_w_set_prompt_visibility(_visible: i32) {}

    #[no_mangle]
    pub extern "C" fn main_w_set_tab_owner(_tab_idx: i32, _owner_name: *const c_char) {}

    #[no_mangle]
    pub extern "C" fn main_w_get_tab_owner(_tab_idx: i32, _buf: *mut u8, _max_len: i32) -> i32 { 0 }

    #[no_mangle]
    pub extern "C" fn main_w_set_tab_cwd(_tab_idx: i32, _path: *const c_char) {}

    #[no_mangle]
    pub extern "C" fn main_w_get_current_print_tab() -> i32 { 0 }
}

#[cfg(test)]
#[cfg(not(windows))]
mod test_mocks {
    use std::os::raw::c_char;

    #[no_mangle]
    pub extern "C" fn main_l_print_info(_msg: *const c_char) {}

    #[no_mangle]
    pub extern "C" fn main_l_print_error(_msg: *const c_char) {}

    #[no_mangle]
    pub extern "C" fn main_l_add_tab(_owner: *const c_char) {}

    #[no_mangle]
    pub extern "C" fn main_l_request_close() {}

    #[no_mangle]
    pub extern "C" fn main_l_replace_last_line(_msg: *const c_char) {}

    #[no_mangle]
    pub extern "C" fn main_l_set_prompt_visibility(_visible: i32) {}

    #[no_mangle]
    pub extern "C" fn main_l_set_tab_owner(_tab_idx: i32, _owner_name: *const c_char) {}

    #[no_mangle]
    pub extern "C" fn main_l_get_tab_owner(_tab_idx: i32, _buf: *mut u8, _max_len: i32) -> i32 { 0 }

    #[no_mangle]
    pub extern "C" fn main_l_set_tab_cwd(_tab_idx: i32, _path: *const c_char) {}

    #[no_mangle]
    pub extern "C" fn main_l_get_current_print_tab() -> i32 { 0 }
}

