use std::ffi::CString;

#[cfg(windows)]
extern "C" {
    #[link_name = "main_w_print_info"] fn ui_print_info(msg: *const i8);
    #[link_name = "main_w_print_error"] fn ui_print_error(msg: *const i8);
    #[link_name = "main_w_add_tab"] fn ui_add_tab(owner: *const i8);
    #[link_name = "main_w_request_close"] fn ui_request_close();
    #[link_name = "main_w_replace_last_line"] fn ui_replace_last_line(msg: *const i8);
    #[link_name = "main_w_set_prompt_visibility"] fn ui_set_prompt_visibility(visible: i32);
    #[link_name = "main_w_set_tab_owner"] fn ui_set_tab_owner(tab_idx: i32, owner_name: *const i8);
    #[link_name = "main_w_get_tab_owner"] fn ui_get_tab_owner(tab_idx: i32, buf: *mut u8, max_len: i32) -> i32;
    #[link_name = "main_w_set_tab_cwd"] fn ui_set_tab_cwd(tab_idx: i32, path: *const i8);
    #[link_name = "main_w_get_current_print_tab"] fn ui_get_current_print_tab() -> i32;
}

#[cfg(not(windows))]
extern "C" {
    #[link_name = "main_l_print_info"] fn ui_print_info(msg: *const i8);
    #[link_name = "main_l_print_error"] fn ui_print_error(msg: *const i8);
    #[link_name = "main_l_add_tab"] fn ui_add_tab(owner: *const i8);
    #[link_name = "main_l_request_close"] fn ui_request_close();
    #[link_name = "main_l_replace_last_line"] fn ui_replace_last_line(msg: *const i8);
    #[link_name = "main_l_set_prompt_visibility"] fn ui_set_prompt_visibility(visible: i32);
    #[link_name = "main_l_set_tab_owner"] fn ui_set_tab_owner(tab_idx: i32, owner_name: *const i8);
    #[link_name = "main_l_get_tab_owner"] fn ui_get_tab_owner(tab_idx: i32, buf: *mut u8, max_len: i32) -> i32;
    #[link_name = "main_l_set_tab_cwd"] fn ui_set_tab_cwd(tab_idx: i32, path: *const i8);
    #[link_name = "main_l_get_current_print_tab"] fn ui_get_current_print_tab() -> i32;
}

pub fn set_prompt_visibility(visible: bool) {
    unsafe { ui_set_prompt_visibility(if visible { 1 } else { 0 }); }
}

pub fn print_info(msg: &str) {
    if let Ok(c_msg) = CString::new(msg) {
        unsafe { ui_print_info(c_msg.as_ptr()); }
    }
}

pub fn print_error(msg: &str) {
    if let Ok(c_msg) = CString::new(msg) {
        unsafe { ui_print_error(c_msg.as_ptr()); }
    }
}

pub fn replace_last_line(msg: &str) {
    if let Ok(c_msg) = CString::new(msg) {
        unsafe { ui_replace_last_line(c_msg.as_ptr()); }
    }
}

pub fn add_tab(owner: &str) {
    if let Ok(c_owner) = CString::new(owner) {
        unsafe { ui_add_tab(c_owner.as_ptr()); }
    } else {
        unsafe { ui_add_tab(std::ptr::null()); }
    }
}

pub fn request_close() {
    unsafe { ui_request_close(); }
}

pub fn set_tab_owner(tab_idx: i32, name: &str) {
    if let Ok(c_name) = CString::new(name) {
        unsafe { ui_set_tab_owner(tab_idx, c_name.as_ptr()); }
    }
}

pub fn get_tab_owner(tab_idx: i32) -> Option<String> {
    let mut buf = [0u8; 128];
    let len = unsafe { ui_get_tab_owner(tab_idx, buf.as_mut_ptr(), buf.len() as i32) };
    if len > 0 {
        Some(String::from_utf8_lossy(&buf[..len as usize]).to_string())
    } else {
        None
    }
}

pub fn set_tab_cwd(tab_idx: i32, path: &str) {
    if let Ok(c_path) = CString::new(path) {
        unsafe { ui_set_tab_cwd(tab_idx, c_path.as_ptr()); }
    }
}

pub fn get_current_print_tab() -> i32 {
    unsafe { ui_get_current_print_tab() }
}
