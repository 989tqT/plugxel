#[path = ".host/.mod_.rs"]
pub mod host;

pub fn execute_cmd(query: &str) {
    host::cmd::run(query);
}

pub fn execute_ps(query: &str) {
    host::ps::run(query);
}

pub fn execute_sh(query: &str) {
    host::sh::run(query);
}

pub fn print_info(msg: &str) {
    unsafe {
        crate::terminal::print_info_host(msg.as_ptr(), msg.len());
    }
}

pub fn print_error(msg: &str) {
    unsafe {
        crate::terminal::print_error_host(msg.as_ptr(), msg.len());
    }
}

extern "C" {
    #[link_name = "print_info"]
    pub fn print_info_host(ptr: *const u8, len: usize);
    #[link_name = "print_error"]
    pub fn print_error_host(ptr: *const u8, len: usize);
    pub fn host_exec(ptr: *const u8, len: usize);
    pub fn host_add_tab(ptr: *const u8, len: usize);
    pub fn host_set_tab_owner(ptr: *const u8, len: usize);
    pub fn host_get_tab_label(ptr: *mut u8, max_len: usize) -> i32;
    pub fn host_get_platform() -> i32;
}
