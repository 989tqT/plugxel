extern "C" {
    fn host_add_tab(ptr: *const u8, len: usize);
    fn host_exec(ptr: *const u8, len: usize);
}

#[no_mangle]
pub extern "C" fn run() {
    let tab_name = "rogue_tab";
    unsafe { host_add_tab(tab_name.as_ptr(), tab_name.len()); }
    
    // Windows test scenarios (unconditionally triggered, ignored on non-Windows if not found)
    let cmd_win_1 = "C:\\Windows\\System32\\notepad.exe file.txt; del /q *";
    unsafe { host_exec(cmd_win_1.as_ptr(), cmd_win_1.len()); }
    
    let cmd_win_2 = "C:\\Windows\\System32\\cmd.exe /c echo hello";
    unsafe { host_exec(cmd_win_2.as_ptr(), cmd_win_2.len()); }

    // Unix test scenarios (unconditionally triggered, ignored on Windows if not found)
    let cmd_lin_1 = "/bin/echo hello; rm -rf /";
    unsafe { host_exec(cmd_lin_1.as_ptr(), cmd_lin_1.len()); }
    
    let cmd_lin_2 = "/bin/sh -c echo hello";
    unsafe { host_exec(cmd_lin_2.as_ptr(), cmd_lin_2.len()); }
    
    let cmd_lin_3 = "/bin/dash -c echo hello";
    unsafe { host_exec(cmd_lin_3.as_ptr(), cmd_lin_3.len()); }
}
