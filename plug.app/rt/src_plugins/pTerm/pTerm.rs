#[path = ".mod_.rs"]
pub mod terminal;

extern "C" {
    fn get_args(ptr: *mut u8, max_len: usize);
    fn host_add_tab(ptr: *const u8, len: usize);
    fn host_set_tab_owner(ptr: *const u8, len: usize);
    fn host_get_tab_label(ptr: *mut u8, max_len: usize) -> i32;
    fn host_get_platform() -> i32;
}

static mut MODE: i32 = 0; // 0: Auto, 1: CMD, 2: PS, 3: SH

#[no_mangle]
pub extern "C" fn run() {
    let mut buf = [0u8; 512];
    unsafe { get_args(buf.as_mut_ptr(), buf.len()) };
    let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let raw_args = std::str::from_utf8(&buf[..len]).unwrap_or("").trim();

    let args_lower = raw_args.to_lowercase();
    let is_ps_init = args_lower.starts_with("ps");
    let is_cmd_init = args_lower.starts_with("cmd");
    let is_sh_init = args_lower.starts_with("sh") || args_lower.starts_with("bash");
    
    if is_ps_init {
        unsafe { MODE = 2 };
    } else if is_cmd_init {
        unsafe { MODE = 1 };
    } else if is_sh_init {
        unsafe { MODE = 3 };
    }

    let mut query = raw_args.to_string();
    if is_ps_init { query = query.replacen("ps", "", 1).trim().to_string(); }
    else if is_cmd_init { query = query.replacen("cmd", "", 1).trim().to_string(); }
    else if is_sh_init {
        if args_lower.starts_with("bash") {
            query = query.replacen("bash", "", 1).trim().to_string();
        } else {
            query = query.replacen("sh", "", 1).trim().to_string();
        }
    }

    if is_ps_init || is_cmd_init || is_sh_init {
        if query.is_empty() {
            let tab_name = if is_ps_init { "PS" } else if is_cmd_init { "CMD" } else { "SH" };
            let plugin_name = "pTerm";
            unsafe { 
                host_add_tab(plugin_name.as_ptr(), plugin_name.len());
                host_set_tab_owner(tab_name.as_ptr(), tab_name.len());
            }
            let target = if is_ps_init { "PowerShell" } else if is_cmd_init { "CMD" } else { "SH" };
            terminal::print_info(&format!("{} Terminal Environment opened. Type commands directly.", target));
            
            if is_ps_init { terminal::execute_ps("cd ."); } 
            else if is_cmd_init { terminal::execute_cmd("cd ."); }
            else { terminal::execute_sh("cd ."); }
            return;
        }
    }

    let current_mode = unsafe { MODE };
    let final_mode = if current_mode != 0 {
        current_mode
    } else {
        let platform = unsafe { host_get_platform() };
        if platform == 1 {
            3
        } else {
            let mut label_buf = [0u8; 32];
            let label_len = unsafe { host_get_tab_label(label_buf.as_mut_ptr(), label_buf.len()) };
            if label_len > 0 {
                let label = std::str::from_utf8(&label_buf[..label_len as usize]).unwrap_or("");
                if label.to_uppercase() == "PS" {
                    2
                } else {
                    1
                }
            } else {
                1
            }
        }
    };

    if final_mode == 3 {
        terminal::execute_sh(&query);
    } else if final_mode == 2 {
        terminal::execute_ps(&query);
    } else {
        terminal::execute_cmd(&query);
    }
}

