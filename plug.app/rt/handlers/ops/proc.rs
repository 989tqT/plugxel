use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Once;
use crate::ops::host::{get_current_print_tab, get_tab_owner};

static INIT: Once = Once::new();
static RUNNING: AtomicBool = AtomicBool::new(false);

#[no_mangle]
pub extern "C" fn c_init() -> i32 {
    INIT.call_once(|| {
        RUNNING.store(true, Ordering::SeqCst);
        
        if let Some(sys_path) = crate::ops::utils::get_plugins_dir() {
            if let Some(path_str) = sys_path.to_str() {
                crate::ops::plugin_mgr::init_plugins(path_str);
            }
        }
    });
    0
}

#[no_mangle]
pub extern "C" fn c_cleanup() {
    RUNNING.store(false, Ordering::SeqCst);
}

/// must be called by ui layer before erasing tab from g_tabs
/// unloads any wasm plugin that was running in that tab
/// tab_idx: 0-based index of tab about to be closed
#[no_mangle]
pub extern "C" fn c_on_tab_close(tab_idx: i32) {
    crate::ops::plugin_mgr::unload_plugin_by_tab(tab_idx);
}


#[no_mangle]
pub extern "C" fn c_is_running() -> i32 {
    if RUNNING.load(Ordering::SeqCst) { 1 } else { 0 }
}

#[no_mangle]
pub extern "C" fn c_parse(input: *mut i8) -> i32 {
    let s = match crate::ops::utils::safe_cstr_to_string(input) {
        Some(val) => val,
        None => return -1,
    };

    let line = s.trim_start().trim_end().to_string();
    if line.is_empty() { return -1; }

    if !line.starts_with('/') {
        let tab_idx = get_current_print_tab();
        if let Some(owner) = get_tab_owner(tab_idx) {
            if crate::ops::plugin_mgr::dispatch_plugin_cmd(&owner, &line) {
                return 0;
            }
        }
    }

    let mut parts = line.splitn(2, char::is_whitespace);
    let cmd = parts.next().unwrap_or("");
    let args = parts.next().map(|a| a.trim()).unwrap_or("");

    let args_clean = args.replace('\0', " ");
    let c_args = crate::ops::utils::to_c_string(&args_clean);

    match cmd {
        "/a" => { return crate::ops::cmds::c_abt::c_abt(c_args.as_ptr() as *const i8); }
        "/?"  => { return crate::ops::cmds::c_q::c_q(c_args.as_ptr() as *const i8); }
        "/e"  => { return crate::ops::cmds::c_e::c_e(c_args.as_ptr() as *const i8); }
        "/tab" => { return crate::ops::cmds::c_nt::c_nt(c_args.as_ptr() as *const i8); }
        "/plug*" => { return crate::ops::cmds::c_plug::check::c_check(c_args.as_ptr() as *const i8); }
        "/plug-" => { return crate::ops::cmds::c_plug::del::c_del(c_args.as_ptr() as *const i8); }
        "/plug" => { return crate::ops::cmds::c_plug::c_plug(c_args.as_ptr() as *const i8); }

        "/cmd" | "/ps" | "/sh" => {
            let plugin_target = "pTerm";
            let full_args = format!("{} {}", cmd.trim_start_matches('/'), args_clean);
            if crate::ops::plugin_mgr::dispatch_plugin_cmd(plugin_target, &full_args.trim()) {
                return 0;
            }
            crate::ops::host::print_error(&format!("Could not run {} plugin.", plugin_target));
            return -1;
        }
        _ => {
            if crate::ops::plugin_mgr::dispatch_plugin_cmd(cmd.trim_start_matches('/'), &args_clean) {
                return 0;
            }

            crate::ops::host::print_error("Unknown command.");
            crate::ops::host::print_info("Type /? for help!!");
            return -1;
        }
    }
}
