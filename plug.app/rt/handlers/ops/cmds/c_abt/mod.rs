#[no_mangle]
pub extern "C" fn c_abt(_args: *const i8) -> i32 {
    let _ = crate::ops::utils::safe_cstr_to_string(_args).unwrap_or_default();
    let msgs = [
        "Name: plug",
        "Version: 1.0.0",
        "Features: Security, UI, Modular Commands",
    ];
    for &m in msgs.iter() {
        crate::ops::host::print_info(m);
    }
    0
}
