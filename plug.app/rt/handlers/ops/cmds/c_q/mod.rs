#[no_mangle]
pub extern "C" fn c_q(_args: *const i8) -> i32 {
    let msgs = [
        "Available Commands:",
        "  /a      - About this application",
        "  /?      - Show this help message",
        "  /e      - Exit application",
        "  /tab    - Open new tab",
        "  /plug   - Install plugin from URL",
        "  /plug*  - Check registry / list plugins",
        "  /plug-  - Delete a plugin by hash",
    ];
    for &m in msgs.iter() {
        crate::ops::host::print_info(m);
    }
    0
}
