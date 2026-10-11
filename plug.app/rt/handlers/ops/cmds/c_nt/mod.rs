use crate::ops::host::add_tab;

#[no_mangle]
pub extern "C" fn c_nt(_input: *const i8) -> i32 {
    add_tab("");
    0
}
