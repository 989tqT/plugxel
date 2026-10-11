use crate::ops::host::request_close;

#[no_mangle]
pub extern "C" fn c_e(_input: *const i8) -> i32 {
    request_close();
    0
}
