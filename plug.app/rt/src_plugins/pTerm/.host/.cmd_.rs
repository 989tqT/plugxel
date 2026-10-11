pub fn run(query: &str) {
    if query.is_empty() {
        crate::terminal::print_info("Terminal Interface: Type commands directly.");
        return;
    }
    
    let full_cmd = format!("cmd /c {}", query);
    
    unsafe {
        crate::terminal::host_exec(full_cmd.as_ptr(), full_cmd.len());
    }
}
