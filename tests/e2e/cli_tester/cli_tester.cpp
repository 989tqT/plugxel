#include <iostream>
#include <string>
#include <vector>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

// rust FFI declarations
extern "C" {
    int c_init(void);
    void c_cleanup(void);
    int c_parse(char* input);
    
    // mocks of Win32/GTK interface logs and callbacks
    void main_w_print_info(const char* msg) { if (msg) std::cout << "[INFO] " << msg << "\n"; }
    void main_w_print_error(const char* msg) { if (msg) std::cerr << "[ERROR] " << msg << "\n"; }
    void main_w_add_tab(const char* owner) { if (owner) std::cout << "[TAB] " << owner << "\n"; }
    void main_w_replace_last_line(const char* msg) { if (msg) std::cout << "[REPLACE] " << msg << "\n"; }
    void main_w_set_prompt_visibility(int visible) {}
    void main_w_set_tab_owner(int tab_idx, const char* owner_name) {}
    int main_w_get_tab_owner(int tab_idx, char* buf, int max_len) { return 0; }
    void main_w_set_tab_cwd(int tab_idx, const char* path) {}
    int main_w_get_current_print_tab() { return 0; }
    void main_w_request_close() { std::cout << "[CLOSE]\n"; }
    
    // linux FFI interface mocks
    void main_l_print_info(const char* msg) { main_w_print_info(msg); }
    void main_l_print_error(const char* msg) { main_w_print_error(msg); }
    void main_l_add_tab(const char* owner) { main_w_add_tab(owner); }
    void main_l_replace_last_line(const char* msg) { main_w_replace_last_line(msg); }
    void main_l_set_prompt_visibility(int visible) {}
    void main_l_set_tab_owner(int tab_idx, const char* owner_name) {}
    int main_l_get_tab_owner(int tab_idx, char* buf, int max_len) { return 0; }
    void main_l_set_tab_cwd(int tab_idx, const char* path) {}
    int main_l_get_current_print_tab() { return 0; }
    void main_l_request_close() { main_w_request_close(); }
}

int main() {
    // initialize standard streams to force UTF-8 on Windows
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif

    if (c_init() != 0) {
        std::cerr << "[ERROR] Failed to initialize command runtime\n";
        return 1;
    }
    
    std::string line;
    while (std::getline(std::cin, line)) {
        if (line.empty()) continue;
        
        // pass to FFI router
        std::vector<char> buf(line.begin(), line.end());
        buf.push_back('\0');
        
        int res = c_parse(buf.data());
        (void)res;
        
        if (line == "/e") {
            break;
        }
    }
    
    c_cleanup();
    return 0;
}
