#include <windows.h>
#include <string>
#include <sys/api/windows/cmp/u_prmt.h>
#include <sys/api/windows/cmp/u_lbl.h>

#include <vector>

struct TabState {
    std::wstring title;
    std::vector<void*> raw_lines;
    std::vector<void*> wrapped_lines;
    std::string input_buffer;
    float content_scroll;
    float content_scroll_target;
    int content_total_height;
    bool user_scrolled;
    bool request_scroll_to_bottom;
    bool follow_on_output;
    int input_cursor;
    std::string plugin_owner;
    std::wstring cwd;
};

extern std::vector<TabState> g_tabs;
extern int g_active_tab;

std::wstring user_prm_get() {
    if (g_active_tab >= 0 && g_active_tab < (int)g_tabs.size()) {
        if (!g_tabs[g_active_tab].cwd.empty()) {
            return g_tabs[g_active_tab].cwd + L">";
        }
    }
    return L"<~>";
}

