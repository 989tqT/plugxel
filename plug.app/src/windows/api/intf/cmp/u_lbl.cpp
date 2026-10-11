#include <windows.h>
#include <string>
#include <atomic>
#include "../../../../../cmn/inc/sys/sys_info.h"
#include <sys/api/windows/cmp/u_lbl.h>
#include <sys/api/windows/main_w.h>

#include <cstring>
#include <cstdlib>

extern HWND g_hwnd;
extern HFONT g_mono_font;
extern void caret_show();

extern "C" void main_w_print_safe(const shared_message_t* sm);
extern "C" void main_w_replace_last_line_safe(const char* msg);

void main_w_print_safe(const shared_message_t* sm) {
    if (!sm || !g_hwnd) return;
    
    int l = (int)strlen(sm->message);
    if (l > MAX_FFI_MSG_LEN) l = MAX_FFI_MSG_LEN;

    static shared_message_t s_msg_pool[32];
    static std::atomic_int s_msg_idx{0};
    
    int idx = s_msg_idx.fetch_add(1) % 32;
    shared_message_t* pool_msg = &s_msg_pool[idx];
    
    pool_msg->tab_idx = sm->tab_idx;
    pool_msg->color = sm->color;
    strncpy(pool_msg->message, sm->message, MAX_FFI_MSG_LEN - 1);
    pool_msg->message[MAX_FFI_MSG_LEN - 1] = '\0';

    PostMessageW(g_hwnd, WM_APP_PRINT_SAFE, 0, (LPARAM)pool_msg);
}

void main_w_replace_last_line_safe(const char* msg) {
    if (!msg || !g_hwnd) return;

    static shared_message_t s_replace_pool[8];
    static std::atomic_int s_replace_idx{0};
    
    int idx = s_replace_idx.fetch_add(1) % 8;
    shared_message_t* pool_msg = &s_replace_pool[idx];
    
    pool_msg->tab_idx = -1;
    pool_msg->color = UI_COLOR_WHITE;
    strncpy(pool_msg->message, msg, MAX_FFI_MSG_LEN - 1);
    pool_msg->message[MAX_FFI_MSG_LEN - 1] = '\0';

    PostMessageW(g_hwnd, WM_APP_REPLACE_LAST, 0, (LPARAM)pool_msg);
}
