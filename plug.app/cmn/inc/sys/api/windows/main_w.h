#ifndef TM_MAIN_W_H
#define TM_MAIN_W_H

#ifdef __cplusplus
extern "C" {
#endif

#include <windows.h>
#include <stdint.h>

#define UI_COLOR_BLACK        0
#define UI_COLOR_BLUE         1
#define UI_COLOR_GREEN        2
#define UI_COLOR_CYAN         3
#define UI_COLOR_RED          4
#define UI_COLOR_MAGENTA      5
#define UI_COLOR_YELLOW       6
#define UI_COLOR_WHITE        7
#define UI_COLOR_BRIGHT       8

typedef struct {
    HANDLE hConsole;
    WORD default_attrs;
    int width;
    int height;
    BOOL animation_enabled;
    BOOL color_enabled;
} ui_state_t;

#define WM_APP_PRINT       (WM_APP + 1)
#define WM_APP_INVALIDATE  (WM_APP + 2)
#define WM_APP_CLEAR       (WM_APP + 3)
#define WM_APP_RECOLOR     (WM_APP + 4)
#define WM_APP_REQUEST_CLOSE (WM_APP + 10)
#define WM_APP_PRINT_TAB   (WM_APP + 20)
#define WM_APP_PRINT_SAFE  (WM_APP + 21)
#define WM_APP_REPLACE_LAST (WM_APP + 22)

#define MAX_FFI_MSG_LEN 4096

typedef struct {
    int tab_idx;
    uint32_t color;
    char message[MAX_FFI_MSG_LEN];
} shared_message_t;

int main_w_init(void);
void main_w_cleanup(void);
void main_w_clear_screen(void);
void main_w_set_color(WORD color);
void main_w_reset_color(void);
void main_w_print_banner(void);
void main_w_print_error(const char* msg);
void main_w_print_success(const char* msg);
void main_w_print_info(const char* msg);
void main_w_print_warning(const char* msg);
void main_w_replace_last_line(const char* msg);

void main_w_print_safe(const shared_message_t* sm);

void main_w_set_current_color(WORD color);
WORD main_w_get_current_color(void);

void main_w_recolor_console_all(void);

void main_w_set_console_title(const char* title);

void main_w_display_command_input(void);
void main_w_show_system_response(const char* response);
void main_w_show_caret(void);
void main_w_ensure_prompt(void);
int main_w_print_tab(void);
void main_w_request_close(void);
void main_w_set_prompt_visibility(int visible);
void main_w_add_tab(const char* owner);
void main_w_set_tab_owner(int tab_idx, const char* owner);
int main_w_get_tab_owner(int tab_idx, char* buf, int max_len);
void main_w_set_tab_cwd(int tab_idx, const char* cwd);
int main_w_get_current_print_tab(void);

void main_w_run_message_loop(void);

extern ui_state_t g_main_w_state;

#ifdef __cplusplus
}
#endif

#endif

