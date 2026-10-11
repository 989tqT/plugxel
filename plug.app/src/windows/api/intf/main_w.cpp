#include <windows.h>
#include <windowsx.h>
#include <vector>
#include <string>
#include <mutex>
#include <atomic>
#include <chrono>
#include <cmath>
#include <sstream>
#include <thread>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <sys/api/windows/cmp/u_prmt.h>
#include <sys/api/windows/cmp/caret.h>
#include <sys/api/windows/cmp/tab.h>
#include <sys/api/windows/cmp/selection.h>
#include <sys/api/windows/cmp/scrollbar.h>
#include <sys/api/windows/cmp/u_lbl.h>
#include <sys/api/windows/cmp/clipboard.h>
#include <sys/api/windows/cmp/effects/m_hover.h>
#include <queue>

extern "C" {
#include "../../../../cmn/inc/sys/sys_info.h"
#include "../../../../cmn/inc/sys/api/windows/main_w.h"
#include "../../../../cmn/inc/sys/c.h"
}

ui_state_t g_main_w_state = {0};

struct DisplayLine {
    std::wstring text;
    COLORREF color;
    bool is_continuation = false;
};

struct TabState {
    std::wstring title = L"";
    std::vector<DisplayLine> raw_lines;
    std::vector<DisplayLine> wrapped_lines;
    std::string input_buffer = "";
    float content_scroll = 0.0f;
    float content_scroll_target = 0.0f;
    int content_total_height = 0;
    bool user_scrolled = false;
    bool request_scroll_to_bottom = true;
    bool follow_on_output = true;
    int input_cursor = 0;
    std::string plugin_owner = "";
    std::wstring cwd = L""; // Current Working Directory for Native mode
};

HWND g_hwnd = NULL;
HFONT g_mono_font = NULL;
std::vector<TabState> g_tabs;
int g_active_tab = 0;
std::mutex g_mutex;
static std::atomic_bool g_running_ui{false};
static std::atomic_bool g_prompt_locked{false};
DWORD g_ui_thread_id = 0;

static float g_tab_scroll = 0.0f;
static float g_tab_scroll_target = 0.0f;
static int g_tab_counter = 1;
static float g_scroll_alpha = 0.0f;
static std::chrono::steady_clock::time_point g_last_scroll_activity;
static const UINT_PTR g_scroll_timer = 2;

static float g_content_scroll = 0.0f;
static float g_content_scroll_target = 0.0f;
static int g_content_total_height = 0;
static std::atomic_bool g_user_scrolled{false};
static std::atomic_bool g_request_scroll_to_bottom{false};

extern const COLORREF COL_BG = RGB(30,30,30);
extern const COLORREF COL_HEADER = RGB(20,20,20);
extern const COLORREF COL_USER = RGB(90,255,90);
extern const COLORREF COL_CMD = RGB(255,90,90);
extern const COLORREF COL_OUTPUT = RGB(230,230,230);
static const int PATH_X_OFFSET = 25;

static std::thread g_cmd_thread;
static std::mutex g_cmd_mutex;
static std::condition_variable g_cmd_cv;
struct CmdItem { int tab; std::string cmd; };
static std::queue<CmdItem> g_cmd_queue;
static std::atomic_bool g_cmd_thread_running{false};
thread_local int g_print_tab = -1;

extern "C" int main_w_print_tab(void) {
    return g_print_tab;
}

extern "C" void main_w_set_tab_cwd(int tab_idx, const char* path) {
    if (tab_idx < 0 || tab_idx >= (int)g_tabs.size()) return;
    if (!path) {
        g_tabs[tab_idx].cwd = L"";
        return;
    }
    int len = MultiByteToWideChar(CP_UTF8, 0, path, -1, NULL, 0);
    if (len > 0) {
        std::wstring wpath(len, 0);
        MultiByteToWideChar(CP_UTF8, 0, path, -1, &wpath[0], len);
        if (!wpath.empty() && wpath.back() == L'\0') wpath.pop_back();
        g_tabs[tab_idx].cwd = wpath;
    }
}
static std::vector<RECT> g_tab_close_rects;
static bool g_mouse_tracked = false;
static RECT g_tab_scroll_track_rect = {0,0,0,0};
static RECT g_tab_scroll_thumb_rect = {0,0,0,0};
static bool g_tab_scroll_thumb_visible = false;
static bool g_drag_tab_scrollbar = false;
static int g_drag_tab_grab_dx = 0;
static RECT g_content_scroll_track_rect = {0,0,0,0};
static RECT g_content_scroll_thumb_rect = {0,0,0,0};
static bool g_content_scroll_thumb_visible = false;
static bool g_drag_content_scrollbar = false;
static int g_drag_content_grab_dy = 0;

#if defined(PLUGXEL_ENABLE_HEADLESS_MODE) || defined(PLUG_ENABLE_HEADLESS_MODE)
#include <iostream>
#include <sstream>

extern "C" bool g_headless_mode;
static std::thread g_headless_stdin_thread;

static void headless_stdin_worker(void) {
    std::string line;
    // read input from stdin line by line
    while (std::getline(std::cin, line)) {
        if (line.empty()) continue;

        // check for test state dump request magic command string
        if (line == "__dump_state__") {
            PostMessageW(g_hwnd, WM_APP + 200, 0, 0);
            continue;
        }

        // convert the utf-8 input line to utf-16
        int n = MultiByteToWideChar(CP_UTF8, 0, line.c_str(), -1, NULL, 0);
        if (n > 0) {
            std::vector<wchar_t> wline(n);
            MultiByteToWideChar(CP_UTF8, 0, line.c_str(), -1, wline.data(), n);

            // post wm_char character message to simulate key press
            for (size_t i = 0; i < wline.size() - 1; ++i) {
                PostMessageW(g_hwnd, WM_CHAR, wline[i], 0);
            }
            // conclude with enter key press
            PostMessageW(g_hwnd, WM_CHAR, L'\r', 0);
        }
    }
    // EOF reached (stdin closed) - exit gracefully
    if (g_hwnd) {
        PostMessageW(g_hwnd, WM_APP_REQUEST_CLOSE, 0, 0);
    }
}
#endif

static void command_worker_thread(void) {
    while (g_cmd_thread_running.load()) {
        CmdItem it = {-1, std::string()};
        {
            std::unique_lock<std::mutex> lk(g_cmd_mutex);
            g_cmd_cv.wait(lk, []{ return !g_cmd_queue.empty() || !g_cmd_thread_running.load(); });
            if (!g_cmd_thread_running.load() && g_cmd_queue.empty()) break;
            if (!g_cmd_queue.empty()) {
                it = std::move(g_cmd_queue.front());
                g_cmd_queue.pop();
            }
        }
        if (it.tab < 0 || it.cmd.empty()) continue;

        g_print_tab = it.tab;
        std::vector<char> buf(it.cmd.begin(), it.cmd.end()); buf.push_back('\0');
        int res = c_parse(buf.data());
        (void)res;
        g_print_tab = -1;

        {
            std::lock_guard<std::mutex> lk(g_mutex);
            if (it.tab >=0 && it.tab < (int)g_tabs.size()) {
                g_tabs[it.tab].follow_on_output = false;
                g_tabs[it.tab].request_scroll_to_bottom = true;
            }
        }

        PostMessageW(g_hwnd, WM_APP_INVALIDATE, 0, 0);
    }
}

static void enqueue_command_nolock(int tab, const std::string &s) {
    std::lock_guard<std::mutex> lk(g_cmd_mutex);
    g_cmd_queue.push({tab, s});
    g_cmd_cv.notify_one();
}

extern "C" int main_w_init(void);
extern "C" void main_w_cleanup(void);
extern "C" void main_w_run_message_loop(void);
extern "C" void main_w_print_banner(void);
extern "C" void main_w_print_error(const char* msg);
extern "C" void main_w_print_success(const char* msg);
extern "C" void main_w_print_info(const char* msg);
extern "C" void main_w_print_warning(const char* msg);
extern "C" void main_w_set_current_color(WORD color);
extern "C" WORD main_w_get_current_color(void);
extern "C" void main_w_set_console_title(const char* title);
extern "C" void main_w_display_command_input(void);
extern "C" void main_w_show_system_response(const char* response);
extern "C" void main_w_show_caret(void);
extern "C" void main_w_ensure_prompt(void);
extern "C" void main_w_set_prompt_visibility(int visible) {
    g_prompt_locked = (visible == 0);
    PostMessageW(g_hwnd, WM_APP_INVALIDATE, 0, 0);
}

void rewrap_tab(int idx, int content_width) {
    if (idx < 0 || idx >= (int)g_tabs.size()) return;
    TabState &t = g_tabs[idx];
    t.wrapped_lines.clear();
    if (content_width <= 0) return;

    HDC hdc = GetDC(g_hwnd);
    HFONT oldf = (HFONT)SelectObject(hdc, g_mono_font);
    SIZE az; GetTextExtentPoint32W(hdc, L"A", 1, &az);
    int char_w = az.cx;
    int line_h = az.cy + 6;
    int chars_per_line = content_width / char_w;
    if (chars_per_line <= 0) chars_per_line = 1;

    for (const auto &raw : t.raw_lines) {
        std::wstring text = raw.text;
        bool is_cmd = (raw.color == COL_CMD);
        std::wstring prefix = L"";
        if (is_cmd) {
            prefix = user_prm_get() + L" ";
        }

        if (text.empty() && !is_cmd) {
            t.wrapped_lines.push_back({L"", raw.color});
            continue;
        }

        std::wstring full = prefix + text;
        if (full.empty()) {
             t.wrapped_lines.push_back({L"", raw.color});
             continue;
        }

        int off = 0;
        bool first_segment = true;
        while (off < (int)full.size()) {
            int take = std::min(chars_per_line, (int)full.size() - off);
            t.wrapped_lines.push_back({full.substr(off, take), raw.color, !first_segment});
            off += take;
            first_segment = false;
        }
    }

    t.content_total_height = (int)t.wrapped_lines.size() * line_h;

    t.content_total_height += line_h * 2; 

    SelectObject(hdc, oldf);
    ReleaseDC(g_hwnd, hdc);
}

void rewrap_all_tabs() {
    std::lock_guard<std::mutex> lk(g_mutex);
    RECT rc; GetClientRect(g_hwnd, &rc);
    int content_width = (rc.right - rc.left) - 32;
    if (content_width < 0) content_width = 0;
    for (int i = 0; i < (int)g_tabs.size(); ++i) {
        rewrap_tab(i, content_width);
    }
}

void push_line(const std::wstring& s, COLORREF color) {
    std::lock_guard<std::mutex> lk(g_mutex);
    if (g_tabs.empty()) g_tabs.emplace_back();
    TabState &t = g_tabs[g_active_tab];
    t.raw_lines.push_back({s, color});

    RECT rc; GetClientRect(g_hwnd, &rc);
    int content_width = (rc.right - rc.left) - 32;
    rewrap_tab(g_active_tab, content_width);

    if (t.follow_on_output || !t.user_scrolled) {
        int avail = (rc.bottom - rc.top) - (44 + 28 + 8) - 12;
        if (avail < 0) avail = 0;
        int diff = t.content_total_height - avail;
        if (diff < 0) diff = 0;
        t.content_scroll_target = (float)diff;
        t.content_scroll = t.content_scroll_target;
        t.request_scroll_to_bottom = false;
    }
    InvalidateRect(g_hwnd, NULL, FALSE);
}

void push_line_tab(int tabidx, const std::wstring& s, COLORREF color) {
    std::lock_guard<std::mutex> lk(g_mutex);
    if (g_tabs.empty()) g_tabs.emplace_back();
    if (tabidx < 0 || tabidx >= (int)g_tabs.size()) return;
    TabState &t = g_tabs[tabidx];
    t.raw_lines.push_back({s, color});

    RECT rc; GetClientRect(g_hwnd, &rc);
    int content_width = (rc.right - rc.left) - 32;
    rewrap_tab(tabidx, content_width);

    if (t.follow_on_output || !t.user_scrolled) {
        int avail = (rc.bottom - rc.top) - (44 + 28 + 8) - 12;
        if (avail < 0) avail = 0;
        int diff = t.content_total_height - avail;
        if (diff < 0) diff = 0;
        t.content_scroll_target = (float)diff;
        t.content_scroll = t.content_scroll_target;
        t.request_scroll_to_bottom = false;
    }
    InvalidateRect(g_hwnd, NULL, FALSE);
}

static void draw_rounded_rect(HDC hdc, RECT rc, int radius, COLORREF color) {
    (void)radius;
    HBRUSH br = CreateSolidBrush(color);
    FillRect(hdc, &rc, br);
    DeleteObject(br);
}

static COLORREF map_word_to_color(WORD w);

static void render(HDC hdc) {
    RECT r;
    GetClientRect(g_hwnd, &r);
    HDC real_hdc = hdc;
    int ww = r.right - r.left;
    int hh = r.bottom - r.top;
    if (ww <= 0) ww = 1;
    if (hh <= 0) hh = 1;
    HDC mem = CreateCompatibleDC(real_hdc);
    HBITMAP bmp = CreateCompatibleBitmap(real_hdc, ww, hh);
    HBITMAP oldbmp = (HBITMAP)SelectObject(mem, bmp);
    hdc = mem;

    std::vector<std::wstring> tab_titles;
    std::vector<DisplayLine> lines_copy;
    std::string input_copy;
    int active_index = 0;
    float tab_content_scroll = 0.0f;
    float tab_content_scroll_target = 0.0f;
    int tab_content_total_height = 0;
    bool tab_user_scrolled = false;
    bool tab_request_scroll_to_bottom = false;
    bool tab_follow_on_output = false; (void)tab_follow_on_output;
    {
        std::lock_guard<std::mutex> lk(g_mutex);
        if (g_tabs.empty()) {
        TabState nt; nt.title = L"Tab 1"; nt.content_scroll = nt.content_scroll_target = 0.0f; nt.content_total_height = 0; nt.user_scrolled = false; nt.request_scroll_to_bottom = true; g_tabs.push_back(std::move(nt));
            g_active_tab = 0;
        }
        active_index = g_active_tab;
        if (active_index < 0) active_index = 0;
        if (active_index >= (int)g_tabs.size()) active_index = (int)g_tabs.size()-1;
        tab_titles.reserve(g_tabs.size());
        for (const auto &t : g_tabs) tab_titles.push_back(t.title);
        lines_copy = g_tabs[active_index].wrapped_lines;
        input_copy = g_tabs[active_index].input_buffer;
        tab_content_scroll = g_tabs[active_index].content_scroll;
        tab_content_scroll_target = g_tabs[active_index].content_scroll_target;
        tab_content_total_height = g_tabs[active_index].content_total_height;
        tab_user_scrolled = g_tabs[active_index].user_scrolled;
        tab_request_scroll_to_bottom = g_tabs[active_index].request_scroll_to_bottom;
        tab_follow_on_output = g_tabs[active_index].follow_on_output;
    }

    g_content_scroll = tab_content_scroll;
    g_content_scroll_target = tab_content_scroll_target;
    g_content_total_height = tab_content_total_height;
    g_user_scrolled = tab_user_scrolled;
    g_request_scroll_to_bottom = tab_request_scroll_to_bottom;

    HBRUSH bg = CreateSolidBrush(COL_BG);
    FillRect(hdc, &r, bg);
    DeleteObject(bg);

    RECT hr = r; hr.bottom = hr.top + 44;
    draw_rounded_rect(hdc, hr, 6, COL_HEADER);

    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, RGB(200,200,200));
    HFONT oldf = (HFONT)SelectObject(hdc, g_mono_font);
    std::wstring title = L"plugxel";
    RECT tr = hr; tr.left += 12; tr.top += 10;
    DrawTextW(hdc, title.c_str(), (int)title.size(), &tr, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);

    RECT tabr = r; tabr.top = hr.bottom; tabr.bottom = hr.bottom + 28;

    RECT pre_content = r; pre_content.top = tabr.bottom; pre_content.left = r.left + 16; pre_content.right = r.right - 16; pre_content.bottom = r.bottom - 8;
    COLORREF pre_content_bg = RGB(16,16,16);
    HBRUSH pre_content_br = CreateSolidBrush(pre_content_bg);
    FillRect(hdc, &pre_content, pre_content_br);
    DeleteObject(pre_content_br);

    tab_render_bar(hdc, tabr, tab_titles, active_index, g_tab_scroll, g_scroll_alpha, g_tab_close_rects, g_hover_close_tab);

    RECT sb = tabr; sb.top = tabr.bottom - 8; sb.bottom = tabr.bottom - 2; sb.left += 12; sb.right -= 12;
    int tabbar_w = (int)tab_titles.size() * 150;
    int visible = sb.right - sb.left;
    RECT sb_inner = sb; sb_inner.top += 1; sb_inner.bottom -= 1;
    g_tab_scroll_track_rect = sb_inner;
    g_tab_scroll_thumb_visible = scrollb_compute_thumb_rect(sb_inner, tabbar_w, visible, g_tab_scroll, g_tab_scroll_thumb_rect);
    scrollb_render_horizontal(hdc, sb_inner, tabbar_w, visible, g_tab_scroll, g_scroll_alpha);

    SIZE az; GetTextExtentPoint32W(hdc, L"A", 1, &az);
    int char_w = az.cx;
    int line_h = az.cy + 6;

    RECT content = r; content.top = tabr.bottom; content.left = r.left + 16; content.right = r.right - 16; content.bottom = r.bottom - 8;
    COLORREF content_bg_color = RGB(16,16,16);
    HBRUSH content_bg = CreateSolidBrush(content_bg_color);
    FillRect(hdc, &content, content_bg);
    DeleteObject(content_bg);

    RECT content_track = {content.right - 8, content.top + 8, content.right - 3, content.bottom - 8};
    int content_visible_h = content.bottom - content.top;
    g_content_scroll_track_rect = content_track;
    g_content_scroll_thumb_visible = scrollb_compute_thumb_rect_vertical(
        content_track,
        tab_content_total_height,
        content_visible_h,
        tab_content_scroll,
        g_content_scroll_thumb_rect
    );

    int y = content.top + 8;
    int chars_per_line = (content.right - content.left) / char_w;
    if (chars_per_line <= 0) chars_per_line = 1;

    std::wstring prompt_p = user_prm_get() + L" ";
    int prompt_len = (int)prompt_p.size();

    int saved_dc = SaveDC(hdc);
    IntersectClipRect(hdc, content.left, content.top, content.right, content.bottom);
    int current_line_idx = 0;
    for (const auto& ln : lines_copy) {
        int sel_s, sel_e;
        if (selection_get_line_range(current_line_idx, (int)ln.text.size(), sel_s, sel_e)) {
            SIZE s1 = {0}, s2 = {0};
            if (sel_s > 0) GetTextExtentPoint32W(hdc, ln.text.c_str(), sel_s, &s1);
            GetTextExtentPoint32W(hdc, ln.text.c_str(), sel_e, &s2);
            RECT rsel = {content.left + s1.cx, y - (int)tab_content_scroll, content.left + s2.cx, y - (int)tab_content_scroll + line_h};
            selection_render_highlight(hdc, rsel);
        }

        COLORREF draw_color = hover_get_color(ln.color, current_line_idx);

        if (ln.color == COL_CMD && !ln.is_continuation) {
            std::wstring p1 = ln.text.substr(0, prompt_len);
            std::wstring p2 = (ln.text.size() > (size_t)prompt_len) ? ln.text.substr(prompt_len) : L"";
            
            // special color for user prompt prefix brightened on hover
            COLORREF user_color = hover_get_color(COL_USER, current_line_idx);
            SetTextColor(hdc, user_color);
            RECT r1 = {content.left, y - (int)tab_content_scroll, content.right, content.bottom};
            DrawTextW(hdc, p1.c_str(), (int)p1.size(), &r1, DT_LEFT|DT_TOP|DT_SINGLELINE | DT_NOPREFIX);
            
            if (!p2.empty()) {
                SIZE psz; GetTextExtentPoint32W(hdc, p1.c_str(), (int)p1.size(), &psz);
                SetTextColor(hdc, draw_color);
                RECT r2 = {content.left + psz.cx, y - (int)tab_content_scroll, content.right, content.bottom};
                DrawTextW(hdc, p2.c_str(), (int)p2.size(), &r2, DT_LEFT|DT_TOP|DT_SINGLELINE | DT_NOPREFIX);
            }
        } else {
            SetTextColor(hdc, draw_color);
            RECT lr = {content.left, y - (int)tab_content_scroll, content.right, content.bottom};
            DrawTextW(hdc, ln.text.c_str(), (int)ln.text.size(), &lr, DT_LEFT|DT_TOP|DT_SINGLELINE | DT_NOPREFIX);
        }
        y += line_h;
        current_line_idx++;
        if (y - (int)tab_content_scroll > content.bottom) break;
    }
    
    if (g_prompt_locked.load()) {

    } else {

        std::wstring prompt = user_prm_get() + L" ➜ ";
        int live_prompt_len = (int)prompt.size();
        std::wstring win;
        if (!input_copy.empty()) {
            int need = MultiByteToWideChar(CP_UTF8, 0, input_copy.c_str(), (int)input_copy.size(), NULL, 0);
            win.resize(need);
            MultiByteToWideChar(CP_UTF8, 0, input_copy.c_str(), (int)input_copy.size(), &win[0], need);
        }

        int cursor_wchar_pos = 0;
        {
            std::lock_guard<std::mutex> lk(g_mutex);
            if (active_index >= 0 && g_tabs[active_index].input_cursor > 0) {
                cursor_wchar_pos = MultiByteToWideChar(CP_UTF8, 0, input_copy.c_str(), g_tabs[active_index].input_cursor, NULL, 0);
            }
        }
        int target_wchar_idx = live_prompt_len + cursor_wchar_pos;

        std::wstring live_full = prompt + win;
        int off = 0;
        int cx = content.left;
        int last_y = y;
        while (off < (int)live_full.size()) {
            int take = std::min(chars_per_line, (int)live_full.size() - off);
            std::wstring part = live_full.substr(off, take);

            int line_start = off;
            int line_end = off + take;

            // draw selection for live input line
            int sel_s, sel_e;
            if (selection_get_line_range(current_line_idx, (int)live_full.size(), sel_s, sel_e)) {
                // determine the overlap between [line_start, line_end) and [sel_s, sel_e)
                int overlap_s = std::max(line_start, sel_s);
                int overlap_e = std::min(line_end, sel_e);
                if (overlap_s < overlap_e) {
                    SIZE s1 = {0}, s2 = {0};
                    if (overlap_s > line_start) GetTextExtentPoint32W(hdc, part.c_str(), overlap_s - line_start, &s1);
                    GetTextExtentPoint32W(hdc, part.c_str(), overlap_e - line_start, &s2);
                    RECT rsel = {content.left + s1.cx, y - (int)tab_content_scroll, content.left + s2.cx, y - (int)tab_content_scroll + line_h};
                    selection_render_highlight(hdc, rsel);
                }
            }

            if (line_end <= live_prompt_len) {
                SetTextColor(hdc, COL_USER);
                RECT ir = {content.left, y - (int)tab_content_scroll, content.right, content.bottom};
                DrawTextW(hdc, part.c_str(), (int)part.size(), &ir, DT_LEFT|DT_TOP|DT_SINGLELINE | DT_NOPREFIX);
            } else if (line_start >= live_prompt_len) {
                SetTextColor(hdc, COL_CMD);
                RECT ir = {content.left, y - (int)tab_content_scroll, content.right, content.bottom};
                DrawTextW(hdc, part.c_str(), (int)part.size(), &ir, DT_LEFT|DT_TOP|DT_SINGLELINE | DT_NOPREFIX);
            } else {
                int p1_len = live_prompt_len - line_start;
                std::wstring p1 = part.substr(0, p1_len);
                std::wstring p2 = part.substr(p1_len);
                
                SetTextColor(hdc, COL_USER);
                RECT r1 = {content.left, y - (int)tab_content_scroll, content.right, content.bottom};
                DrawTextW(hdc, p1.c_str(), (int)p1.size(), &r1, DT_LEFT|DT_TOP|DT_SINGLELINE | DT_NOPREFIX);
                
                SIZE psz; GetTextExtentPoint32W(hdc, p1.c_str(), (int)p1.size(), &psz);
                SetTextColor(hdc, COL_CMD);
                RECT r2 = {content.left + psz.cx, y - (int)tab_content_scroll, content.right, content.bottom};
                DrawTextW(hdc, p2.c_str(), (int)p2.size(), &r2, DT_LEFT|DT_TOP|DT_SINGLELINE | DT_NOPREFIX);
            }

            if (target_wchar_idx >= off && target_wchar_idx <= off + take) {
                std::wstring to_cursor = part.substr(0, target_wchar_idx - off);
                SIZE cpsz; GetTextExtentPoint32W(hdc, to_cursor.c_str(), (int)to_cursor.size(), &cpsz);
                cx = content.left + cpsz.cx;
                last_y = y;
            }

            y += line_h;
            off += take;
            if (y - (int)tab_content_scroll > content.bottom + line_h) break;
        }

        int baseline = last_y - (int)tab_content_scroll;
        caret_draw(hdc, cx, baseline, line_h - 6);
    }

    scrollb_render_vertical(
        hdc,
        content_track,
        tab_content_total_height,
        content_visible_h,
        tab_content_scroll,
        0.45f
    );

    RestoreDC(hdc, saved_dc);
    SelectObject(hdc, oldf);

    {
        std::lock_guard<std::mutex> lk(g_mutex);
        if (active_index >= 0 && active_index < (int)g_tabs.size()) {
            g_tabs[active_index].content_scroll = tab_content_scroll;
            g_tabs[active_index].content_scroll_target = tab_content_scroll_target;
            g_tabs[active_index].user_scrolled = tab_user_scrolled;
            g_tabs[active_index].request_scroll_to_bottom = tab_request_scroll_to_bottom;
        }
    }

    BitBlt(real_hdc, 0, 0, ww, hh, hdc, 0, 0, SRCCOPY);
    SelectObject(mem, oldbmp);
    DeleteObject(bmp);
    DeleteDC(mem);
}

static LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
#if defined(PLUGXEL_ENABLE_HEADLESS_MODE) || defined(PLUG_ENABLE_HEADLESS_MODE)
    case WM_APP + 200: { // WM_APP_DUMP_STATE
        std::lock_guard<std::mutex> lk(g_mutex);
        std::cout << "\n---STATE_DUMP_START---\n";
        std::cout << "{\n";
        std::cout << "  \"active_tab\": " << g_active_tab << ",\n";
        std::cout << "  \"tabs\": [\n";
        for (size_t i = 0; i < g_tabs.size(); ++i) {
            std::wstring wtitle = g_tabs[i].title;
            int n1 = WideCharToMultiByte(CP_UTF8, 0, wtitle.c_str(), -1, NULL, 0, NULL, NULL);
            std::string title_utf8;
            if (n1 > 0) {
                title_utf8.resize(n1 - 1);
                WideCharToMultiByte(CP_UTF8, 0, wtitle.c_str(), -1, &title_utf8[0], n1, NULL, NULL);
            }
            std::string raw_input = g_tabs[i].input_buffer;
            std::string escaped_input;
            for (char c : raw_input) {
                if (c == '\\') escaped_input += "\\\\";
                else if (c == '"') escaped_input += "\\\"";
                else escaped_input += c;
            }
            std::cout << "    {\n";
            std::cout << "      \"index\": " << i << ",\n";
            std::cout << "      \"title\": \"" << title_utf8 << "\",\n";
            std::cout << "      \"input_buffer\": \"" << escaped_input << "\",\n";
            std::cout << "      \"plugin_owner\": \"" << (g_tabs[i].plugin_owner.empty() ? "" : g_tabs[i].plugin_owner) << "\"\n";
            std::cout << "    }" << (i + 1 < g_tabs.size() ? "," : "") << "\n";
        }
        std::cout << "  ]\n";
        std::cout << "}\n";
        std::cout << "---STATE_DUMP_END---\n" << std::endl;
        return 0;
    }
#endif
    case WM_APP + 100: {
        std::lock_guard<std::mutex> lk(g_mutex);
        TabState t;
        g_tab_counter++;
        t.title = L"Tab " + std::to_wstring(g_tab_counter);
        t.content_scroll = t.content_scroll_target = 0.0f;
        t.content_total_height = 0;
        t.user_scrolled = false;
        t.request_scroll_to_bottom = true;
        t.follow_on_output = true;
        if (lParam) {
            t.plugin_owner = (const char*)lParam;
            free((void*)lParam);
        }
        g_tabs.push_back(std::move(t));
        g_active_tab = (int)g_tabs.size()-1;
        g_tab_scroll = g_tab_scroll_target = 0.0f;
        g_content_scroll = g_content_scroll_target = 0.0f;
        g_user_scrolled = false;
        g_request_scroll_to_bottom = true;
        InvalidateRect(hwnd, NULL, FALSE);
        return 0; }
    case WM_APP_PRINT: {
        char* txt = (char*)lParam;
        COLORREF col = (COLORREF)wParam;
        if (txt) {
            int n = MultiByteToWideChar(CP_UTF8,0,txt,-1,NULL,0);
            if (n>1) {
                std::wstring w; w.resize(n-1);
                MultiByteToWideChar(CP_UTF8,0,txt,-1,&w[0],n);
                push_line(w, col);
            }
            free(txt);
        }
        return 0;
    }
    case WM_APP_PRINT_TAB: {
        char* data = (char*)lParam;
        if (!data) return 0;
        int tab = 0; COLORREF col = COL_OUTPUT;
        memcpy(&tab, data, sizeof(tab));
        memcpy(&col, data + sizeof(tab), sizeof(col));
        char* txt = data + sizeof(tab) + sizeof(col);
        int n = MultiByteToWideChar(CP_UTF8,0,txt,-1,NULL,0);
        if (n>1) {
            std::wstring w; w.resize(n-1);
            MultiByteToWideChar(CP_UTF8,0,txt,-1,&w[0],n);
            push_line_tab(tab, w, col);
        }
        free(data);
        return 0;
    }
    case WM_APP_PRINT_SAFE: {
        shared_message_t* sm = (shared_message_t*)lParam;
        if (sm) {
            int n = MultiByteToWideChar(CP_UTF8, 0, sm->message, -1, NULL, 0);
            if (n > 1) {
                std::wstring w; w.resize(n - 1);
                MultiByteToWideChar(CP_UTF8, 0, sm->message, -1, &w[0], n);
                if (sm->tab_idx >= 0) {
                    push_line_tab(sm->tab_idx, w, (COLORREF)sm->color);
                } else {
                    push_line(w, (COLORREF)sm->color);
                }
            }
        }
        return 0;
    }
    case WM_APP_REPLACE_LAST: {
        shared_message_t* sm = (shared_message_t*)lParam;
        if (sm) {
            int n = MultiByteToWideChar(CP_UTF8, 0, sm->message, -1, NULL, 0);
            if (n >= 1) {
                std::wstring w; if (n > 1) { w.resize(n - 1); MultiByteToWideChar(CP_UTF8, 0, sm->message, -1, &w[0], n); }
                int tabidx = sm->tab_idx;
                std::lock_guard<std::mutex> lk(g_mutex);
                if (tabidx < 0) tabidx = g_active_tab;
                if (tabidx >= 0 && tabidx < (int)g_tabs.size() && !g_tabs[tabidx].raw_lines.empty()) {
                    g_tabs[tabidx].raw_lines.back().text = w;
                    RECT rr; GetClientRect(hwnd, &rr);
                    rewrap_tab(tabidx, (rr.right - rr.left) - 32);
                    InvalidateRect(hwnd, NULL, FALSE);
                }
            }
        }
        return 0;
    }
    case WM_APP_INVALIDATE: {
        InvalidateRect(hwnd, NULL, FALSE);
        return 0;
    }
    case WM_APP_CLEAR: {
        std::lock_guard<std::mutex> lk(g_mutex);
        if (!g_tabs.empty()) {
            g_tabs[g_active_tab].raw_lines.clear();
            g_tabs[g_active_tab].wrapped_lines.clear();
            g_tabs[g_active_tab].content_total_height = 0;
        }
        InvalidateRect(hwnd, NULL, TRUE);
        return 0;
    }
    case WM_APP_RECOLOR: {
        WORD color_word = (WORD)wParam;
        std::lock_guard<std::mutex> lk(g_mutex);
        COLORREF newc = map_word_to_color(color_word);
        RECT rr; GetClientRect(hwnd, &rr);
        int cw = (rr.right - rr.left) - 32;
        for (int i=0; i<(int)g_tabs.size(); ++i) {
             for (auto &ln : g_tabs[i].raw_lines) ln.color = newc;
             rewrap_tab(i, cw);
        }
        InvalidateRect(hwnd, NULL, FALSE);
        return 0;
    }
    case WM_APP_REQUEST_CLOSE: {
        g_running_ui = false;
        DestroyWindow(hwnd);
        return 0;
    }
    case WM_NCHITTEST: {
        POINT pt = { GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
        ScreenToClient(hwnd, &pt);
        RECT r; GetClientRect(hwnd, &r);
        RECT hr = r; hr.bottom = hr.top + 44;
        int btnx_add_tab = r.right - 120;
        RECT add_tab_control_rect = {btnx_add_tab, hr.top+8, btnx_add_tab+28, hr.top+36};
        if (PtInRect(&add_tab_control_rect, pt)) return HTCLIENT;

        int tabs_count = 0;
        {
            std::lock_guard<std::mutex> lk(g_mutex);
            tabs_count = (int)g_tabs.size();
        }
        int tx = 12 - (int)g_tab_scroll;
        for (int i = 0; i < tabs_count; ++i) {
            RECT trt = {tx, hr.bottom+4, tx+140, hr.bottom+24};
            if (PtInRect(&trt, pt)) return HTCLIENT;
            tx += 150;
        }

        if (PtInRect(&hr, pt)) return HTCAPTION;
        return HTCLIENT;
        break; }
    case WM_CREATE:
        caret_init(hwnd);
        clipboard_init(hwnd);
        SetTimer(hwnd, g_scroll_timer, 16, NULL);
        break;
    case WM_TIMER:
        if (caret_on_timer(wParam)) {
        } else if (wParam == g_scroll_timer) {
            float prev_tab = g_tab_scroll;
            g_tab_scroll = g_tab_scroll_target;
            {
                std::lock_guard<std::mutex> lk(g_mutex);
                if (!g_tabs.empty() && g_active_tab >= 0 && g_active_tab < (int)g_tabs.size()) {
                    TabState &t = g_tabs[g_active_tab];
                    float prev = t.content_scroll;
                    t.content_scroll = t.content_scroll_target;
                    if (t.content_total_height > 0) {
                        RECT rc; GetClientRect(hwnd, &rc);
                        int tabbar_h = 44 + 28 + 8 + 12;
                        int ch = (rc.bottom - rc.top) - tabbar_h;
                        float maxc = (t.content_total_height > ch) ? (float)(t.content_total_height - ch + 24) : 0.0f;
                        if (t.content_scroll < 0.0f) t.content_scroll = 0.0f;
                        if (t.content_scroll > maxc) t.content_scroll = maxc;
                    }
                    if (prev != t.content_scroll) InvalidateRect(hwnd, NULL, FALSE);
                }
            }
            if (prev_tab != g_tab_scroll) InvalidateRect(hwnd, NULL, FALSE);
        }
        break;
    case WM_CHAR: {
        if (g_prompt_locked.load()) return 0;
        wchar_t ch = (wchar_t)wParam;

        if (ch < 32 && ch != L'\r' && ch != L'\b') return 0;

        if (ch == L'\r') {
            std::string in;
            {
                std::lock_guard<std::mutex> lk(g_mutex);
                if (g_active_tab >= 0 && g_active_tab < (int)g_tabs.size()) {
                    in = g_tabs[g_active_tab].input_buffer;
                    g_tabs[g_active_tab].input_buffer.clear();
                    g_tabs[g_active_tab].input_cursor = 0;
                }
            }

            if (!in.empty()) {
                size_t l = in.size() + 1;
                char* dup = (char*)malloc(l);
                if (dup) {
                    memcpy(dup, in.c_str(), l);
                    PostMessageW(g_hwnd, WM_APP_PRINT, (WPARAM)COL_CMD, (LPARAM)dup);
                }
                enqueue_command_nolock(g_active_tab, in);
                {
                    std::lock_guard<std::mutex> lk(g_mutex);
                    if (g_active_tab >= 0 && g_active_tab < (int)g_tabs.size()) {
                        TabState& tab = g_tabs[g_active_tab];
                        tab.user_scrolled = false;
                        tab.request_scroll_to_bottom = true;
                        tab.follow_on_output = true;
                        int avail = 0;
                        RECT rc; GetClientRect(g_hwnd, &rc);
                        RECT tabr = rc; tabr.top = 44; tabr.bottom = 44 + 28;
                        avail = (rc.bottom - rc.top) - (tabr.bottom + 8) - 12;
                        int diff = tab.content_total_height - avail;
                        if (diff < 0) diff = 0;
                        tab.content_scroll_target = (float)diff;
                    }
                }
            } else {
                PostMessageW(g_hwnd, WM_APP_PRINT, (WPARAM)COL_OUTPUT, (LPARAM)strdup(""));
            }
            PostMessageW(g_hwnd, WM_APP_INVALIDATE, 0, 0);
        } else if (ch == L'\b') {
            std::lock_guard<std::mutex> lk(g_mutex);
            if (g_active_tab >= 0 && g_active_tab < (int)g_tabs.size()) {
                TabState& tab = g_tabs[g_active_tab];
                if (!tab.input_buffer.empty() && tab.input_cursor > 0 && tab.input_cursor <= (int)tab.input_buffer.size()) {
                    int to_erase = 1;
                    int pos = tab.input_cursor - 1;
                    while (pos > 0 && (tab.input_buffer[pos] & 0xC0) == 0x80) {
                        pos--;
                        to_erase++;
                    }
                    tab.input_buffer.erase(pos, to_erase);
                    tab.input_cursor = pos;
                    caret_show();
                }
            }
        } else {
            wchar_t ws[2] = {ch, 0};
            int outn = WideCharToMultiByte(CP_UTF8, 0, ws, 1, NULL, 0, NULL, NULL);
            if (outn > 0) {
                std::string tmp(outn, '\0');
                WideCharToMultiByte(CP_UTF8, 0, ws, 1, &tmp[0], outn, NULL, NULL);
                std::lock_guard<std::mutex> lk(g_mutex);
                if (g_active_tab >= 0 && g_active_tab < (int)g_tabs.size()) {
                    TabState& tab = g_tabs[g_active_tab];
                    if (tab.input_cursor >= 0 && tab.input_cursor <= (int)tab.input_buffer.size()) {
                        tab.input_buffer.insert(tab.input_cursor, tmp);
                        tab.input_cursor += outn;
                        caret_show();
                    }
                }
            }
        }
        InvalidateRect(hwnd, NULL, FALSE);
        break; }
    case WM_KEYDOWN:
        if (g_prompt_locked.load()) return 0;
        if (wParam == VK_TAB) {
            std::lock_guard<std::mutex> lk(g_mutex);
            if (!g_tabs.empty()) g_active_tab = (g_active_tab + 1) % g_tabs.size();
            InvalidateRect(hwnd, NULL, FALSE);
        } else if (wParam == VK_LEFT) {
            std::lock_guard<std::mutex> lk(g_mutex);
            if (g_active_tab >= 0 && g_tabs[g_active_tab].input_cursor > 0) {
                g_tabs[g_active_tab].input_cursor--;
                caret_show();
                InvalidateRect(hwnd, NULL, FALSE);
            }
        } else if (wParam == VK_RIGHT) {
            std::lock_guard<std::mutex> lk(g_mutex);
            if (g_active_tab >= 0 && g_tabs[g_active_tab].input_cursor < (int)g_tabs[g_active_tab].input_buffer.size()) {
                g_tabs[g_active_tab].input_cursor++;
                caret_show();
                InvalidateRect(hwnd, NULL, FALSE);
            }
        } else if (wParam == VK_HOME) {
            std::lock_guard<std::mutex> lk(g_mutex);
            if (g_active_tab >= 0) {
                g_tabs[g_active_tab].input_cursor = 0;
                caret_show();
                InvalidateRect(hwnd, NULL, FALSE);
            }
        } else if (wParam == VK_END) {
            std::lock_guard<std::mutex> lk(g_mutex);
            if (g_active_tab >= 0) {
                g_tabs[g_active_tab].input_cursor = (int)g_tabs[g_active_tab].input_buffer.size();
                caret_show();
                InvalidateRect(hwnd, NULL, FALSE);
            }
        } else if (wParam == VK_DELETE) {
            std::lock_guard<std::mutex> lk(g_mutex);
            if (g_active_tab >= 0 && g_tabs[g_active_tab].input_cursor < (int)g_tabs[g_active_tab].input_buffer.size()) {
                g_tabs[g_active_tab].input_buffer.erase(g_tabs[g_active_tab].input_cursor, 1);
                InvalidateRect(hwnd, NULL, FALSE);
            }
        }
        break;
    case WM_MOUSEMOVE: {
        POINT pt = { GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
        if (g_drag_content_scrollbar) {
            std::lock_guard<std::mutex> lk(g_mutex);
            if (!g_tabs.empty() && g_active_tab >= 0 && g_active_tab < (int)g_tabs.size()) {
                TabState &t = g_tabs[g_active_tab];
                int track_h = g_content_scroll_track_rect.bottom - g_content_scroll_track_rect.top;
                int thumb_h = g_content_scroll_thumb_rect.bottom - g_content_scroll_thumb_rect.top;
                int drag_y = pt.y - g_drag_content_grab_dy;
                int min_y = g_content_scroll_track_rect.top;
                int max_y = g_content_scroll_track_rect.bottom - thumb_h;
                if (drag_y < min_y) drag_y = min_y;
                if (drag_y > max_y) drag_y = max_y;

                float ratio = (max_y > min_y) ? (float)(drag_y - min_y) / (float)(max_y - min_y) : 0.0f;
                RECT rc; GetClientRect(hwnd, &rc);
                RECT tabr = rc; tabr.top = 44; tabr.bottom = 44 + 28;
                int ch = (rc.bottom - rc.top) - (tabr.bottom + 8) - 12;
                float maxc = 0.0f;
                if (t.content_total_height > ch) maxc = (float)(t.content_total_height - ch + 24);
                t.content_scroll_target = ratio * maxc;
                if (maxc <= 0.0f) t.content_scroll_target = 0.0f;
                t.content_scroll_target = scrollb_clamp_offset(t.content_scroll_target, t.content_total_height, ch);
                t.content_scroll = t.content_scroll_target;
                t.user_scrolled = true;
            }
            InvalidateRect(hwnd, NULL, FALSE);
            break;
        }
        if (g_drag_tab_scrollbar) {
            int track_w = g_tab_scroll_track_rect.right - g_tab_scroll_track_rect.left;
            int thumb_w = g_tab_scroll_thumb_rect.right - g_tab_scroll_thumb_rect.left;
            int tabs_count = 0;
            {
                std::lock_guard<std::mutex> lk(g_mutex);
                tabs_count = (int)g_tabs.size();
            }
            int tabbar_w = tabs_count * 150;
            int visible_w = track_w;
            int drag_x = pt.x - g_drag_tab_grab_dx;
            int min_x = g_tab_scroll_track_rect.left;
            int max_x = g_tab_scroll_track_rect.right - thumb_w;
            if (drag_x < min_x) drag_x = min_x;
            if (drag_x > max_x) drag_x = max_x;

            float ratio = (max_x > min_x) ? (float)(drag_x - min_x) / (float)(max_x - min_x) : 0.0f;
            float max_off = (float)(tabbar_w - visible_w);
            if (max_off < 0.0f) max_off = 0.0f;
            g_tab_scroll_target = ratio * max_off;
            g_tab_scroll_target = scrollb_clamp_offset(g_tab_scroll_target, tabbar_w, visible_w);
            g_tab_scroll = g_tab_scroll_target;
            InvalidateRect(hwnd, NULL, FALSE);
            break;
        }
        hover_tab_update(hwnd, tab_close_hit_test(pt, g_tab_close_rects));

        // use modular hover effect for text lines
        RECT content_rc; GetClientRect(hwnd, &content_rc);
        content_rc.top = 44 + 28; // Below header and tabs
        content_rc.left += 16; content_rc.right -= 16; content_rc.bottom -= 8;
        
        if (PtInRect(&content_rc, pt)) {
            HDC hdc = GetDC(hwnd);
            HFONT oldf = (HFONT)SelectObject(hdc, g_mono_font);
            SIZE az; GetTextExtentPoint32W(hdc, L"A", 1, &az);
            int char_w = az.cx;
            int line_h = az.cy + 6;
            SelectObject(hdc, oldf);
            ReleaseDC(hwnd, hdc);

            hover_update(hwnd, pt, content_rc, g_content_scroll, line_h);

            // selection update
            if (g_selection.dragging) {
                int total_lines = 0;
                {
                    std::lock_guard<std::mutex> lk(g_mutex);
                    if (g_active_tab >= 0 && g_active_tab < (int)g_tabs.size()) {
                        total_lines = (int)g_tabs[g_active_tab].wrapped_lines.size() + 5; // buffer for input
                    }
                }
                SelectionPos pos = selection_map_point(pt, content_rc, g_content_scroll, char_w, line_h, total_lines);
                selection_update(pos);
                InvalidateRect(hwnd, NULL, FALSE);
            }
        }

        if (!g_mouse_tracked) {
            TRACKMOUSEEVENT tme = { sizeof(tme), TME_LEAVE, hwnd, 0 };
            TrackMouseEvent(&tme);
            g_mouse_tracked = true;
        }
        break; }
    case WM_SETCURSOR:
        if (LOWORD(lParam) == HTCLIENT) {
            SetCursor(LoadCursor(NULL, IDC_ARROW));
            return TRUE;
        }
        break;
    case WM_WINDOWPOSCHANGED: {
        RedrawWindow(hwnd, NULL, NULL, RDW_INVALIDATE | RDW_ERASE | RDW_UPDATENOW);
        return 0;
    }
    case WM_ERASEBKGND: {
        return 1;
    }
    case WM_MOUSELEAVE: {
        g_mouse_tracked = false;
        hover_reset(hwnd); 
        break; }
    case WM_MOUSEWHEEL: {
        int z = GET_WHEEL_DELTA_WPARAM(wParam);
        POINT pt = { GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
        ScreenToClient(hwnd, &pt);
        RECT r; GetClientRect(hwnd, &r);
        RECT tabr = r; tabr.top = 44; tabr.bottom = 44 + 28;
        int delta = (z / WHEEL_DELTA) * 24;
        if (PtInRect(&tabr, pt)) {
            g_tab_scroll_target -= (float)delta;
            int tabbar_w = (int)g_tabs.size() * 150;
            int visible = (g_tab_scroll_track_rect.right - g_tab_scroll_track_rect.left);
            g_tab_scroll_target = scrollb_clamp_offset(g_tab_scroll_target, tabbar_w, visible);
        } else {
            int idx = -1;
            {
                std::lock_guard<std::mutex> lk(g_mutex);
                if (g_active_tab >= 0 && g_active_tab < (int)g_tabs.size()) {
                    idx = g_active_tab;
                    TabState &t = g_tabs[idx];
                    t.content_scroll_target -= (float)delta;
                    int ch = (r.bottom - r.top) - (tabr.bottom + 8) - 12;
                    float maxc = 0.0f;
                    if (t.content_total_height > ch) {
                        maxc = (float)(t.content_total_height - ch + 24);
                        if (t.content_scroll_target < 0.0f) t.content_scroll_target = 0.0f;
                        if (t.content_scroll_target > maxc) t.content_scroll_target = maxc;
                    } else {
                        t.content_scroll_target = 0.0f;
                    }
                    if (maxc > 0.0f && t.content_scroll_target >= maxc - 2.0f) {
                        t.content_scroll_target = maxc;
                        t.user_scrolled = false;
                    } else {
                        t.user_scrolled = true;
                    }
                }
            }
            if (idx != -1) {
                std::thread([idx]{ std::this_thread::sleep_for(std::chrono::milliseconds(1200)); std::lock_guard<std::mutex> lk(g_mutex); if (idx >=0 && idx < (int)g_tabs.size()) g_tabs[idx].user_scrolled = false; }).detach();
            }
        }
        g_last_scroll_activity = std::chrono::steady_clock::now();
        InvalidateRect(hwnd, NULL, FALSE);
        break;
    }
    case WM_LBUTTONDOWN: {
        POINT pt = { GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
        RECT r; GetClientRect(hwnd, &r);
        if (g_content_scroll_thumb_visible && PtInRect(&g_content_scroll_thumb_rect, pt)) {
            g_drag_content_scrollbar = true;
            g_drag_content_grab_dy = pt.y - g_content_scroll_thumb_rect.top;
            SetCapture(hwnd);
            return 0;
        }
        if (g_tab_scroll_thumb_visible && PtInRect(&g_tab_scroll_thumb_rect, pt)) {
            g_drag_tab_scrollbar = true;
            g_drag_tab_grab_dx = pt.x - g_tab_scroll_thumb_rect.left;
            SetCapture(hwnd);
            return 0;
        }

        // check tab close hit under lock then release before ffi callback
        int close_idx = -1;
        {
            std::lock_guard<std::mutex> lk(g_mutex);
            close_idx = tab_close_hit_test(pt, g_tab_close_rects);
        }
        if (close_idx != -1) {
            // notify rust runtime before erasing so it can still read tab owner
            // must be outside g_mutex because rust calls back into get_tab_owner / print_info
            // which also lock g_mutex — re-entry on non-recursive mutex = instant deadlock
            c_on_tab_close(close_idx);
            {
                std::lock_guard<std::mutex> lk(g_mutex);
                if (close_idx >= 0 && close_idx < (int)g_tabs.size()) {
                    g_tabs.erase(g_tabs.begin() + close_idx);
                    if (g_active_tab >= (int)g_tabs.size()) g_active_tab = (int)g_tabs.size() - 1;
                }
                selection_clear();
            }
            InvalidateRect(hwnd, NULL, FALSE);
            break;
        }

        {
        std::lock_guard<std::mutex> lk(g_mutex);
        RECT tabr = r; tabr.top = 44; tabr.bottom = 72;
        int hit = tab_hit_test_pt(pt, tabr, (int)g_tabs.size(), g_tab_scroll);
        if (hit != -1) {
            g_active_tab = hit;
            selection_clear();
            InvalidateRect(hwnd, NULL, FALSE);
            break;
        }

        // start text selection
        RECT content_rc; GetClientRect(hwnd, &content_rc);
        content_rc.top = 44 + 28; content_rc.left += 16; content_rc.right -= 16; content_rc.bottom -= 8;
        if (PtInRect(&content_rc, pt)) {
            HDC hdc = GetDC(hwnd);
            HFONT oldf = (HFONT)SelectObject(hdc, g_mono_font);
            SIZE az; GetTextExtentPoint32W(hdc, L"A", 1, &az);
            int char_w = az.cx;
            int line_h = az.cy + 6;
            SelectObject(hdc, oldf);
            ReleaseDC(hwnd, hdc);

            int total_lines = (int)g_tabs[g_active_tab].wrapped_lines.size() + 5;
            SelectionPos pos = selection_map_point(pt, content_rc, g_content_scroll, char_w, line_h, total_lines);
            selection_start(g_active_tab, pos);
            SetCapture(hwnd);
            InvalidateRect(hwnd, NULL, FALSE);
        } else {
            selection_clear();
            InvalidateRect(hwnd, NULL, FALSE);
        }
        } // end g_mutex scope
        break; }
    case WM_LBUTTONUP:
        if (g_selection.dragging) {
            selection_stop();
            ReleaseCapture();
            InvalidateRect(hwnd, NULL, FALSE);
        }
        if (g_drag_content_scrollbar) {
            g_drag_content_scrollbar = false;
            ReleaseCapture();
            return 0;
        }
        if (g_drag_tab_scrollbar) {
            g_drag_tab_scrollbar = false;
            ReleaseCapture();
            return 0;
        }
        break;
    case WM_SIZE: {
        RECT rc; GetClientRect(hwnd, &rc);
        int ww = rc.right - rc.left; int wh = rc.bottom - rc.top;
        if (!IsZoomed(hwnd)) {
            HRGN rgn = CreateRoundRectRgn(0,0,ww+1,wh+1,16,16);
            SetWindowRgn(hwnd, rgn, TRUE);
        } else {
            SetWindowRgn(hwnd, NULL, TRUE);
        }
        rewrap_all_tabs();
        InvalidateRect(hwnd, NULL, FALSE);
        break; }
    case WM_PAINT: {
        PAINTSTRUCT ps; HDC hdc = BeginPaint(hwnd, &ps);
        HFONT oldf = (HFONT)SelectObject(hdc, g_mono_font);
        render(hdc);
        SelectObject(hdc, oldf);
        EndPaint(hwnd, &ps);
        break; }
    case WM_CLOSE:
        g_running_ui = false;
        DestroyWindow(hwnd);
        break;
    case WM_DESTROY:
        caret_cleanup();
        PostQuitMessage(0);
        break;

    default:
        return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}

extern "C" int main_w_init(void) {
    HINSTANCE hInst = GetModuleHandle(NULL);
    WNDCLASSW wc = {0};
    wc.lpfnWndProc = MainWndProc;
    wc.hInstance = hInst;
    wc.lpszClassName = L"plugMainWindowClass";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW+1);
    RegisterClassW(&wc);

    g_mono_font = CreateFontA(18,0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,FIXED_PITCH | FF_DONTCARE, "Consolas");

    int window_width = 900;
    int window_height = 420;
    int screen_width = GetSystemMetrics(SM_CXSCREEN);
    int screen_height = GetSystemMetrics(SM_CYSCREEN);
    int center_x = (screen_width - window_width) / 2;
    int center_y = (screen_height - window_height) / 2;
    
    DWORD style = WS_POPUP | WS_VISIBLE;
#if defined(PLUGXEL_ENABLE_HEADLESS_MODE) || defined(PLUG_ENABLE_HEADLESS_MODE)
    if (g_headless_mode) {
        style = WS_POPUP;
    }
#endif

    g_hwnd = CreateWindowExW(WS_EX_APPWINDOW, wc.lpszClassName, L"plugxel", style, center_x, center_y, window_width, window_height, NULL, NULL, hInst, NULL);
    if (!g_hwnd) return -1;

#if defined(PLUGXEL_ENABLE_HEADLESS_MODE) || defined(PLUG_ENABLE_HEADLESS_MODE)
    if (g_headless_mode) {
        ShowWindow(g_hwnd, SW_HIDE);
    } else {
        ShowWindow(g_hwnd, SW_SHOW);
    }
#else
    ShowWindow(g_hwnd, SW_SHOW);
#endif

    UpdateWindow(g_hwnd);

    HRGN r = CreateRoundRectRgn(0,0,window_width+1,window_height+1,16,16);
    SetWindowRgn(g_hwnd, r, TRUE);

    g_tabs.clear();
    TabState t; t.title = L"Tab 1"; t.content_scroll = t.content_scroll_target = 0.0f; t.content_total_height = 0; t.user_scrolled = false; t.request_scroll_to_bottom = true; t.follow_on_output = true; g_tabs.push_back(std::move(t)); g_active_tab = 0;

    g_running_ui = true;
    g_ui_thread_id = GetCurrentThreadId();
    g_main_w_state.hConsole = NULL;
    g_main_w_state.width = window_width;
    g_main_w_state.height = window_height;
    g_main_w_state.animation_enabled = TRUE;
    g_main_w_state.color_enabled = TRUE;

    g_cmd_thread_running = true;
    g_cmd_thread = std::thread(command_worker_thread);

#if defined(PLUGXEL_ENABLE_HEADLESS_MODE) || defined(PLUG_ENABLE_HEADLESS_MODE)
    if (g_headless_mode) {
        g_headless_stdin_thread = std::thread(headless_stdin_worker);
    }
#endif

    g_last_scroll_activity = std::chrono::steady_clock::now();
    return 0;
}

extern "C" void main_w_cleanup(void) {
    if (g_hwnd) DestroyWindow(g_hwnd);
    if (g_mono_font) { DeleteObject(g_mono_font); g_mono_font = NULL; }
    g_tabs.clear();

    g_cmd_thread_running = false;
    g_cmd_cv.notify_all();
    if (g_cmd_thread.joinable()) g_cmd_thread.join();

#if defined(PLUGXEL_ENABLE_HEADLESS_MODE) || defined(PLUG_ENABLE_HEADLESS_MODE)
    if (g_headless_stdin_thread.joinable()) {
        g_headless_stdin_thread.detach();
    }
#endif
}

extern "C" void main_w_run_message_loop(void) {
    MSG msg;
    while (g_running_ui) {
        while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        Sleep(8);
    }
}

extern "C" void main_w_print_banner(void) {
    char username[256];
    DWORD username_len = sizeof(username);
    if (!GetUserNameA(username, &username_len)) {
        strcpy(username, "User");
    }

    char welcome_msg[512];
    snprintf(welcome_msg, sizeof(welcome_msg), "Welcome, %s!", username);

    main_w_print_info(welcome_msg);
}

extern "C" void main_w_print_error(const char* msg) {
    if (!msg) return;
#if defined(PLUGXEL_ENABLE_HEADLESS_MODE) || defined(PLUG_ENABLE_HEADLESS_MODE)
    if (g_headless_mode) {
        std::cerr << "[ERROR] " << msg << std::endl;
    }
#endif
    size_t l = strlen(msg) + 1;
    char* dup = (char*)malloc(l);
    if (dup) {
        memcpy(dup, msg, l);
        PostMessageW(g_hwnd, WM_APP_PRINT, (WPARAM)COL_CMD, (LPARAM)dup);
    }
}

extern "C" void main_w_print_success(const char* msg) {
    if (!msg) return;
#if defined(PLUGXEL_ENABLE_HEADLESS_MODE) || defined(PLUG_ENABLE_HEADLESS_MODE)
    if (g_headless_mode) {
        std::cout << "[SUCCESS] " << msg << std::endl;
    }
#endif
    size_t l = strlen(msg) + 1;
    char* dup = (char*)malloc(l);
    if (dup) {
        memcpy(dup, msg, l);
        PostMessageW(g_hwnd, WM_APP_PRINT, (WPARAM)COL_USER, (LPARAM)dup);
    }
}

extern "C" void main_w_print_info(const char* msg) {
    if (!msg) return;
#if defined(PLUGXEL_ENABLE_HEADLESS_MODE) || defined(PLUG_ENABLE_HEADLESS_MODE)
    if (g_headless_mode) {
        std::cout << "[INFO] " << msg << std::endl;
    }
#endif
    size_t l = strlen(msg) + 1;
    char* dup = (char*)malloc(l);
    if (dup) {
        memcpy(dup, msg, l);
        PostMessageW(g_hwnd, WM_APP_PRINT, (WPARAM)COL_OUTPUT, (LPARAM)dup);
    }
}

extern "C" void main_w_print_warning(const char* msg) {
    if (!msg) return;
#if defined(PLUGXEL_ENABLE_HEADLESS_MODE) || defined(PLUG_ENABLE_HEADLESS_MODE)
    if (g_headless_mode) {
        std::cout << "[WARNING] " << msg << std::endl;
    }
#endif
    size_t l = strlen(msg) + 1;
    char* dup = (char*)malloc(l);
    if (dup) {
        memcpy(dup, msg, l);
        PostMessageW(g_hwnd, WM_APP_PRINT, (WPARAM)COL_CMD, (LPARAM)dup);
    }
}

extern "C" void main_w_set_console_title(const char* title) { if (!title) return; int n = MultiByteToWideChar(CP_UTF8,0,title,-1,NULL,0); std::wstring w; w.resize(n-1); MultiByteToWideChar(CP_UTF8,0,title,-1,&w[0],n); SetWindowTextW(g_hwnd, w.c_str()); }

extern "C" void main_w_display_command_input(void) { InvalidateRect(g_hwnd, NULL, FALSE); }
extern "C" void main_w_show_caret(void) { caret_show(); }
extern "C" void main_w_ensure_prompt(void) { main_w_display_command_input(); }

extern "C" void main_w_request_close(void) {
    if (g_hwnd) PostMessageW(g_hwnd, WM_APP_REQUEST_CLOSE, 0, 0);
}

extern "C" void main_w_replace_last_line_internal(const char* msg) {
    if (!msg) return;
    std::lock_guard<std::mutex> lk(g_mutex);
    if (g_tabs.empty()) return;
    TabState &t = g_tabs[g_active_tab];
    if (t.raw_lines.empty()) return;

    int n = MultiByteToWideChar(CP_UTF8, 0, msg, -1, NULL, 0);
    if (n >= 1) {
        std::wstring w; if (n > 1) { w.resize(n - 1); MultiByteToWideChar(CP_UTF8, 0, msg, -1, &w[0], n); }
        t.raw_lines.back().text = w;
        RECT rc; GetClientRect(g_hwnd, &rc);
        int content_width = (rc.right - rc.left) - 32;
        rewrap_tab(g_active_tab, content_width);
        InvalidateRect(g_hwnd, NULL, FALSE);
    }
}

extern "C" void main_w_replace_last_line_safe(const char* msg);

extern "C" void main_w_replace_last_line(const char* msg) {
    main_w_replace_last_line_safe(msg);
}



extern "C" void main_w_add_tab(const char* owner) {
    if (!g_hwnd) return;
    std::wstring w_owner = L"";
    if (owner) {
        int n = MultiByteToWideChar(CP_UTF8, 0, owner, -1, NULL, 0);
        if (n > 1) { w_owner.resize(n - 1); MultiByteToWideChar(CP_UTF8, 0, owner, -1, &w_owner[0], n); }
    }
    // we'll use a hack pass owner in lparam
    PostMessageW(g_hwnd, WM_APP + 100, 0, (LPARAM)(owner ? _strdup(owner) : nullptr));
}

static WORD g_current_color_word = 0;

static COLORREF map_word_to_color(WORD w) {
    if (w & FOREGROUND_RED) return COL_CMD;
    if (w & FOREGROUND_GREEN) return COL_USER;
    if (w & FOREGROUND_BLUE) return COL_OUTPUT;
    return COL_OUTPUT;
}

extern "C" void main_w_clear_screen(void) {
    if (GetCurrentThreadId() != g_ui_thread_id) {
        PostMessageW(g_hwnd, WM_APP_CLEAR, 0, 0);
        return;
    }
    std::lock_guard<std::mutex> lk(g_mutex);
    if (!g_tabs.empty()) {
        g_tabs[g_active_tab].raw_lines.clear();
        g_tabs[g_active_tab].wrapped_lines.clear();
        g_tabs[g_active_tab].content_total_height = 0;
    }
    InvalidateRect(g_hwnd, NULL, TRUE);
}

extern "C" void main_w_recolor_console_all(void) {
    if (GetCurrentThreadId() != g_ui_thread_id) {
        PostMessageW(g_hwnd, WM_APP_RECOLOR, (WPARAM)g_current_color_word, 0);
        return;
    }
    std::lock_guard<std::mutex> lk(g_mutex);
    COLORREF newc = map_word_to_color(g_current_color_word);
    RECT rr; GetClientRect(g_hwnd, &rr);
    int cw = (rr.right - rr.left) - 32;
    for (int i=0; i<(int)g_tabs.size(); ++i) {
        for (auto &ln : g_tabs[i].raw_lines) {
            ln.color = newc;
        }
        rewrap_tab(i, cw);
    }
    InvalidateRect(g_hwnd, NULL, FALSE);
}

extern "C" void main_w_set_current_color(WORD color) { g_current_color_word = color; }
extern "C" WORD main_w_get_current_color(void) { return g_current_color_word; }

extern "C" void main_w_set_tab_owner(int tab_idx, const char* owner_name) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (tab_idx >= 0 && tab_idx < (int)g_tabs.size()) {
        g_tabs[tab_idx].plugin_owner = owner_name ? owner_name : "";
    }
}

extern "C" int main_w_get_tab_owner(int tab_idx, char* buf, int max_len) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (tab_idx >= 0 && tab_idx < (int)g_tabs.size() && buf && max_len > 0) {
        strncpy(buf, g_tabs[tab_idx].plugin_owner.c_str(), max_len - 1);
        buf[max_len - 1] = '\0';
        return (int)strlen(buf);
    }
    return 0;
}
extern "C" int main_w_get_active_tab(void) {
    return g_active_tab;
}

extern "C" int main_w_get_current_print_tab(void) {
    return g_active_tab; // For now, we assume print goes to active tab.
}

