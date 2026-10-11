#include <sys/api/windows/cmp/caret.h>
#include <atomic>
#include <windows.h>
#include <vector>
#include <string>
#include <mutex>
#include <algorithm>

struct DisplayLine {
    std::wstring text;
    COLORREF color;
    bool is_continuation;
};

struct TabState {
    std::wstring title;
    std::vector<DisplayLine> raw_lines;
    std::vector<DisplayLine> wrapped_lines;
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
extern std::mutex g_mutex;
extern HFONT g_mono_font;
extern std::wstring user_prm_get();

static HWND g_caret_hwnd = NULL;
static std::atomic_int g_caret_phase{0};
static UINT_PTR g_caret_timer_id = 5001;
static WNDPROC g_old_caret_wndproc = NULL;

static LRESULT CALLBACK caret_wndproc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_LBUTTONDOWN) {
        int pt_x = (int)(short)LOWORD(lParam);
        int pt_y = (int)(short)HIWORD(lParam);
        
        RECT rc; GetClientRect(hwnd, &rc);
        int content_top = 44 + 28;
        int content_left = rc.left + 16;
        
        if (pt_y > content_top) {
            std::lock_guard<std::mutex> lk(g_mutex);
            if (!g_tabs.empty() && g_active_tab >= 0 && g_active_tab < (int)g_tabs.size()) {
                TabState &t = g_tabs[g_active_tab];
                std::wstring prompt = user_prm_get() + L" ➜ ";
                std::wstring win;
                if (!t.input_buffer.empty()) {
                    int need = MultiByteToWideChar(CP_UTF8, 0, t.input_buffer.c_str(), (int)t.input_buffer.size(), NULL, 0);
                    win.resize(need);
                    MultiByteToWideChar(CP_UTF8, 0, t.input_buffer.c_str(), (int)t.input_buffer.size(), &win[0], need);
                }
                std::wstring live_full = prompt + win;

                HDC hdc = GetDC(hwnd);
                SelectObject(hdc, g_mono_font);
                SIZE az; GetTextExtentPoint32W(hdc, L"A", 1, &az);
                int char_w = az.cx;
                int line_h = az.cy + 6;
                int content_width = (rc.right - rc.left) - 32;
                int chars_per_line = content_width / char_w;
                if (chars_per_line <= 0) chars_per_line = 1;

                int target_line = (pt_y - (content_top + 8) + (int)t.content_scroll) / line_h;
                
                int total_wrapped = (int)t.wrapped_lines.size();
                int off = 0;
                int live_lines_count = 0;
                std::vector<int> col_starts;
                std::vector<int> col_lens;
                while (off < (int)live_full.size()) {
                    int take = std::min(chars_per_line, (int)live_full.size() - off);
                    col_starts.push_back(off);
                    col_lens.push_back(take);
                    off += take;
                    live_lines_count++;
                }
                if (live_lines_count == 0) {
                    col_starts.push_back(0);
                    col_lens.push_back(0);
                    live_lines_count = 1;
                }

                if (target_line >= total_wrapped && target_line < total_wrapped + live_lines_count) {
                    int l_idx = target_line - total_wrapped;
                    int start_off = col_starts[l_idx];
                    int take = col_lens[l_idx];
                    std::wstring part = live_full.substr(start_off, take);
                    
                    int click_col = (int)part.size();
                    for (int c = 0; c < (int)part.size(); ++c) {
                        SIZE csz;
                        GetTextExtentPoint32W(hdc, part.c_str(), c, &csz);
                        if (pt_x < content_left + csz.cx) {
                            click_col = c;
                            break;
                        }
                    }
                    
                    int wchar_idx = start_off + click_col - (int)prompt.size();
                    if (wchar_idx < 0) wchar_idx = 0;
                    if (wchar_idx > (int)win.size()) wchar_idx = (int)win.size();
                    
                    int byte_idx = 0;
                    if (wchar_idx > 0) {
                        byte_idx = WideCharToMultiByte(CP_UTF8, 0, win.c_str(), wchar_idx, NULL, 0, NULL, NULL);
                    }
                    t.input_cursor = byte_idx;
                    g_caret_phase.store(0); // Reset blink
                    if (g_caret_hwnd) InvalidateRect(g_caret_hwnd, NULL, FALSE);
                }
                ReleaseDC(hwnd, hdc);
            }
        }
    }
    return CallWindowProc(g_old_caret_wndproc, hwnd, msg, wParam, lParam);
}

void caret_init(HWND hwnd) {
    g_caret_hwnd = hwnd;
    SetTimer(g_caret_hwnd, g_caret_timer_id, 430, NULL);
    if (!g_old_caret_wndproc) {
        g_old_caret_wndproc = (WNDPROC)SetWindowLongPtr(hwnd, GWLP_WNDPROC, (LONG_PTR)caret_wndproc);
    }
}

void caret_cleanup() {
    if (g_caret_hwnd) {
        KillTimer(g_caret_hwnd, g_caret_timer_id);
        g_caret_hwnd = NULL;
    }
}

bool caret_on_timer(UINT_PTR timer_id) {
    if (timer_id != g_caret_timer_id) return false;
    int prev = g_caret_phase.load();
    g_caret_phase.store((prev + 1) & 1);
    if (g_caret_hwnd) InvalidateRect(g_caret_hwnd, NULL, FALSE);
    return true;
}

void caret_show() {
    g_caret_phase.store(0);
    if (g_caret_hwnd) {
        KillTimer(g_caret_hwnd, g_caret_timer_id);
        SetTimer(g_caret_hwnd, g_caret_timer_id, 430, NULL);
        InvalidateRect(g_caret_hwnd, NULL, FALSE);
    }
}

bool caret_is_visible() { return true; }

void caret_draw(HDC hdc, int cx, int baseline, int font_cy) {
    int phase = g_caret_phase.load();
    COLORREF col = (phase == 0) ? RGB(255,255,255) : RGB(230,60,60);
    int caret_w = (font_cy / 8 > 4) ? (font_cy / 8) : 4;
    RECT crect = { cx, baseline, cx + caret_w, baseline + font_cy };
    RECT clip;
    GetClipBox(hdc, &clip);
    RECT drawRect;
    if (!IntersectRect(&drawRect, &crect, &clip)) return;
    HBRUSH cbr = CreateSolidBrush(col);
    FillRect(hdc, &drawRect, cbr);
    DeleteObject(cbr);
}

