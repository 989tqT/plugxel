#include <sys/api/windows/cmp/selection.h>
#include <algorithm>
#include <vector>
#include <string>
#include <mutex>
#include <windows.h>
#include <windowsx.h>

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
extern std::wstring user_prm_get();
extern HWND g_hwnd;
extern HFONT g_mono_font;
extern void caret_show();

SelectionState g_selection = { false, false, {0,0}, {0,0}, -1 };

static WNDPROC g_old_selection_wndproc = NULL;

static LRESULT CALLBACK selection_wndproc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_KEYDOWN && g_selection.active && (g_selection.start.line != g_selection.end.line || g_selection.start.col != g_selection.end.col)) {
        if (wParam == VK_DELETE || wParam == VK_BACK) {
            std::lock_guard<std::mutex> lk(g_mutex);
            if (!g_tabs.empty() && g_active_tab >= 0 && g_active_tab < (int)g_tabs.size() && g_active_tab == g_selection.tab_idx) {
                TabState &t = g_tabs[g_active_tab];
                std::wstring prompt = user_prm_get() + L" ➜ ";
                std::wstring win;
                if (!t.input_buffer.empty()) {
                    int need = MultiByteToWideChar(CP_UTF8, 0, t.input_buffer.c_str(), (int)t.input_buffer.size(), NULL, 0);
                    win.resize(need);
                    MultiByteToWideChar(CP_UTF8, 0, t.input_buffer.c_str(), (int)t.input_buffer.size(), &win[0], need);
                }
                std::wstring live_full = prompt + win;

                SelectionPos s = std::min(g_selection.start, g_selection.end);
                SelectionPos e = std::max(g_selection.start, g_selection.end);

                int base_line = (int)t.wrapped_lines.size();

                if (e.line >= base_line) {
                    if (s.line < base_line) {
                        s.line = base_line;
                        s.col = 0;
                    }

                    RECT rc; GetClientRect(hwnd, &rc);
                    HDC hdc = GetDC(hwnd);
                    SelectObject(hdc, g_mono_font);
                    SIZE az; GetTextExtentPoint32W(hdc, L"A", 1, &az);
                    ReleaseDC(hwnd, hdc);

                    int char_w = az.cx;
                    int content_width = (rc.right - rc.left) - 32;
                    int chars_per_line = content_width / char_w;
                    if (chars_per_line <= 0) chars_per_line = 1;

                    int off = 0;
                    int current_line = base_line;
                    int start_char_idx = -1;
                    int end_char_idx = -1;

                    while (off < (int)live_full.size()) {
                        int take = std::min(chars_per_line, (int)live_full.size() - off);
                        
                        if (current_line == s.line) {
                            int local_col = s.col;
                            if (local_col > take) local_col = take;
                            start_char_idx = off + local_col;
                        }
                        if (current_line == e.line) {
                            int local_col = e.col;
                            if (local_col > take) local_col = take;
                            end_char_idx = off + local_col;
                        }
                        
                        off += take;
                        current_line++;
                    }

                    if (end_char_idx == -1) end_char_idx = (int)live_full.size();
                    if (start_char_idx == -1) start_char_idx = (int)live_full.size();

                    int prompt_len = (int)prompt.size();
                    start_char_idx -= prompt_len;
                    end_char_idx -= prompt_len;

                    if (start_char_idx < 0) start_char_idx = 0;
                    if (end_char_idx < 0) end_char_idx = 0;
                    if (start_char_idx > (int)win.size()) start_char_idx = (int)win.size();
                    if (end_char_idx > (int)win.size()) end_char_idx = (int)win.size();

                    if (start_char_idx < end_char_idx) {
                        win.erase(start_char_idx, end_char_idx - start_char_idx);
                        
                        int byte_len = WideCharToMultiByte(CP_UTF8, 0, win.c_str(), (int)win.size(), NULL, 0, NULL, NULL);
                        std::string new_utf8;
                        if (byte_len > 0) {
                            new_utf8.resize(byte_len);
                            WideCharToMultiByte(CP_UTF8, 0, win.c_str(), (int)win.size(), &new_utf8[0], byte_len, NULL, NULL);
                        }
                        t.input_buffer = new_utf8;
                        
                        int byte_idx = 0;
                        if (start_char_idx > 0) {
                            byte_idx = WideCharToMultiByte(CP_UTF8, 0, win.c_str(), start_char_idx, NULL, 0, NULL, NULL);
                        }
                        t.input_cursor = byte_idx;
                    }
                }
            }
            g_selection.active = false;
            g_selection.dragging = false;
            caret_show();
            InvalidateRect(hwnd, NULL, FALSE);
            return 0; // Handled
        }
    }
    return CallWindowProc(g_old_selection_wndproc, hwnd, msg, wParam, lParam);
}

void selection_init() {
    g_selection.active = false;
    g_selection.dragging = false;
    g_selection.start = { -1, -1 };
    g_selection.end = { -1, -1 };
    g_selection.tab_idx = -1;
}

void selection_start(int tab_idx, SelectionPos pos) {
    g_selection.tab_idx = tab_idx;
    g_selection.start = pos;
    g_selection.end = pos;
    g_selection.dragging = true;
    g_selection.active = true;

    if (!g_old_selection_wndproc && g_hwnd) {
        g_old_selection_wndproc = (WNDPROC)SetWindowLongPtr(g_hwnd, GWLP_WNDPROC, (LONG_PTR)selection_wndproc);
    }
}

void selection_update(SelectionPos pos) {
    if (g_selection.dragging) {
        g_selection.end = pos;
        if (g_selection.start != g_selection.end) {
            g_selection.active = true;
        }
    }
}

void selection_stop() {
    g_selection.dragging = false;
    if (g_selection.active && g_selection.start == g_selection.end) {
        g_selection.active = false;
    }
}

void selection_clear() {
    selection_init();
}

bool selection_is_selected(int line, int col) {
    if (!g_selection.active) return false;

    SelectionPos norm_start = std::min(g_selection.start, g_selection.end);
    SelectionPos norm_end = std::max(g_selection.start, g_selection.end);

    SelectionPos current = { line, col };

    if (current.line > norm_start.line && current.line < norm_end.line) return true;
    if (current.line == norm_start.line && current.line == norm_end.line) {
        return col >= norm_start.col && col < norm_end.col;
    }
    if (current.line == norm_start.line) return col >= norm_start.col;
    if (current.line == norm_end.line) return col < norm_end.col;

    return false;
}

bool selection_get_line_range(int line_idx, int line_len, int& out_start, int& out_end) {
    if (!g_selection.active) return false;

    SelectionPos norm_start = std::min(g_selection.start, g_selection.end);
    SelectionPos norm_end = std::max(g_selection.start, g_selection.end);

    if (line_idx < norm_start.line || line_idx > norm_end.line) return false;

    if (line_idx > norm_start.line && line_idx < norm_end.line) {
        out_start = 0;
        out_end = line_len;
        return true;
    }

    if (norm_start.line == norm_end.line) {
        out_start = norm_start.col;
        out_end = norm_end.col;
    } else if (line_idx == norm_start.line) {
        out_start = norm_start.col;
        out_end = line_len;
    } else { // line_idx == norm_end.line
        out_start = 0;
        out_end = norm_end.col;
    }
    
    // clamp to valid indexes
    if (out_start < 0) out_start = 0;
    if (out_end > line_len) out_end = line_len;
    if (out_start >= out_end) return false;

    return true;
}

SelectionPos selection_map_point(POINT pt, RECT content_rc, float scroll, int char_w, int line_h, int total_lines) {
    if (char_w <= 0 || line_h <= 0) return { -1, -1 };

    // coordinate relative to start of text top-left of first line
    int local_x = pt.x - (content_rc.left);
    int local_y = pt.y - (content_rc.top + 8) + (int)scroll;

    int line = local_y / line_h;
    int col = local_x / char_w;

    if (line < 0) line = 0;
    if (line >= total_lines) line = total_lines - 1;
    if (col < 0) col = 0;

    return { line, col };
}

void selection_render_highlight(HDC hdc, RECT rect) {
    if (rect.left >= rect.right || rect.top >= rect.bottom) return;

    int w = rect.right - rect.left;
    int h = rect.bottom - rect.top;

    // create memory dc for alpha-blended highlight
    HDC memDC = CreateCompatibleDC(hdc);
    HBITMAP memBM = CreateCompatibleBitmap(hdc, w, h);
    HBITMAP oldBM = (HBITMAP)SelectObject(memDC, memBM);

    // draw rounded rectangle mask on memory dc
    // we use a vibrant blue with a subtle border logic
    HBRUSH hb = CreateSolidBrush(RGB(65, 133, 244)); // Google Blue or similar vibrant blue
    HPEN hp = CreatePen(PS_NULL, 0, 0);
    HBRUSH oldB = (HBRUSH)SelectObject(memDC, hb);
    HPEN oldP = (HPEN)SelectObject(memDC, hp);

    // fill with highlight color
    RoundRect(memDC, 0, 0, w, h, 4, 4);

    // restore and cleanup drawing objects for memdc
    SelectObject(memDC, oldB);
    SelectObject(memDC, oldP);
    DeleteObject(hb);
    DeleteObject(hp);

    // alpha blend constants
    BLENDFUNCTION bf;
    bf.BlendOp = AC_SRC_OVER;
    bf.BlendFlags = 0;
    bf.SourceConstantAlpha = 110; // ~43% transparency
    bf.AlphaFormat = 0;

    // blend to target hdc
    GdiAlphaBlend(hdc, rect.left, rect.top, w, h,
                  memDC, 0, 0, w, h, bf);

    // cleanup memory dc
    SelectObject(memDC, oldBM);
    DeleteObject(memBM);
    DeleteDC(memDC);
}
