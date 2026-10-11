#include <windows.h>
#include <windowsx.h>
#include <vector>
#include <string>
#include <mutex>
#include <algorithm>
#include <sys/api/windows/cmp/clipboard.h>
#include <sys/api/windows/cmp/u_prmt.h>
#include <sys/api/windows/cmp/caret.h>

struct DisplayLine {
    std::wstring text;
    COLORREF color;
    bool is_continuation = false;
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

extern HFONT g_mono_font;
extern std::vector<TabState> g_tabs;
extern int g_active_tab;
extern std::mutex g_mutex;
extern const COLORREF COL_CMD;
extern const COLORREF COL_USER;
extern const COLORREF COL_OUTPUT;

extern std::wstring user_prm_get();

struct SelectionPos {
    int line;
    int col;
};

static SelectionPos g_sel_start = {-1, -1};
static SelectionPos g_sel_end = {-1, -1};
static bool g_is_selecting = false;
static WNDPROC g_old_wndproc = NULL;

static std::vector<std::wstring> get_all_wrapped_lines(TabState &t, HWND hwnd) {
    std::vector<std::wstring> lines;
    for (const auto& dl : t.wrapped_lines) lines.push_back(dl.text);

    std::wstring prompt = user_prm_get() + L" ➜ ";

    std::wstring win;
    if (!t.input_buffer.empty()) {
        int need = MultiByteToWideChar(CP_UTF8, 0, t.input_buffer.c_str(), (int)t.input_buffer.size(), NULL, 0);
        win.resize(need);
        MultiByteToWideChar(CP_UTF8, 0, t.input_buffer.c_str(), (int)t.input_buffer.size(), &win[0], need);
    }
    
    std::wstring live_full = prompt + win;

    RECT rc; GetClientRect(hwnd, &rc);
    int content_width = (rc.right - rc.left) - 32;
    HDC hdc = GetDC(hwnd);
    SelectObject(hdc, g_mono_font);
    SIZE az; GetTextExtentPoint32W(hdc, L"A", 1, &az);
    int char_w = az.cx;
    int chars_per_line = content_width / char_w;
    if (chars_per_line <= 0) chars_per_line = 1;
    ReleaseDC(hwnd, hdc);
    
    int off = 0;
    while (off < (int)live_full.size()) {
        int take = std::min(chars_per_line, (int)live_full.size() - off);
        lines.push_back(live_full.substr(off, take));
        off += take;
    }
    
    return lines;
}

static SelectionPos mouse_to_text(HWND hwnd, POINT pt) {
    std::lock_guard<std::mutex> lk(g_mutex);
    if (g_tabs.empty() || g_active_tab < 0 || g_active_tab >= (int)g_tabs.size()) return {-1, -1};
    
    TabState &t = g_tabs[g_active_tab];
    std::vector<std::wstring> all_lines = get_all_wrapped_lines(t, hwnd);

    RECT rc; GetClientRect(hwnd, &rc);
    int content_left = rc.left + 16;
    int content_top = 44 + 28;
    
    HDC hdc = GetDC(hwnd);
    SelectObject(hdc, g_mono_font);
    
    SIZE az; GetTextExtentPoint32W(hdc, L"A", 1, &az);
    int line_h = az.cy + 6;
    
    SelectionPos res = {-1, -1};
    int target_line = (pt.y - (content_top + 8) + (int)t.content_scroll) / line_h;
    if (target_line < 0) target_line = 0;
    if (target_line >= (int)all_lines.size()) target_line = (int)all_lines.size() - 1;
    res.line = target_line;

    if (res.line >= 0 && res.line < (int)all_lines.size()) {
        std::wstring text = all_lines[res.line];
        res.col = (int)text.size();
        for (int c = 0; c < (int)text.size(); ++c) {
            SIZE csz;
            GetTextExtentPoint32W(hdc, text.c_str(), c, &csz);
            if (pt.x < content_left + csz.cx) {
                res.col = c;
                break;
            }
        }
    }
    
    ReleaseDC(hwnd, hdc);
    return res;
}

static void draw_selection(HDC hdc, HWND hwnd) {
    std::lock_guard<std::mutex> lk(g_mutex);
    if (g_sel_start.line == -1 || g_sel_end.line == -1) return;
    if (g_tabs.empty() || g_active_tab < 0 || g_active_tab >= (int)g_tabs.size()) return;

    TabState &t = g_tabs[g_active_tab];
    std::vector<std::wstring> all_lines = get_all_wrapped_lines(t, hwnd);

    RECT rc;
    GetClientRect(hwnd, &rc);
    int content_left = rc.left + 16;
    int content_top = 44 + 28;
    
    SelectionPos s = g_sel_start;
    SelectionPos e = g_sel_end;
    if (s.line > e.line || (s.line == e.line && s.col > e.col)) {
        std::swap(s, e);
    }

    SelectObject(hdc, g_mono_font);
    SetBkMode(hdc, OPAQUE);
    SetBkColor(hdc, RGB(0, 100, 255));
    SetTextColor(hdc, RGB(255, 255, 255));

    SIZE az;
    GetTextExtentPoint32W(hdc, L"A", 1, &az);
    int line_h = az.cy + 6;
    int y_orig = content_top + 8;

    int saved = SaveDC(hdc);
    IntersectClipRect(hdc, rc.left + 16, content_top, rc.right - 16, rc.bottom - 8);

    for (int i = s.line; i <= e.line; ++i) {
        if (i < 0 || i >= (int)all_lines.size()) continue;
        int y = y_orig + i * line_h - (int)t.content_scroll;
        if (y + line_h < content_top || y > rc.bottom) continue;

        std::wstring text = all_lines[i];
        int line_s_col = (i == s.line) ? s.col : 0;
        int line_e_col = (i == e.line) ? e.col : (int)text.size();
        
        if (line_s_col < 0) line_s_col = 0;
        if (line_e_col > (int)text.size()) line_e_col = (int)text.size();
        if (line_s_col >= line_e_col) continue;

        std::wstring sel_text = text.substr(line_s_col, line_e_col - line_s_col);
        SIZE offset_sz;
        GetTextExtentPoint32W(hdc, text.c_str(), line_s_col, &offset_sz);

        TextOutW(hdc, content_left + offset_sz.cx, y, sel_text.c_str(), (int)sel_text.size());
    }
    RestoreDC(hdc, saved);
}

static void copy_to_clipboard(HWND hwnd) {
    std::lock_guard<std::mutex> lk(g_mutex);
    if (g_sel_start.line == -1 || g_sel_end.line == -1) return;
    if (g_tabs.empty() || g_active_tab < 0 || g_active_tab >= (int)g_tabs.size()) return;

    TabState &t = g_tabs[g_active_tab];
    std::vector<std::wstring> all_lines = get_all_wrapped_lines(t, hwnd);
    std::wstring result;

    SelectionPos s = g_sel_start;
    SelectionPos e = g_sel_end;
    if (s.line > e.line || (s.line == e.line && s.col > e.col)) {
        std::swap(s, e);
    }
    
    for (int i = s.line; i <= e.line; ++i) {
        if (i < 0 || i >= (int)all_lines.size()) continue;
        std::wstring text = all_lines[i];
        
        int line_s_col = (i == s.line) ? s.col : 0;
        int line_e_col = (i == e.line) ? e.col : (int)text.size();

        if (line_s_col < 0) line_s_col = 0;
        if (line_e_col > (int)text.size()) line_e_col = (int)text.size();
        
        if (line_s_col < line_e_col) {
            result += text.substr(line_s_col, line_e_col - line_s_col);
        }
        if (i < e.line) result += L"\r\n";
    }

    if (!result.empty()) {
        if (OpenClipboard(hwnd)) {
            EmptyClipboard();
            size_t size = (result.size() + 1) * sizeof(wchar_t);
            HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, size);
            if (hg) {
                void* ptr = GlobalLock(hg);
                if (ptr) {
                    memcpy(ptr, result.c_str(), size);
                    GlobalUnlock(hg);
                    SetClipboardData(CF_UNICODETEXT, hg);
                }
            }
            CloseClipboard();
        }
    }
}

static void paste_from_clipboard(HWND hwnd) {
    if (OpenClipboard(hwnd)) {
        HANDLE hData = GetClipboardData(CF_UNICODETEXT);
        if (hData) {
            wchar_t *text = (wchar_t*)GlobalLock(hData);
            if (text) {
                int n = WideCharToMultiByte(CP_UTF8, 0, text, -1, NULL, 0, NULL, NULL);
                if (n > 1) {

                    std::string utf8(n - 1, '\0');
                    WideCharToMultiByte(CP_UTF8, 0, text, -1, &utf8[0], n - 1, NULL, NULL);

                    std::string sanitized;
                    for (char c : utf8) {
                        if ((unsigned char)c >= 32) sanitized += c;
                    }

                    std::lock_guard<std::mutex> lk(g_mutex);
                    if (!g_tabs.empty() && g_active_tab >= 0) {
                        TabState &t = g_tabs[g_active_tab];
                        if (t.input_cursor < 0) t.input_cursor = 0;
                        if (t.input_cursor > (int)t.input_buffer.size()) t.input_cursor = (int)t.input_buffer.size();
                        t.input_buffer.insert(t.input_cursor, sanitized);
                        t.input_cursor += (int)sanitized.size();
                    }
                }
                GlobalUnlock(hData);
            }
        }
        CloseClipboard();
        caret_show();
        InvalidateRect(hwnd, NULL, FALSE);
    }
}

static LRESULT CALLBACK clipboard_wndproc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_LBUTTONDOWN: {
            POINT pt = { GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
            if (pt.y > 72) {
                g_sel_start = mouse_to_text(hwnd, pt);
                g_sel_end = g_sel_start;
                g_is_selecting = true;
                SetCapture(hwnd);
                InvalidateRect(hwnd, NULL, FALSE);
            }
            break;
        }
        case WM_MOUSEMOVE: {
            if (g_is_selecting) {
                POINT pt = { GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
                SelectionPos current = mouse_to_text(hwnd, pt);
                if (current.line != g_sel_end.line || current.col != g_sel_end.col) {
                    g_sel_end = current;
                    InvalidateRect(hwnd, NULL, FALSE);
                }
            }
            break;
        }
        case WM_LBUTTONUP: {
            if (g_is_selecting) {
                g_is_selecting = false;
                ReleaseCapture();
                InvalidateRect(hwnd, NULL, FALSE);
            }
            break;
        }
        case WM_KEYDOWN: {
            if (GetKeyState(VK_CONTROL) & 0x8000) {
                if (wParam == 'C') {
                    copy_to_clipboard(hwnd);
                    return 0;
                } else if (wParam == 'V') {
                    paste_from_clipboard(hwnd);
                    return 0;
                } else if (wParam == 'A') {
                    std::lock_guard<std::mutex> lk(g_mutex);
                    if (!g_tabs.empty() && g_active_tab >= 0) {
                        TabState &t = g_tabs[g_active_tab];
                        std::vector<std::wstring> all_lines = get_all_wrapped_lines(t, hwnd);
                        g_sel_start = {0, 0};
                        int last = (int)all_lines.size() - 1;
                        if (last < 0) last = 0;
                        int last_col = (last < (int)all_lines.size()) ? (int)all_lines[last].size() : 0;
                        g_sel_end = {last, last_col};
                        InvalidateRect(hwnd, NULL, FALSE);
                    }
                    return 0;
                }
            }
            break;
        }
        case WM_PAINT: {
            LRESULT res = CallWindowProc(g_old_wndproc, hwnd, msg, wParam, lParam);
            HDC hdc = GetDC(hwnd);
            draw_selection(hdc, hwnd);
            ReleaseDC(hwnd, hdc);
            return res;
        }
    }
    return CallWindowProc(g_old_wndproc, hwnd, msg, wParam, lParam);
}

extern "C" void clipboard_init(HWND hwnd) {
    if (!g_old_wndproc) {
        g_old_wndproc = (WNDPROC)SetWindowLongPtr(hwnd, GWLP_WNDPROC, (LONG_PTR)clipboard_wndproc);
    }
}
