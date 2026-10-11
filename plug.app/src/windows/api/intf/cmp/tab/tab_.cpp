#include <sys/api/windows/cmp/tab.h>
#include <windows.h>
#include <string>
#include <vector>
#include <algorithm>

void tab_render_bar(HDC hdc, RECT tabr, const std::vector<std::wstring>& titles, int active_index, float g_tab_scroll, float g_scroll_alpha, std::vector<RECT>& out_close_rects, int hover_close_index) {
    const int active_extension = 12;
    int tx = 12 - (int)g_tab_scroll;
    out_close_rects.clear(); out_close_rects.resize(titles.size());
    for (size_t i=0;i<titles.size();++i) {
        std::wstring t = titles[i].empty() ? (L"tab " + std::to_wstring((int)i+1)) : titles[i];
        RECT trt;
        if ((int)i == active_index) trt = {tx, tabr.top+4, tx+140, tabr.bottom + active_extension};
        else trt = {tx, tabr.top+4, tx+140, tabr.bottom-4};

        COLORREF tab_bg_color = RGB(8,8,8);
        COLORREF tab_border_color = RGB(18,18,18);
        COLORREF text_color = RGB(220, 220, 220);
        if ((int)i == active_index) { tab_bg_color = RGB(20,20,20); tab_border_color = RGB(30,30,30); }

        HBRUSH bg_brush = CreateSolidBrush(tab_bg_color);
        HBRUSH old_brush = (HBRUSH)SelectObject(hdc, bg_brush);
        if ((int)i == active_index) {
            RoundRect(hdc, trt.left, trt.top, trt.right, trt.bottom, 12, 12);
        } else {
            HPEN border_pen = CreatePen(PS_SOLID, 1, tab_border_color);
            HPEN old_pen = (HPEN)SelectObject(hdc, border_pen);
            Rectangle(hdc, trt.left, trt.top, trt.right, trt.bottom);
            SelectObject(hdc, old_pen);
            DeleteObject(border_pen);
        }
        SelectObject(hdc, old_brush); DeleteObject(bg_brush);

        SetTextColor(hdc, text_color);
        DrawTextW(hdc, t.c_str(), (int)t.size(), &trt, DT_CENTER|DT_VCENTER|DT_SINGLELINE | DT_NOPREFIX);

        int circle_size = 8;
        int circle_x = trt.right - 20;
        int circle_y = trt.top + (trt.bottom - trt.top - circle_size) / 2;
        RECT circle_rect = {circle_x, circle_y, circle_x + circle_size, circle_y + circle_size};
        COLORREF dot_color = (hover_close_index == (int)i) ? RGB(200,80,80) : RGB(100,200,100);
        HBRUSH dot_br = CreateSolidBrush(dot_color);
        FillRect(hdc, &circle_rect, dot_br);
        DeleteObject(dot_br);
        out_close_rects[i] = circle_rect;
        tx += 150;
    }
}

int tab_hit_test_pt(POINT pt, RECT hr, int tabs_count, float g_tab_scroll) {
    int tx = 12 - (int)g_tab_scroll;
    for (int i=0;i<tabs_count;++i) {
        RECT trt = {tx, hr.top + 4, tx+140, hr.bottom - 4};
        if (PtInRect(&trt, pt)) return i;
        tx += 150;
    }
    return -1;
}

int tab_close_hit_test(POINT pt, const std::vector<RECT>& close_rects) {
    for (int i=0;i<(int)close_rects.size();++i) {
        if (PtInRect(&close_rects[i], pt)) return i;
    }
    return -1;
}

