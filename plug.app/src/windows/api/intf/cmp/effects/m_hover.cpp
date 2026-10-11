#include <sys/api/windows/cmp/effects/m_hover.h>

// global hover index variables
int g_hover_line_idx = -1;
int g_hover_close_tab = -1;

void hover_update(HWND hwnd, POINT pt, RECT content_rc, float scroll, int line_h) {
    if (PtInRect(&content_rc, pt)) {
        // calculate the relative y within the content area including scroll
        int local_y = pt.y - content_rc.top - 8 + (int)scroll;
        int new_hover_line = (line_h > 0) ? (local_y / line_h) : -1;
        
        if (new_hover_line < 0) new_hover_line = -1;
        
        // only invalidate if the hover line changed to reduce flickering
        if (new_hover_line != g_hover_line_idx) {
            g_hover_line_idx = new_hover_line;
            InvalidateRect(hwnd, NULL, FALSE);
        }
    } else if (g_hover_line_idx != -1) {
        // clear hover if mouse moved out of the content area
        g_hover_line_idx = -1;
        InvalidateRect(hwnd, NULL, FALSE);
    }
}

void hover_tab_update(HWND hwnd, int hover_idx) {
    if (hover_idx != g_hover_close_tab) {
        g_hover_close_tab = hover_idx;
        InvalidateRect(hwnd, NULL, FALSE);
    }
}

void hover_reset(HWND hwnd) {
    bool changed = false;
    if (g_hover_line_idx != -1) {
        g_hover_line_idx = -1;
        changed = true;
    }
    if (g_hover_close_tab != -1) {
        g_hover_close_tab = -1;
        changed = true;
    }
    if (changed) {
        InvalidateRect(hwnd, NULL, FALSE);
    }
}

COLORREF hover_get_color(COLORREF base_color, int line_idx) {
    if (line_idx == g_hover_line_idx) {
        // brighten the color for hover effect
        int r = GetRValue(base_color) + 40; if (r > 255) r = 255;
        int g = GetGValue(base_color) + 40; if (g > 255) g = 255;
        int b = GetBValue(base_color) + 40; if (b > 255) b = 255;
        
        // special case for light grey output to ensure it pops
        if (r > 220 && g > 220 && b > 220) {
            return RGB(255, 255, 255);
        }
        
        return RGB(r, g, b);
    }
    return base_color;
}
