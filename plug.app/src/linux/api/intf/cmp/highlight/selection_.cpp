#include <sys/api/linux/cmp/selection.h>
#include <sys/api/linux/main_l.h>
#include <cairo.h>
#include <algorithm>

SelectionState g_selection = { false, false, {-1, -1}, {-1, -1}, -1 };

void selection_l_draw(void* cr_ptr) {
    if (!g_selection.active || g_selection.tab_idx != g_active_tab) return;
    if (g_tabs.empty()) return;

    cairo_t* cr = (cairo_t*)cr_ptr;
    cairo_save(cr);

    // google blue highlight color with ~40% opacity
    cairo_set_source_rgba(cr, 65.0/255.0, 133.0/255.0, 244.0/255.0, 0.4);

    SelectionPos s = std::min(g_selection.start, g_selection.end);
    SelectionPos e = std::max(g_selection.start, g_selection.end);

    TabState& t = g_tabs[g_active_tab];
    
    cairo_select_font_face(cr, "monospace", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
    cairo_set_font_size(cr, 14);
    cairo_font_extents_t fe;
    cairo_font_extents(cr, &fe);
    int line_h = fe.height + 4;

    cairo_text_extents_t space_te;
    cairo_text_extents(cr, "A", &space_te);
    int char_w = space_te.x_advance;
    if (char_w == 0) char_w = 8;

    int start_y = 40 - (int)t.content_scroll;

    for (int i = s.line; i <= e.line && i < (int)t.wrapped_lines.size(); ++i) {
        int y = start_y + (i * line_h);
        if (y + line_h < 40) continue; 

        int len = t.wrapped_lines[i].text.length();
        int col_start = (i == s.line) ? s.col : 0;
        int col_end = (i == e.line) ? e.col : len;

        if (col_end < col_start) col_end = col_start;

        int hl_x = 10 + col_start * char_w;
        int hl_w = (col_end - col_start) * char_w;
        if (hl_w == 0 && i != e.line) hl_w = char_w; // highlight newline

        cairo_rectangle(cr, hl_x, y, hl_w, line_h);
        cairo_fill(cr);
    }

    cairo_restore(cr);
}
