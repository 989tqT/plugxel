#include <sys/api/linux/cmp/tab.h>
#include <sys/api/linux/main_l.h>
#include <cairo.h>
#include <math.h>

void tab_l_draw(void* cr_ptr, int width) {
    if (g_tabs.empty()) return;
    
    cairo_t* cr = (cairo_t*)cr_ptr;
    
    // tab metrics
    int x_offset = 10;
    int y = 5;
    int h = 35;
    int r = 8;
    int tab_padding = 15;
    
    // rebuild close button hit boxes each frame
    g_tab_close_boxes.resize(g_tabs.size());

    for (size_t i = 0; i < g_tabs.size(); ++i) {
        cairo_text_extents_t te;
        cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
        cairo_set_font_size(cr, 13);
        cairo_text_extents(cr, g_tabs[i].title.c_str(), &te);
        int w = (int)te.width + tab_padding * 2 + 24; // 24 for close button
        
        // draw tab background
        cairo_new_sub_path(cr);
        cairo_arc(cr, x_offset + w - r, y + r, r, -M_PI/2, 0);
        cairo_line_to(cr, x_offset + w, y + h);
        cairo_line_to(cr, x_offset, y + h);
        cairo_arc(cr, x_offset + r, y + r, r, M_PI, -M_PI/2);
        cairo_close_path(cr);
        
        if ((int)i == g_active_tab) {
            cairo_set_source_rgb(cr, 0.094, 0.094, 0.094);
        } else {
            cairo_set_source_rgb(cr, 0.11, 0.11, 0.11);
        }
        cairo_fill(cr);

        // close button position
        int close_bx = x_offset + w - 20;
        int close_by = y + 13;
        int close_bw = 10;
        int close_bh = 10;

        // store hit box for click detection
        g_tab_close_boxes[i] = { close_bx, close_by, close_bw, close_bh };

        // draw close button green normally red on hover
        if (g_hover_close_tab == (int)i) {
            cairo_set_source_rgb(cr, 0.9, 0.2, 0.2); // Red on hover
        } else {
            cairo_set_source_rgb(cr, 0.2, 0.75, 0.2); // Green normal
        }
        // draw as a rounded small square
        double bx = close_bx, by2 = close_by, bw = close_bw, bh = close_bh, br = 2.5;
        cairo_new_sub_path(cr);
        cairo_arc(cr, bx + bw - br, by2 + br, br, -M_PI/2, 0);
        cairo_arc(cr, bx + bw - br, by2 + bh - br, br, 0, M_PI/2);
        cairo_arc(cr, bx + br, by2 + bh - br, br, M_PI/2, M_PI);
        cairo_arc(cr, bx + br, by2 + br, br, M_PI, -M_PI/2);
        cairo_close_path(cr);
        cairo_fill(cr);

        // draw tab text
        if ((int)i == g_active_tab) {
            cairo_set_source_rgb(cr, 0.9, 0.9, 0.9);
        } else {
            cairo_set_source_rgb(cr, 0.5, 0.5, 0.5);
        }
        cairo_move_to(cr, x_offset + tab_padding, y + 22);
        cairo_show_text(cr, g_tabs[i].title.c_str());
        
        g_tabs[i].hit_x = x_offset;
        g_tabs[i].hit_w = w;

        x_offset += w + 4;
    }
}
