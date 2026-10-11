#include <sys/api/linux/cmp/scrollbar.h>
#include <sys/api/linux/main_l.h>
#include <cairo.h>

void scrollb_l_draw(void* cr_ptr, int width, int height) {
    if (g_tabs.empty()) return;
    TabState &t = g_tabs[g_active_tab];
    
    if (t.content_total_height <= height - 40) return; // No scroll needed

    cairo_t* cr = (cairo_t*)cr_ptr;
    
    // draw track
    cairo_set_source_rgb(cr, 0.15, 0.15, 0.15);
    cairo_rectangle(cr, width - 8, 45, 4, height - 50);
    cairo_fill(cr);
    
    // calculate thumb size and position
    float viewport_ratio = (float)(height - 40) / (float)t.content_total_height;
    int thumb_height = (height - 50) * viewport_ratio;
    if (thumb_height < 20) thumb_height = 20; // Minimum thumb height
    
    float scroll_ratio = t.content_scroll / (float)(t.content_total_height - (height - 40));
    int thumb_y = 45 + scroll_ratio * (height - 50 - thumb_height);
    
    // draw thumb
    cairo_set_source_rgb(cr, 0.4, 0.4, 0.4);
    cairo_rectangle(cr, width - 8, thumb_y, 4, thumb_height);
    cairo_fill(cr);
}
