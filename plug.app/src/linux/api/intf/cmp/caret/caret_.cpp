#include <sys/api/linux/cmp/caret.h>
#include <cairo.h>
#include <gtk/gtk.h>

static bool g_caret_visible = true;
static gint64 g_last_blink_time = 0;

void caret_l_draw(void* cr_ptr, int x, int y) {
    // caret blink logic 500ms toggle
    gint64 current_time = g_get_monotonic_time(); // microseconds
    if (current_time - g_last_blink_time > 500000) {
        g_caret_visible = !g_caret_visible;
        g_last_blink_time = current_time;
    }

    cairo_t* cr = (cairo_t*)cr_ptr;
    cairo_save(cr);

    if (g_caret_visible) {
        cairo_set_source_rgb(cr, 255.0/255.0, 90.0/255.0, 90.0/255.0); // Red
    } else {
        cairo_set_source_rgb(cr, 1.0, 1.0, 1.0); // White
    }
    
    // draw thick caret
    cairo_rectangle(cr, x, y - 12, 6, 14);
    cairo_fill(cr);
    
    cairo_restore(cr);
}

void caret_l_update(void) {
    // force caret visible immediately on typing
    g_caret_visible = true;
    g_last_blink_time = g_get_monotonic_time();
}
