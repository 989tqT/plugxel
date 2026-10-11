#include <sys/api/linux/cmp/u_lbl.h>
#include <cairo.h>

void u_lbl_l_draw(void* cr_ptr, int x, int y, const char* text) {
    cairo_t* cr = (cairo_t*)cr_ptr;
    cairo_set_source_rgb(cr, 0.8, 0.8, 0.8); // White-grey text
    cairo_select_font_face(cr, "monospace", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
    cairo_set_font_size(cr, 14);
    cairo_move_to(cr, x, y);
    cairo_show_text(cr, text);
}
