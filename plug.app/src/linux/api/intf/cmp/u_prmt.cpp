#include <sys/api/linux/cmp/u_prmt.h>
#include <cairo.h>

void u_prmt_l_draw(void* cr_ptr, int x, int y) {
    cairo_t* cr = (cairo_t*)cr_ptr;
    
    // save state
    cairo_save(cr);

    // green color for prompt matches windows col_user
    cairo_set_source_rgb(cr, 90.0/255.0, 255.0/255.0, 90.0/255.0); 
    
    // font setup
    cairo_select_font_face(cr, "monospace", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
    cairo_set_font_size(cr, 14);
    
    cairo_move_to(cr, x, y);
    cairo_show_text(cr, "<~> -> ");

    // restore state
    cairo_restore(cr);
}
