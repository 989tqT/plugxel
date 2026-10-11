#include <sys/api/linux/cmp/clipboard.h>

void clipb_l_copy(const char* text) {
    // gtk clipboard copy
}

char* clipb_l_paste(void) {
    return 0; // gtk clipboard paste
}
