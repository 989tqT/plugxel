#ifndef CLIPBOARD_L_H
#define CLIPBOARD_L_H

#ifdef __cplusplus
extern "C" {
#endif

void clipb_l_copy(const char* text);
char* clipb_l_paste(void);

#ifdef __cplusplus
}
#endif

#endif
