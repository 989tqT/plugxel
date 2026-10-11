#ifndef SYS_API_COMP_CARET_H
#define SYS_API_COMP_CARET_H

#include <windows.h>

void caret_init(HWND hwnd);
void caret_cleanup();
bool caret_on_timer(UINT_PTR timer_id);
void caret_show();
bool caret_is_visible();
void caret_draw(HDC hdc, int cx, int baseline, int font_cy);

#endif

