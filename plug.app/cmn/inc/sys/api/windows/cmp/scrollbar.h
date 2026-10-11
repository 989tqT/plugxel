#ifndef SYS_API_COMP_SCROLLBAR_H
#define SYS_API_COMP_SCROLLBAR_H

#include <windows.h>

float scrollb_clamp_offset(float offset, int content_len, int visible_len);
bool scrollb_compute_thumb_rect(RECT track, int content_len, int visible_len, float offset, RECT& out_thumb);
void scrollb_render_horizontal(HDC hdc, RECT track, int content_len, int visible_len, float offset, float alpha);
bool scrollb_compute_thumb_rect_vertical(RECT track, int content_len, int visible_len, float offset, RECT& out_thumb);
void scrollb_render_vertical(HDC hdc, RECT track, int content_len, int visible_len, float offset, float alpha);

#endif
