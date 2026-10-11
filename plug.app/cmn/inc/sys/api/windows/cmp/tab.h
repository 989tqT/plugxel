#ifndef SYS_API_COMP_TAB_H
#define SYS_API_COMP_TAB_H

#include <windows.h>
#include <vector>
#include <string>

void tab_render_bar(HDC hdc, RECT tabr, const std::vector<std::wstring>& titles, int active_index, float g_tab_scroll, float g_scroll_alpha, std::vector<RECT>& out_close_rects, int hover_close_index);

int tab_hit_test_pt(POINT pt, RECT hr, int tabs_count, float g_tab_scroll);

int tab_close_hit_test(POINT pt, const std::vector<RECT>& close_rects);

#endif

