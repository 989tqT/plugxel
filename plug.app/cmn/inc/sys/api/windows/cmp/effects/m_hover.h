#ifndef M_HOVER_H
#define M_HOVER_H

#include <windows.h>
#include <vector>

/**
 * @brief Global index of the line currently being hovered by the mouse.
 * -1 if no line is hovered.
 */
extern int g_hover_line_idx;

/**
 * @brief Global index of the tab close button currently being hovered.
 * -1 if none.
 */
extern int g_hover_close_tab;

/**
 * @brief Handles mouse movement within the content area to track line hovering.
 * @param hwnd Handle to the main window.
 * @param pt Current mouse position in client coordinates.
 * @param content_rc The rectangle defining the scrollable content area.
 * @param scroll Current vertical scroll offset.
 * @param line_h Height of a single text line in pixels.
 */
void hover_update(HWND hwnd, POINT pt, RECT content_rc, float scroll, int line_h);

/**
 * @brief Standard Windows function to check if a point is inside a tab close rect.
 * Note: Decoupled here to keep main_w.cpp clean.
 */
typedef int (*hit_test_fn)(POINT pt, const std::vector<RECT>& rects);

/**
 * @brief Updates the hover state for tab close buttons.
 */
void hover_tab_update(HWND hwnd, int hover_idx);

/**
 * @brief Resets the hover state when the mouse leaves the window or content area.
 * @param hwnd Handle to the main window.
 */
void hover_reset(HWND hwnd);

/**
 * @brief Calculates the appropriate color for a line based on its hover state.
 * @param base_color The original color of the line text.
 * @param line_idx The index of the line being rendered.
 * @return The highlighted color if hovered, otherwise the base color.
 */
COLORREF hover_get_color(COLORREF base_color, int line_idx);

#endif // M_HOVER_H
