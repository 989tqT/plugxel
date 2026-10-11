#ifndef SELECTION_H
#define SELECTION_H

#include <windows.h>
#include <vector>

/**
 * @brief Represents a logical position in the terminal text.
 */
struct SelectionPos {
    int line; // Line index (0-based)
    int col;  // Character/Column index (0-based)

    bool operator==(const SelectionPos& other) const {
        return line == other.line && col == other.col;
    }
    bool operator!=(const SelectionPos& other) const {
        return !(*this == other);
    }
    bool operator<(const SelectionPos& other) const {
        if (line != other.line) return line < other.line;
        return col < other.col;
    }
    bool operator<=(const SelectionPos& other) const {
        return *this < other || *this == other;
    }
};

/**
 * @brief Global selection state.
 */
struct SelectionState {
    bool active;        // Is there an active selection?
    bool dragging;      // Is the user currently dragging to select?
    SelectionPos start; // Selection start position
    SelectionPos end;   // Current/End selection position
    int tab_idx;        // Which tab the selection belongs to
};

extern SelectionState g_selection;

/**
 * @brief Initializes/resets the selection state.
 */
void selection_init();

/**
 * @brief Starts a new selection at the given logical position.
 */
void selection_start(int tab_idx, SelectionPos pos);

/**
 * @brief Updates the selection end point during a drag operation.
 */
void selection_update(SelectionPos pos);

/**
 * @brief Ends the selection dragging operation.
 */
void selection_stop();

/**
 * @brief Clears the active selection.
 */
void selection_clear();

/**
 * @brief Checks if a specific character position is within the current selection.
 */
bool selection_is_selected(int line, int col);

/**
 * @brief Returns the selected character range [start, end) for a specific line.
 * @param line_idx The line to check.
 * @param line_len Total length of the text on that line.
 * @param out_start Start index of selection on this line.
 * @param out_end End index (exclusive) of selection on this line.
 * @return True if any part of the line is selected.
 */
bool selection_get_line_range(int line_idx, int line_len, int& out_start, int& out_end);

/**
 * @brief Helper to map screen coordinates to logical text coordinates.
 */
SelectionPos selection_map_point(POINT pt, RECT content_rc, float scroll, int char_w, int line_h, int total_lines);

/**
 * @brief Renders a beautiful, semi-transparent selection highlight.
 * @param hdc The device context to draw into.
 * @param rect The rectangle to highlight.
 */
void selection_render_highlight(HDC hdc, RECT rect);

#endif // SELECTION_H
