#ifndef MAIN_L_H
#define MAIN_L_H

#ifdef __cplusplus
// forward declare for c++ code
typedef struct _GtkWidget GtkWidget;

#include <vector>
#include <string>

struct ColorRGB {
    double r, g, b;
};

struct DisplayLine {
    std::string text;
    ColorRGB color;
    bool is_continuation = false;
};

struct TabState {
    std::string title = "";
    std::vector<DisplayLine> raw_lines;
    std::vector<DisplayLine> wrapped_lines;
    std::string input_buffer = "";
    float content_scroll = 0.0f;
    float content_scroll_target = 0.0f;
    int content_total_height = 0;
    bool user_scrolled = false;
    bool request_scroll_to_bottom = true;
    bool follow_on_output = true;
    int input_cursor = 0;
    std::string plugin_owner = "";
    std::string cwd = ""; 
    int hit_x = 0;
    int hit_w = 0;
    int hover_line = -1;
};

struct SelectionPos {
    int line;
    int col;
    bool operator<(const SelectionPos& other) const {
        if (line != other.line) return line < other.line;
        return col < other.col;
    }
    bool operator==(const SelectionPos& other) const {
        return line == other.line && col == other.col;
    }
    bool operator!=(const SelectionPos& other) const {
        return !(*this == other);
    }
};

struct SelectionState {
    bool active;
    bool dragging;
    SelectionPos start;
    SelectionPos end;
    int tab_idx;
};

#endif // __cplusplus

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int window_width;
    int window_height;
    float scroll_offset;
    int max_scroll;
} ui_state_l_t;

extern ui_state_l_t g_main_l_state;

#ifdef __cplusplus
extern GtkWidget* g_drawing_area;
extern std::vector<TabState> g_tabs;
extern int g_active_tab;
extern SelectionState g_selection;

struct HitBox { int x, y, w, h; };
extern std::vector<HitBox> g_tab_close_boxes;
extern int g_hover_close_tab;
extern int g_char_w;
#endif

int main_l_init(void);
void main_l_run_message_loop(void);
void main_l_cleanup(void);

void main_l_print_banner(void);
void main_l_print_info(const char* msg);
void main_l_print_error(const char* msg);
void main_l_set_prompt_visibility(int visible);
void main_l_add_tab(const char* owner);
void main_l_request_close(void);
void main_l_replace_last_line(const char* msg);
void main_l_set_tab_owner(int tab_idx, const char* owner);
int main_l_get_tab_owner(int tab_idx, char* buf, int max_len);
void main_l_set_tab_cwd(int tab_idx, const char* cwd);
int main_l_get_current_print_tab(void);

#ifdef __cplusplus
}
#endif

#endif
