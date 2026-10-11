#include <sys/api/linux/main_l.h>
#include <sys/api/linux/cmp/u_prmt.h>
#include <sys/api/linux/cmp/u_lbl.h>
#include <sys/api/linux/cmp/tab.h>
#include <sys/api/linux/cmp/caret.h>
#include <sys/api/linux/cmp/clipboard.h>
#include <sys/api/linux/cmp/selection.h>
#include <sys/api/linux/cmp/scrollbar.h>
#include <sys/api/linux/cmp/effects/m_hover.h>

#include <sys/c.h> // For c_parse
#include <sys/sys_info.h> // For sys_info

#include <gtk/gtk.h>
#include <cairo.h>
#include <iostream>
#include <vector>
#include <string>
#include <mutex>
#include <queue>
#include <thread>
#include <condition_variable>
#include <atomic>

static gboolean print_info_idle(gpointer data);

ui_state_l_t g_main_l_state = {0};
GtkWidget* g_drawing_area = NULL;
static GtkApplication* g_app = NULL;
GtkWidget* g_window = NULL;

const ColorRGB COL_BG = {30.0/255.0, 30.0/255.0, 30.0/255.0};
const ColorRGB COL_HEADER = {20.0/255.0, 20.0/255.0, 20.0/255.0};
const ColorRGB COL_USER = {90.0/255.0, 255.0/255.0, 90.0/255.0};
const ColorRGB COL_CMD = {255.0/255.0, 90.0/255.0, 90.0/255.0};
const ColorRGB COL_OUTPUT = {230.0/255.0, 230.0/255.0, 230.0/255.0};

std::vector<TabState> g_tabs;
int g_active_tab = 0;
std::mutex g_mutex;

#if defined(PLUGXEL_ENABLE_HEADLESS_MODE) || defined(PLUG_ENABLE_HEADLESS_MODE)
extern "C" bool g_headless_mode;
#else
static constexpr bool g_headless_mode = false;
#endif
static std::thread g_cmd_thread;
static std::mutex g_cmd_mutex;
static std::condition_variable g_cmd_cv;
struct CmdItem { int tab; std::string cmd; };
static std::queue<CmdItem> g_cmd_queue;
static std::atomic_bool g_cmd_thread_running{false};
static std::thread g_headless_stdin_thread;

struct PrintData {
    int tab_idx;
    std::string msg;
    ColorRGB color;
    bool is_continuation;
};

struct ReplaceLastLineData {
    int tab_idx;
    std::string msg;
};


static void headless_stdin_worker(void) {
    std::string line;
    while (std::getline(std::cin, line)) {
        if (line.empty()) continue;

        if (line == "__dump_state__") {
            std::lock_guard<std::mutex> lk(g_mutex);
            std::cout << "\n---STATE_DUMP_START---\n";
            std::cout << "{\n";
            std::cout << "  \"active_tab\": " << g_active_tab << ",\n";
            std::cout << "  \"tabs\": [\n";
            for (size_t i = 0; i < g_tabs.size(); ++i) {
                std::string title_utf8 = g_tabs[i].title;
                std::string raw_input = g_tabs[i].input_buffer;
                std::string escaped_input;
                for (char c : raw_input) {
                    if (c == '\\') escaped_input += "\\\\";
                    else if (c == '"') escaped_input += "\\\"";
                    else escaped_input += c;
                }
                std::cout << "    {\n";
                std::cout << "      \"index\": " << i << ",\n";
                std::cout << "      \"title\": \"" << title_utf8 << "\",\n";
                std::cout << "      \"input_buffer\": \"" << escaped_input << "\",\n";
                std::cout << "      \"plugin_owner\": \"" << (g_tabs[i].plugin_owner.empty() ? "" : g_tabs[i].plugin_owner) << "\"\n";
                std::cout << "    }" << (i + 1 < g_tabs.size() ? "," : "") << "\n";
            }
            std::cout << "  ]\n";
            std::cout << "}\n";
            std::cout << "---STATE_DUMP_END---\n" << std::endl;
            continue;
        }

        // push command to queue
        {
            std::lock_guard<std::mutex> clk(g_cmd_mutex);
            g_cmd_queue.push({g_active_tab, line});
            g_cmd_cv.notify_one();
        }
    }
    // EOF reached (stdin closed) - exit gracefully
    main_l_request_close();
}
thread_local int g_print_tab = -1;
int g_hover_close_tab = -1;
std::vector<HitBox> g_tab_close_boxes;
int g_char_w = 8;
static int g_tab_counter = 1;



static void on_draw(GtkDrawingArea *area, cairo_t *cr, int width, int height, gpointer user_data) {
    std::lock_guard<std::mutex> lk(g_mutex);

    // 1 draw background
    cairo_set_source_rgb(cr, COL_BG.r, COL_BG.g, COL_BG.b);
    cairo_paint(cr);

    // 2 draw top bar header background
    cairo_set_source_rgb(cr, COL_HEADER.r, COL_HEADER.g, COL_HEADER.b);
    cairo_rectangle(cr, 0, 0, width, 40);
    cairo_fill(cr);

    // draw tab component
    tab_l_draw(cr, width);

    if (g_tabs.empty()) return;
    TabState &t = g_tabs[g_active_tab];

    // 3 setup font for text rendering
    cairo_select_font_face(cr, "monospace", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
    cairo_set_font_size(cr, 14);

    cairo_font_extents_t fe;
    cairo_font_extents(cr, &fe);
    int line_h = fe.height + 4; // add padding

    // proper word-wrap rewrap whenever raw_lines changed
// store last seen raw_lines count on tab to know when to rewrap
    if (t.wrapped_lines.empty() || t.wrapped_lines.size() != t.raw_lines.size()) {
        t.wrapped_lines.clear();
        const int max_w = width - 24; // leave 8px left margin + scrollbar gap
        const int left_margin = 10;
        cairo_text_extents_t wte;

        for (const auto& raw : t.raw_lines) {
            const std::string& text = raw.text;
            if (text.empty()) {
                t.wrapped_lines.push_back({"", raw.color, false});
                continue;
            }
            // split text into word wrap greedily by pixel width
            std::string current_line;
            bool first_seg = true;
            size_t pos = 0;
            while (pos <= text.size()) {
                // find next word boundary
                size_t space = text.find_first_of(" \t", pos);
                if (space == std::string::npos) space = text.size();
                std::string word = text.substr(pos, space - pos);

                std::string candidate = first_seg ? word : (current_line + " " + word);
                cairo_text_extents(cr, candidate.c_str(), &wte);

                if (!first_seg && (left_margin + wte.x_advance) > max_w) {
                    // flush current line
                    t.wrapped_lines.push_back({current_line, raw.color, !first_seg});
                    current_line = word;
                    first_seg = false;
                } else {
                    current_line = candidate;
                    first_seg = false;
                }
                pos = space + 1;
            }
            if (!current_line.empty()) {
                t.wrapped_lines.push_back({current_line, raw.color, false});
            }
        }
        t.content_total_height = (int)t.wrapped_lines.size() * line_h + line_h * 3;
    }

    // clip rendering area to below header
    cairo_rectangle(cr, 0, 40, width, height - 40);
    cairo_clip(cr);

    int start_y = 40 - (int)t.content_scroll;
    int current_y = start_y;

    int i = 0;
    for (const auto& line : t.wrapped_lines) {
        if (current_y + line_h > 40 && current_y < height) {
            double r = line.color.r;
            double g = line.color.g;
            double b = line.color.b;
            
            if (i == t.hover_line) {
                r += 40.0/255.0; if (r > 1.0) r = 1.0;
                g += 40.0/255.0; if (g > 1.0) g = 1.0;
                b += 40.0/255.0; if (b > 1.0) b = 1.0;
                if (r > 0.86 && g > 0.86 && b > 0.86) {
                    r = 1.0; g = 1.0; b = 1.0;
                }
            }
            
            cairo_set_source_rgb(cr, r, g, b);
            cairo_move_to(cr, 10, current_y + fe.ascent);
            cairo_show_text(cr, line.text.c_str());
        }
        current_y += line_h;
        i++;
    }

    // 3.5 draw selection highlight
    selection_l_draw(cr);

    // 4 draw input prompt
    cairo_reset_clip(cr);
    int input_y = current_y + fe.ascent;
    if (input_y > 40 && input_y < height) {
        u_prmt_l_draw(cr, 10, input_y);
        
        cairo_text_extents_t prompt_te;
        cairo_text_extents(cr, "<~> -> ", &prompt_te);
        int input_x = 10 + prompt_te.x_advance;

        // measure actual char width for selection accuracy
        cairo_text_extents_t aw;
        cairo_text_extents(cr, "A", &aw);
        if (aw.x_advance > 0) g_char_w = (int)aw.x_advance;

        cairo_set_source_rgb(cr, COL_OUTPUT.r, COL_OUTPUT.g, COL_OUTPUT.b);
        cairo_move_to(cr, input_x, input_y);
        cairo_show_text(cr, t.input_buffer.c_str());

        // 5 draw caret
        cairo_text_extents_t caret_te;
        cairo_text_extents(cr, t.input_buffer.substr(0, t.input_cursor).c_str(), &caret_te);
        caret_l_draw(cr, input_x + caret_te.x_advance, input_y);
    }

    // 6 draw scrollbar component
    scrollb_l_draw(cr, width, height);
}

static gboolean on_key_pressed(GtkEventControllerKey *controller, guint keyval, guint keycode, GdkModifierType state, gpointer user_data) {
    std::lock_guard<std::mutex> lk(g_mutex);
    if (g_tabs.empty()) return FALSE;
    TabState &t = g_tabs[g_active_tab];

    caret_l_update(); // reset blink

    if ((state & GDK_CONTROL_MASK) != 0) {
        if (keyval == GDK_KEY_c || keyval == GDK_KEY_C) {
            if (g_selection.active) {
                SelectionPos s = std::min(g_selection.start, g_selection.end);
                SelectionPos e = std::max(g_selection.start, g_selection.end);
                std::string copied_text = "";
                for (int i = s.line; i <= e.line && i < (int)t.wrapped_lines.size(); ++i) {
                    int col_start = (i == s.line) ? s.col : 0;
                    int col_end = (i == e.line) ? e.col : t.wrapped_lines[i].text.length();
                    if (col_end < col_start) col_end = col_start;
                    copied_text += t.wrapped_lines[i].text.substr(col_start, col_end - col_start);
                    if (i < e.line) copied_text += "\n";
                }
                GdkClipboard *cb = gtk_widget_get_clipboard(g_drawing_area);
                gdk_clipboard_set_text(cb, copied_text.c_str());
            }
            return TRUE;
        } else if (keyval == GDK_KEY_v || keyval == GDK_KEY_V) {
            GdkClipboard *cb = gtk_widget_get_clipboard(g_drawing_area);
            gdk_clipboard_read_text_async(cb, NULL, [](GObject *source, GAsyncResult *res, gpointer data) {
                char *text = gdk_clipboard_read_text_finish(GDK_CLIPBOARD(source), res, NULL);
                if (text) {
                    std::lock_guard<std::mutex> lk(g_mutex);
                    if (!g_tabs.empty()) {
                        TabState &tab = g_tabs[g_active_tab];
                        // strip newlines for input buffer
                        std::string sanitized;
                        for (int i=0; text[i]; i++) {
                            if ((unsigned char)text[i] >= 32) sanitized += text[i];
                        }
                        tab.input_buffer.insert(tab.input_cursor, sanitized);
                        tab.input_cursor += sanitized.length();
                        gtk_widget_queue_draw(g_drawing_area);
                    }
                    g_free(text);
                }
            }, NULL);
            return TRUE;
        } else if (keyval == GDK_KEY_a || keyval == GDK_KEY_A) {
            g_selection.active = true;
            g_selection.tab_idx = g_active_tab;
            g_selection.start = {0, 0};
            int last_line = t.wrapped_lines.empty() ? 0 : t.wrapped_lines.size() - 1;
            int last_col = t.wrapped_lines.empty() ? 0 : t.wrapped_lines.back().text.length();
            g_selection.end = {last_line, last_col};
            gtk_widget_queue_draw(g_drawing_area);
            return TRUE;
        }
    }

    if (keyval == GDK_KEY_BackSpace) {
        if (t.input_cursor > 0) {
            t.input_buffer.erase(t.input_cursor - 1, 1);
            t.input_cursor--;
        }
        return TRUE;
    } else if (keyval == GDK_KEY_Return || keyval == GDK_KEY_KP_Enter) {
        if (!t.input_buffer.empty()) {
            // push to command queue
            {
                std::lock_guard<std::mutex> clk(g_cmd_mutex);
                g_cmd_queue.push({g_active_tab, t.input_buffer});
                g_cmd_cv.notify_one();
            }
            t.raw_lines.push_back({t.input_buffer, COL_CMD, false});
            t.wrapped_lines.clear();
            t.input_buffer.clear();
            t.input_cursor = 0;
        }
        return TRUE;
    } else if (keyval == GDK_KEY_Left) {
        if (t.input_cursor > 0) t.input_cursor--;
        return TRUE;
    } else if (keyval == GDK_KEY_Right) {
        if (t.input_cursor < (int)t.input_buffer.length()) t.input_cursor++;
        return TRUE;
    } else {
        // handle printable character rudimentary ascii for now
        guint32 unicode = gdk_keyval_to_unicode(keyval);
        if (unicode != 0 && unicode >= 32 && unicode != 127) {
            char buf[8] = {0};
            int len = g_unichar_to_utf8(unicode, buf);
            t.input_buffer.insert(t.input_cursor, buf, len);
            t.input_cursor += len;
            return TRUE;
        }
    }
    return FALSE;
}

static gboolean on_scroll(GtkEventControllerScroll *controller, double dx, double dy, gpointer user_data) {
    std::lock_guard<std::mutex> lk(g_mutex);
    if (g_tabs.empty()) return FALSE;
    TabState &t = g_tabs[g_active_tab];
    
    // smooth scrolling target increment
    t.content_scroll_target += dy * 40.0; // 40px per scroll tick
    
    // clamp target
    int view_h = gtk_widget_get_height(g_drawing_area) - 40;
    float max_scroll = t.content_total_height - view_h;
    if (max_scroll < 0) max_scroll = 0;
    
    if (t.content_scroll_target < 0) t.content_scroll_target = 0;
    if (t.content_scroll_target > max_scroll) t.content_scroll_target = max_scroll;
    
    t.user_scrolled = true;
    t.follow_on_output = false; // Disable auto-scroll when user manually scrolls
    
    return TRUE;
}

static void on_click(GtkGestureClick *gesture, int n_press, double x, double y, gpointer user_data) {
    bool should_quit = false;
    int close_idx = -1;
    int tab_hit = -1;

    // phase 1 hit-test under lock record result release lock
    {
        std::lock_guard<std::mutex> lk(g_mutex);
        if (g_tabs.empty()) return;

        if (y < 40) {
            for (size_t i = 0; i < g_tab_close_boxes.size(); ++i) {
                const HitBox& cb = g_tab_close_boxes[i];
                if (x >= cb.x && x <= cb.x + cb.w && y >= cb.y && y <= cb.y + cb.h) {
                    if (g_tabs.size() > 1) {
                        close_idx = (int)i;
                    } else {
                        should_quit = true;
                    }
                    goto done_hittest;
                }
                if (x >= g_tabs[i].hit_x && x <= g_tabs[i].hit_x + g_tabs[i].hit_w) {
                    tab_hit = (int)i;
                    goto done_hittest;
                }
            }
        } else {
            g_selection.active = false;
            g_selection.dragging = false;
        }
        done_hittest:;
    }

    // phase 2 ffi callback outside g_mutex to prevent deadlock
// rust call back into get_tab_owner print_info which also lock g_mutex
    if (close_idx != -1) {
        c_on_tab_close(close_idx);
        {
            std::lock_guard<std::mutex> lk(g_mutex);
            if (close_idx >= 0 && close_idx < (int)g_tabs.size()) {
                g_tabs.erase(g_tabs.begin() + close_idx);
                if (g_active_tab >= (int)g_tabs.size()) g_active_tab = (int)g_tabs.size() - 1;
            }
        }
    } else if (tab_hit != -1) {
        std::lock_guard<std::mutex> lk(g_mutex);
        g_active_tab = tab_hit;
    }

    if (g_drawing_area) gtk_widget_queue_draw(g_drawing_area);

    // quit outside mutex to prevent deadlock
    if (should_quit && g_app) {
        g_application_quit(G_APPLICATION(g_app));
    }
}

static void on_drag_begin(GtkGestureDrag *gesture, double start_x, double start_y, gpointer user_data) {
    std::lock_guard<std::mutex> lk(g_mutex);
    if (g_tabs.empty() || start_y < 40) return;
    
    TabState &t = g_tabs[g_active_tab];
    int line_h = 18;
    int char_w = g_char_w;
    
    int local_y = start_y - 40 + t.content_scroll;
    int line = local_y / line_h;
    int col = (start_x - 10) / char_w;
    if (line < 0) line = 0;
    if (col < 0) col = 0;
    
    g_selection.active = true;
    g_selection.dragging = true;
    g_selection.tab_idx = g_active_tab;
    g_selection.start = {line, col};
    g_selection.end = {line, col};
}

static void on_drag_update(GtkGestureDrag *gesture, double offset_x, double offset_y, gpointer user_data) {
    std::lock_guard<std::mutex> lk(g_mutex);
    if (!g_selection.dragging || g_selection.tab_idx != g_active_tab) return;
    
    double start_x, start_y;
    gtk_gesture_drag_get_start_point(gesture, &start_x, &start_y);
    
    double cur_x = start_x + offset_x;
    double cur_y = start_y + offset_y;
    
    TabState &t = g_tabs[g_active_tab];
    int line_h = 18;
    int char_w = g_char_w;
    
    int local_y = cur_y - 40 + t.content_scroll;
    int line = local_y / line_h;
    int col = (cur_x - 10) / char_w;
    if (line < 0) line = 0;
    if (col < 0) col = 0;
    
    g_selection.end = {line, col};
}

static void on_motion(GtkEventControllerMotion *controller, double x, double y, gpointer user_data) {
    std::lock_guard<std::mutex> lk(g_mutex);
    if (g_tabs.empty()) return;
    
    TabState &t = g_tabs[g_active_tab];
    
    if (y < 40) {
        t.hover_line = -1;
        // track which close button hovered
        int new_hover = -1;
        for (size_t i = 0; i < g_tab_close_boxes.size(); ++i) {
            const HitBox& cb = g_tab_close_boxes[i];
            if (x >= cb.x && x <= cb.x + cb.w && y >= cb.y && y <= cb.y + cb.h) {
                new_hover = (int)i;
                break;
            }
        }
        g_hover_close_tab = new_hover;
    } else {
        g_hover_close_tab = -1;
        int line_h = 18; 
        int local_y = y - 40 + t.content_scroll;
        int line = local_y / line_h;
        
        if (line < 0 || line >= (int)t.wrapped_lines.size()) {
            line = -1;
        }
        
        t.hover_line = line;
    }
}

static void on_drag_end(GtkGestureDrag *gesture, double offset_x, double offset_y, gpointer user_data) {
    std::lock_guard<std::mutex> lk(g_mutex);
    g_selection.dragging = false;
    if (g_selection.start == g_selection.end) {
        g_selection.active = false;
    }
}

static gboolean on_tick(GtkWidget *widget, GdkFrameClock *frame_clock, gpointer user_data) {
    {
        std::lock_guard<std::mutex> lk(g_mutex);
        if (!g_tabs.empty()) {
            TabState &t = g_tabs[g_active_tab];
            
            // smooth scroll interpolation
            if (t.content_scroll != t.content_scroll_target) {
                t.content_scroll += (t.content_scroll_target - t.content_scroll) * 0.3f;
                if (std::abs(t.content_scroll - t.content_scroll_target) < 0.5f) {
                    t.content_scroll = t.content_scroll_target;
                }
            }
        }
    }

    gtk_widget_queue_draw(widget);
    return G_SOURCE_CONTINUE;
}

static void on_activate(GtkApplication *app, gpointer user_data) {
#if defined(PLUGXEL_ENABLE_HEADLESS_MODE) || defined(PLUG_ENABLE_HEADLESS_MODE)
    if (g_headless_mode) {
        // headless mode create minimal window without show for ci headless testing
        g_window = gtk_application_window_new(app);
        gtk_window_set_title(GTK_WINDOW(g_window), "PLUGXEL");
        gtk_window_set_default_size(GTK_WINDOW(g_window), 900, 600);

        g_drawing_area = gtk_drawing_area_new();
        gtk_widget_set_focusable(g_drawing_area, TRUE);
        gtk_drawing_area_set_draw_func(GTK_DRAWING_AREA(g_drawing_area), on_draw, NULL, NULL);

        // keyboard controller
        GtkEventController *key_ctrl = gtk_event_controller_key_new();
        g_signal_connect(key_ctrl, "key-pressed", G_CALLBACK(on_key_pressed), NULL);
        gtk_widget_add_controller(g_drawing_area, key_ctrl);

        // scroll controller
        GtkEventController *scroll_ctrl = gtk_event_controller_scroll_new(GTK_EVENT_CONTROLLER_SCROLL_VERTICAL);
        g_signal_connect(scroll_ctrl, "scroll", G_CALLBACK(on_scroll), NULL);
        gtk_widget_add_controller(g_drawing_area, scroll_ctrl);

        // click gesture
        GtkGesture *click_gesture = gtk_gesture_click_new();
        gtk_gesture_single_set_button(GTK_GESTURE_SINGLE(click_gesture), GDK_BUTTON_PRIMARY);
        g_signal_connect(click_gesture, "pressed", G_CALLBACK(on_click), NULL);
        gtk_widget_add_controller(g_drawing_area, GTK_EVENT_CONTROLLER(click_gesture));

        // drag gesture for text selection
        GtkGesture *drag_gesture = gtk_gesture_drag_new();
        gtk_gesture_single_set_button(GTK_GESTURE_SINGLE(drag_gesture), GDK_BUTTON_PRIMARY);
        g_signal_connect(drag_gesture, "drag-begin", G_CALLBACK(on_drag_begin), NULL);
        g_signal_connect(drag_gesture, "drag-update", G_CALLBACK(on_drag_update), NULL);
        g_signal_connect(drag_gesture, "drag-end", G_CALLBACK(on_drag_end), NULL);
        gtk_widget_add_controller(g_drawing_area, GTK_EVENT_CONTROLLER(drag_gesture));

        // group click and drag gestures
        gtk_gesture_group(click_gesture, drag_gesture);

        // motion controller for hover effects
        GtkEventController *motion_ctrl = gtk_event_controller_motion_new();
        g_signal_connect(motion_ctrl, "motion", G_CALLBACK(on_motion), NULL);
        gtk_widget_add_controller(g_drawing_area, motion_ctrl);

        // setup animation tick
        gtk_widget_add_tick_callback(g_drawing_area, on_tick, NULL, NULL);

        gtk_window_set_child(GTK_WINDOW(g_window), g_drawing_area);
        // in headless mode under xvfb make widgets visible for GTK main loop
        // use gtk_widget_set_visible instead of gtk_window_present to avoid xvfb issues
        gtk_widget_set_visible(g_window, TRUE);
        gtk_widget_set_visible(g_drawing_area, TRUE);
        gtk_widget_grab_focus(g_drawing_area);
    } else
#endif
    {
        g_window = gtk_application_window_new(app);
        gtk_window_set_title(GTK_WINDOW(g_window), "PLUGXEL");
        gtk_window_set_default_size(GTK_WINDOW(g_window), 900, 600);

        g_drawing_area = gtk_drawing_area_new();
        gtk_widget_set_focusable(g_drawing_area, TRUE);
        gtk_drawing_area_set_draw_func(GTK_DRAWING_AREA(g_drawing_area), on_draw, NULL, NULL);

        // keyboard controller
        GtkEventController *key_ctrl = gtk_event_controller_key_new();
        g_signal_connect(key_ctrl, "key-pressed", G_CALLBACK(on_key_pressed), NULL);
        gtk_widget_add_controller(g_drawing_area, key_ctrl);

        // scroll controller
        GtkEventController *scroll_ctrl = gtk_event_controller_scroll_new(GTK_EVENT_CONTROLLER_SCROLL_VERTICAL);
        g_signal_connect(scroll_ctrl, "scroll", G_CALLBACK(on_scroll), NULL);
        gtk_widget_add_controller(g_drawing_area, scroll_ctrl);

        // click gesture
        GtkGesture *click_gesture = gtk_gesture_click_new();
        gtk_gesture_single_set_button(GTK_GESTURE_SINGLE(click_gesture), GDK_BUTTON_PRIMARY);
        g_signal_connect(click_gesture, "pressed", G_CALLBACK(on_click), NULL);
        gtk_widget_add_controller(g_drawing_area, GTK_EVENT_CONTROLLER(click_gesture));

        // drag gesture for text selection
        GtkGesture *drag_gesture = gtk_gesture_drag_new();
        gtk_gesture_single_set_button(GTK_GESTURE_SINGLE(drag_gesture), GDK_BUTTON_PRIMARY);
        g_signal_connect(drag_gesture, "drag-begin", G_CALLBACK(on_drag_begin), NULL);
        g_signal_connect(drag_gesture, "drag-update", G_CALLBACK(on_drag_update), NULL);
        g_signal_connect(drag_gesture, "drag-end", G_CALLBACK(on_drag_end), NULL);
        gtk_widget_add_controller(g_drawing_area, GTK_EVENT_CONTROLLER(drag_gesture));

        // group click and drag gestures
        gtk_gesture_group(click_gesture, drag_gesture);

        // motion controller for hover effects
        GtkEventController *motion_ctrl = gtk_event_controller_motion_new();
        g_signal_connect(motion_ctrl, "motion", G_CALLBACK(on_motion), NULL);
        gtk_widget_add_controller(g_drawing_area, motion_ctrl);

        // setup animation tick
        gtk_widget_add_tick_callback(g_drawing_area, on_tick, NULL, NULL);

        gtk_window_set_child(GTK_WINDOW(g_window), g_drawing_area);
        gtk_window_present(GTK_WINDOW(g_window));
        gtk_widget_grab_focus(g_drawing_area);
    }

    // initialize first tab
    {
        std::lock_guard<std::mutex> lk(g_mutex);
        TabState t;
        t.title = "Tab 1";
        g_tabs.push_back(t);
    }

    // start command processor thread eagerly so stdin ready before any frame-clock tick fires critical for headless ci reliability
    if (!g_cmd_thread_running) {
        g_cmd_thread_running = true;
        g_cmd_thread = std::thread([]() {
            while (g_cmd_thread_running) {
                CmdItem it = {-1, ""};
                {
                    std::unique_lock<std::mutex> lk(g_cmd_mutex);
                    g_cmd_cv.wait(lk, []{ return !g_cmd_queue.empty() || !g_cmd_thread_running; });
                    if (!g_cmd_queue.empty()) {
                        it = g_cmd_queue.front();
                        g_cmd_queue.pop();
                    }
                }
                if (it.tab >= 0) {
                    g_print_tab = it.tab;
                    c_parse(it.cmd.data());
                    g_print_tab = -1;
                }
            }
        });
        if (g_headless_mode) {
            g_headless_stdin_thread = std::thread(headless_stdin_worker);
        }
    }

    main_l_print_banner();
    main_l_print_info("Type /? for help or /e to exit");
}

int main_l_init(void) {
    g_app = gtk_application_new("com.plugxel.terminal", G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(g_app, "activate", G_CALLBACK(on_activate), NULL);
    return 0;
}

void main_l_run_message_loop(void) {
    g_application_run(G_APPLICATION(g_app), 0, NULL);
}

void main_l_cleanup(void) {
    // signal command thread to stop and wake it so it can exit
    g_cmd_thread_running = false;
    g_cmd_cv.notify_all();
    if (g_cmd_thread.joinable()) {
        g_cmd_thread.join();
    }
    // stdin worker blocks on getline; detach so it doesn't prevent exit
    if (g_headless_stdin_thread.joinable()) {
        g_headless_stdin_thread.detach();
    }
    if (g_app) {
        g_object_unref(g_app);
        g_app = NULL;
    }
    if (g_drawing_area) gtk_widget_queue_draw(g_drawing_area);
}

void main_l_print_info(const char* msg) {
    if (!g_drawing_area) return;
    int target_tab = (g_print_tab != -1) ? g_print_tab : g_active_tab;
    PrintData* pd = new PrintData{target_tab, msg ? msg : "", COL_OUTPUT, false};
    g_idle_add(print_info_idle, pd);
}

void main_l_print_banner(void) {
    if (!g_drawing_area) return;
    PrintData* pd = new PrintData{g_active_tab, "Welcome, " + std::string(g_sys_info_main.user_name) + "!", COL_USER, false};
    g_idle_add(print_info_idle, pd);
}

void main_l_print_error(const char* msg) {
    if (!g_drawing_area) return;
    int target_tab = (g_print_tab != -1) ? g_print_tab : g_active_tab;
    PrintData* pd = new PrintData{target_tab, msg ? msg : "", COL_CMD, false};
    g_idle_add(print_info_idle, pd);
}

extern "C" {

void main_l_set_prompt_visibility(int visible) {
    // no-op on linux gtk for now
}

int main_l_get_current_print_tab(void) {
    return g_print_tab != -1 ? g_print_tab : g_active_tab;
}

void main_l_set_tab_owner(int tab_idx, const char* owner) {
    std::lock_guard<std::mutex> lk(g_mutex);
    if (tab_idx >= 0 && tab_idx < g_tabs.size()) {
        g_tabs[tab_idx].plugin_owner = owner ? owner : "";
    }
}

void main_l_set_tab_cwd(int tab_idx, const char* cwd) {
    std::lock_guard<std::mutex> lk(g_mutex);
    if (tab_idx >= 0 && tab_idx < g_tabs.size()) {
        g_tabs[tab_idx].cwd = cwd ? cwd : "";
    }
}

} // extern "C"

static gboolean print_info_idle(gpointer data) {
    PrintData* pd = static_cast<PrintData*>(data);
    std::lock_guard<std::mutex> lk(g_mutex);
    if (pd->tab_idx >= 0 && pd->tab_idx < (int)g_tabs.size()) {
        g_tabs[pd->tab_idx].raw_lines.push_back({pd->msg, pd->color, pd->is_continuation});
        g_tabs[pd->tab_idx].wrapped_lines.clear();
        if (g_drawing_area) gtk_widget_queue_draw(g_drawing_area);
    }
    delete pd;
    return G_SOURCE_REMOVE;
}

static gboolean add_tab_idle(gpointer data) {
    const char* owner = static_cast<const char*>(data);
    std::lock_guard<std::mutex> lk(g_mutex);
    TabState new_tab;
    g_tab_counter++;
    new_tab.title = "Tab " + std::to_string(g_tab_counter);
    if (owner && strlen(owner) > 0) {
        new_tab.plugin_owner = owner;
    }
    g_tabs.push_back(new_tab);
    g_active_tab = g_tabs.size() - 1;
    if (g_drawing_area) gtk_widget_queue_draw(g_drawing_area);
    free(const_cast<char*>(owner)); // free the strdup'd string
    return G_SOURCE_REMOVE;
}

extern "C" {

void main_l_add_tab(const char* owner) {
    if (!g_drawing_area) return;
    char* owner_copy = owner ? strdup(owner) : nullptr;
    g_idle_add(add_tab_idle, owner_copy);
}

int main_l_get_tab_owner(int tab_idx, char* buf, int max_len) {
    std::lock_guard<std::mutex> lk(g_mutex);
    if (tab_idx >= 0 && tab_idx < (int)g_tabs.size() && buf && max_len > 0) {
        strncpy(buf, g_tabs[tab_idx].plugin_owner.c_str(), max_len - 1);
        buf[max_len - 1] = '\0';
        return (int)strlen(buf);
    }
    return 0;
}

} // extern "C"

static gboolean replace_last_line_idle(gpointer data) {
    ReplaceLastLineData* d = static_cast<ReplaceLastLineData*>(data);
    std::lock_guard<std::mutex> lk(g_mutex);
    if (d->tab_idx >= 0 && d->tab_idx < (int)g_tabs.size() && !g_tabs[d->tab_idx].raw_lines.empty()) {
        g_tabs[d->tab_idx].raw_lines.back().text = d->msg;
        g_tabs[d->tab_idx].wrapped_lines.clear();
        if (g_drawing_area) gtk_widget_queue_draw(g_drawing_area);
    }
    delete d;
    return G_SOURCE_REMOVE;
}

extern "C" {

void main_l_replace_last_line(const char* msg) {
    if (!g_drawing_area) return;
    int target_tab = (g_print_tab != -1) ? g_print_tab : g_active_tab;
    ReplaceLastLineData* d = new ReplaceLastLineData{target_tab, msg ? msg : ""};
    g_idle_add(replace_last_line_idle, d);
}

void main_l_request_close(void) {
    if (g_app) {
        g_application_quit(G_APPLICATION(g_app));
    }
}

// satisfy llvm compiler-rt linking requirement on linux
void __rust_probestack() {}

} // extern "C"
