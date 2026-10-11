#include <iostream>
#include <string>
#include <vector>
#include <cassert>
#include <algorithm>

// custom lightweight assertion macro
#define ASSERT_TRUE(expr, msg) \
    if (!(expr)) { \
        std::cout << "[FAIL] " << msg << " (Expected true, but was false)\n"; \
        failed_count++; \
    } else { \
        std::cout << "[PASS] " << msg << "\n"; \
        passed_count++; \
    }

#define ASSERT_EQ(val1, val2, msg) \
    if ((val1) != (val2)) { \
        std::cout << "[FAIL] " << msg << " (Expected " << (val2) << ", got " << (val1) << ")\n"; \
        failed_count++; \
    } else { \
        std::cout << "[PASS] " << msg << "\n"; \
        passed_count++; \
    }

int passed_count = 0;
int failed_count = 0;

// subsystem 1: Caret word boundary navigation helper logic
int find_word_boundary_left(const std::string& text, int current_cursor) {
    if (current_cursor <= 0) return 0;
    int idx = current_cursor - 1;
    
    // skip trailing spaces
    while (idx > 0 && text[idx] == ' ') {
        idx--;
    }
    // skip non-spaces (word segment)
    while (idx > 0 && text[idx] != ' ') {
        idx--;
    }
    if (idx > 0 && text[idx] == ' ') {
        return idx + 1;
    }
    return idx;
}

int find_word_boundary_right(const std::string& text, int current_cursor) {
    int len = static_cast<int>(text.length());
    if (current_cursor >= len) return len;
    int idx = current_cursor;
    
    // skip word segment
    while (idx < len && text[idx] != ' ') {
        idx++;
    }
    // skip spaces
    while (idx < len && text[idx] == ' ') {
        idx++;
    }
    return idx;
}

// subsystem 2: Scrollbar size calculations helper logic
int calculate_scroll_thumb_height(int visible_height, int total_height, int min_thumb_size) {
    if (total_height <= visible_height) return visible_height;
    int computed = (visible_height * visible_height) / total_height;
    return std::max(computed, min_thumb_size);
}

void test_caret_word_navigation() {
    std::string line = "hello world from plugxel";
    
    // navigate left from "world" (index 11 is 'd')
    int idx = find_word_boundary_left(line, 11);
    ASSERT_EQ(idx, 6, "caret_word_left_navigation"); // should boundary at 'w' (index 6)
    
    // navigate right from "hello" (index 0)
    idx = find_word_boundary_right(line, 0);
    ASSERT_EQ(idx, 6, "caret_word_right_navigation"); // should jump to "world" (index 6)
}

void test_scrollbar_thumb_size() {
    // scrollbar target logic check
    int thumb1 = calculate_scroll_thumb_height(100, 500, 20);
    ASSERT_EQ(thumb1, 20, "scrollbar_thumb_standard_height"); // (100 * 100) / 500 = 20
    
    int thumb2 = calculate_scroll_thumb_height(100, 1000, 20);
    ASSERT_EQ(thumb2, 20, "scrollbar_thumb_min_height_enforced"); // (100 * 100) / 1000 = 10 -> min 20 enforced
}

int main() {
    std::cout << "=== Running C++ UI Subsystem Helper Unit Tests ===\n";
    test_caret_word_navigation();
    test_scrollbar_thumb_size();
    std::cout << "Passed: " << passed_count << ", Failed: " << failed_count << "\n";
    return (failed_count > 0) ? 1 : 0;
}
