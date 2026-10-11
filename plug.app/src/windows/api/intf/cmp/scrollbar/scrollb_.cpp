#include <sys/api/windows/cmp/scrollbar.h>
#include <algorithm>

float scrollb_clamp_offset(float offset, int content_len, int visible_len) {
    if (content_len <= visible_len || visible_len <= 0) return 0.0f;
    float max_offset = (float)(content_len - visible_len);
    if (offset < 0.0f) return 0.0f;
    if (offset > max_offset) return max_offset;
    return offset;
}

bool scrollb_compute_thumb_rect(RECT track, int content_len, int visible_len, float offset, RECT& out_thumb) {
    const int track_len = track.right - track.left;
    if (track_len <= 0 || content_len <= visible_len || visible_len <= 0) {
        out_thumb = {0, 0, 0, 0};
        return false;
    }

    float clamped = scrollb_clamp_offset(offset, content_len, visible_len);
    float ratio = (float)visible_len / (float)content_len;
    int thumb_w = std::max(24, (int)(track_len * ratio));
    if (thumb_w > track_len) thumb_w = track_len;

    float max_offset = (float)(content_len - visible_len);
    float pos_ratio = (max_offset > 0.0f) ? (clamped / max_offset) : 0.0f;
    int span = track_len - thumb_w;
    int thumb_x = track.left + (int)(span * pos_ratio);

    out_thumb = {thumb_x, track.top, thumb_x + thumb_w, track.bottom};
    return true;
}

void scrollb_render_horizontal(HDC hdc, RECT track, int content_len, int visible_len, float offset, float alpha) {
    RECT thumb = {0, 0, 0, 0};
    if (!scrollb_compute_thumb_rect(track, content_len, visible_len, offset, thumb)) return;
    if (alpha <= 0.0f) return;

    HBRUSH track_br = CreateSolidBrush(RGB(45, 45, 45));
    FillRect(hdc, &track, track_br);
    DeleteObject(track_br);

    HBRUSH thumb_br = CreateSolidBrush(RGB(120, 120, 120));
    FillRect(hdc, &thumb, thumb_br);
    DeleteObject(thumb_br);
}

bool scrollb_compute_thumb_rect_vertical(RECT track, int content_len, int visible_len, float offset, RECT& out_thumb) {
    const int track_len = track.bottom - track.top;
    if (track_len <= 0 || content_len <= visible_len || visible_len <= 0) {
        out_thumb = {0, 0, 0, 0};
        return false;
    }

    float clamped = scrollb_clamp_offset(offset, content_len, visible_len);
    float ratio = (float)visible_len / (float)content_len;
    int thumb_h = std::max(28, (int)(track_len * ratio));
    if (thumb_h > track_len) thumb_h = track_len;

    float max_offset = (float)(content_len - visible_len);
    float pos_ratio = (max_offset > 0.0f) ? (clamped / max_offset) : 0.0f;
    int span = track_len - thumb_h;
    int thumb_y = track.top + (int)(span * pos_ratio);

    out_thumb = {track.left, thumb_y, track.right, thumb_y + thumb_h};
    return true;
}

void scrollb_render_vertical(HDC hdc, RECT track, int content_len, int visible_len, float offset, float alpha) {
    RECT thumb = {0, 0, 0, 0};
    if (!scrollb_compute_thumb_rect_vertical(track, content_len, visible_len, offset, thumb)) return;
    if (alpha <= 0.0f) return;

    HBRUSH track_br = CreateSolidBrush(RGB(34, 34, 34));
    FillRect(hdc, &track, track_br);
    DeleteObject(track_br);

    HBRUSH thumb_br = CreateSolidBrush(RGB(225, 225, 225));
    FillRect(hdc, &thumb, thumb_br);
    DeleteObject(thumb_br);
}
