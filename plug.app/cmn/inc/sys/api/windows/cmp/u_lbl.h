#ifndef TM_USER_HUD_H
#define TM_USER_HUD_H

#ifdef __cplusplus
extern "C" {
#endif

void main_w_print_banner(void);
void main_w_print_error(const char* msg);
void main_w_print_success(const char* msg);
void main_w_print_info(const char* msg);
void main_w_print_warning(const char* msg);
void main_w_show_system_response(const char* response);

#ifdef __cplusplus
}
#endif

#endif

