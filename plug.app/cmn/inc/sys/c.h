#ifndef TM_C_H
#define TM_C_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32
#include <windows.h>
#else
#ifndef BOOL
typedef int BOOL;
#endif
#endif

typedef int (*c_handler_t)(const char* args);

int c_init(void);
void c_cleanup(void);
void c_on_tab_close(int tab_idx);
int c_parse(char* input);
BOOL c_is_running(void);

int c_abt(const char* args);
int c_q(const char* args);
int c_e(const char* args);

#ifdef __cplusplus
}
#endif

#endif

