#ifndef TM_ADMIN_H
#define TM_ADMIN_H

#ifdef _WIN32
#include <windows.h>
#else
#ifndef BOOL
typedef int BOOL;
#define TRUE 1
#define FALSE 0
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifndef MAX_PATH_LENGTH
#define MAX_PATH_LENGTH 4096
#endif
#define MAX_RESTART_ATTEMPTS 3

#define MSG_INFO 0
#define MSG_WARNING 1
#define MSG_ERROR 2
#define MSG_SUCCESS 3

BOOL admin_init(void);
void admin_cleanup(void);
BOOL admin_check_privileges(void);
BOOL admin_restart_elevated(void);
void admin_display_prompt(const char* message, int message_type);

BOOL admin_init_c(void);
void admin_cleanup_c(void);
BOOL admin_check_privileges_c(void);
BOOL admin_restart_elevated_c(void);
void admin_display_prompt_c(const char* message, int message_type);

#ifdef __cplusplus
}
#endif

#endif
