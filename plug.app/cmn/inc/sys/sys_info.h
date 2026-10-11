#ifndef SYS_INFO_H
#define SYS_INFO_H

#include <stddef.h>

#ifdef _WIN32
#include <windows.h>
#else
#ifndef BOOL
typedef int BOOL;
#endif
#ifndef DWORD
typedef unsigned int DWORD;
#endif
#ifndef MAX_COMPUTERNAME_LENGTH
#define MAX_COMPUTERNAME_LENGTH 256
#endif
#ifndef MAX_PATH
#define MAX_PATH 4096
#endif
#endif

typedef struct {
    DWORD major_version;
    DWORD minor_version;
    DWORD build_number;
    BOOL is_64bit;
    size_t total_memory;
    size_t available_memory;
    char computer_name[MAX_COMPUTERNAME_LENGTH + 1];
    char user_name[MAX_PATH];
} sys_info_t;

extern sys_info_t g_sys_info_main;

#endif
