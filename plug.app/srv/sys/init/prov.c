#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "sys/srv/prov.h"

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#ifndef MAX_PATH
#define MAX_PATH 4096
#endif
#endif

static int create_dir_recursive(const char *path) {
    char tmp[MAX_PATH];
    strncpy(tmp, path, MAX_PATH - 1);
    tmp[MAX_PATH - 1] = '\0';
    size_t len = strlen(tmp);
    if (len == 0) return -1;
    
    for (size_t i = 1; i < len; ++i) {
        if (tmp[i] == '\\' || tmp[i] == '/') {
            char save = tmp[i];
            tmp[i] = '\0';
#ifdef _WIN32
            CreateDirectoryA(tmp, NULL);
#else
            mkdir(tmp, 0755);
#endif
            tmp[i] = save;
        }
    }
#ifdef _WIN32
    CreateDirectoryA(tmp, NULL);
#else
    mkdir(tmp, 0755);
#endif
    return 0;
}

static void get_base_dir(char* base, size_t max_len) {
#ifdef _WIN32
    char system_drive[MAX_PATH] = {0};
    DWORD r = GetEnvironmentVariableA("SystemDrive", system_drive, (DWORD)MAX_PATH);
    if (r == 0) {
        snprintf(base, max_len, "C:\\.plugxel");
    } else {
        snprintf(base, max_len, "%s\\.plugxel", system_drive);
    }
#else
    const char* home = getenv("HOME");
    if (home) {
        snprintf(base, max_len, "%s/.plugxel", home);
    } else {
        snprintf(base, max_len, "/tmp/.plugxel");
    }
#endif
}

int prov_create_system_dirs(void) {
    char base[MAX_PATH] = {0};
    get_base_dir(base, MAX_PATH);

    char plugins_path[MAX_PATH];
#ifdef _WIN32
    snprintf(plugins_path, sizeof(plugins_path), "%s\\plugins", base);
#else
    snprintf(plugins_path, sizeof(plugins_path), "%s/plugins", base);
#endif

    create_dir_recursive(base);
    create_dir_recursive(plugins_path);

    return 0;
}

int prov_check_or_run(void) {
    return prov_create_system_dirs();
}
