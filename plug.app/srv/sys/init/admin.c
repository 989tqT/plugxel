#include "sys/srv/admin.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
#include <shellapi.h>
#include <winnt.h>
#else
#include <unistd.h>
#include <sys/types.h>
#include <limits.h>
#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif
#endif

typedef struct {
    BOOL is_admin;
    char exe_path[MAX_PATH_LENGTH];
    unsigned int restart_attempts;
    BOOL system_initialized;
    void* current_process_handle;
    unsigned int current_process_id;
} admin_state_t;

static admin_state_t g_admin_state = {0};

void admin_display_prompt(const char* message, int message_type);
BOOL admin_check_privileges(void);
BOOL admin_restart_elevated(void);
static BOOL admin_service_clear(void);

static BOOL get_executable_path(char* buffer, size_t max_size) {
#ifdef _WIN32
    return GetModuleFileNameA(NULL, buffer, (DWORD)max_size) > 0;
#elif defined(__APPLE__)
    uint32_t size = max_size;
    return _NSGetExecutablePath(buffer, &size) == 0;
#else
    ssize_t len = readlink("/proc/self/exe", buffer, max_size - 1);
    if (len != -1) {
        buffer[len] = '\0';
        return TRUE;
    }
    return FALSE;
#endif
}

BOOL admin_init(void) {
    memset(&g_admin_state, 0, sizeof(admin_state_t));
    
#ifdef _WIN32
    g_admin_state.current_process_id = GetCurrentProcessId();
    g_admin_state.current_process_handle = GetCurrentProcess();
#else
    g_admin_state.current_process_id = getpid();
    g_admin_state.current_process_handle = NULL;
#endif

    g_admin_state.restart_attempts = 0;
    g_admin_state.system_initialized = FALSE;
    
    if (!get_executable_path(g_admin_state.exe_path, MAX_PATH_LENGTH)) {
        admin_display_prompt("Failed to get executable path", MSG_ERROR);
        return FALSE;
    }
    
    g_admin_state.is_admin = admin_check_privileges();
    
    if (!g_admin_state.is_admin) {
        admin_display_prompt("Administrator privileges required!", MSG_WARNING);
        admin_display_prompt("Attempting to restart with elevated privileges...", MSG_INFO);
        
        if (!admin_restart_elevated()) {
            admin_display_prompt("Failed to restart with admin privileges! Please run as administrator/root.", MSG_ERROR);
            return FALSE;
        }
        
        return FALSE;
    }
    
    g_admin_state.system_initialized = TRUE;
    admin_display_prompt("Admin system initialized successfully", MSG_SUCCESS);
    
    return TRUE;
}

void admin_cleanup(void) {
    if (g_admin_state.system_initialized) {
        admin_service_clear();
        g_admin_state.system_initialized = FALSE;
    }
}

BOOL admin_check_privileges(void) {
#if defined(PLUGXEL_ENABLE_HEADLESS_MODE) || defined(PLUG_ENABLE_HEADLESS_MODE)
    {
        const char* headless = (getenv("PLUGXEL_HEADLESS") ? getenv("PLUGXEL_HEADLESS") : getenv("PLUG_HEADLESS"));
        if (headless && strcmp(headless, "1") == 0) {
            return TRUE;
        }
    }
#endif

#ifdef _WIN32
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdministratorsGroup = NULL;
    
    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdministratorsGroup)) {
        CheckTokenMembership(NULL, AdministratorsGroup, &isAdmin);
        FreeSid(AdministratorsGroup);
    }
    
    return isAdmin;
#else
    // IMPORTANT: Never force a GTK4/Wayland GUI to run as root!
    // It breaks DBus session bus and completely blocks keyboard inputs.
    // Privileged commands should be run using 'sudo' per-command, not globally.
    return TRUE;
#endif
}

BOOL admin_restart_elevated(void) {
    if (g_admin_state.restart_attempts >= MAX_RESTART_ATTEMPTS) {
        admin_display_prompt("Maximum restart attempts reached", MSG_ERROR);
        return FALSE;
    }
    
    g_admin_state.restart_attempts++;
    
#ifdef _WIN32
    HINSTANCE h = ShellExecuteA(NULL, "runas", g_admin_state.exe_path, 
                                NULL, NULL, SW_SHOWNORMAL);
    intptr_t code = (intptr_t)h;
    
    if (code <= 32) {
        admin_display_prompt("UAC elevation failed or denied", MSG_ERROR);
        return FALSE;
    }
#else
    char *args[] = {"sudo", g_admin_state.exe_path, NULL};
    execvp("sudo", args);
    admin_display_prompt("Elevation using sudo failed", MSG_ERROR);
    return FALSE;
#endif

    admin_display_prompt("Restarting with elevated privileges...", MSG_INFO);
    return TRUE;
}

void admin_display_prompt(const char* message, int message_type) {
    if (!message) return;
    
#ifdef _WIN32
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    WORD color = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
    
    switch (message_type) {
        case MSG_INFO: color = FOREGROUND_BLUE | FOREGROUND_INTENSITY; break;
        case MSG_WARNING: color = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY; break;
        case MSG_ERROR: color = FOREGROUND_RED | FOREGROUND_INTENSITY; break;
        case MSG_SUCCESS: color = FOREGROUND_GREEN | FOREGROUND_INTENSITY; break;
    }
    
    SetConsoleTextAttribute(hConsole, color);
    printf("[ADMIN] %s\n", message);
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
#else
    const char* color_code = "\033[0m"; // Reset
    switch (message_type) {
        case MSG_INFO: color_code = "\033[1;34m"; break; // Bold Blue
        case MSG_WARNING: color_code = "\033[1;33m"; break; // Bold Yellow
        case MSG_ERROR: color_code = "\033[1;31m"; break; // Bold Red
        case MSG_SUCCESS: color_code = "\033[1;32m"; break; // Bold Green
    }
    printf("%s[ADMIN] %s\033[0m\n", color_code, message);
#endif
}

static BOOL admin_service_clear(void) {
    memset(g_admin_state.exe_path, 0, sizeof(g_admin_state.exe_path));
    
#ifdef _WIN32
    if (g_admin_state.current_process_handle && g_admin_state.current_process_handle != GetCurrentProcess()) {
        CloseHandle((HANDLE)g_admin_state.current_process_handle);
        g_admin_state.current_process_handle = NULL;
    }
#endif
    
    return TRUE;
}

#ifdef __cplusplus
extern "C" {
#endif
    BOOL admin_init_c(void) { return admin_init(); }
    void admin_cleanup_c(void) { admin_cleanup(); }
    BOOL admin_check_privileges_c(void) { return admin_check_privileges(); }
    BOOL admin_restart_elevated_c(void) { return admin_restart_elevated(); }
    void admin_display_prompt_c(const char* message, int message_type) { admin_display_prompt(message, message_type); }
#ifdef __cplusplus
}
#endif
