#include <iostream>
#include <string>

#ifdef _WIN32
#include <windows.h>
#include <winternl.h>
#else
#include <unistd.h>
#include <sys/utsname.h>
#include <pwd.h>
#include <sys/types.h>
#include <string.h>
#endif

#include "../cmn/inc/sys/c.h"
#ifdef _WIN32
#include "../cmn/inc/sys/api/windows/main_w.h"
#define main_ui_init main_w_init
#define main_ui_run_message_loop main_w_run_message_loop
#define main_ui_cleanup main_w_cleanup
#define main_ui_print_banner main_w_print_banner
#define main_ui_print_info main_w_print_info
#else
#include "../cmn/inc/sys/api/linux/main_l.h"
#define main_ui_init main_l_init
#define main_ui_run_message_loop main_l_run_message_loop
#define main_ui_cleanup main_l_cleanup
#define main_ui_print_banner main_l_print_banner
#define main_ui_print_info main_l_print_info
#endif
#include "../cmn/inc/sys/sys_info.h"
#include "../cmn/inc/main.h"
#include "../cmn/inc/sys/srv/admin.h"
#include "../cmn/inc/sys/srv/prov.h"

typedef int (*c_handler_t)(const char* args);

struct CommandEntry {
    const char* name;
    const char* description;
    c_handler_t handler;
};

extern "C" {
    extern int c_init(void);
    extern void c_cleanup(void);
    extern BOOL c_is_running(void);
    extern int c_parse(char* input);
}

sys_info_t g_sys_info_main = {0};

int get_system_info(sys_info_t* info) {
    if (!info) return -1;

#ifdef _WIN32
    OSVERSIONINFOEXA osvi = {};
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXA);
    
    typedef NTSTATUS(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);
    HMODULE hMod = GetModuleHandleA("ntdll.dll");
    if (hMod) {
        RtlGetVersionPtr fxPtr = (RtlGetVersionPtr)GetProcAddress(hMod, "RtlGetVersion");
        if (fxPtr) {
            fxPtr((PRTL_OSVERSIONINFOW)&osvi);
        }
    }
    
    info->major_version = osvi.dwMajorVersion;
    info->minor_version = osvi.dwMinorVersion;
    info->build_number = osvi.dwBuildNumber;

    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);
    info->is_64bit = (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 || si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64);

    MEMORYSTATUSEX memStatus = {};
    memStatus.dwLength = sizeof(MEMORYSTATUSEX);
    if (GlobalMemoryStatusEx(&memStatus)) {
        info->total_memory = memStatus.ullTotalPhys;
        info->available_memory = memStatus.ullAvailPhys;
    }

    DWORD size = sizeof(info->computer_name);
    GetComputerNameA(info->computer_name, &size);

    size = sizeof(info->user_name);
    GetUserNameA(info->user_name, &size);
#else
    struct utsname buffer;
    if (uname(&buffer) == 0) {
        info->major_version = 1;
        info->minor_version = 0;
        info->build_number = 0;
    }
    
    info->is_64bit = (sizeof(void*) == 8);

    long pages = sysconf(_SC_PHYS_PAGES);
    long page_size = sysconf(_SC_PAGE_SIZE);
    if (pages > 0 && page_size > 0) {
        info->total_memory = (size_t)pages * (size_t)page_size;
        
        long avail_pages = sysconf(_SC_AVPHYS_PAGES);
        if (avail_pages > 0) {
            info->available_memory = (size_t)avail_pages * (size_t)page_size;
        } else {
            info->available_memory = info->total_memory;
        }
    } else {
        info->total_memory = 0;
        info->available_memory = 0;
    }

    gethostname(info->computer_name, sizeof(info->computer_name));

    struct passwd *pw = getpwuid(geteuid());
    if (pw && pw->pw_name) {
        strncpy(info->user_name, pw->pw_name, sizeof(info->user_name) - 1);
        info->user_name[sizeof(info->user_name) - 1] = '\0';
    } else {
        strcpy(info->user_name, "User");
    }
#endif
    
    return 0;
}

void cleanup_resources(void);
void show_startup_banner(void);

static void display_startup_error(const char* title, const char* message) {
#ifdef _WIN32
    MessageBoxA(NULL, message, title, MB_OK | MB_ICONERROR);
#else
    std::cerr << "[" << title << "] " << message << std::endl;
#endif
}

#if defined(PLUGXEL_ENABLE_HEADLESS_MODE) || defined(PLUG_ENABLE_HEADLESS_MODE)
extern "C" { bool g_headless_mode = false; }
#endif

int main() {
#if defined(PLUGXEL_ENABLE_HEADLESS_MODE) || defined(PLUG_ENABLE_HEADLESS_MODE)
    {
        const char* headless = (getenv("PLUGXEL_HEADLESS") ? getenv("PLUGXEL_HEADLESS") : getenv("PLUG_HEADLESS"));
        if (headless && strcmp(headless, "1") == 0) {
            g_headless_mode = true;
        }
    }
#endif

#ifdef _WIN32
    OSVERSIONINFOEXA osvi = {};
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXA);
    
    typedef NTSTATUS(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);
    HMODULE hMod = GetModuleHandleA("ntdll.dll");
    if (hMod) {
        RtlGetVersionPtr fxPtr = (RtlGetVersionPtr)GetProcAddress(hMod, "RtlGetVersion");
        if (fxPtr) {
            fxPtr((PRTL_OSVERSIONINFOW)&osvi);
        }
    }
    
    if (osvi.dwMajorVersion < 10) {
        display_startup_error("plugxel", "Unsupported OS. Windows 10+ required.");
        return 1;
    }
#endif

    int admin_status = admin_init_c();
    if (admin_status == FALSE) {
        return 0;
    }
    
    prov_check_or_run();

    if (get_system_info(&g_sys_info_main) != 0) {
        display_startup_error("plugxel Error", "Failed to get system information");
        return 1;
    }

    if (c_init() != 0) {
        display_startup_error("plugxel Error", "Failed to initialize command system");
        return 1;
    }

    if (main_ui_init() == 0) {
        show_startup_banner();
        main_ui_run_message_loop();
        main_ui_cleanup();
    } else {
        display_startup_error("plugxel Error", "Failed to initialize main UI");
        cleanup_resources();
        return 1;
    }
    
    cleanup_resources();
    
    return 0;
}

void cleanup_resources(void) {
    c_cleanup();
}

void show_startup_banner(void) {
    main_ui_print_banner();
    main_ui_print_info("Type /? for help or /e to exit");
}
