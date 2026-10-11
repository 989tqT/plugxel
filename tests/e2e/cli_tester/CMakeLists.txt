cmake_minimum_required(VERSION 3.15)
project(cli_tester CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT DEFINED RUST_LIB_PATH)
    message(FATAL_ERROR "RUST_LIB_PATH must be defined!")
endif()

add_executable(cli_tester cli_tester.cpp)

# Define static imported Rust core
add_library(rust_core STATIC IMPORTED)
set_target_properties(rust_core PROPERTIES
    IMPORTED_LOCATION "${RUST_LIB_PATH}"
)

if(WIN32)
    target_compile_definitions(cli_tester PRIVATE NOMINMAX)
    
    # Static runtime linking matching the project setup
    if(MSVC)
        set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    endif()

    target_link_libraries(cli_tester PRIVATE
        rust_core
        winpthread
        kernel32 user32 gdi32 winspool comdlg32 advapi32 crypt32 shell32 ole32 oleaut32 uuid
        psapi shlwapi ws2_32 userenv ntdll iphlpapi bcrypt secur32 dbghelp
        comctl32 urlmon wininet msimg32
        ntdll
    )
else()
    target_link_libraries(cli_tester PRIVATE
        rust_core
        pthread
        dl
        m
    )
endif()
