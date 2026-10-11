cmake_minimum_required(VERSION 3.20)
project(plugxel LANGUAGES C CXX)

if(WIN32)
    enable_language(RC)
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(ROOT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../..")
set(APP_DIR "${ROOT_DIR}/plug.app")
set(COMMON_DIR "${APP_DIR}/cmn")

if(NOT DEFINED RUST_LIB_PATH)
    message(FATAL_ERROR "RUST_LIB_PATH must be defined!")
endif()

add_library(rust_core STATIC IMPORTED)
set_target_properties(rust_core PROPERTIES IMPORTED_LOCATION "${RUST_LIB_PATH}")

set(SOURCES
    "${APP_DIR}/src/main.cpp"
    "${APP_DIR}/srv/sys/init/admin.c"
    "${APP_DIR}/srv/sys/init/prov.c"
    "${APP_DIR}/src/windows/api/intf/main_w.cpp"
    "${APP_DIR}/src/windows/api/intf/cmp/u_prmt.cpp"
    "${APP_DIR}/src/windows/api/intf/cmp/u_lbl.cpp"
    "${APP_DIR}/src/windows/api/intf/cmp/caret/caret_.cpp"
    "${APP_DIR}/src/windows/api/intf/cmp/tab/tab_.cpp"
    "${APP_DIR}/src/windows/api/intf/cmp/scrollbar/scrollb_.cpp"
    "${APP_DIR}/src/windows/api/intf/cmp/clipboard/clipb_.cpp"
    "${APP_DIR}/src/windows/api/intf/cmp/effects/m_hover.cpp"
    "${APP_DIR}/src/windows/api/intf/cmp/highlight/selection_.cpp"
)

# Thêm RC file đã generate
if(WIN32 AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/plug_manifest.rc")
    list(APPEND SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/plug_manifest.rc")
endif()

if(HIDE_CONSOLE)
    add_executable(plugxel WIN32 ${SOURCES})
else()
    add_executable(plugxel ${SOURCES})
endif()

target_compile_definitions(plugxel PRIVATE NOMINMAX)

option(PLUGXEL_ENABLE_HEADLESS_MODE "Enable headless mode for E2E testing" OFF)
option(PLUG_ENABLE_HEADLESS_MODE "Enable headless mode for E2E testing (legacy)" OFF)
if(PLUGXEL_ENABLE_HEADLESS_MODE OR PLUG_ENABLE_HEADLESS_MODE)
    target_compile_definitions(plugxel PRIVATE PLUGXEL_ENABLE_HEADLESS_MODE PLUG_ENABLE_HEADLESS_MODE)
endif()

target_include_directories(plugxel PRIVATE
    "${APP_DIR}/inc"
    "${COMMON_DIR}/inc"
    "${COMMON_DIR}/inc/sys/api/cmp"
)

if(MSVC)
    # Use CMake's policy to set runtime library consistently (/MT for static linkage).
    # This avoids the D9025 "overriding '/MD' with '/MT'" warning that occurs when
    # manually passing /MT via target_compile_options while CMAKE_BUILD_TYPE=Release
    # injects /MD through CMAKE_CXX_FLAGS_RELEASE.
    set_property(TARGET plugxel PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")

    target_compile_options(plugxel PRIVATE
        /O2       # Maximize speed
        /Gw       # Global data optimization
        /Gy       # Enable function-level linking
        /GL       # Whole-program optimization (required for /LTCG to be meaningful)
        /wd4068   # Suppress unknown pragma warnings
    )
    target_link_options(plugxel PRIVATE
        /OPT:REF        # Remove unreferenced functions/data
        /OPT:ICF        # Identical COMDAT folding
        /LTCG           # Link-time code generation (requires /GL above)
        /MANIFEST:NO    # Suppress linker manifest embedding; RC file already embeds
                        # "1 24 plug.manifest". Without this, linker also tries to embed
                        # with ID=1 → CVT1100 duplicate resource → LNK1123.
    )
    if(HIDE_CONSOLE)
        target_link_options(plugxel PRIVATE "/ENTRY:mainCRTStartup")
    endif()

    target_link_libraries(plugxel PRIVATE
        rust_core
        kernel32 user32 gdi32 advapi32 crypt32 shell32 ole32 oleaut32 uuid
        psapi shlwapi ws2_32 userenv ntdll iphlpapi bcrypt secur32 dbghelp
        comctl32 urlmon wininet msimg32
    )
else()
    target_compile_options(plugxel PRIVATE -Os -ffunction-sections -fdata-sections -flto)
    target_link_options(plugxel PRIVATE -static -static-libgcc -static-libstdc++ -Wl,--gc-sections -flto -s)
    
    if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        target_link_options(plugxel PRIVATE -fuse-ld=lld)
    endif()

    target_link_libraries(plugxel PRIVATE
        rust_core
        winpthread
        kernel32 user32 gdi32 winspool comdlg32 advapi32 crypt32 shell32 ole32 oleaut32 uuid
        psapi shlwapi ws2_32 userenv ntdll iphlpapi bcrypt secur32 dbghelp
        comctl32 urlmon wininet msimg32
        ntdll
    )
endif()

option(COMPILE_RUST_CORE "Automatically compile the Rust library core inside the build" ON)

if(COMPILE_RUST_CORE)
    find_program(CARGO_EXECUTABLE cargo)
    if(NOT CARGO_EXECUTABLE)
        message(FATAL_ERROR "cargo executable not found! Install Rust or disable COMPILE_RUST_CORE.")
    endif()

    if(MSVC)
        set(CARGO_TARGET "x86_64-pc-windows-msvc")
    else()
        set(CARGO_TARGET "x86_64-pc-windows-gnu")
    endif()

    add_custom_command(
        OUTPUT "${RUST_LIB_PATH}"
        COMMAND "${CARGO_EXECUTABLE}" build --release --lib --target "${CARGO_TARGET}"
        WORKING_DIRECTORY "${APP_DIR}/rt"
        DEPENDS 
            "${APP_DIR}/rt/Cargo.toml" 
            "${APP_DIR}/rt/handlers/lib.rs"
        COMMENT "Compiling Rust library core (${CARGO_TARGET})..."
    )
    
    add_custom_target(cargo_build DEPENDS "${RUST_LIB_PATH}")
    add_dependencies(plugxel cargo_build)
endif()

