cmake_minimum_required(VERSION 3.20)
project(plugxel LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(PLUGXEL_ENABLE_HEADLESS_MODE "Enable headless mode for E2E testing" OFF)
option(PLUG_ENABLE_HEADLESS_MODE "Enable headless mode for E2E testing (legacy)" OFF)
if(PLUGXEL_ENABLE_HEADLESS_MODE OR PLUG_ENABLE_HEADLESS_MODE)
    add_compile_definitions(PLUGXEL_ENABLE_HEADLESS_MODE PLUG_ENABLE_HEADLESS_MODE)
endif()

option(HIDE_CONSOLE "Hide console window" OFF)

set(ROOT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../..")
set(APP_DIR "${ROOT_DIR}/plug.app")
set(COMMON_DIR "${APP_DIR}/cmn")

if(NOT DEFINED RUST_LIB_PATH)
    message(FATAL_ERROR "RUST_LIB_PATH must be defined!")
endif()

add_library(rust_core STATIC IMPORTED)
set_target_properties(rust_core PROPERTIES IMPORTED_LOCATION "${RUST_LIB_PATH}")

find_package(PkgConfig REQUIRED)
pkg_check_modules(GTK4 REQUIRED gtk4)

set(SOURCES
    "${APP_DIR}/src/main.cpp"
    "${APP_DIR}/srv/sys/init/admin.c"
    "${APP_DIR}/srv/sys/init/prov.c"
    "${APP_DIR}/src/linux/api/intf/main_l.cpp"
    "${APP_DIR}/src/linux/api/intf/cmp/u_prmt.cpp"
    "${APP_DIR}/src/linux/api/intf/cmp/u_lbl.cpp"
    "${APP_DIR}/src/linux/api/intf/cmp/caret/caret_.cpp"
    "${APP_DIR}/src/linux/api/intf/cmp/tab/tab_.cpp"
    "${APP_DIR}/src/linux/api/intf/cmp/scrollbar/scrollb_.cpp"
    "${APP_DIR}/src/linux/api/intf/cmp/clipboard/clipb_.cpp"
    "${APP_DIR}/src/linux/api/intf/cmp/effects/m_hover.cpp"
    "${APP_DIR}/src/linux/api/intf/cmp/highlight/selection_.cpp"
)

add_executable(plugxel ${SOURCES})

target_include_directories(plugxel PRIVATE
    "${APP_DIR}/inc"
    "${COMMON_DIR}/inc"
    "${COMMON_DIR}/inc/sys/api/cmp"
    ${GTK4_INCLUDE_DIRS}
)

target_link_directories(plugxel PRIVATE
    ${GTK4_LIBRARY_DIRS}
)

target_compile_options(plugxel PRIVATE -O3 -ffunction-sections -fdata-sections -flto)
target_link_options(plugxel PRIVATE -Wl,--gc-sections -flto -s)

target_link_libraries(plugxel PRIVATE
    rust_core
    ${GTK4_LIBRARIES}
    pthread
    dl
    m
)
