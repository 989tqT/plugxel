cmake_minimum_required(VERSION 3.15)
project(cpp_ui_unit_tests CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(test_runner test_runner.cpp)
