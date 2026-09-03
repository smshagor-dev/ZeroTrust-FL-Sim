cmake_minimum_required(VERSION 3.24)

project(
    zerotrust_agg
    VERSION 0.1.0
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(
    Python
    REQUIRED
    COMPONENTS Interpreter Development.Module
)

execute_process(
    COMMAND "${Python_EXECUTABLE}" -m pybind11 --cmakedir
    OUTPUT_VARIABLE PYBIND11_CMAKE_DIR
    OUTPUT_STRIP_TRAILING_WHITESPACE
    COMMAND_ERROR_IS_FATAL ANY
)

find_package(
    pybind11
    CONFIG
    REQUIRED
    HINTS "${PYBIND11_CMAKE_DIR}"
)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/python")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/python")

foreach(CONFIG Debug Release RelWithDebInfo MinSizeRel)
    string(TOUPPER "${CONFIG}" CONFIG_UPPER)
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_${CONFIG_UPPER} "${CMAKE_BINARY_DIR}/python")
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${CONFIG_UPPER} "${CMAKE_BINARY_DIR}/python")
endforeach()

pybind11_add_module(
    zerotrust_agg
    MODULE
    src/bindings.cpp
)

target_compile_features(zerotrust_agg PRIVATE cxx_std_20)
target_include_directories(zerotrust_agg PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/include")

if(MSVC)
    target_compile_options(zerotrust_agg PRIVATE /W4 /permissive-)
else()
    target_compile_options(zerotrust_agg PRIVATE -Wall -Wextra -Wpedantic)
endif()
