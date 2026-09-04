cmake_minimum_required(VERSION 3.24)

project(
    zerotrust_fl_cpp
    VERSION 0.4.0
    LANGUAGES CXX
)

option(ZTFL_ENABLE_OPENMP "Enable OpenMP parallel aggregation" ON)
option(ZTFL_NATIVE_ARCH "Optimize generated C++ code for the local CPU" OFF)
option(ZTFL_ENABLE_CKKS "Enable Microsoft SEAL CKKS encrypted aggregation" ON)
set(ZTFL_ENABLE_CUDA "AUTO" CACHE STRING "Enable CUDA aggregation: AUTO, ON, or OFF")
set_property(CACHE ZTFL_ENABLE_CUDA PROPERTY STRINGS AUTO ON OFF)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

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

if(ZTFL_ENABLE_OPENMP)
    find_package(OpenMP QUIET COMPONENTS CXX)
endif()

if(ZTFL_ENABLE_CKKS)
    include(FetchContent)
    set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
    set(SEAL_BUILD_DEPS ON CACHE BOOL "" FORCE)
    set(SEAL_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
    set(SEAL_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(SEAL_BUILD_BENCH OFF CACHE BOOL "" FORCE)
    set(SEAL_BUILD_SEAL_C OFF CACHE BOOL "" FORCE)
    set(SEAL_USE_ZLIB OFF CACHE BOOL "" FORCE)
    set(SEAL_USE_ZSTD OFF CACHE BOOL "" FORCE)
    set(SEAL_USE_INTEL_HEXL OFF CACHE BOOL "" FORCE)
    set(SEAL_SECURE_COMPILE_OPTIONS ON CACHE BOOL "" FORCE)
    FetchContent_Declare(
        microsoft_seal
        GIT_REPOSITORY https://github.com/microsoft/SEAL.git
        GIT_TAG v4.4.3
        GIT_SHALLOW TRUE
    )
    FetchContent_MakeAvailable(microsoft_seal)
endif()

string(TOUPPER "${ZTFL_ENABLE_CUDA}" ZTFL_ENABLE_CUDA_NORMALIZED)
if(NOT ZTFL_ENABLE_CUDA_NORMALIZED MATCHES "^(AUTO|ON|OFF)$")
    message(FATAL_ERROR "ZTFL_ENABLE_CUDA must be AUTO, ON, or OFF")
endif()

set(ZTFL_CUDA_ACTIVE OFF)
if(NOT ZTFL_ENABLE_CUDA_NORMALIZED STREQUAL "OFF")
    include(CheckLanguage)
    check_language(CUDA)
    if(CMAKE_CUDA_COMPILER)
        enable_language(CUDA)
        find_package(CUDAToolkit REQUIRED)
        set(ZTFL_CUDA_ACTIVE ON)
        message(STATUS "ZeroTrust-FL CUDA acceleration enabled with ${CMAKE_CUDA_COMPILER}")
    elseif(ZTFL_ENABLE_CUDA_NORMALIZED STREQUAL "ON")
        message(FATAL_ERROR "ZTFL_ENABLE_CUDA=ON but no CUDA compiler was found")
    else()
        message(STATUS "CUDA compiler not found; building CPU-only aggregation backend")
    endif()
endif()

if(NOT CMAKE_LIBRARY_OUTPUT_DIRECTORY)
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/python")
endif()
if(NOT CMAKE_RUNTIME_OUTPUT_DIRECTORY)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/python")
endif()

foreach(CONFIG Debug Release RelWithDebInfo MinSizeRel)
    string(TOUPPER "${CONFIG}" CONFIG_UPPER)
    if(NOT CMAKE_LIBRARY_OUTPUT_DIRECTORY_${CONFIG_UPPER})
        set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_${CONFIG_UPPER} "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}")
    endif()
    if(NOT CMAKE_RUNTIME_OUTPUT_DIRECTORY_${CONFIG_UPPER})
        set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${CONFIG_UPPER} "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}")
    endif()
endforeach()

add_library(
    zerotrust_aggregation_core
    STATIC
    src/byzantine_aggregator.cpp
    src/simd_distance.cpp
)

if(ZTFL_ENABLE_CKKS)
    target_sources(
        zerotrust_aggregation_core
        PRIVATE
        src/ckks_secure_aggregation.cpp
    )
endif()

if(ZTFL_CUDA_ACTIVE)
    target_sources(
        zerotrust_aggregation_core
        PRIVATE
        src/cuda_aggregation.cu
    )
    set_target_properties(
        zerotrust_aggregation_core
        PROPERTIES
        CUDA_STANDARD 17
        CUDA_STANDARD_REQUIRED ON
        CUDA_EXTENSIONS OFF
        CUDA_SEPARABLE_COMPILATION OFF
    )
endif()

target_include_directories(
    zerotrust_aggregation_core
    PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

target_compile_features(zerotrust_aggregation_core PUBLIC cxx_std_20)

if(OpenMP_CXX_FOUND)
    target_link_libraries(zerotrust_aggregation_core PUBLIC OpenMP::OpenMP_CXX)
    target_compile_definitions(zerotrust_aggregation_core PUBLIC ZTFL_HAS_OPENMP=1)
endif()

if(ZTFL_ENABLE_CKKS)
    target_link_libraries(zerotrust_aggregation_core PUBLIC SEAL::seal)
    target_compile_definitions(zerotrust_aggregation_core PUBLIC ZTFL_HAS_CKKS=1)
endif()

if(ZTFL_CUDA_ACTIVE)
    target_link_libraries(zerotrust_aggregation_core PUBLIC CUDA::cudart)
    target_compile_definitions(zerotrust_aggregation_core PUBLIC ZTFL_HAS_CUDA=1)
endif()

pybind11_add_module(
    zerotrust_fl_cpp
    MODULE
    src/aggregator_pybind.cpp
)

target_link_libraries(zerotrust_fl_cpp PRIVATE zerotrust_aggregation_core)
target_compile_features(zerotrust_fl_cpp PRIVATE cxx_std_20)

if(MSVC)
    target_compile_options(
        zerotrust_aggregation_core
        PRIVATE
        $<$<COMPILE_LANGUAGE:CXX>:/O2;/W4;/permissive->
    )
    target_compile_options(zerotrust_fl_cpp PRIVATE /O2 /W4 /permissive-)
else()
    target_compile_options(
        zerotrust_aggregation_core
        PRIVATE
        $<$<COMPILE_LANGUAGE:CXX>:-O3;-Wall;-Wextra;-Wpedantic>
        $<$<COMPILE_LANGUAGE:CUDA>:-O3>
    )
    target_compile_options(zerotrust_fl_cpp PRIVATE -O3 -Wall -Wextra -Wpedantic)
    if(ZTFL_NATIVE_ARCH)
        target_compile_options(
            zerotrust_aggregation_core
            PRIVATE
            $<$<COMPILE_LANGUAGE:CXX>:-march=native>
        )
        target_compile_options(zerotrust_fl_cpp PRIVATE -march=native)
    endif()
endif()

include(CheckIPOSupported)
check_ipo_supported(RESULT ZTFL_IPO_SUPPORTED OUTPUT ZTFL_IPO_ERROR LANGUAGES CXX)
if(ZTFL_IPO_SUPPORTED)
    set_property(
        TARGET zerotrust_aggregation_core
        PROPERTY INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE
    )
    set_property(
        TARGET zerotrust_fl_cpp
        PROPERTY INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE
    )
endif()
