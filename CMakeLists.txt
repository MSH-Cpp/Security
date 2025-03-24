cmake_minimum_required(VERSION 3.20)

set(PROJECT_VERSION "0.0.1")

project(
    MSH_CRYPTO_PROJECT
    VERSION ${PROJECT_VERSION}
    LANGUAGES CXX
)

# C++ Standard Configuration
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Project Options
option(ENABLE_COVERAGE "Enable coverage reporting" ON)
option(ENABLE_STATIC_ANALYSIS "Enable static analysis" ON)
option(BUILD_TESTING "Build test suite" ON)

# Include custom CMake modules
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(cppcheck)
include(opencppcoverage)

# Set tiny-aes-c paths
set(PREBUILT_DIR "${CMAKE_INSTALL_PREFIX}")
set(PREBUILT_INCLUDE_DIR "${PREBUILT_DIR}/include")
set(PREBUILT_LIBRARY_DIR "${PREBUILT_DIR}/lib")

set(TINY_AES_C_LIBRARY "${PREBUILT_LIBRARY_DIR}/tiny-aes-c.lib")
set(TINY_AES_C_LIBRARY_DEBUG "${PREBUILT_LIBRARY_DIR}/tiny-aes-c-d.lib")

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    if(NOT EXISTS "${TINY_AES_C_LIBRARY_DEBUG}")
        message(FATAL_ERROR ">>>>> tiny-aes-c library not found at ${TINY_AES_C_LIBRARY_DEBUG}")
    endif()
else()
    if(NOT EXISTS "${TINY_AES_C_LIBRARY}")
        message(FATAL_ERROR ">>>>> tiny-aes-c library not found at ${TINY_AES_C_LIBRARY}")
    endif()
endif()

add_subdirectory(interface)
add_subdirectory(tinyaes_impl)

# Testing
if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    if(BUILD_TESTING)
        # Find Catch2
        find_package(Catch2 3.5.3 REQUIRED)
        include(CTest)
        enable_testing()

        add_subdirectory(tests)
    endif()
endif()
