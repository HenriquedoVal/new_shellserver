cmake_minimum_required(VERSION 3.19)

project(nss C)

# libgit2
set(CMAKE_BUILD_TYPE_COPY "${CMAKE_BUILD_TYPE}")

set(CMAKE_BUILD_TYPE  "Release" CACHE STRING "" FORCE)
set(USE_THREADS       "Win32"   CACHE STRING "" FORCE)
set(BUILD_SHARED_LIBS OFF       CACHE BOOL   "" FORCE)
set(BUILD_CLI         OFF       CACHE BOOL   "" FORCE)
set(BUILD_TESTS       OFF       CACHE BOOL   "" FORCE)
set(STATIC_CRT        OFF       CACHE BOOL   "" FORCE)

add_subdirectory(libgit2)

unset(BUILD_CLI)
unset(BUILD_TESTS)
unset(STATIC_CRT)
unset(BUILD_SHARED_LIBS)
set(CMAKE_BUILD_TYPE "${CMAKE_BUILD_TYPE_COPY}")
unset(CMAKE_BUILD_TYPE_COPY)

# nss
set(CMAKE_C_STANDARD 99)

if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    add_compile_options(-fsanitize=address)
    if (NOT MSVC)
        add_link_options(-fsanitize=address)
    endif()
endif()

if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    add_executable(nss_server server.c)
else()
    add_executable(nss_server WIN32 server.c)
endif()

target_include_directories(nss_server PRIVATE "libgit2/include")
target_link_libraries(nss_server libgit2package Delayimp)
target_link_options(nss_server PRIVATE
    "-delayload:winhttp.dll"
    "-delayload:rpcrt4.dll"
    "-delayload:crypt32.dll"
    "-delayload:ole32.dll"
    "-delayload:secur32.dll"
)

add_library(nss_client SHARED client.c)
target_include_directories(nss_client PRIVATE "${PROJECT_BINARY_DIR}")

# add_executable(test_client test_client.c)
# target_include_directories(test_client PRIVATE "${PROJECT_BINARY_DIR}")
# target_link_libraries(test_client nss_client)
