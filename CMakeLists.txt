cmake_minimum_required(VERSION 3.10)

project(nss C)

# libgit2

set(CMAKE_BUILD_TYPE_COPY "${CMAKE_BUILD_TYPE}")

set(CMAKE_BUILD_TYPE "Release" CACHE STRING "" FORCE)
set(BUILD_SHARED_LIBS OFF      CACHE BOOL   "" FORCE)
set(BUILD_CLI         OFF      CACHE BOOL   "" FORCE)
set(BUILD_TESTS       OFF      CACHE BOOL   "" FORCE)

add_subdirectory(libgit2)

unset(BUILD_TESTS)
unset(BUILD_CLI)
unset(BUILD_SHARED_LIBS)
set(CMAKE_BUILD_TYPE "${CMAKE_BUILD_TYPE_COPY}")
unset(CMAKE_BUILD_TYPE_COPY)

# nss

if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug" AND MSVC)
    add_compile_options(-fsanitize=address)
endif()
add_executable(nss_server server.c)
target_include_directories(nss_server PUBLIC "libgit2/include")
target_link_libraries(nss_server libgit2package)

add_library(nss_client SHARED client.c)
target_include_directories(nss_client PUBLIC "${PROJECT_BINARY_DIR}")

# add_executable(test_client test_client.c)
# target_include_directories(test_client PUBLIC "${PROJECT_BINARY_DIR}")
# target_link_libraries(test_client client)
