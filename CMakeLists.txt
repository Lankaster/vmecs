cmake_minimum_required(VERSION 3.18)
# 3.16: https://cmake.org/cmake/help/latest/module/FindGnuTLS.html
# 3.18: https://cmake.org/cmake/help/latest/module/FindOpenSSL.html

option(BUILD_SHARED_LIBS "Build using shared libraries" ON)
option(BUILD_WITH_CLANG "Build using clang"  OFF )

option(USE_MBEDTLS "Use mbedTLS for TLS connections." OFF)
option(USE_GNUTLS "Use GnuTLS for TLS connections." OFF)
option(USE_OPENSSL "Use OpenSSL for TLS connections." ON)

project(vmecs)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules")

# set basic compile flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -fPIC -Wall -pedantic -Wno-address -Wno-unused-function")

# Check
if(BUILD_WITH_CLANG)
    message("* Use clang for build")
    set(CMAKE_C_COMPILER "clang")
else()
    message("* Use default compiler")
endif()

if(BUILD_SHARED_LIBS)
    message("* Build with shared libs")
else()
    message("* Build static version")
endif()

# Use GNU default dirs
include(GNUInstallDirs)

# add common headers
include_directories(${PROJECT_SOURCE_DIR})

message(STATUS "Compile using flags: '${CMAKE_C_FLAGS}'")

macro(add_exe_batch exe_name)
	file(GLOB c_list ${ARGN})
	add_executable(${exe_name} ${c_list})
	install(TARGETS ${exe_name} DESTINATION bin)
endmacro()

macro(add_lib_batch lib_name linkage)
	file(GLOB c_list ${ARGN})
	add_library(${lib_name} ${linkage} ${c_list})
	install(TARGETS ${lib_name} DESTINATION lib)
endmacro()

add_subdirectory(app)
add_subdirectory(proto)
add_subdirectory(crypto)
add_subdirectory(pub)
add_subdirectory(toml)
