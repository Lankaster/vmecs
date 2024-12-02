#cmake_minimum_required(VERSION 2.8)
project(CryptoLibrary LANGUAGES C)


# Default to OpenSSL if no option is selected
if (NOT USE_OPENSSL AND NOT USE_MBEDTLS AND NOT USE_GNUTLS)
    message(STATUS "No cryptographic library specified. Defaulting to OpenSSL.")
    set(USE_OPENSSL ON)
endif()

if (USE_MBEDTLS)
    message("use MbedTLS library")
    set(USE_GNUTLS OFF)
    set(USE_OPENSSL OFF)
endif()

if (USE_GNUTLS)
    message("use GnuTLS library")
    set(USE_MBEDTLS OFF)
    set(USE_OPENSSL OFF)
endif()

if (USE_OPENSSL)
    message("use OpenSSL library")
    set(USE_GNUTLS OFF)
    set(USE_MBEDTLS OFF)
endif()


find_path(MBEDTLS_INCLUDE_DIR
          NAMES mbedtls/ssl.h
          PATH_SUFFIXES include)

if(MBEDTLS_INCLUDE_DIR)
  if(EXISTS "${MBEDTLS_INCLUDE_DIR}/mbedtls/build_info.h")  # 3.x
    set(_version_header "${MBEDTLS_INCLUDE_DIR}/mbedtls/build_info.h")
  elseif(EXISTS "${MBEDTLS_INCLUDE_DIR}/mbedtls/version.h")  # 2.x
    set(_version_header "${MBEDTLS_INCLUDE_DIR}/mbedtls/version.h")
  else()
    unset(_version_header)
  endif()
  if(_version_header)
    set(_version_regex "#[\t ]*define[\t ]+MBEDTLS_VERSION_STRING[\t ]+\"([0-9.]+)\"")
    file(STRINGS "${_version_header}" _version_str REGEX "${_version_regex}")
    string(REGEX REPLACE "${_version_regex}" "\\1" _version_str "${_version_str}")
    set(MBEDTLS_VERSION "${_version_str}")
    unset(_version_regex)
    unset(_version_str)
    unset(_version_header)
  endif()
endif()


# Add source files based on selected library
if(USE_MBEDTLS)
    find_package(MbedTLS REQUIRED)
    set(SSL_SOURCES aes_mb.c hash_mb.c)
    include_directories(${MBEDTLS_INCLUDE_DIRS})

    # Define the mbedTLS version macro for conditional compilation
    if(MBEDTLS_VERSION LESS 3)
        add_definitions(-DMBEDTLS_VERSION_2)
    else()
        add_definitions(-DMBEDTLS_VERSION_3)
    endif()
elseif(USE_OPENSSL)
    find_package(OpenSSL REQUIRED)
    set(SSL_SOURCES aes.c hash.c)
    include_directories(${OPENSSL_INCLUDE_DIRS})
elseif(USE_GNUTLS)
    find_package(GnuTLS REQUIRED)
    set(SSL_SOURCES aes_gnu.c hash_gnu.c)
    include_directories(${GNUTLS_INCLUDE_DIRS})
else()
    message(FATAL_ERROR "No SSL library selected.")
endif()

# Create the library
if(BUILD_SHARED_LIBS)
    add_lib_batch(vmecs-crypto SHARED ${SSL_SOURCES})
else()
    add_lib_batch(vmecs-crypto STATIC ${SSL_SOURCES})
endif()


# Link the libraries based on the chosen SSL option
if(USE_MBEDTLS)
    target_link_libraries(vmecs-crypto ${MBEDTLS_LIBRARIES})
elseif(USE_OPENSSL)
    target_link_libraries(vmecs-crypto OpenSSL::SSL OpenSSL::Crypto)
elseif(USE_GNUTLS)
    target_link_libraries(vmecs-crypto ${GNUTLS_LIBRARIES})
endif()

