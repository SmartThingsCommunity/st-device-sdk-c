cmake_minimum_required(VERSION 3.15)
project(st_device_sdk_c C)

set(CMAKE_C_STANDARD 99)

set(CJSON_DIR src/deps/json)
set(LIBSODIUM_DIR src/deps/libsodium)
set(MBEDTLS_DIR src/deps/mbedtls)
set(CURL_DIR src/deps/curl)

include(CheckIncludeFileCXX)
check_include_file_cxx(${CJSON_DIR}/cJSON/cJSON.h CJSON_H)
if (NOT CJSON_H)
    message(STATUS "submodule init for cJSON")
    execute_process(COMMAND git submodule update --init ${CJSON_DIR}
            WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")
endif (NOT CJSON_H)

check_include_file_cxx(${LIBSODIUM_DIR}/libsodium/src/libsodium/include/sodium.h LIBSODIUM_H)
if (NOT LIBSODIUM_H)
    message(STATUS "submodule init for libsodium")
    execute_process(COMMAND git submodule update --init ${LIBSODIUM_DIR}
            WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")
endif (NOT LIBSODIUM_H)

check_include_file_cxx(${MBEDTLS_DIR}/mbedtls/include/ssl.h MBEDTLS_H)
if (NOT MBEDTLS_H)
    message(STATUS "submodule init for mbedtls")
    execute_process(COMMAND git submodule update --init ${MBEDTLS_DIR}
            WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")
endif (NOT MBEDTLS_H)

check_include_file_cxx(${CURL_DIR}/curl/include/curl/curl.h CURL_H)
if (NOT CURL_H)
    message(STATUS "submodule init for curl")
    execute_process(COMMAND git submodule update --init ${CURL_DIR}
            WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")
endif (NOT CURL_H)

add_library(iotcore "")
add_subdirectory(src)