include ("component.cmake")

if(CONFIG_STDK_IOT_CORE_OS_SUPPORT_POSIX)
set(CJSON_DIR deps/json)
include(CheckIncludeFile)
check_include_file(${CJSON_DIR}/cJSON/cJSON.h CJSON_H)
if (NOT CJSON_H)
    message(STATUS "submodule init for cJSON")
    execute_process(COMMAND git submodule update --init ${CJSON_DIR}
                    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")
    set(STDK_INCLUDE_PATH "${STDK_INCLUDE_PATH}" ${CJSON_DIR}/cJSON)
endif (NOT CJSON_H)

set(MBEDTLS_DIR deps/mbedtls)
check_include_file(${MBEDTLS_DIR}/mbedtls/include/ssl.h MBEDTLS_H)
if (NOT MBEDTLS_H)
    message(STATUS "submodule init for mbedtls")
    execute_process(COMMAND git submodule update --init ${MBEDTLS_DIR}
                    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")
    set(STDK_INCLUDE_PATH "${STDK_INCLUDE_PATH}" ${MBEDTLS_DIR}/mbedtls/include)
endif (NOT MBEDTLS_H)

set(LIBSODIUM_DIR deps/libsodium)
check_include_file(${LIBSODIUM_DIR}/libsodium/src/libsodium/include/sodium.h SODIUM_H)
if (NOT SODIUM_H)
    message(STATUS "submodule init for libsodium")
    execute_process(COMMAND git submodule update --init ${LIBSODIUM_DIR}
            WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")
    set(STDK_INCLUDE_PATH "${STDK_INCLUDE_PATH}" ${LIBSODIUM_DIR}/libsodium/src/libsodium/include)
    set(STDK_INCLUDE_PATH "${STDK_INCLUDE_PATH}" ${LIBSODIUM_DIR}/libsodium/src/libsodium/include/sodium)
    set(STDK_INCLUDE_PATH "${STDK_INCLUDE_PATH}" ${LIBSODIUM_DIR}/port/include)
endif (NOT SODIUM_H)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC -fpic")
set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build shared libraries" FORCE)
set(ENABLE_CJSON_TEST OFF CACHE BOOL "Enable building cJSON test" FORCE)
add_subdirectory(${CJSON_DIR}/cJSON)
set(STDK_LINK_LIBRARY ${STDK_LINK_LIBRARY} cjson)

set(ENABLE_PROGRAMS OFF CACHE BOOL "Build mbed TLS programs." FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "Build mbed TLS tests." FORCE)
add_subdirectory(${MBEDTLS_DIR}/mbedtls)
set(STDK_LINK_LIBRARY ${STDK_LINK_LIBRARY} mbedtls mbedx509 mbedcrypto)

add_subdirectory(${LIBSODIUM_DIR})
set(STDK_LINK_LIBRARY ${STDK_LINK_LIBRARY} sodium)
endif()

if(CMAKE_C_COMPILER_ID STREQUAL "GNU" AND CMAKE_BUILD_TYPE MATCHES UnitTest)
    foreach(mock ${MOCKED_FUNCTIONS})
        set(CMAKE_C_FLAGS_UNITTEST "${CMAKE_C_FLAGS_UNITTEST} -Wl,--wrap=${mock}")
    endforeach()
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -include ${CMAKE_CURRENT_LIST_DIR}/include/iot_common.h")

add_library(iotcore
        iot_api.c
        iot_capability.c
        iot_wt.c
        iot_main.c
        iot_nv_data.c
        iot_util.c
        iot_uuid.c
        iot_root_ca.c
        iot_log_file.c
        iot_dump_log.c
        )

foreach(TMP_DIR ${STDK_SRC_PATH})
    add_subdirectory(${TMP_DIR})
endforeach()

target_include_directories(iotcore
        PRIVATE
        include/os
        include/mqtt
        include/external
        ${STDK_INCLUDE_PATH}
        PUBLIC
        include/bsp
        include
        )

target_link_libraries(iotcore
        PRIVATE
        ${STDK_LINK_LIBRARY}
        )
