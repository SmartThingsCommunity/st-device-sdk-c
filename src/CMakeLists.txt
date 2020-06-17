set(CJSON_DIR deps/json)
include(CheckIncludeFile)
check_include_file(${CJSON_DIR}/cJSON/cJSON.h CJSON_H)
if (NOT CJSON_H)
    message(STATUS "submodule init for cJSON")
    execute_process(COMMAND git submodule update --init ${CJSON_DIR}
                    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")
endif (NOT CJSON_H)

set(MBEDTLS_DIR deps/mbedtls)
check_include_file(${MBEDTLS_DIR}/mbedtls/include/ssl.h MBEDTLS_H)
if (NOT MBEDTLS_H)
    message(STATUS "submodule init for mbedtls")
    execute_process(COMMAND git submodule update --init ${MBEDTLS_DIR}
                    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")
endif (NOT MBEDTLS_H)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC -fpic")
set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build shared libraries" FORCE)
set(ENABLE_CJSON_TEST OFF CACHE BOOL "Enable building cJSON test" FORCE)
add_subdirectory(deps/json/cJSON)

set(ENABLE_PROGRAMS OFF CACHE BOOL "Build mbed TLS programs." FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "Build mbed TLS tests." FORCE)
add_subdirectory(deps/mbedtls/mbedtls)

if(CMAKE_C_COMPILER_ID STREQUAL "GNU" AND CMAKE_BUILD_TYPE MATCHES UnitTest)
    foreach(mock ${MOCKED_FUNCTIONS})
        set(CMAKE_C_FLAGS_UNITTEST "${CMAKE_C_FLAGS_UNITTEST} -Wl,--wrap=${mock}")
    endforeach()
endif()

add_library(iotcore
        iot_api.c
        iot_capability.c
        iot_wt.c
        iot_main.c
        iot_nv_data.c
        iot_util.c
        iot_uuid.c
        iot_root_ca.c
        iot_dump_log.c
        )

target_link_libraries(iotcore
        PRIVATE
        curl
        sodium
        mbedcrypto
        mbedx509
        mbedtls
        cjson
        )

target_include_directories(iotcore
        PRIVATE
        deps/json/cJSON
        deps/mbedtls/mbedtls/include
        port/net/mbedtls
        include/bsp
        include/bsp/posix
        include/os
        include/mqtt
        include/external
        PUBLIC
        include
        )

add_subdirectory(port/bsp/posix)
add_subdirectory(port/os/posix)
add_subdirectory(port/net)
add_subdirectory(easysetup)
add_subdirectory(mqtt)
add_subdirectory(security)
