cmake_minimum_required(VERSION 3.15)
project(st_device_sdk_c C)

set(CMAKE_C_STANDARD 99)

set(STDK_EXTRA_CFLAGS
    CONFIG_STDK_IOT_CORE_OS_SUPPORT_POSIX
    CONFIG_STDK_IOT_CORE_USE_MBEDTLS
    CONFIG_STDK_IOT_CORE_NET_MBEDTLS
    CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_ED25519
    CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_VERIFY
#    CONFIG_STDK_IOT_CORE_LOG_LEVEL_ERROR
#    CONFIG_STDK_IOT_CORE_LOG_LEVEL_WARN
#    CONFIG_STDK_IOT_CORE_LOG_LEVEL_INFO
#    CONFIG_STDK_IOT_CORE_LOG_LEVEL_DEBUG
    )
foreach(stdk_extra_cflags ${STDK_EXTRA_CFLAGS})
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D${stdk_extra_cflags}")
endforeach()

if(CMAKE_C_COMPILER_ID STREQUAL "GNU" AND CMAKE_BUILD_TYPE MATCHES Debug)
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fprofile-arcs -ftest-coverage")
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DSUPPORT_TC_ON_STATIC_FUNC")
    set(MOCKED_FUNCTIONS
        iot_bsp_wifi_get_mac
        iot_os_malloc
        iot_os_free
        iot_bsp_wifi_get_scan_result
        )
endif()

add_subdirectory(src)
if(CMAKE_C_COMPILER_ID STREQUAL "GNU" AND CMAKE_BUILD_TYPE MATCHES Debug)
    add_subdirectory(test)
endif()
