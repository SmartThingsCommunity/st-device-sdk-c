cmake_minimum_required(VERSION 3.15)
project(st_device_sdk_c C)

set(CMAKE_C_STANDARD 99)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DCONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_ED25519")

if(CMAKE_C_COMPILER_ID STREQUAL "GNU" AND CMAKE_BUILD_TYPE MATCHES Debug)
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fprofile-arcs -ftest-coverage")
    set(MOCKED_FUNCTIONS
        iot_bsp_wifi_get_mac
        malloc
        )
endif()

add_subdirectory(src)
if(CMAKE_C_COMPILER_ID STREQUAL "GNU" AND CMAKE_BUILD_TYPE MATCHES Debug)
    add_subdirectory(test)
endif()