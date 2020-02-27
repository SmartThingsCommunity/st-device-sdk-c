cmake_minimum_required(VERSION 3.15)
project(st_device_sdk_c C)

set(CMAKE_C_STANDARD 99)

if(CMAKE_BUILD_TYPE MATCHES Debug)
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fprofile-arcs -ftest-coverage")
endif()
add_subdirectory(src)
if(CMAKE_C_COMPILER_ID STREQUAL "GNU" AND CMAKE_BUILD_TYPE MATCHES Debug)
    set(MOCKED_FUNCTIONS
        iot_bsp_wifi_get_mac)
    foreach(mock ${MOCKED_FUNCTIONS})
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wl,--wrap=${mock}")
    endforeach()
    add_subdirectory(test)
endif()