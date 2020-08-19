cmake_minimum_required(VERSION 3.13)
project(st_device_sdk_c C)

set(CMAKE_C_STANDARD 99)

set(CMAKE_CXX_FLAGS_UNITTEST "-g --coverage -DSUPPORT_TC_ON_STATIC_FUNC" CACHE STRING
    "Flags used by the C++ compiler during unit test builds."
    FORCE)
set(CMAKE_C_FLAGS_UNITTEST "-g --coverage -DSUPPORT_TC_ON_STATIC_FUNC" CACHE STRING
    "Flags used by the C compiler during unit test builds."
    FORCE)
set(CMAKE_EXE_LINKER_FLAGS_UNITTEST "--coverage" CACHE STRING
    "Flags used for linking binaries during unit test builds."
    FORCE)
set(CMAKE_SHARED_LINKER_FLAGS_UNITTEST "--coverage" CACHE STRING
    "Flags used by the shared libraries linker during unit test builds."
    FORCE
    )
mark_as_advanced(
        CMAKE_CXX_FLAGS_UNITTEST
        CMAKE_C_FLAGS_UNITTEST
        CMAKE_EXE_LINKER_FLAGS_UNITTEST
        CMAKE_SHARED_LINKER_FLAGS_UNITTEST)
set(CMAKE_BUILD_TYPE "${CMAKE_BUILD_TYPE}" CACHE STRING
    "Choose the type of build, options are: None Debug Release RelWithDebInfo MinSizeRel UnitTest."
    FORCE
    )

if(NOT STDK_IOT_CORE_USE_DEFINED_CONFIG)
    if(EXISTS ${stdk_config})
        message("include stdk_config : ${stdk_config}")
        include("${stdk_config}")
    else()
        message("include default stdk_config")
        include("stdkconfig.cmake")
    endif()
endif()

if(CMAKE_C_COMPILER_ID STREQUAL "GNU" AND CMAKE_BUILD_TYPE MATCHES UnitTest)
    foreach(stdk_extra_cflags ${STDK_UNITTEST_EXTRA_CFLAGS})
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D${stdk_extra_cflags}")
        set(${stdk_extra_cflags} "y")
    endforeach()

    set(MOCKED_FUNCTIONS
        iot_bsp_wifi_get_mac
        iot_os_malloc
        iot_os_realloc
        iot_os_free
        iot_os_strdup
        iot_bsp_wifi_get_scan_result
        iot_bsp_system_set_time_in_sec
        iot_os_delay
        iot_net_init
        iot_bsp_wifi_set_mode
        )
else()
    foreach(stdk_extra_cflags ${STDK_EXTRA_CFLAGS})
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D${stdk_extra_cflags}")
        set(${stdk_extra_cflags} "y")
    endforeach()
endif()

add_subdirectory(src)
if(CMAKE_C_COMPILER_ID STREQUAL "GNU" AND CMAKE_BUILD_TYPE MATCHES UnitTest)
    add_subdirectory(test)
endif()
