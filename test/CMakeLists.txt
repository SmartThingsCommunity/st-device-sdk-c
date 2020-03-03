option(ENABLE_STDK_TEST "Enables st-device-sdk-c test" ON)
if(ENABLE_STDK_TEST)
    set(CMOCKA_DIR framework/cmocka)
    include(CheckIncludeFile)
    check_include_file(${CMOCKA_DIR}/include/cmocka.h CMOCKA_H)
    if (NOT CMOCKA_H)
        message(STATUS "submodule init for cmocka")
        execute_process(COMMAND git submodule update --init ${CJSON_DIR}
                        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")
    endif (NOT CMOCKA_H)

    add_subdirectory(${CMOCKA_DIR})
    include_directories(${cmocka-header_SOURCE_DIR}
                        ${st_device_sdk_c_SOURCE_DIR}/src/include
                        ${st_device_sdk_c_SOURCE_DIR}/src/include/bsp
                        ${st_device_sdk_c_SOURCE_DIR}/src/include/bsp/posix
                        ${st_device_sdk_c_SOURCE_DIR}/src/include/os
                        ${st_device_sdk_c_SOURCE_DIR}/src/include/mqtt
                        ${st_device_sdk_c_SOURCE_DIR}/src/deps/json/cJSON
                        ${st_device_sdk_c_SOURCE_DIR}/src/deps/mbedtls/mbedtls/include
                        ${st_device_sdk_c_SOURCE_DIR}/src/port/net/mbedtls)

    add_executable(stdk_test
                   TC_main.c
                   TCs.h
                   TC_iot_util.c
                   TC_iot_api.c
                   TC_iot_uuid.c
                   TC_iot_capability.c
                   TC_iot_crypto.c
                   TC_mock_functions.c
                   TC_mock_functions.h)

    target_link_libraries(stdk_test
                          PRIVATE
                          iotcore
                          cmocka
                          pthread
                          rt
                          )
endif()