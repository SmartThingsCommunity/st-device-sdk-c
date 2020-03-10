option(ENABLE_STDK_TEST "Enables st-device-sdk-c test" ON)
if(ENABLE_STDK_TEST)
    set(CMOCKA_DIR framework/cmocka)
    include(CheckIncludeFile)
    check_include_file(${CMOCKA_DIR}/include/cmocka.h CMOCKA_H)
    if (NOT CMOCKA_H)
        message(STATUS "submodule init for cmocka")
        execute_process(COMMAND git submodule update --init ${CMOCKA_DIR}
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


    foreach(mock ${MOCKED_FUNCTIONS})
        set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Wl,--wrap=${mock}")
    endforeach()


    add_executable(stdk_test
                   TEST_main.c
                   TC_MOCK_functions.c
                   TC_MOCK_functions.h
                   TC_STORY_easysetup_d2d.c
                   TCs.h
                   TC_FUNC_iot_util.c
                   TC_FUNC_iot_api.c
                   TC_FUNC_iot_uuid.c
                   TC_FUNC_iot_capability.c
                   TC_FUNC_iot_crypto.c
                   TC_FUNC_iot_nv_data.c
                   TC_FUNC_iot_easysetup_d2d.c
                   TC_FUNC_iot_easysetup_crypto.c)

    target_link_libraries(stdk_test
                          PRIVATE
                          iotcore
                          cmocka
                          pthread
                          rt
                          cjson
                          curl
                          )
endif()