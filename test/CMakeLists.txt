option(ENABLE_STDK_TEST "Enables st-device-sdk-c test" ON)
if(ENABLE_STDK_TEST)
    set(CMOCKA_DIR framework/cmocka)
    add_subdirectory(${CMOCKA_DIR})
    include_directories(${cmocka-header_SOURCE_DIR}
                        ${st_device_sdk_c_SOURCE_DIR}/src/include
                        ${st_device_sdk_c_SOURCE_DIR}/src/include/certs
                        ${st_device_sdk_c_SOURCE_DIR}/src/include/bsp
                        ${st_device_sdk_c_SOURCE_DIR}/src/include/bsp/posix
                        ${st_device_sdk_c_SOURCE_DIR}/src/include/os
                        ${st_device_sdk_c_SOURCE_DIR}/src/include/mqtt
                        ${st_device_sdk_c_SOURCE_DIR}/src/include/external
                        ${st_device_sdk_c_SOURCE_DIR}/src/deps/json/cJSON
                        ${st_device_sdk_c_SOURCE_DIR}/src/deps/mbedtls/mbedtls/include
                        ${st_device_sdk_c_SOURCE_DIR}/src/port/net/mbedtls)

    foreach(mock ${MOCKED_FUNCTIONS})
        set(CMAKE_C_FLAGS_UNITTEST "${CMAKE_C_FLAGS_UNITTEST} -Wl,--wrap=${mock}")
    endforeach()

    if("${CMAKE_C_FLAGS}" MATCHES "-DCONFIG_STDK_IOT_CORE_SECURITY_BACKEND_SOFTWARE")
        set(SECURITY_EXTRA_SRCS TC_FUNC_iot_security_be_bsp.c)
    endif()

    add_executable(stdk_test
                   TEST_main.c
                   TC_MOCK_functions.h
                   TC_MOCK_iot_bsp.c
                   TC_MOCK_iot_os.c
                   TC_MOCK_iot_net.c
                   TCs.h
                   TC_FUNC_iot_util.c
                   TC_FUNC_iot_api.c
                   TC_FUNC_iot_uuid.c
                   TC_FUNC_iot_capability.c
                   TC_FUNC_iot_crypto.c
                   TC_FUNC_iot_nv_data.c
                   TC_FUNC_iot_easysetup_d2d.c
                   TC_FUNC_iot_easysetup_crypto.c
                   TC_FUNC_iot_main.c
                   TC_FUNC_iot_mqtt_client.c
                   TC_FUNC_iot_security_common.c
                   TC_FUNC_iot_security_storage.c
                   TC_FUNC_iot_security_helper.c
                   TC_FUNC_iot_security_helper_ed25519.c
                   ${SECURITY_EXTRA_SRCS}
                   TC_FUNC_iot_wt.c
                   TC_FUNC_iot_easysetup_httpd.c)

    target_link_libraries(stdk_test
                          PRIVATE
                          iotcore
                          cmocka
                          pthread
                          rt
                          cjson
                          )
endif()
