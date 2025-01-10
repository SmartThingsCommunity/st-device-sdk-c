idf_component_register(SRCS "main.c"
                            "device_control.c"
                            "iot_cli_cmd.c"
                            "iot_uart_cli.c"
                    EMBED_FILES "device_info.json"
                                "onboarding_config.json"
                    )

set(stdk_config ${CMAKE_CURRENT_LIST_DIR}/stdkconfig.cmake)
add_subdirectory(../../.. iotcore)
target_link_libraries(${COMPONENT_LIB} PUBLIC iotcore)
