idf_component_register(SRCS "main.c"
                            "device_control.c"
                            "iot_cli_cmd.c"
                            "iot_uart_cli.c"
                    EMBED_FILES "device_info.json"
                                "onboarding_config.json"
                    )

set(stdk_config ${CMAKE_CURRENT_LIST_DIR}/stdkconfig.cmake)

set(STDK_LINK_LIBRARY
        __idf_libsodium
        __idf_json
   )

set(STDK_INCLUDE_PATH
        "$ENV{IDF_PATH}/components/freertos/include/freertos"
        "$ENV{IDF_PATH}/components/nvs_flash/include"
        "$ENV{IDF_PATH}/components/spi_flash/include"
        "$ENV{IDF_PATH}/components/bootloader_support/include"
    )

add_subdirectory(../../.. iotcore)
target_link_libraries(${COMPONENT_LIB} PUBLIC iotcore)
