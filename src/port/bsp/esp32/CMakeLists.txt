target_sources(iotcore
	PRIVATE
        iot_bsp_debug_esp32.c
        iot_bsp_fs_esp32.c
        iot_bsp_nv_data_esp32.c
        iot_bsp_random_esp32.c
        iot_bsp_system_esp32.c
        iot_bsp_wifi_esp32.c
        )

if(CONFIG_STDK_IOT_CORE_EASYSETUP_BLE)
target_sources(iotcore
	PUBLIC
		iot_bsp_ble_esp32.c
        )
        target_link_libraries(iotcore PRIVATE idf::bt)
endif()

target_link_libraries(iotcore PRIVATE idf::spi_flash idf::esp_partition idf::esp_wifi idf::json idf::nvs_flash idf::bootloader_support)
