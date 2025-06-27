target_sources(iotcore
	PRIVATE
        iot_bsp_debug_bk7236.c
        iot_bsp_fs_bk7236.c
        iot_bsp_nv_data_bk7236.c
        iot_bsp_random_bk7236.c
        iot_bsp_system_bk7236.c
        iot_bsp_wifi_bk7236.c
        )

if(CONFIG_STDK_IOT_CORE_EASYSETUP_BLE)
target_sources(iotcore
	PRIVATE
		iot_bsp_ble_bk7236.c
        )
        target_link_libraries(iotcore PRIVATE armino::bk_bluetooth)
endif()

target_link_libraries(iotcore PRIVATE armino::easy_flash armino::bk_wifi armino::json armino::lwip_intf_v2_1 armino::mbedtls)
