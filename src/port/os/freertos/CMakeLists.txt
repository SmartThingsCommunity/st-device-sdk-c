target_sources(iotcore
        PRIVATE
        iot_os_util_freertos.c
        )

if(CONFIG_STDK_IOT_CORE_BSP_SUPPORT_ESP32)
	target_link_libraries(iotcore PRIVATE idf::freertos)
endif()
