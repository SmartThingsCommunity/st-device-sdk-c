#
# Port Crypto Cmake
#

target_sources(iotcore
	PRIVATE
	reference/port_crypto_reference.c
	reference/mbedtls_helper.c
	reference/libsodium_helper.c
)

if(CONFIG_STDK_IOT_CORE_BSP_SUPPORT_ESP32 OR
		CONFIG_STDK_IOT_CORE_BSP_SUPPORT_ESP32S2 OR
		CONFIG_STDK_IOT_CORE_BSP_SUPPORT_ESP32C3)
	target_link_libraries(iotcore PRIVATE idf::mbedtls idf::espressif__libsodium)
endif()
