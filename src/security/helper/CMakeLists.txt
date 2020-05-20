set(HELPER_SRCS
	libsodium/iot_security_helper_libsodium.c
)

if("${CMAKE_C_FLAGS}" MATCHES "-DCONFIG_STDK_IOT_CORE_USE_MBEDTLS")
set(HELPER_SRCS
	${HELPER_SRCS}
	mbedtls/iot_security_helper_mbedtls.c
)
endif()

target_sources(iotcore
	PRIVATE
	${HELPER_SRCS}
)
