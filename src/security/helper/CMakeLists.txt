set(HELPER_SRCS
	libsodium/iot_security_helper_libsodium.c
)

target_sources(iotcore
	PRIVATE
	${HELPER_SRCS}
)
