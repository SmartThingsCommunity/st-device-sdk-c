add_subdirectory(backend)

target_sources(iotcore
	PRIVATE
	iot_security_util.c
	iot_security_common.c
	iot_security_crypto.c
	iot_security_ecdh.c
	iot_security_manager.c
	iot_security_storage.c
)
