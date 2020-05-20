add_subdirectory(backend)

target_sources(iotcore
	PRIVATE
	iot_security_common.c
	iot_security_storage.c
)
