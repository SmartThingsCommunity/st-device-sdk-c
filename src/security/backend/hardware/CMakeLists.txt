if(${CONFIG_STDK_IOT_CORE_SECURITY_BACKEND_HARDWARE_VIRTUAL})
	add_subdirectory(virtual)
else
	target_sources(iotcore
		PRIVATE
		iot_security_be_hardware.c
	)
endif()
