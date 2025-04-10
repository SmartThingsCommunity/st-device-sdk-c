#
# Component Cmake
#
message("Enter component.cmake")

if(CONFIG_STDK_IOT_CORE)
	set(STDK_INCLUDE_PATH "${STDK_INCLUDE_PATH}" include include/bsp include/os include/mqtt)
	set(STDK_INCLUDE_PATH "${STDK_INCLUDE_PATH}" include/external)

	if(CONFIG_STDK_IOT_CORE_BSP_SUPPORT_ESP32 OR
			CONFIG_STDK_IOT_CORE_BSP_SUPPORT_ESP32S2 OR
			CONFIG_STDK_IOT_CORE_BSP_SUPPORT_ESP32C3)
		set(STDK_SRC_PATH "${STDK_SRC_PATH}" port/bsp/esp32)
		set(STDK_INCLUDE_PATH "${STDK_INCLUDE_PATH}" include/bsp/esp32)
        elseif(CONFIG_STDK_IOT_CORE_BSP_SUPPORT_RASPBERRY)
                set(STDK_SRC_PATH "${STDK_SRC_PATH}" port/bsp/raspberry)
                set(STDK_INCLUDE_PATH "${STDK_INCLUDE_PATH}" include/bsp/raspberry)
	else()
		set(STDK_SRC_PATH "${STDK_SRC_PATH}" port/bsp/posix)
		set(STDK_INCLUDE_PATH "${STDK_INCLUDE_PATH}" include/bsp/posix)
	endif()

	set(STDK_INCLUDE_PATH "${STDK_INCLUDE_PATH}" port/net)
	if(CONFIG_STDK_IOT_CORE_USE_MBEDTLS)
		set(STDK_SRC_PATH "${STDK_SRC_PATH}" port/net/mbedtls)
	endif()

	if(CONFIG_STDK_IOT_CORE_OS_SUPPORT_FREERTOS)
		set(STDK_SRC_PATH "${STDK_SRC_PATH}" port/os/freertos)
	elseif(CONFIG_STDK_IOT_CORE_OS_SUPPORT_POSIX)
		set(STDK_SRC_PATH "${STDK_SRC_PATH}" port/os/posix)
	endif()

	if (CONFIG_STDK_IOT_CORE_SECURITY_BACKEND_HARDWARE_ESE)
		set(STDK_INCLUDE_PATH "${STDK_INCLUDE_PATH}" port/security)
	elseif (CONFIG_STDK_IOT_CORE_SECURITY_BACKEND_SOFTWARE)
		set(STDK_SRC_PATH "${STDK_SRC_PATH}" port/crypto)
	endif()

	set(STDK_SRC_PATH "${STDK_SRC_PATH}" security)
	set(STDK_SRC_PATH "${STDK_SRC_PATH}" easysetup)
	set(STDK_SRC_PATH "${STDK_SRC_PATH}" mqtt)

else()
	message("Fail to find SDK config")
# Disable SmartThing Device SDK support
	set(STDK_INCLUDE_PATH "")
	set(STDK_SRC_PATH "")
endif()
