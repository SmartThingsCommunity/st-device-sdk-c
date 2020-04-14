#
# Component Makefile
#

ifdef CONFIG_STDK_IOT_CORE

COMPONENT_ADD_INCLUDEDIRS += include include/bsp include/os include/mqtt include/external

COMPONENT_SRCDIRS += ./

ifeq ($(CONFIG_STDK_IOT_CORE_BSP_SUPPORT_ESP8266),y)
	COMPONENT_SRCDIRS += port/bsp/esp8266
	COMPONENT_ADD_INCLUDEDIRS += include/bsp/esp8266
else ifeq ($(CONFIG_STDK_IOT_CORE_BSP_SUPPORT_ESP32),y)
	COMPONENT_SRCDIRS += port/bsp/esp32
	COMPONENT_ADD_INCLUDEDIRS += include/bsp/esp32
else ifeq ($(CONFIG_STDK_IOT_CORE_BSP_SUPPORT_RTL8195),y)
	COMPONENT_SRCDIRS += port/bsp/rtl8195
	COMPONENT_ADD_INCLUDEDIRS += include/bsp/rtl8195
else ifeq ($(CONFIG_STDK_IOT_CORE_BSP_SUPPORT_RTL8720C),y)
        COMPONENT_SRCDIRS += port/bsp/rtl8720c
        COMPONENT_ADD_INCLUDEDIRS += include/bsp/rtl8720c
else ifeq ($(CONFIG_STDK_IOT_CORE_BSP_SUPPORT_RTL8721C),y)
	COMPONENT_SRCDIRS += port/bsp/rtl8721c
	COMPONENT_ADD_INCLUDEDIRS += include/bsp/rtl8721c
else
	COMPONENT_SRCDIRS += port/bsp/posix
	COMPONENT_ADD_INCLUDEDIRS += include/bsp/posix
endif

ifeq ($(CONFIG_STDK_IOT_CORE_OS_SUPPORT_FREERTOS),y)
	COMPONENT_SRCDIRS += port/os/freertos
else ifeq ($(CONFIG_STDK_IOT_CORE_OS_SUPPORT_TIZENRT),y)
	COMPONENT_SRCDIRS += port/os/tizenrt
else ifeq ($(CONFIG_STDK_IOT_CORE_OS_SUPPORT_POSIX),y)
	COMPONENT_SRCDIRS += port/os/posix
endif

ifeq ($(CONFIG_STDK_IOT_CORE_NET_MBEDTLS),y)
	COMPONENT_SRCDIRS += port/net/mbedtls
	COMPONENT_ADD_INCLUDEDIRS += port/net/mbedtls
else
	COMPONENT_SRCDIRS += port/net/openssl
	COMPONENT_ADD_INCLUDEDIRS += port/net/openssl
endif

COMPONENT_SRCDIRS += deps/cbor/tinycbor/src
COMPONENT_ADD_INCLUDEDIRS += deps/cbor/tinycbor/src

COMPONENT_SRCDIRS += crypto
ifdef CONFIG_STDK_IOT_CORE_USE_MBEDTLS
COMPONENT_SRCDIRS += crypto/mbedtls
endif
ifdef CONFIG_STDK_IOT_CORE_FS_SW_ENCRYPTION
COMPONENT_ADD_LDFLAGS += $(COMPONENT_PATH)/crypto/ss/lib/libiot_crypto_ss.a
COMPONENT_ADD_LINKER_DEPS := $(COMPONENT_PATH)/crypto/ss/lib/libiot_crypto_ss.a
else
COMPONENT_SRCDIRS += crypto/ss
endif

COMPONENT_SRCDIRS += easysetup

ifdef CONFIG_STDK_IOT_CORE_EASYSETUP_HTTP
COMPONENT_SRCDIRS += easysetup/http
endif
ifdef CONFIG_STDK_IOT_CORE_EASYSETUP_POSIX_TESTING
COMPONENT_SRCDIRS += easysetup/posix_testing
endif

CPPFLAGS += -include $(COMPONENT_PATH)/include/iot_common.h

COMPONENT_SRCDIRS += mqtt/client mqtt/packet

CFLAGS += -std=c99

else
# Disable SmartThing Device SDK support
COMPONENT_ADD_INCLUDEDIRS :=
COMPONENT_SRCDIRS :=
endif
