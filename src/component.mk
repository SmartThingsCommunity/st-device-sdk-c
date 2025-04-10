#
# Component Makefile
#

ifdef CONFIG_STDK_IOT_CORE

COMPONENT_ADD_INCLUDEDIRS += include include/bsp include/os include/mqtt include/external include/port

COMPONENT_SRCDIRS += ./

ifeq ($(CONFIG_STDK_IOT_CORE_BSP_SUPPORT_ESP8266),y)
	COMPONENT_SRCDIRS += port/bsp/esp8266
	COMPONENT_ADD_INCLUDEDIRS += include/bsp/esp8266
	ifdef CONFIG_STDK_IOT_CORE_FS_SW_ENCRYPTION
	COMPONENT_ADD_LDFLAGS += -L $(COMPONENT_PATH)/port/bsp/esp8266 -liot_security_ss
	endif
else ifeq ($(CONFIG_STDK_IOT_CORE_BSP_SUPPORT_ESP32),y)
	COMPONENT_SRCDIRS += port/bsp/esp32
	COMPONENT_ADD_INCLUDEDIRS += include/bsp/esp32
else ifeq ($(CONFIG_STDK_IOT_CORE_BSP_SUPPORT_ESP32S2),y)
	COMPONENT_SRCDIRS += port/bsp/esp32s2
	COMPONENT_ADD_INCLUDEDIRS += include/bsp/esp32s2
else ifeq ($(CONFIG_STDK_IOT_CORE_BSP_SUPPORT_ESP32C3),y)
	COMPONENT_SRCDIRS += port/bsp/esp32c3
	COMPONENT_ADD_INCLUDEDIRS += include/bsp/esp32c3
else ifeq ($(CONFIG_STDK_IOT_CORE_BSP_SUPPORT_RTL8195),y)
	COMPONENT_SRCDIRS += port/bsp/rtl8195
	COMPONENT_ADD_INCLUDEDIRS += include/bsp/rtl8195
else ifeq ($(CONFIG_STDK_IOT_CORE_BSP_SUPPORT_RTL8720C),y)
        COMPONENT_SRCDIRS += port/bsp/rtl8720c
        COMPONENT_ADD_INCLUDEDIRS += include/bsp/rtl8720c
else ifeq ($(CONFIG_STDK_IOT_CORE_BSP_SUPPORT_RTL8721C),y)
	COMPONENT_SRCDIRS += port/bsp/rtl8721c
	COMPONENT_ADD_INCLUDEDIRS += include/bsp/rtl8721c
else ifeq ($(CONFIG_STDK_IOT_CORE_BSP_SUPPORT_EMW3166),y)
	COMPONENT_SRCDIRS += port/bsp/emw3166
	COMPONENT_ADD_INCLUDEDIRS += include/bsp/emw3166
else ifeq ($(CONFIG_STDK_IOT_CORE_BSP_SUPPORT_EMW3080),y)
	COMPONENT_SRCDIRS += port/bsp/emw3080
	COMPONENT_ADD_INCLUDEDIRS += include/bsp/emw3080
else ifeq ($(CONFIG_STDK_IOT_CORE_BSP_SUPPORT_BL602),y)
	include $(BL60X_SDK_PATH)/components/network/ble/ble_common.mk
	CPPFLAGS += -DSTDK_IOT_CORE_BSP_SUPPORT_BL602
	CPPFLAGS += -DMBEDTLS_ECDH_LEGACY_CONTEXT
	CPPFLAGS += -U__STDC_HOSTED__
	COMPONENT_SRCDIRS += port/bsp/bl602

	COMPONENT_ADD_INCLUDEDIRS += include/bsp/bl602
	COMPONENT_SRCDIRS += deps/json/cJSON
	COMPONENT_SRCDIRS += \
	deps/libsodium/libsodium/src/libsodium/sodium \
	deps/libsodium/libsodium/src/libsodium/crypto_sign \
	deps/libsodium/libsodium/src/libsodium/crypto_sign/ed25519 \
	deps/libsodium/libsodium/src/libsodium/crypto_sign/ed25519/ref10 \
	deps/libsodium/libsodium/src/libsodium/crypto_hash/sha512/cp \
	deps/libsodium/libsodium/src/libsodium/crypto_core/ed25519/ref10

	COMPONENT_ADD_INCLUDEDIRS += deps/json/cJSON
	COMPONENT_ADD_INCLUDEDIRS += deps/libsodium/libsodium/src/libsodium/include
	COMPONENT_ADD_INCLUDEDIRS += deps/libsodium/port/include/sodium

	CFLAGS += -I$(IOT_CORE_PATH)/src/deps/libsodium/port/include
	CFLAGS += -I$(IOT_CORE_PATH)/src/deps/libsodium/libsodium/src/libsodium/include/sodium
else ifeq ($(CONFIG_STDK_IOT_CORE_BSP_SUPPORT_TIZENRT),y)
	COMPONENT_SRCDIRS += port/bsp/tizenrt
	COMPONENT_ADD_INCLUDEDIRS += include/bsp/tizenrt
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
else ifeq ($(CONFIG_STDK_IOT_CORE_OS_SUPPORT_MOCOS),y)
	COMPONENT_SRCDIRS += port/os/mocos
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

COMPONENT_SRCDIRS += security
COMPONENT_SRCDIRS += port/crypto/reference
ifeq ($(CONFIG_STDK_IOT_CORE_SECURITY_BACKEND_SOFTWARE),y)
	COMPONENT_SRCDIRS += security/backend/software
else ifeq ($(CONFIG_STDK_IOT_CORE_SECURITY_BACKEND_HARDWARE),y)
	COMPONENT_SRCDIRS += security/backend/hardware
endif

COMPONENT_SRCDIRS += easysetup

ifdef CONFIG_STDK_IOT_CORE_EASYSETUP_BLE
COMPONENT_SRCDIRS += easysetup/ble
COMPONENT_SRCDIRS += easysetup/discovery/advertiser
endif

ifdef CONFIG_STDK_IOT_CORE_EASYSETUP_DISCOVERY_SSID
COMPONENT_SRCDIRS += easysetup/discovery/ssid
endif

ifdef CONFIG_STDK_IOT_CORE_EASYSETUP_HTTP
COMPONENT_SRCDIRS += easysetup/http
endif

ifdef CONFIG_STDK_IOT_CORE_EASYSETUP_X509
	COMPONENT_SRCDIRS += easysetup/http/tls
else
	COMPONENT_SRCDIRS += easysetup/http/tcp
endif

CPPFLAGS += -include $(COMPONENT_PATH)/include/iot_common.h

COMPONENT_SRCDIRS += mqtt/client mqtt/packet

CFLAGS += -std=c99

else
# Disable SmartThing Device SDK support
COMPONENT_ADD_INCLUDEDIRS :=
COMPONENT_SRCDIRS :=
endif
