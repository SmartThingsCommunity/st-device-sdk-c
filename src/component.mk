#
# Component Makefile
#

ifdef CONFIG_STDK_IOT_CORE

COMPONENT_ADD_INCLUDEDIRS += include include/bsp include/os include/mqtt include/mqtt/freertos

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
else
	COMPONENT_SRCDIRS += port/bsp/posix
	COMPONENT_ADD_INCLUDEDIRS += include/bsp/posix
endif

# Todo : define os config
ifeq ($(CONFIG_STDK_IOT_CORE_OS_SUPPORT_FREERTOS),y)
	COMPONENT_SRCDIRS += port/os/freertos
else
	COMPONENT_SRCDIRS += port/os/posix
endif

ifeq ($(CONFIG_STDK_IOT_CORE_NET_OPENSSL),y)
	COMPONENT_SRCDIRS += port/net/openssl
	COMPONENT_ADD_INCLUDEDIRS += port/net/openssl
else ifeq ($(CONFIG_STDK_IOT_CORE_NET_MBEDTLS),y)
	COMPONENT_SRCDIRS += port/net/mbedtls
	COMPONENT_ADD_INCLUDEDIRS += port/net/mbedtls
endif

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
COMPONENT_SRCDIRS += easysetup/http \
			easysetup/http/lwip_httpd
endif
ifdef CONFIG_STDK_IOT_CORE_EASYSETUP_POSIX_TESTING
COMPONENT_SRCDIRS += easysetup/posix_testing
endif

CPPFLAGS += -include $(COMPONENT_PATH)/include/iot_common.h

COMPONENT_SRCDIRS += mqtt/client mqtt/packet mqtt/client/freertos

BILERPLATE_HEADER=$(COMPONENT_PATH)/include/certs/boilerplate.h
ROOT_CA_FILE=$(COMPONENT_PATH)/certs/root_ca.pem
ROOT_CA_SOURCE=$(COMPONENT_PATH)/iot_root_ca.c
ROOT_CA_BACKUP_FILE=$(ROOT_CA_SOURCE).bak
result := $(shell cat $(BILERPLATE_HEADER) > $(ROOT_CA_SOURCE); echo $$?;)
ifneq ($(result),0)
	$(error)
endif
result := $(shell xxd -i $(ROOT_CA_FILE) >> $(ROOT_CA_SOURCE); echo $$?;)
ifneq ($(result),0)
	$(error)
endif
$(shell sed -i.bak 's/_.*pem/st_root_ca/g' $(ROOT_CA_SOURCE))
$(shell sed -i.bak 's/unsigned/const unsigned/g' $(ROOT_CA_SOURCE))
$(shell rm $(ROOT_CA_BACKUP_FILE))

CFLAGS += -std=c99

else
# Disable SmartThing Device Kit support
COMPONENT_ADD_INCLUDEDIRS :=
COMPONENT_SRCDIRS :=
endif
