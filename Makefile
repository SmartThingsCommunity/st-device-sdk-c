TOPDIR	:= $(CURDIR)

include stdkconfig
include $(TOPDIR)/make/common.mk

STDK_CFLAGS := $(foreach STDK_CONFIG, $(STDK_CONFIGS), -DCONFIG_$(STDK_CONFIG))

BSP_DIR = src/port/bsp/posix
OS_DIR = src/port/os/posix
ifneq ($(findstring STDK_IOT_CORE_NET_MBEDTLS, $(STDK_CONFIGS)),)
NET_DIR = src/port/net/mbedtls
else
NET_DIR = src/port/net/openssl
endif
CRYPTO_DIR = src/port/crypto/reference

SECURITY_DIR = src/security
EASYSETUP_DIR = src/easysetup
MQTT_DIR = src/mqtt
BUILD_DIR = $(TOPDIR)/build
OUTPUT_DIR = $(TOPDIR)/output
CBOR_DIR = src/deps/cbor/tinycbor/src


CFLAGS	:= -std=c99 -D_GNU_SOURCE
CFLAGS	+= $(STDK_CFLAGS)


INCS	:= -I/usr/include -Isrc/include -Isrc/include/mqtt -Isrc/include/os -Isrc/include/bsp -Isrc/include/external -I$(NET_DIR) -Isrc/include/port
INCS	+= -Isrc/include/security
INCS	+= -I$(CBOR_DIR)

SRCS	:= $(wildcard src/*.c)
SRCS	+= $(wildcard $(CBOR_DIR)/*.c)
SRCS	+= $(wildcard $(BSP_DIR)/*.c)
SRCS	+= $(wildcard $(OS_DIR)/*.c)
SRCS	+= $(wildcard $(NET_DIR)/*.c)
SRCS	+= $(wildcard $(CRYPTO_DIR)/*.c)
SRCS	+= $(EASYSETUP_DIR)/iot_easysetup_st_mqtt.c
ifneq ($(findstring STDK_IOT_CORE_EASYSETUP_DISCOVERY_SSID, $(STDK_CONFIGS)),)
SRCS	+= $(wildcard $(EASYSETUP_DIR)/discovery/ssid/iot_easysetup_discovery_ssid.c)
endif
ifneq ($(findstring STDK_IOT_CORE_EASYSETUP_HTTP, $(STDK_CONFIGS)),)
SRCS	+= $(wildcard $(EASYSETUP_DIR)/http/*.c)
endif
ifneq ($(findstring STDK_IOT_CORE_EASYSETUP_X509, $(STDK_CONFIGS)),)
SRCS	+= $(wildcard $(EASYSETUP_DIR)/http/tls/*.c)
else
SRCS	+= $(wildcard $(EASYSETUP_DIR)/http/tcp/*.c)
endif
SRCS	+= $(wildcard $(MQTT_DIR)/client/*.c)
SRCS	+= $(wildcard $(MQTT_DIR)/packet/*.c)
SRCS	+= $(wildcard $(SECURITY_DIR)/*.c)
ifneq ($(findstring STDK_IOT_CORE_SECURITY_BACKEND_SOFTWARE, $(STDK_CONFIGS)),)
SRCS	+= $(wildcard $(SECURITY_DIR)/backend/software/*.c)
endif

SVACE_SRCS	:= $(wildcard src/*.c)
SVACE_SRCS += $(wildcard $(NET_DIR)/*.c)
SVACE_SRCS += $(wildcard $(CRYPTO_DIR)/*.c)
SVACE_SRCS	+= $(EASYSETUP_DIR)/iot_easysetup_st_mqtt.c
ifneq ($(findstring STDK_IOT_CORE_EASYSETUP_DISCOVERY_SSID, $(STDK_CONFIGS)),)
SVACE_SRCS	+= $(wildcard $(EASYSETUP_DIR)/discovery/ssid/iot_easysetup_discovery_ssid.c)
endif
ifneq ($(findstring STDK_IOT_CORE_EASYSETUP_HTTP, $(STDK_CONFIGS)),)
SVACE_SRCS	+= $(wildcard $(EASYSETUP_DIR)/http/*.c)
endif
ifneq ($(findstring STDK_IOT_CORE_EASYSETUP_X509, $(STDK_CONFIGS)),)
SVACE_SRCS	+= $(wildcard $(EASYSETUP_DIR)/http/tls/*.c)
else
SVACE_SRCS	+= $(wildcard $(EASYSETUP_DIR)/http/tcp/*.c)
endif
SVACE_SRCS	+= $(wildcard $(MQTT_DIR)/client/*.c)
SVACE_SRCS	+= $(wildcard $(MQTT_DIR)/packet/*.c)
SVACE_SRCS	+= $(wildcard $(SECURITY_DIR)/*.c)
ifneq ($(findstring STDK_IOT_CORE_SECURITY_BACKEND_SOFTWARE, $(STDK_CONFIGS)),)
SVACE_SRCS	+= $(wildcard $(SECURITY_DIR)/backend/software/*.c)
endif

OBJS	= $(SRCS:%.c=%.o)
SVACE_OBJS	= $(SVACE_SRCS:%.c=%.o)
TARGET	= libiotcore.a

export TOPDIR
export CFLAGS
export LOCAL_CFLAGS
export BUILD_DIR
export PREFIX

JSON_DIR = src/deps/json
LIBSODIUM_DIR = src/deps/libsodium
MBEDTLS_DIR = src/deps/mbedtls

DEPS_DIRS = $(JSON_DIR) $(LIBSODIUM_DIR) $(MBEDTLS_DIR)

result	:= $(shell git submodule update --init $(JSON_DIR))
result	:= $(shell git submodule update --init $(LIBSODIUM_DIR))
result	:= $(shell git submodule update --init $(MBEDTLS_DIR))

INCS	+= -I$(JSON_DIR)/cJSON
INCS	+= -I$(MBEDTLS_DIR)/mbedtls/include
INCS	+= -I$(LIBSODIUM_DIR)/libsodium/src/libsodium/include -I$(LIBSODIUM_DIR)/libsodium/src/libsodium/include/sodium -I$(LIBSODIUM_DIR)/port/include

LOCAL_CFLAGS := $(INCS)
PREFIX := stdk_


.PHONY: all clean
all: prepare subdir $(TARGET)

prepare:
	@mkdir -p $(BUILD_DIR)
	@mkdir -p $(OUTPUT_DIR)

subdir:
	@for dir in $(DEPS_DIRS); do \
		$(MAKE) -C $$dir; \
		if [ $$? != 0 ]; then \
			exit 1; \
		fi; \
	done

clean:
	@for dir in $(DEPS_DIRS); do \
		$(MAKE) -C $$dir clean; \
	done
	@rm -rf $(BUILD_DIR)
	@rm -rf $(OUTPUT_DIR)

$(TARGET): $(OBJS)
	@echo "  AR    $(BUILD_DIR)/$@"
	@$(AR) -rcs $(BUILD_DIR)/$@ $(BUILD_DIR)/*.o
	@$(MV) -f $(BUILD_DIR)/$(TARGET) $(OUTPUT_DIR)
	@echo "================================"
	@echo "=             DONE             ="
	@echo "================================"

svace : $(SVACE_OBJS)
	@echo "================================"
	@echo "=             DONE             ="
	@echo "================================"
