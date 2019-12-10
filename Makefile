TOPDIR	:= $(CURDIR)

include stdkconfig
include $(TOPDIR)/make/common.mk

BSP_DIR = src/port/bsp/posix
OS_DIR = src/port/os/posix
ifneq ($(findstring CONFIG_STDK_IOT_CORE_NET_MBEDTLS, $(CFLAGS_CONFIG)),)
NET_DIR = src/port/net/mbedtls
else
NET_DIR = src/port/net/openssl
endif
CRYPTO_DIR = src/crypto
EASYSETUP_DIR = src/easysetup
MQTT_DIR = src/mqtt
BUILD_DIR = $(TOPDIR)/build
OUTPUT_DIR = $(TOPDIR)/output

CFLAGS	:= -std=c99 -D_GNU_SOURCE
CFLAGS	+= $(CFLAGS_CONFIG)

INCS	:= -I/usr/include -Isrc/include -Isrc/include/mqtt -Isrc/include/os -Isrc/include/bsp -I$(NET_DIR)

SRCS	:= $(wildcard src/*.c)
SRCS	+= $(wildcard $(BSP_DIR)/*.c)
SRCS	+= $(wildcard $(OS_DIR)/*.c)
SRCS	+= $(wildcard $(NET_DIR)/*.c)
SRCS	+= $(wildcard $(CRYPTO_DIR)/*.c)
SRCS	+= $(EASYSETUP_DIR)/iot_easysetup_st_mqtt.c \
			$(EASYSETUP_DIR)/iot_easysetup_crypto.c \
			$(wildcard $(EASYSETUP_DIR)/posix_testing/*.c)
SRCS	+= $(wildcard $(MQTT_DIR)/client/*.c)
SRCS	+= $(wildcard $(MQTT_DIR)/packet/*.c)

OBJS	= $(SRCS:%.c=%.o)
TARGET	= libiotcore.a

export TOPDIR
export CFLAGS
export LOCAL_CFLAGS
export BUILD_DIR
export PREFIX

JSON_DIR = src/deps/json
CURL_DIR = src/deps/curl
LIBSODIUM_DIR = src/deps/libsodium
MBEDTLS_DIR = src/deps/mbedtls

DEPS_DIRS = $(JSON_DIR) $(CURL_DIR) $(LIBSODIUM_DIR) $(MBEDTLS_DIR)

result	:= $(shell git submodule update --init $(JSON_DIR))
result	:= $(shell git submodule update --init $(CURL_DIR))
result	:= $(shell git submodule update --init $(LIBSODIUM_DIR))
result	:= $(shell git submodule update --init $(MBEDTLS_DIR))

INCS	+= -I$(JSON_DIR)/cJSON
INCS	+= -I$(CURL_DIR)/curl/include
INCS	+= -I$(MBEDTLS_DIR)/mbedtls/include
INCS	+= -I$(LIBSODIUM_DIR)/libsodium/src/libsodium/include -I$(LIBSODIUM_DIR)/libsodium/src/libsodium/include/sodium -I$(LIBSODIUM_DIR)/port/include

ifneq ($(findstring, "CONFIG_STDK_IOT_CORE_USE_MBEDTLS", $(CFLAGS_CONFIG)), '')
	SRCS += $(wildcard $(CRYPTO_DIR)/mbedtls/*.c)
endif

LOCAL_CFLAGS := $(INCS)
PREFIX := stdk_

BILERPLATE_HEADER = src/include/certs/boilerplate.h
ROOT_CA_FILE = src/certs/root_ca.pem
ROOT_CA_SOURCE = src/iot_root_ca.c
SRCS	+= $(ROOT_CA_SOURCE)

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

$(ROOT_CA_SOURCE):
	@cat $(BILERPLATE_HEADER) > $(ROOT_CA_SOURCE)
	@if [ $$? != 0 ]; then \
		exit 1; \
	fi
	@xxd -i $(ROOT_CA_FILE) >> $(ROOT_CA_SOURCE)
	@if [ $$? != 0 ]; then \
		exit 1; \
	fi
	@sed -i.bak 's/src.*pem/st_root_ca/g' $(ROOT_CA_SOURCE)
	@sed -i.bak 's/unsigned/const unsigned/g' $(ROOT_CA_SOURCE)
	@rm -f $(ROOT_CA_SOURCE).bak

clean:
	@for dir in $(DEPS_DIRS); do \
		$(MAKE) -C $$dir clean; \
	done
	@rm -f $(ROOT_CA_SOURCE)
	@rm -rf $(BUILD_DIR)
	@rm -rf $(OUTPUT_DIR)

$(TARGET): $(OBJS) $(ROOT_CA_SOURCE)
	@echo "  AR    $(BUILD_DIR)/$@"
	@$(AR) -rcs $(BUILD_DIR)/$@ $(BUILD_DIR)/*.o
	@$(MV) -f $(BUILD_DIR)/$(TARGET) $(OUTPUT_DIR)
	@echo "================================"
	@echo "=             DONE             ="
	@echo "================================"
