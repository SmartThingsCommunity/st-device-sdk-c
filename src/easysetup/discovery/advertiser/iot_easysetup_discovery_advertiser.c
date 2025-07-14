/* ***************************************************************************
 *
 * Copyright (c) 2021 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/
#include <string.h>
#include <iot_nv_data.h>
#include <iot_easysetup.h>
#include <iot_debug.h>
#include <iot_error.h>
#include <security/iot_security_util.h>
#include <iot_error.h>
#include <iot_bsp_ble.h>

typedef struct
{
	uint16_t mn_code;
	size_t mn_data_len;
	uint8_t *mn_data; /* BLE AD Type : 0xFF */
	char *local_name; /* BLE AD Type : 0x09, Null-terminated char */
} adv_data;

static void generate_hybrid_serial(struct iot_context *ctx, uint8_t *hybrid_serial_out)
{
	char *serial = NULL;
	size_t length;
	size_t base64_written = 0;
	iot_error_t err = IOT_ERROR_NONE;
	unsigned char hash_buffer[IOT_SECURITY_SHA256_LEN] = { 0, };
	unsigned char base64url_buffer[IOT_SECURITY_B64_ENCODE_LEN(IOT_SECURITY_SHA256_LEN)] = { 0, };
	char hybrid_serial[HYBRID_SERIAL_NUMBER_SIZE + 1] = { 0, };

	err = iot_nv_get_serial_number(&serial, &length);
	if (err != IOT_ERROR_NONE) {
		IOT_ERROR("Failed to get serial number (%d)", err);
		goto out;
	}

	err = iot_security_sha256((unsigned char*)serial, length, hash_buffer, sizeof(hash_buffer));
	if (err != IOT_ERROR_NONE) {
		IOT_ERROR("Failed sha256 (%d)", err);
		goto out;
	}
	err = iot_security_base64_encode_urlsafe(hash_buffer, sizeof(hash_buffer),
									base64url_buffer, sizeof(base64url_buffer), &base64_written);
	if (err != IOT_ERROR_NONE) {
		err = IOT_ERROR_SECURITY_BASE64_URL_ENCODE;
		goto out;
	}

	if (ctx->devconf.hashed_sn) {
		iot_os_free(ctx->devconf.hashed_sn);
		ctx->devconf.hashed_sn = NULL;
	}

	ctx->devconf.hashed_sn = iot_os_malloc(base64_written + 1);
	if (!ctx->devconf.hashed_sn) {
		err = IOT_ERROR_MEM_ALLOC;
		goto out;
	}
	memset(ctx->devconf.hashed_sn, '\0', base64_written + 1);
	memcpy(ctx->devconf.hashed_sn, base64url_buffer, base64_written);

	memcpy(hybrid_serial, ctx->devconf.hashed_sn, HASH_SERIAL_NUMBER_HYBRID_PORTION);
	memcpy(hybrid_serial + HASH_SERIAL_NUMBER_HYBRID_PORTION, serial + length - PLAIN_SERIAL_NUMBER_HYBRID_PORTION,
		PLAIN_SERIAL_NUMBER_HYBRID_PORTION);
	memcpy(hybrid_serial_out, hybrid_serial, HYBRID_SERIAL_NUMBER_SIZE);

out:
	if (err && ctx->devconf.hashed_sn) {
		iot_os_free(ctx->devconf.hashed_sn);
		ctx->devconf.hashed_sn = NULL;
	}
	if (serial) {
		iot_os_free(serial);
	}
}

#define BLE_MANUFACTURER_CODE_SAMSUNG (0x0075)
#define ONBOARDING_MN_DATA_CONTROL_VERSION (0x42) // Active Scan Required
#define ONBOARDING_MN_DATA_SERVICE_ID (0x0C)  // Samsung Connect
#define ONBOARDING_MN_DATA_PACKET_VERSION (0x83)
#define ONBOARDING_MN_DATA_OCF_INFO_ONBOARDING_SUPPORTED (1 << 0)
#define ONBOARDING_MN_DATA_OCF_INFO_OWNED_STATE (1 << 1)
#define ONBOARDING_MN_DATA_OCF_INFO_ONBOARDING_READY (1 << 2)
#define ONBOARDING_MN_DATA_FEATURE (0x59) // Custom Data, Address, Setup Availalbe Network, Setup Info
#define ONBOARDING_MN_DATA_SETUP_AVAILABLE_NETWORK (0x04) // BLE
#define ONBOARDING_MN_DATA_ADDRESS_TRANSFER (0x01)  // BT Address
#define ONBOARDING_MN_DATA_CUSTOM_DATA_LEN (0x0A)
#define ONBOARDING_MN_DATA_CUSTOM_TYPE (0x03)  // Hybrid serial number
#define ONBOARDING_MN_DATA_CUSTOM_TYPE_LEN (0x08)

/*
 * Manufacturer Data Format : Control&Version(1Byte) + ServiceID(1Byte) + PacketVersion(1Byte) +
 * OCFInfo(1Byte) + Feature(1Byte) + mnId(4Bytes) + setupId(3Bytes) + SetupAvailableNetwork(1Byte) +
 * AddressTransfer(1Byte) + MacAddress(6Bytes) + TLV(10Bytes)
 * */
static int generate_manufacturer_data(struct iot_context *ctx, uint8_t **mn_data, size_t *mn_data_len)
{
    uint8_t mac_address[6] = {0,};
    uint8_t hybrid_serial[8] = {0,};
    uint8_t *data = NULL;
    uint8_t offset = 0;

    data = (uint8_t *)iot_os_malloc(31);
    if (data == NULL)
    {
        return 0;
    }

    data[offset++] = ONBOARDING_MN_DATA_CONTROL_VERSION;
    data[offset++] = ONBOARDING_MN_DATA_SERVICE_ID;
    data[offset++] = ONBOARDING_MN_DATA_PACKET_VERSION;
    if (ctx->wifi_update_enabled) {
        data[offset++] = ONBOARDING_MN_DATA_OCF_INFO_ONBOARDING_SUPPORTED | ONBOARDING_MN_DATA_OCF_INFO_OWNED_STATE;
    } else {
        data[offset++] = ONBOARDING_MN_DATA_OCF_INFO_ONBOARDING_SUPPORTED | ONBOARDING_MN_DATA_OCF_INFO_ONBOARDING_READY;
    }
    data[offset++] = ONBOARDING_MN_DATA_FEATURE;
    memcpy(data + offset, ctx->devconf.mnid, strlen(ctx->devconf.mnid));
    offset += strlen(ctx->devconf.mnid);
    memcpy(data + offset, ctx->devconf.setupid, strlen(ctx->devconf.setupid));
    offset += strlen(ctx->devconf.setupid);

    data[offset++] = ONBOARDING_MN_DATA_SETUP_AVAILABLE_NETWORK;
    data[offset++] = ONBOARDING_MN_DATA_ADDRESS_TRANSFER;
    iot_bsp_ble_get_mac_address(mac_address);
    memcpy(data + offset, mac_address, sizeof(mac_address));
    offset += sizeof(mac_address);

    data[offset++] = ONBOARDING_MN_DATA_CUSTOM_DATA_LEN;
    data[offset++] = ONBOARDING_MN_DATA_CUSTOM_TYPE;
    data[offset++] = ONBOARDING_MN_DATA_CUSTOM_TYPE_LEN;
    generate_hybrid_serial(ctx, hybrid_serial);
    memcpy(data + offset, hybrid_serial, 8);
    offset += 8;

    *mn_data_len = offset;
    *mn_data = data;
    return 1;
}

static void print_adv_data(adv_data *data)
{
    IOT_INFO("MN code : 0x%04X", data->mn_code);
    IOT_INFO("Local name : %s", data->local_name);
    IOT_INFO("MN data : [ Control: 0x%02X, ServiceId : 0x%02X, PacketVersion : 0x%02X, "
		    "OCFInfo : 0x%02X, Feature : 0x%02X, mnId : %c%c%c%c, "
		    "setupId : %c%c%c, SetupNetwork : 0x%02X, AddressTrans : 0x%02X, "
		    "MacAddr : %02X:%02X:%02X:%02X:%02X:%02X, "
		    "TLVDataLen : %d, TLVType : 0x%02X, TLVTypeLen : %d, "
		    "HybridSerial : %c%c%c%c%c%c%c%c ]",
		    data->mn_data[0], data->mn_data[1], data->mn_data[2],
		    data->mn_data[3], data->mn_data[4], data->mn_data[5], data->mn_data[6], data->mn_data[7], data->mn_data[8],
		    data->mn_data[9], data->mn_data[10], data->mn_data[11], data->mn_data[12], data->mn_data[13],
		    data->mn_data[14], data->mn_data[15], data->mn_data[16], data->mn_data[17], data->mn_data[18], data->mn_data[19],
		    data->mn_data[20], data->mn_data[21], data->mn_data[22],
		    data->mn_data[23], data->mn_data[24], data->mn_data[25], data->mn_data[26],
		    data->mn_data[27], data->mn_data[28], data->mn_data[29], data->mn_data[30]);
}

static int generate_advertise_data(struct iot_context *ctx, adv_data *data)
{
    data->mn_code = BLE_MANUFACTURER_CODE_SAMSUNG;
    data->local_name = (char *)ctx->devconf.device_onboarding_id;
    generate_manufacturer_data(ctx, &data->mn_data, &data->mn_data_len);
    print_adv_data(data);
    return 0;
}

iot_error_t iot_easysetup_start_ble_advertisement(struct iot_context *ctx)
{
    adv_data data = {0};

    IOT_INFO("Start ble adv");
    generate_advertise_data(ctx, &data);
    iot_bsp_ble_start_adv(data.mn_code, data.mn_data, data.mn_data_len, data.local_name);
    return 0;
}
