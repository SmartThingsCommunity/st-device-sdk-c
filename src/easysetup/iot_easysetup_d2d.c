/* ***************************************************************************
 *
 * Copyright 2019 Samsung Electronics All Rights Reserved.
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
#include "cJSON.h"
#include "iot_main.h"
#include "iot_bsp_random.h"
#include "iot_easysetup.h"
#include "iot_internal.h"
#include "iot_nv_data.h"
#include "iot_util.h"
#include "iot_uuid.h"
#include "iot_debug.h"

#define HASH_SIZE (4)
#define PIN_SIZE	8
#define MAC_ADDR_BUFFER_SIZE	20
#define URL_BUFFER_SIZE		64
#define WIFIINFO_BUFFER_SIZE	20
#define ES_CONFIRM_MAX_DELAY	10000

#define JSON_H	cJSON

static char *_es_json_parse_string(JSON_H *json, const char *name)
{
	char *buf = NULL;
	cJSON *recv = NULL;
	unsigned int buf_len;

	if (!json || !name) {
		IOT_ERROR("invalid args");
		return NULL;
	}

	if ((recv = cJSON_GetObjectItem(json, name)) == NULL) {
		IOT_ERROR("failed to find '%s'", name);
		return NULL;
	}
	buf_len = (strlen(recv->valuestring) + 1);

	IOT_DEBUG("'%s' (%d): %s",
			name, buf_len, recv->valuestring);

	if ((buf = (char *)malloc(buf_len)) == NULL) {
		IOT_ERROR("failed to malloc for buf");
		return NULL;
	}
	memset(buf, 0, buf_len);
	memcpy(buf, recv->valuestring, strlen(recv->valuestring));

	return buf;
}

static iot_error_t _es_crypto_cipher_gen_iv(iot_crypto_cipher_info_t *iv_info)
{
	int i;
	iot_error_t err = IOT_ERROR_NONE;
	size_t iv_len;
	unsigned char *iv;

	iv_len = IOT_CRYPTO_IV_LEN;
	if ((iv = (unsigned char *)malloc(iv_len)) == NULL) {
		IOT_ERROR("failed to malloc for iv");
		err = IOT_ERROR_MEM_ALLOC;
		goto out;
	}

	for (i = 0; i < iv_len; i++) {
		iv[i] = (unsigned char)iot_bsp_random() & 0xff;
	}
	iv_info->iv = iv;
	iv_info->iv_len = iv_len;
	IOT_DEBUG("iv_info->iv_len[%d], iv_len[%d]",iv_info->iv_len, iv_len);
out:
	return err;
}

static iot_error_t _es_crypto_cipher_aes(iot_crypto_cipher_info_t *iv_info, iot_crypto_cipher_mode_t mode,
			unsigned char *input, unsigned char *output, size_t input_len, size_t output_len, size_t *dst_len)
{
	iot_error_t err;
	size_t olen;

	iv_info->mode = mode;
	err = iot_crypto_cipher_aes(iv_info, input, input_len, output, &olen, output_len);
	if (err) {
		IOT_ERROR("iot_crypto_cipher_aes = %d", err);
		goto exit;
	}
	*dst_len = olen;
exit:
	return err;
}

iot_error_t iot_easysetup_create_ssid(struct iot_devconf_prov_data *devconf, char *ssid, size_t ssid_len)
{
	char *serial = NULL;
	unsigned char hash_buffer[IOT_CRYPTO_SHA256_LEN] = { 0, };
	unsigned char base64url_buffer[IOT_CRYPTO_CAL_B64_LEN(IOT_CRYPTO_SHA256_LEN)] = { 0, };
	size_t base64_written = 0;
	char ssid_build[33] = { 0, };
	unsigned char last_sn[HASH_SIZE + 1] = { 0,};
	unsigned char hashed_sn[HASH_SIZE + 1] = { 0,};
	unsigned int length;
	int i;
	iot_error_t err = IOT_ERROR_NONE;

	err = iot_nv_get_serial_number(&serial, &length);
	if (err != IOT_ERROR_NONE) {
		IOT_ERROR("Failed to get serial number : %d\n", err);
		goto out;
	}
	err = iot_crypto_sha256((unsigned char*)serial, length, hash_buffer);
	if (err != IOT_ERROR_NONE) {
		IOT_ERROR("Failed sha256 (str: %s, len: %zu\n", serial, length);
		goto out;
	}
	err = iot_crypto_base64_encode_urlsafe(hash_buffer, sizeof(hash_buffer),
						base64url_buffer, sizeof(base64url_buffer), &base64_written);
	if (err != IOT_ERROR_NONE)
		goto out;

	if (base64_written >= HASH_SIZE) {
		devconf->hashed_sn = calloc(sizeof(char), base64_written + 1);
		if (!devconf->hashed_sn) {
			err = IOT_ERROR_MEM_ALLOC;
			goto out;
		}
		memcpy(devconf->hashed_sn, base64url_buffer, base64_written);
		memcpy(hashed_sn, base64url_buffer, HASH_SIZE);
	} else {
		err = IOT_ERROR_CRYPTO_BASE64_URLSAFE;
		goto out;
	}
	hashed_sn[HASH_SIZE] = '\0';

	for (i = 0; i < HASH_SIZE; i++) {
		if (length < (HASH_SIZE - i))
			last_sn[i] = 0;
		else
			last_sn[i] = serial[length - (HASH_SIZE - i)];
	}
	last_sn[HASH_SIZE] = '\0';
	IOT_INFO(">> %s[%c%c%c%c] <<", devconf->device_onboarding_id,
				last_sn[0], last_sn[1],
				last_sn[2], last_sn[3]);

	snprintf(ssid_build, sizeof(ssid_build), "%s_E4%3s%3s6%4s%4s",
			devconf->device_onboarding_id, devconf->mnid, devconf->setupid, hashed_sn, last_sn);
	memcpy(ssid, ssid_build, ssid_len < strlen(ssid_build) ? ssid_len : strlen(ssid_build));
out:
	if (err && devconf->hashed_sn) {
		free(devconf->hashed_sn);
		devconf->hashed_sn = NULL;
	}
	if (serial)
		free(serial);
	return err;
}

static iot_error_t _es_deviceinfo_handler(struct iot_context *ctx, char **out_payload)
{
	char *output_ptr = NULL;
	cJSON *root = NULL;
	iot_error_t err = IOT_ERROR_NONE;
	size_t base64_written = 0;
	size_t encode_buf_len = 0;
	unsigned char *encode_buf = NULL;

	root = cJSON_CreateObject();
	if (!root) {
		IOT_ERROR("json create failed");
		return IOT_ERROR_MEM_ALLOC;
	}
	cJSON_AddItemToObject(root, "protocolVersion", cJSON_CreateString("0.4.2"));
	cJSON_AddItemToObject(root, "firmwareVersion", cJSON_CreateString(ctx->device_info.firmware_version));
	cJSON_AddItemToObject(root, "hashedSn", cJSON_CreateString((char *)ctx->devconf.hashed_sn));
	cJSON_AddNumberToObject(root, "wifiSupportFrequency", (double) iot_bsp_wifi_get_freq());

	err = _es_crypto_cipher_gen_iv(ctx->es_crypto_cipher_info);
	if (err != IOT_ERROR_NONE) {
		IOT_ERROR("failed to generate cipher iv!!");
		goto out;
	}

	encode_buf_len = IOT_CRYPTO_CAL_B64_LEN(ctx->es_crypto_cipher_info->iv_len);
	if ((encode_buf = (unsigned char *)malloc(encode_buf_len)) == NULL) {
		IOT_ERROR("failed to malloc for encode_buf");
		err = IOT_ERROR_MEM_ALLOC;
		goto out;
	}

	err = iot_crypto_base64_encode_urlsafe(ctx->es_crypto_cipher_info->iv, ctx->es_crypto_cipher_info->iv_len,
						encode_buf, encode_buf_len, &base64_written);
	if (err != IOT_ERROR_NONE) {
		IOT_ERROR("base64 encode error!!");
		goto out;
	}

	cJSON_AddItemToObject(root, "iv", cJSON_CreateString((char *)encode_buf));
	output_ptr = cJSON_PrintUnformatted(root);

	*out_payload = output_ptr;
out:
	if (encode_buf)
		free(encode_buf);
	if (root)
		cJSON_Delete(root);
	return IOT_ERROR_NONE;
}

static iot_error_t _es_wifiscaninfo_handler(struct iot_context *ctx, char **out_payload)
{
	char *ptr = NULL;
	char *output_ptr = NULL;
	char wifi_bssid[WIFIINFO_BUFFER_SIZE] = {0, };
	cJSON *root = NULL;
	cJSON *array = NULL;
	cJSON *array_obj = NULL;
	int i;
	iot_error_t err = IOT_ERROR_NONE;
	size_t input_len = 0;
	size_t output_len = 0;
	size_t result_len = 0;
	unsigned char *encode_buf = NULL;
	unsigned char *encrypt_buf = NULL;
#if 0
	char *total_ptr = NULL;
	size_t item_size = 0;
	size_t total_size = 0;
#endif

	if (!ctx->scan_num)
		return IOT_ERROR_EASYSETUP_WIFI_SCANLIST_NOT_FOUND;

	array = cJSON_CreateArray();
	if (!array) {
		IOT_ERROR("json_array create failed");
		return IOT_ERROR_MEM_ALLOC;
	}

	for(i = 0; i < ctx->scan_num; i++) {
		if ((ctx->scan_result[i].authmode <  IOT_WIFI_AUTH_OPEN) ||
			(ctx->scan_result[i].authmode >= IOT_WIFI_AUTH_WPA2_ENTERPRISE)) {
			IOT_DEBUG("Unsupported authType %d, %s", ctx->scan_result[i].authmode,
								(char *)ctx->scan_result[i].ssid);
			continue;
		}
		snprintf(wifi_bssid, sizeof(wifi_bssid), "%02X:%02X:%02X:%02X:%02X:%02X",
						ctx->scan_result[i].bssid[0], ctx->scan_result[i].bssid[1],
						ctx->scan_result[i].bssid[2], ctx->scan_result[i].bssid[3],
						ctx->scan_result[i].bssid[4], ctx->scan_result[i].bssid[5]);

		array_obj = cJSON_CreateObject();
		if (!array_obj) {
			IOT_ERROR("json create failed");
			err = IOT_ERROR_MEM_ALLOC;
			goto out;
		}
		cJSON_AddItemToObject(array_obj, "bssid", cJSON_CreateString(wifi_bssid));
		cJSON_AddItemToObject(array_obj, "ssid", cJSON_CreateString((char*)ctx->scan_result[i].ssid));
		cJSON_AddNumberToObject(array_obj, "rssi", (double) ctx->scan_result[i].rssi);
		cJSON_AddNumberToObject(array_obj, "frequency", (double) ctx->scan_result[i].freq);
		cJSON_AddNumberToObject(array_obj, "authType", ctx->scan_result[i].authmode);
#if 0
		total_ptr = cJSON_PrintUnformatted(array);
		ptr = cJSON_PrintUnformatted(array_obj);
		total_size = strlen(total_ptr);
		item_size = strlen(ptr);
		cJSON_free(total_ptr);
		cJSON_free(ptr);
		total_ptr = NULL;
		ptr = NULL;

		IOT_DEBUG("[%d] total_size: %d, item_size: %d, extra: %d", length, total_size, item_size,
						strlen("{\"wifiScanInfos\":}") + strlen(", "));
		if ((total_size + item_size + strlen("{\"wifiScanInfos\":}") + strlen(", ")) >= length) {
			IOT_INFO("Too large payload. just skip to add item");
			cJSON_Delete(array_obj);
			break;
		}
#endif
		cJSON_AddItemToArray(array, array_obj);
	}

	root = cJSON_CreateObject();
	if (!root) {
		IOT_ERROR("json create failed");
		err = IOT_ERROR_MEM_ALLOC;
		goto out;
	}
	cJSON_AddItemToObject(root, "wifiScanInfo", (cJSON *)array);

	ptr = cJSON_PrintUnformatted(root);

	input_len = strlen(ptr);
	output_len = iot_crypto_cipher_get_align_size(IOT_CRYPTO_CIPHER_AES256, input_len);
	if ((encrypt_buf = malloc(output_len)) == NULL) {
		IOT_ERROR("failed to malloc for encrypt_buf");
		err = IOT_ERROR_MEM_ALLOC;
		goto out;
	}

	err = _es_crypto_cipher_aes(ctx->es_crypto_cipher_info, IOT_CRYPTO_CIPHER_ENCRYPT,
					(unsigned char *) ptr, encrypt_buf, input_len, output_len, &result_len);
	if (err) {
		IOT_ERROR("AES256 Encryption error!! : %d", err);
		goto out;
	}

	input_len = result_len;
	output_len = IOT_CRYPTO_CAL_B64_LEN(input_len);
	if ((encode_buf = malloc(output_len)) == NULL) {
		IOT_ERROR("failed to malloc for encode_buf");
		err = IOT_ERROR_MEM_ALLOC;
		goto out;
	}

	err = iot_crypto_base64_encode_urlsafe(encrypt_buf, input_len,
						encode_buf, output_len, &result_len);
	if (err != IOT_ERROR_NONE) {
		IOT_ERROR("base64 encode error!!");
		goto out;
	}

	if (root)
		cJSON_Delete(root);
	root = NULL;

	root = cJSON_CreateObject();
	if (!root) {
		IOT_ERROR("json create failed");
		err = IOT_ERROR_MEM_ALLOC;
		goto out;
	}
	cJSON_AddItemToObject(root, "message", cJSON_CreateString((char *) encode_buf));
	output_ptr = cJSON_PrintUnformatted(root);

	*out_payload = output_ptr;
out:
	if (ptr)
		free(ptr);
	if (encode_buf)
		free(encode_buf);
	if (encrypt_buf)
		free(encrypt_buf);
	if (root)
		cJSON_Delete(root);
	return err;
}

static iot_error_t _es_keyinfo_handler(struct iot_context *ctx, char *in_payload, char **out_payload)
{
	char *ptr = NULL;
	char *output_ptr = NULL;
	char tmp[3] = {0};
	char rand_asc[IOT_CRYPTO_SHA256_LEN * 2 + 1] = { 0 };
	cJSON *recv = NULL;
	cJSON *root = NULL;
	cJSON *array = NULL;
	int i, j;
	iot_crypto_pk_info_t pk_info;
	iot_crypto_ecdh_params_t params;
	iot_error_t err = IOT_ERROR_NONE;
	unsigned char val;
	unsigned char key_tsec_curve[IOT_CRYPTO_ED25519_LEN];
	unsigned char key_spub_sign[IOT_CRYPTO_ED25519_LEN];
	unsigned char key_rand[IOT_CRYPTO_SHA256_LEN];
	unsigned char *encode_buf = NULL;
	unsigned char *encrypt_buf = NULL;
	unsigned char *master_secret = NULL;
	unsigned char *p_spub_str = NULL;
	unsigned char *p_rand_str = NULL;
	size_t input_len = 0;
	size_t output_len = 0;
	size_t result_len = 0;
	size_t spub_len = 0;
	size_t rand_asc_len = 0;

	root = cJSON_Parse(in_payload);
	if (!root) {
		IOT_ERROR("Invalid json format of payload");
		err = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto exit;
	}

	if ((recv = cJSON_GetObjectItem(root, "spub")) == NULL) {
		IOT_INFO("no spub info");
		err  = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto exit;
	}
	p_spub_str = (unsigned char *)cJSON_GetStringValue(recv);
	IOT_DEBUG("spub_info = %s", p_spub_str);
	err = iot_crypto_base64_decode_urlsafe(p_spub_str, strlen((char*)p_spub_str),
					key_spub_sign, sizeof(key_spub_sign),
					&spub_len);
	if (err) {
		IOT_WARN("spub decode error %d", err);
		err = IOT_ERROR_EASYSETUP_SPUB_DECODE_ERROR;
		goto exit;
	} else if (spub_len != IOT_CRYPTO_ED25519_LEN) {
		IOT_WARN("invalid spub length : %u", spub_len);
		err = IOT_ERROR_EASYSETUP_SPUB_DECODE_ERROR;
		goto exit;
	} else {
		IOT_INFO("spub len %u", spub_len);
	}

	if ((recv = cJSON_GetObjectItem(root, "rand")) == NULL) {
		IOT_INFO("no spub info");
		err = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto exit;
	}
	p_rand_str = (unsigned char *)cJSON_GetStringValue(recv);
	IOT_DEBUG("rand_info = %s", p_rand_str);
	err = iot_crypto_base64_decode(p_rand_str, strlen((char*)p_rand_str),
					(unsigned char *)rand_asc, sizeof(rand_asc), &rand_asc_len);
	if (err) {
		IOT_WARN("rand decode error %d", err);
		err = IOT_ERROR_EASYSETUP_RAND_DECODE_ERROR;
		goto exit;
	} else {
		IOT_INFO("rand len %u", rand_asc_len);
	}

	if (rand_asc_len != (sizeof(rand_asc) - 1)) {
		IOT_ERROR("rand size is mismatch (%d != %d)", rand_asc_len, (sizeof(rand_asc) - 1));
		err = IOT_ERROR_CRYPTO_BASE;
		goto exit;
	}

	for (i = 0, j = 0; i < sizeof(rand_asc) - 1; i += 2, j++) {
		memcpy(tmp, rand_asc + i, 2);
		val = (unsigned char)strtol((const char *)tmp, NULL, 16);
		key_rand[j] = val;
	}

	iot_es_crypto_init_pk(&pk_info, ctx->devconf.pk_type);
	err = iot_es_crypto_load_pk(&pk_info);
	if (err) {
		IOT_ERROR("Cannot get key info %d", err);
		goto exit;
	}

	if (pk_info.type != IOT_CRYPTO_PK_ED25519) {
		IOT_ERROR("%d is not suported yet", pk_info.type);
		err = IOT_ERROR_EASYSETUP_NOT_SUPPORTED;
		goto exit_pk;
	}

	err = iot_crypto_ed25519_convert_seckey(pk_info.seckey, key_tsec_curve);
	if (err) {
		IOT_ERROR("Cannot convert seckey of things %d", err);
		goto exit;
	}

	master_secret = malloc(IOT_CRYPTO_SECRET_LEN + 1);
	if (!master_secret) {
		IOT_ERROR("failed to malloc for master_secret");
		err = IOT_ERROR_MEM_ALLOC;
		goto exit_pk;
	}
	memset(master_secret, '\0', IOT_CRYPTO_SECRET_LEN + 1);

	params.s_pubkey = key_spub_sign;
	params.t_seckey = key_tsec_curve;
	params.hash_token = key_rand;
	params.hash_token_len = sizeof(key_rand);

	err = iot_crypto_ecdh_gen_master_secret(master_secret, IOT_CRYPTO_SECRET_LEN, &params);
	if (err) {
		IOT_ERROR("master secret generation failed %d", err);
		goto exit_secret;
	} else {
		IOT_INFO("master secret generation success");
	}

	ctx->es_crypto_cipher_info->type = IOT_CRYPTO_CIPHER_AES256;
	ctx->es_crypto_cipher_info->key = master_secret;
	ctx->es_crypto_cipher_info->key_len = IOT_CRYPTO_SECRET_LEN;

	if (root)
		cJSON_Delete(root);
	root = NULL;

	root = cJSON_CreateObject();
	if (!root) {
		IOT_ERROR("json create failed");
		err = IOT_ERROR_MEM_ALLOC;
		goto exit_secret;
	}

	array = cJSON_CreateArray();
	if (!array) {
		err = IOT_ERROR_MEM_ALLOC;
		goto exit_secret;
	}

	for (i = OVF_BIT_JUSTWORKS; i < OVF_BIT_MAX_FEATURE; i++) {
		if (ctx->devconf.ownership_validation_type & (1 << i)) {
			cJSON_AddItemToArray(array, cJSON_CreateNumber(i));
		}
	}
	cJSON_AddItemToObject(root, "otmSupportFeatures", array);

	ptr = cJSON_PrintUnformatted(root);

	input_len = strlen(ptr);
	output_len = iot_crypto_cipher_get_align_size(IOT_CRYPTO_CIPHER_AES256, input_len);
	if ((encrypt_buf = malloc(output_len)) == NULL) {
		IOT_ERROR("failed to malloc for encrypt_buf");
		err = IOT_ERROR_MEM_ALLOC;
		goto exit;
	}

	err = _es_crypto_cipher_aes(ctx->es_crypto_cipher_info, IOT_CRYPTO_CIPHER_ENCRYPT,
						(unsigned char *) ptr, encrypt_buf, input_len, output_len, &result_len);
	if (err) {
		IOT_ERROR("AES256 Encryption error!! : %d", err);
		goto exit_secret;
	}

	input_len = result_len;
	output_len = IOT_CRYPTO_CAL_B64_LEN(input_len);
	if ((encode_buf = malloc(output_len)) == NULL) {
		IOT_ERROR("failed to malloc for encode_buf");
		err = IOT_ERROR_MEM_ALLOC;
		goto exit_secret;
	}

	err = iot_crypto_base64_encode_urlsafe(encrypt_buf, input_len,
						encode_buf, output_len, &result_len);
	if (err != IOT_ERROR_NONE) {
		IOT_ERROR("base64 encode error!!");
		goto exit_secret;
	}

	if (root)
		cJSON_Delete(root);
	root = NULL;

	root = cJSON_CreateObject();
	if (!root) {
		IOT_ERROR("json create failed");
		err = IOT_ERROR_MEM_ALLOC;
		goto exit_secret;
	}
	cJSON_AddItemToObject(root, "message", cJSON_CreateString((char *) encode_buf));
	output_ptr = cJSON_PrintUnformatted(root);

	*out_payload = output_ptr;
exit_secret:
	if (ptr)
		free(ptr);
	if (encode_buf)
		free(encode_buf);
	if (encrypt_buf)
		free(encrypt_buf);
	if (err && master_secret)
		free(master_secret);
exit_pk:
		iot_es_crypto_free_pk(&pk_info);
exit:
	if (root)
		cJSON_Delete(root);
	return err;
}

void st_conn_ownership_confirm(IOT_CTX *iot_ctx, bool confirm)
{
	struct iot_context *ctx = (struct iot_context*)iot_ctx;

	if (ctx->curr_otm_feature == OVF_BIT_BUTTON) {
		if (confirm == true) {
			IOT_INFO("To confirm is reported!!");
			iot_os_eventgroup_set_bits(ctx->iot_events, IOT_EVENT_BIT_EASYSETUP_CONFIRM);
		}
	}
}

static iot_error_t _es_confirm_check_manager(struct iot_context *ctx, enum ownership_validation_feature confirm_feature, char *sn)
{
	char *dev_sn = NULL;
	unsigned int curr_event = 0;
	unsigned int devsn_len;
	iot_error_t err = IOT_ERROR_NONE;

	iot_os_eventgroup_clear_bits(ctx->iot_events, IOT_EVENT_BIT_EASYSETUP_CONFIRM);
	ctx->curr_otm_feature = confirm_feature;

	err = iot_state_update(ctx, IOT_STATE_PROV_CONFIRMING,
			IOT_STATE_OPT_NEED_INTERACT);
	if (err != IOT_ERROR_NONE) {
		IOT_ERROR("failed handle cmd (%d): %d", IOT_STATE_PROV_CONFIRMING, err);
		err = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto out;
	}

	switch (confirm_feature)
	{
		case OVF_BIT_JUSTWORKS:
			IOT_INFO("There is no confirmation request. The check is skipped");
			break;
		case OVF_BIT_QR:
			IOT_INFO("The QR code confirmation is requested\n");
			if (sn == NULL) {
				IOT_ERROR("to get invalid QR serial num\n");
				err = IOT_ERROR_EASYSETUP_INVALID_QR;
				break;
			}

			err = iot_nv_get_serial_number(&dev_sn, &devsn_len);
			if (err != IOT_ERROR_NONE) {
				IOT_ERROR("failed to get serial num\n");
				err = IOT_ERROR_EASYSETUP_SERIAL_NOT_FOUND;
			}

			if (!strcmp(sn, dev_sn)) {
				IOT_INFO("confirm");
			} else {
				IOT_ERROR("confirm fail");
				err = IOT_ERROR_EASYSETUP_CONFIRM_DENIED;
			}
			break;
		case OVF_BIT_BUTTON:
			IOT_INFO("The button confirmation is requested");

			curr_event = iot_os_eventgroup_wait_bits(ctx->iot_events, IOT_EVENT_BIT_EASYSETUP_CONFIRM, false, false, ES_CONFIRM_MAX_DELAY);
			IOT_DEBUG("curr_event = %d", curr_event);

			if (curr_event & IOT_EVENT_BIT_EASYSETUP_CONFIRM) {
				IOT_INFO("confirm");
			} else {
				IOT_ERROR("confirm failed");
				err = IOT_ERROR_EASYSETUP_CONFIRM_DENIED;
			}
			break;
		case OVF_BIT_PIN:
			IOT_INFO("The pin number confirmation is requested");
			break;
		default:
			IOT_INFO("Not Supported confirmation type is requested");
			break;
	}

out:
	return err;
}

static iot_error_t _es_confirminfo_handler(struct iot_context *ctx, char *in_payload, char **out_payload)
{
	char *ptr = NULL;
	char *output_ptr = NULL;
	char *rev_message = NULL;
	cJSON *recv = NULL;
	cJSON *root = NULL;
	iot_error_t err = IOT_ERROR_NONE;
	size_t input_len = 0;
	size_t output_len = 0;
	size_t result_len = 0;
	unsigned char *decode_buf = NULL;
	unsigned char *encode_buf = NULL;
	unsigned char *decrypt_buf = NULL;
	unsigned char *encrypt_buf = NULL;

	root = cJSON_Parse(in_payload);
	if (!root) {
		IOT_ERROR("Invalid args");
		err = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto out;
	}

	if ((recv = cJSON_GetObjectItem(root, "message")) == NULL) {
		IOT_INFO("no message");
		err = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto out;
	}

	rev_message = _es_json_parse_string(root, "message");

	input_len = (unsigned int)strlen(rev_message);
	output_len = input_len;
	if ((decode_buf = malloc(output_len)) == NULL) {
		IOT_ERROR("failed to malloc for decode_buf");
		err = IOT_ERROR_MEM_ALLOC;
		goto out;
	}

	err = iot_crypto_base64_decode_urlsafe((unsigned char *) rev_message, input_len,
					decode_buf, output_len,
					&result_len);

	input_len = result_len;
	output_len = iot_crypto_cipher_get_align_size(IOT_CRYPTO_CIPHER_AES256, input_len);
	if ((decrypt_buf = malloc(output_len)) == NULL) {
		IOT_ERROR("failed to malloc for decrypt_buf");
		err = IOT_ERROR_MEM_ALLOC;
		goto out;
	}

	err = _es_crypto_cipher_aes(ctx->es_crypto_cipher_info, IOT_CRYPTO_CIPHER_DECRYPT,
						decode_buf, decrypt_buf, input_len, output_len, &result_len);
	if (err) {
		IOT_ERROR("AES256 Encryption error!! : %d", err);
		goto out;
	}

	if (root)
		cJSON_Delete(root);
	root = NULL;

	root = cJSON_Parse((char *) decrypt_buf);
	if (!root) {
		IOT_ERROR("Invalid payload json format");
		err = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto out;
	}

	if ((recv = cJSON_GetObjectItem(root, "otmSupportFeature")) == NULL) {
		IOT_INFO("no otmsupportfeature info");
		err = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto out;
	}

	IOT_INFO("otmSupportFeature = %d", recv->valueint);

	if ((recv->valueint >= OVF_BIT_JUSTWORKS) || (recv->valueint < OVF_BIT_MAX_FEATURE)) {
		char *sn = NULL;

		if (recv->valueint == OVF_BIT_QR)
			sn = _es_json_parse_string(root, "sn");

		err = _es_confirm_check_manager(ctx, recv->valueint, sn);
		if (err == IOT_ERROR_EASYSETUP_CONFIRM_DENIED)
			goto out;
	} else
		IOT_ERROR("Not supported otmsupportfeature : %d", recv->valueint);

	if (root)
		cJSON_Delete(root);
	root = NULL;

	root = cJSON_CreateObject();
	if (!root) {
		IOT_ERROR("json create failed");
		err = IOT_ERROR_MEM_ALLOC;
		goto out;
	}

	ptr = cJSON_PrintUnformatted(root);

	input_len = (unsigned int)strlen(ptr);
	output_len = iot_crypto_cipher_get_align_size(IOT_CRYPTO_CIPHER_AES256, input_len);
	if ((encrypt_buf = malloc(output_len)) == NULL) {
		IOT_ERROR("failed to malloc for encrypt_buf");
		err = IOT_ERROR_MEM_ALLOC;
		goto out;
	}

	err = _es_crypto_cipher_aes(ctx->es_crypto_cipher_info, IOT_CRYPTO_CIPHER_ENCRYPT,
						(unsigned char *) ptr, encrypt_buf, input_len, output_len, &result_len);
	if (err) {
		IOT_ERROR("AES256 Encryption error!! : %d", err);
		goto out;
	}

	input_len = result_len;
	output_len = IOT_CRYPTO_CAL_B64_LEN(input_len);
	if ((encode_buf = (unsigned char *)malloc(output_len)) == NULL) {
		IOT_ERROR("failed to malloc for encode_buf");
		err = IOT_ERROR_MEM_ALLOC;
		goto out;
	}

	err = iot_crypto_base64_encode_urlsafe(encrypt_buf, input_len,
						encode_buf, output_len, &result_len);
	if (err != IOT_ERROR_NONE) {
		IOT_ERROR("base64 encode error!!");
		goto out;
	}

	if (root)
		cJSON_Delete(root);
	root = NULL;

	root = cJSON_CreateObject();
	if (!root) {
		IOT_ERROR("json create failed");
		err = IOT_ERROR_MEM_ALLOC;
		goto out;
	}
	cJSON_AddItemToObject(root, "message", cJSON_CreateString((char *) encode_buf));
	output_ptr = cJSON_PrintUnformatted(root);

	*out_payload = output_ptr;
out:
	if (ptr)
		free(ptr);
	if (rev_message)
		free(rev_message);
	if (decode_buf)
		free(decode_buf);
	if (decrypt_buf)
		free(decrypt_buf);
	if (encrypt_buf)
		free(encrypt_buf);
	if (encode_buf)
		free(encode_buf);
	if (root)
		cJSON_Delete(root);
	return err;
}

static iot_error_t _es_confirm_handler(struct iot_context *ctx, char *in_payload, char **out_payload)
{
	bool validation = true;
	char pin[PIN_SIZE + 1];
	char *ptr = NULL;
	char *output_ptr = NULL;
	char *rev_message = NULL;
	cJSON *recv = NULL;
	cJSON *root = NULL;
	int i;
	iot_error_t err = IOT_ERROR_NONE;
	size_t input_len = 0;
	size_t output_len = 0;
	size_t result_len = 0;
	unsigned char *decode_buf = NULL;
	unsigned char *decrypt_buf = NULL;
	unsigned char *encode_buf = NULL;
	unsigned char *encrypt_buf = NULL;

	root = cJSON_Parse(in_payload);
	if (!root) {
		IOT_ERROR("Invalid args");
		err = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto out;
	}

	rev_message = _es_json_parse_string(root, "message");

	if (!rev_message) {
		IOT_ERROR("Invalid args");
		err = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto out;
	}

	input_len = (unsigned int)strlen(rev_message);
	output_len = input_len;
	if ((decode_buf = malloc(output_len)) == NULL) {
		IOT_ERROR("failed to malloc for decode_buf");
		err = IOT_ERROR_MEM_ALLOC;
		goto out;
	}
	err = iot_crypto_base64_decode_urlsafe((unsigned char *) rev_message, input_len,
					decode_buf, output_len, &result_len);

	output_len = iot_crypto_cipher_get_align_size(IOT_CRYPTO_CIPHER_AES256, input_len);
	if ((decrypt_buf = malloc(output_len)) == NULL) {
		IOT_ERROR("failed to malloc for decrypt_buf");
		err = IOT_ERROR_MEM_ALLOC;
		goto out;
	}

	err = _es_crypto_cipher_aes(ctx->es_crypto_cipher_info, IOT_CRYPTO_CIPHER_DECRYPT,
						decode_buf, decrypt_buf, result_len, output_len, &result_len);
	if (err) {
		IOT_ERROR("AES256 Encryption error!! : %d", err);
		goto out;
	}

	root = cJSON_Parse((char *)decrypt_buf);
	if (!root) {
		IOT_ERROR("Invalid payload json format");
		err = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto out;
	}

	if ((recv = cJSON_GetObjectItem(root, "pin")) == NULL) {
		IOT_INFO("no pin info");
		err = IOT_ERROR_EASYSETUP_INVALID_PIN;
		goto out;
	}

	if (!ctx || !ctx->pin) {
		IOT_ERROR("no pin from application");
		err = IOT_ERROR_EASYSETUP_PIN_NOT_FOUND;
		goto out;
	}

	strncpy(pin, recv->valuestring, sizeof(pin) - 1);
	pin[PIN_SIZE] = '\0';
	IOT_INFO("pin = %s", pin);
	for (i = 0; i < PIN_SIZE; i++) {
		if (pin[i] > '9' || pin[i] < '0') {
			IOT_ERROR("invalid pin number from application");
			validation = false;
			break;
		}
	}

	for (i = 0; i < PIN_SIZE; i++) {
		if (ctx->pin->pin[i] != pin[i]) {
			IOT_ERROR("the reported pin number is not matched[%d]", i);
			validation = false;
			break;
		}
	}
	cJSON_Delete(root);
	root = NULL;
	if (!validation) {
		err = IOT_ERROR_EASYSETUP_INVALID_PIN;
		goto out;
	}

	/*
	 * output payload
	 */
	root = cJSON_CreateObject();
	if (!root) {
		IOT_ERROR("json create failed");
		err = IOT_ERROR_EASYSETUP_INTERNAL_SERVER_ERROR;
		goto out;
	}
	ptr = cJSON_PrintUnformatted(root);

	input_len = (unsigned int)strlen(ptr);
	output_len = iot_crypto_cipher_get_align_size(IOT_CRYPTO_CIPHER_AES256, input_len);
	if ((encrypt_buf = malloc(output_len)) == NULL) {
		IOT_ERROR("failed to malloc for encrypt_buf");
		err = IOT_ERROR_MEM_ALLOC;
		goto out;
	}

	err = _es_crypto_cipher_aes(ctx->es_crypto_cipher_info, IOT_CRYPTO_CIPHER_ENCRYPT,
						(unsigned char *) ptr, encrypt_buf, input_len, output_len, &result_len);
	if (err) {
		IOT_ERROR("AES256 Encryption error!! : %d", err);
		goto out;
	}

	input_len = result_len;
	output_len = IOT_CRYPTO_CAL_B64_LEN(input_len);
	if ((encode_buf = malloc(output_len)) == NULL) {
		IOT_ERROR("failed to malloc encode_buf");
		err = IOT_ERROR_MEM_ALLOC;
		goto out;
	}

	err = iot_crypto_base64_encode_urlsafe(encrypt_buf, input_len,
						encode_buf, output_len, &result_len);
	if (err != IOT_ERROR_NONE) {
		IOT_ERROR("base64 encode error!!");
		goto out;
	}

	if (root)
		cJSON_Delete(root);
	root = NULL;

	root = cJSON_CreateObject();
	if (!root) {
		IOT_ERROR("json create failed");
		err = IOT_ERROR_MEM_ALLOC;
		goto out;
	}
	cJSON_AddItemToObject(root, "message", cJSON_CreateString((char *) encode_buf));
	output_ptr = cJSON_PrintUnformatted(root);

	*out_payload = output_ptr;
out:
	if (ptr)
		free(ptr);
	if (decode_buf)
		free(decode_buf);
	if (decrypt_buf)
		free(decrypt_buf);
	if (encrypt_buf)
		free(encrypt_buf);
	if (encode_buf)
		free(encode_buf);
	if (root)
		cJSON_Delete(root);
	return err;
}

static iot_error_t _es_wifi_prov_parse(struct iot_context *ctx, char *in_payload)
{
	struct iot_wifi_prov_data *wifi_prov = NULL;
	char bssid[] = "00:00:00:00:00:00";
	cJSON *item = NULL;
	cJSON *root = NULL;
	cJSON *wifi_credential = NULL;
	iot_error_t err = IOT_ERROR_NONE;
	int i = 0;

	root = cJSON_Parse(in_payload);
	if (!root) {
		IOT_ERROR("Invalid args");
		err = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto wifi_parse_out;
	}

	if ((wifi_credential = cJSON_GetObjectItem(root, "wifiCredential")) == NULL) {
		IOT_ERROR("failed to find wifiCredential");
		err = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto wifi_parse_out;
	}

	if ((wifi_prov = (struct iot_wifi_prov_data *)malloc(sizeof(struct iot_wifi_prov_data))) == NULL) {
		IOT_ERROR("failed to malloc for wifi_prov_data");
		err = IOT_ERROR_MEM_ALLOC;
		goto wifi_parse_out;
	}

	memset(wifi_prov, 0, sizeof(struct iot_wifi_prov_data));

	if ((item = cJSON_GetObjectItem(wifi_credential, "ssid")) == NULL) {
		IOT_ERROR("failed to find ssid");
		err = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto wifi_parse_out;
	}
	strncpy(wifi_prov->ssid, cJSON_GetStringValue(item), sizeof(wifi_prov->ssid) - 1);

	// password is optional.
	if ((item = cJSON_GetObjectItem(wifi_credential, "password")) == NULL) {
		IOT_INFO("No wifi password");
		wifi_prov->security_type = IOT_WIFI_AUTH_OPEN;
	} else {
		if (strlen(cJSON_GetStringValue(item)) > 0) {
			strncpy(wifi_prov->password, cJSON_GetStringValue(item), sizeof(wifi_prov->password) - 1);
			for (i = 0; i < ctx->scan_num; i++) {
				if (!strcmp(wifi_prov->ssid, (char *)ctx->scan_result[i].ssid)) {
					wifi_prov->security_type = ctx->scan_result[i].authmode;
					IOT_DEBUG("%s is type %d", wifi_prov->ssid, wifi_prov->security_type);
					break;
				}
			}
			if (i == ctx->scan_num) {
				IOT_DEBUG("%s doesn't exist in scan list. So assume it as WPA", wifi_prov->ssid);
				wifi_prov->security_type = IOT_WIFI_AUTH_WPA_WPA2_PSK;
			}
		} else {
			wifi_prov->security_type = IOT_WIFI_AUTH_OPEN;
		}
	}

	if ((item = cJSON_GetObjectItem(wifi_credential, "macAddress")) == NULL)
		IOT_INFO("no macAddress");
	else
		strncpy(bssid, cJSON_GetStringValue(item), sizeof(bssid));

	err = iot_util_convert_str_mac(bssid, &wifi_prov->bssid);
	if (err) {
		IOT_ERROR("Failed to convert str to mac address (error : %d) : %s", err, bssid);
		goto wifi_parse_out;
	}

	err = iot_nv_set_wifi_prov_data(wifi_prov);
	if (err) {
		IOT_ERROR("failed to set the cloud prov data");
		goto wifi_parse_out;
	}

	IOT_INFO("ssid: %s", wifi_prov->ssid);
	IOT_DEBUG("password: %s", wifi_prov->password);
	IOT_INFO("mac addr: %s", bssid);

wifi_parse_out:
	if (wifi_prov)
		free(wifi_prov);
	if (root)
		cJSON_Delete(root);
	return err;
}

static iot_error_t _es_cloud_prov_parse(char *in_payload)
{
	struct iot_cloud_prov_data *cloud_prov = NULL;
	char *full_url = NULL;
	char *location_id_str = NULL;
	char *room_id_str = NULL;
	cJSON *root = NULL;
	iot_error_t err = IOT_ERROR_NONE;
	url_parse_t url = { .protocol = NULL, .domain = NULL, .port = 0};

	root = cJSON_Parse(in_payload);
	if (!root) {
		IOT_ERROR("Invalid payload json format");
		err = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto cloud_parse_out;
	}

	if ((cloud_prov = (struct iot_cloud_prov_data *)malloc(sizeof(struct iot_cloud_prov_data))) == NULL) {
		IOT_ERROR("failed to alloc mem");
		err = IOT_ERROR_MEM_ALLOC;
		goto cloud_parse_out;
	}

	memset(cloud_prov, 0, sizeof(struct iot_cloud_prov_data));

	if ((full_url = _es_json_parse_string(root, "brokerUrl")) == NULL) {
		IOT_ERROR("failed to find brokerUrl");
		err = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto cloud_parse_out;
	}

	err = iot_util_url_parse(full_url, &url);
	if (err) {
		IOT_ERROR("failed to parse broker url");
		err = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto cloud_parse_out;
	}

	location_id_str = _es_json_parse_string(root, "locationId");
	err = iot_util_convert_str_uuid(location_id_str, &cloud_prov->location_id);
	if (err) {
		IOT_ERROR("failed to convert locationId");
		goto cloud_parse_out;
	}

	room_id_str = _es_json_parse_string(root, "roomId");
	/* roomId is optional */
	if (room_id_str) {
		err = iot_util_convert_str_uuid(room_id_str, &cloud_prov->room_id);
		if (err != IOT_ERROR_NONE) {
			IOT_ERROR("failed to convert roomId");
			goto cloud_parse_out;
		}
	} else {
		IOT_INFO("no roomId");
	}

	if ((cloud_prov->label = _es_json_parse_string(root, "deviceName")) == NULL) {
		IOT_INFO("No deviceName");
	}

	cloud_prov->broker_url = url.domain;
	cloud_prov->broker_port = url.port;

	err = iot_nv_set_cloud_prov_data(cloud_prov);
	if (err) {
		IOT_ERROR("failed to set the cloud prov data");
		cloud_prov->broker_url = NULL;
		cloud_prov->broker_port = 0;
		goto cloud_parse_out;
	}

	IOT_INFO("brokerUrl: %s:%d", cloud_prov->broker_url, cloud_prov->broker_port);
	IOT_DEBUG("locationId : %s", location_id_str);
	IOT_DEBUG("roomId : %s", room_id_str);
	IOT_INFO("deviceName : %s", cloud_prov->label);

cloud_parse_out:
	if (err) {
		if (url.domain)
			free(url.domain);
	}

	if (url.protocol)
		free(url.protocol);
	if (full_url)
		free(full_url);
	if (cloud_prov)
		free(cloud_prov);
	if (location_id_str)
		free(location_id_str);
	if (room_id_str)
		free(room_id_str);
	if (root)
		cJSON_Delete(root);
	return err;
}

static iot_error_t _es_wifiprovisioninginfo_handler(struct iot_context *ctx, char *in_payload, char **out_payload)
{
	struct iot_uuid uuid;
	char *ptr = NULL;
	char *output_ptr = NULL;
	char *rev_message = NULL;
	cJSON *root = NULL;
	int uuid_len = 40;
	iot_error_t err = IOT_ERROR_NONE;
	size_t input_len = 0;
	size_t output_len = 0;
	size_t result_len = 0;
	unsigned char *decode_buf = NULL;
	unsigned char *encode_buf = NULL;
	unsigned char *decrypt_buf = NULL;
	unsigned char *encrypt_buf = NULL;

	root = cJSON_Parse(in_payload);
	if (!root) {
		IOT_ERROR("Invalid args");
		err = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto out;
	}

	rev_message = _es_json_parse_string(root, "message");

	input_len = strlen(rev_message);
	output_len = input_len;
	if ((decode_buf = malloc(output_len)) == NULL) {
		IOT_ERROR("failed to malloc for decode_buf");
		err = IOT_ERROR_MEM_ALLOC;
		goto out;
	}

	err = iot_crypto_base64_decode_urlsafe((unsigned char *) rev_message, input_len,
					decode_buf, output_len,
					&result_len);

	if (root)
		cJSON_Delete(root);
	root = NULL;

	input_len = result_len;
	output_len = iot_crypto_cipher_get_align_size(IOT_CRYPTO_CIPHER_AES256, input_len);
	if ((decrypt_buf = malloc(output_len)) == NULL) {
		IOT_ERROR("failed to malloc for decrypt_buf");
		err = IOT_ERROR_MEM_ALLOC;
		goto out;
	}

	err = _es_crypto_cipher_aes(ctx->es_crypto_cipher_info, IOT_CRYPTO_CIPHER_DECRYPT,
						decode_buf, decrypt_buf, input_len, output_len, &result_len);
	if (err) {
		IOT_ERROR("AES256 Decryption error!! : %d", err);
		goto out;
	}

	err = _es_wifi_prov_parse(ctx, (char *)decrypt_buf);
	if (err) {
		IOT_ERROR("failed to parse wifi_prov");
		goto out;
	}

	err = _es_cloud_prov_parse((char *)decrypt_buf);
	if (err) {
		IOT_ERROR("failed to parse cloud_prov");
		goto out;
	}

	err = iot_random_uuid_from_mac(&uuid);
	if (err) {
		IOT_ERROR("To get uuid is failed (error : %d)", err);
		goto out;
	}

	ctx->lookup_id = (char *) malloc(uuid_len);

	err = iot_util_convert_uuid_str(&uuid, ctx->lookup_id, uuid_len);
	if (err) {
		IOT_ERROR("Failed to convert uuid to str (error : %d)", err);
		goto out;
	}

	IOT_DEBUG("lookupid = %s", ctx->lookup_id);

	root = cJSON_CreateObject();
	if (!root) {
		IOT_ERROR("json create failed");
		goto out;
	}
	cJSON_AddItemToObject(root, "lookupId", cJSON_CreateString(ctx->lookup_id));

	ptr = cJSON_PrintUnformatted(root);

	input_len = (unsigned int)strlen(ptr);
	output_len = iot_crypto_cipher_get_align_size(IOT_CRYPTO_CIPHER_AES256, input_len);
	if ((encrypt_buf = malloc(output_len)) == NULL) {
		IOT_ERROR("failed to malloc for encrypt_buf");
		err = IOT_ERROR_MEM_ALLOC;
		goto out;
	}

	err = _es_crypto_cipher_aes(ctx->es_crypto_cipher_info, IOT_CRYPTO_CIPHER_ENCRYPT,
						(unsigned char *) ptr, encrypt_buf, input_len, output_len, &result_len);
	if (err) {
		IOT_ERROR("AES256 Encryption error!! : %d", err);
		goto out;
	}

	input_len = result_len;
	output_len = IOT_CRYPTO_CAL_B64_LEN(input_len);
	if ((encode_buf = malloc(output_len)) == NULL) {
		IOT_ERROR("failed to malloc for encode_buf");
		err = IOT_ERROR_MEM_ALLOC;
		goto out;
	}

	err = iot_crypto_base64_encode_urlsafe(encrypt_buf, input_len,
						encode_buf, output_len, &result_len);
	if (err != IOT_ERROR_NONE) {
		IOT_ERROR("base64 encode error!!");
		goto out;
	}

	if (root)
		cJSON_Delete(root);
	root = NULL;

	root = cJSON_CreateObject();
	if (!root) {
		IOT_ERROR("json create failed");
		err = IOT_ERROR_MEM_ALLOC;
		goto out;
	}
	cJSON_AddItemToObject(root, "message", cJSON_CreateString((char *) encode_buf));
	output_ptr = cJSON_PrintUnformatted(root);

	*out_payload = output_ptr;

	err = iot_nv_get_prov_data(&ctx->prov_data);
	if (err) {
		IOT_WARN("No provisining from nv");
	} else {
		IOT_INFO("provisioning success");
	}
out:
	if (ptr)
		free(ptr);
	if (rev_message)
		free(rev_message);
	if (decode_buf)
		free(decode_buf);
	if (decrypt_buf)
		free(decrypt_buf);
	if (encrypt_buf)
		free(encrypt_buf);
	if (encode_buf)
		free(encode_buf);
	if (root)
		cJSON_Delete(root);
	return err;
}

static iot_error_t _es_setupcomplete_handler(struct iot_context *ctx, char *in_payload, char **out_payload)
{
	char *ptr = NULL;
	char *output_ptr = NULL;
	cJSON *root = NULL;
	iot_error_t err = IOT_ERROR_NONE;
	size_t input_len = 0;
	size_t output_len = 0;
	size_t result_len = 0;
	unsigned char *encode_buf = NULL;
	unsigned char *encrypt_buf = NULL;

	root = cJSON_CreateObject();
	if (!root) {
		IOT_ERROR("json create failed");
		err = IOT_ERROR_MEM_ALLOC;
		goto out;
	}

	ptr = cJSON_PrintUnformatted(root);

	input_len = strlen(ptr);
	output_len = iot_crypto_cipher_get_align_size(IOT_CRYPTO_CIPHER_AES256, input_len);
	if ((encrypt_buf = malloc(output_len)) == NULL) {
		IOT_ERROR("failed to malloc for encrypt_buf");
		err = IOT_ERROR_MEM_ALLOC;
		goto out;
	}

	err = _es_crypto_cipher_aes(ctx->es_crypto_cipher_info, IOT_CRYPTO_CIPHER_ENCRYPT,
						(unsigned char *) ptr, encrypt_buf, input_len, output_len, &result_len);
	if (err) {
		IOT_ERROR("AES256 Encryption error!! : %d", err);
		goto out;
	}

	input_len = result_len;
	output_len = (input_len * 2);
	if ((encode_buf = (unsigned char *)malloc(output_len)) == NULL) {
		IOT_ERROR("failed to malloc for encode_buf");
		err = IOT_ERROR_MEM_ALLOC;
		goto out;
	}

	err = iot_crypto_base64_encode_urlsafe(encrypt_buf, input_len,
						encode_buf, output_len, &result_len);
	if (err != IOT_ERROR_NONE) {
		IOT_ERROR("base64 encode error!!");
		goto out;
	}

	if (root)
		cJSON_Delete(root);
	root = NULL;

	root = cJSON_CreateObject();
	if (!root) {
		IOT_ERROR("json create failed");
		err = IOT_ERROR_MEM_ALLOC;
		goto out;
	}
	cJSON_AddItemToObject(root, "message", cJSON_CreateString((char *) encode_buf));
	output_ptr = cJSON_PrintUnformatted(root);

	*out_payload = output_ptr;

out:
	if (ptr)
		free(ptr);
	if (encrypt_buf)
		free(encrypt_buf);
	if (encode_buf)
		free(encode_buf);
	if (root)
		cJSON_Delete(root);
	return err;
}

#if defined(CONFIG_STDK_IOT_CORE_EASYSETUP_HTTP_LOG_SUPPORT)
static iot_error_t _es_log_systeminfo_handler(struct iot_context *ctx, char **out_payload)
{
	char *output_ptr = NULL;
	cJSON *root = NULL;
	iot_error_t err = IOT_ERROR_NONE;

	root = cJSON_CreateObject();
	if (!root) {
		IOT_ERROR("json create failed");
		err = IOT_ERROR_MEM_ALLOC;
		goto out;
	}

	cJSON_AddItemToObject(root, "version", cJSON_CreateString("1.0"));

	output_ptr = cJSON_PrintUnformatted(root);

	*out_payload = output_ptr;

out:
	if (root)
		cJSON_Delete(root);
	return err;
}

static iot_error_t _es_log_create_dump_handler(struct iot_context *ctx, char *in_payload, char **out_payload)
{
	char *output_ptr = NULL;
	cJSON *root = NULL;
	iot_error_t err = IOT_ERROR_NONE;

	root = cJSON_CreateObject();
	if (!root) {
		IOT_ERROR("json create failed");
		err = IOT_ERROR_MEM_ALLOC;
		goto out;
	}

	output_ptr = cJSON_PrintUnformatted(root);

	*out_payload = output_ptr;

out:
	if (root)
		cJSON_Delete(root);
	return err;
}

static iot_error_t _es_log_get_dump_handler(struct iot_context *ctx, char **out_payload)
{
	char *log_dump = NULL;
	char *output_ptr = NULL;
	cJSON *item = NULL;
	cJSON *root = NULL;
	iot_error_t err = IOT_ERROR_NONE;

	item = cJSON_CreateObject();
	if (!item) {
		IOT_ERROR("json create failed");
		err = IOT_ERROR_MEM_ALLOC;
		goto out;
	}

	log_dump = iot_debug_get_log();
	cJSON_AddNumberToObject(item, "code", 1);
	cJSON_AddItemToObject(item, "message", cJSON_CreateString(log_dump));

	root = cJSON_CreateObject();
	if (!root) {
		IOT_ERROR("json create failed");
		err = IOT_ERROR_MEM_ALLOC;
		goto out;
	}

	cJSON_AddItemToObject(root, "error", item);

	output_ptr = cJSON_PrintUnformatted(root);

	*out_payload = output_ptr;
out:
	if (root)
		cJSON_Delete(root);
	return err;
}
#endif

iot_error_t iot_easysetup_request_handler(struct iot_context *ctx, struct iot_easysetup_payload request)
{
	iot_error_t err = IOT_ERROR_NONE;
	int ret = IOT_OS_TRUE;
	struct iot_easysetup_payload response;

	if (!ctx)
		return IOT_ERROR_INVALID_ARGS;

	response.step = request.step;
	response.payload = NULL;

	switch (request.step) {
	case IOT_EASYSETUP_STEP_DEVICEINFO:
		err = _es_deviceinfo_handler(ctx, &response.payload);
		if (err)
			IOT_ERROR("failed to handle deviceinfo %d", err);
		break;
	case IOT_EASYSETUP_STEP_WIFISCANINFO:
		err = _es_wifiscaninfo_handler(ctx, &response.payload);
		if (err)
			IOT_ERROR("failed to handle wifiscaninfo %d", err);
		break;
	case IOT_EASYSETUP_STEP_KEYINFO:
		err = _es_keyinfo_handler(ctx, request.payload, &response.payload);
		if (err)
			IOT_ERROR("failed to handle keyinfo %d", err);
		break;
	case IOT_EASYSETUP_STEP_CONFIRMINFO:
		err = _es_confirminfo_handler(ctx, request.payload, &response.payload);
		if (err)
			IOT_ERROR("failed to handle confirminfo %d", err);
		break;
	case IOT_EASYSETUP_STEP_CONFIRM:
		err = _es_confirm_handler(ctx, request.payload, &response.payload);
		if (err)
			IOT_ERROR("failed to handle confirm %d", err);
		break;
	case IOT_EASYSETUP_STEP_WIFIPROVIONINGINFO:
		err = _es_wifiprovisioninginfo_handler(ctx, request.payload, &response.payload);
		if (err)
			IOT_ERROR("failed to handle wifiprovisionininginfo %d", err);
		break;
	case IOT_EASYSETUP_STEP_SETUPCOMPLETE:
		err = _es_setupcomplete_handler(ctx, request.payload, &response.payload);
		if (err)
			IOT_ERROR("failed to handle setupcomplete %d", err);
		break;
#if defined(CONFIG_STDK_IOT_CORE_EASYSETUP_HTTP_LOG_SUPPORT)
	case IOT_EASYSETUP_STEP_LOG_SYSTEMINFO:
		err = _es_log_systeminfo_handler(ctx, &response.payload);
		if (err)
			IOT_ERROR("failed to handle logsysteminfo %d", err);
		break;
	case IOT_EASYSETUP_STEP_LOG_CREATE_DUMP:
		err = _es_log_create_dump_handler(ctx, request.payload, &response.payload);
		if (err)
			IOT_ERROR("failed to handle logcreatedump %d", err);
	break;
	case IOT_EASYSETUP_STEP_LOG_GET_DUMP:
		err = _es_log_get_dump_handler(ctx, &response.payload);
		if (err)
			IOT_ERROR("failed to handle loggetdump %d", err);
		break;
#endif
	default:
		IOT_WARN("invalid step %d", request.step);
		err = IOT_ERROR_INVALID_ARGS;
		break;
	}

	response.err = err;

	if (ctx->easysetup_resp_queue) {
		ret = iot_os_queue_send(ctx->easysetup_resp_queue, &response, 0);
		if (ret != IOT_OS_TRUE) {
			IOT_ERROR("Cannot put the response into easysetup_resp_queue");
			err = IOT_ERROR_EASYSETUP_BASE;
		} else {
			iot_os_eventgroup_set_bits(ctx->iot_events,
				IOT_EVENT_BIT_EASYSETUP_RESP);
			err = IOT_ERROR_NONE;
		}
	} else {
		IOT_ERROR("easysetup_resp_queue is deleted");
		err = IOT_ERROR_NONE;
	}

	return err;
}
