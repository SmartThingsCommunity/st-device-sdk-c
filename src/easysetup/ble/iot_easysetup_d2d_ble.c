/* ***************************************************************************
 *
 * Copyright (c) 2019-2020 Samsung Electronics All Rights Reserved.
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
#include <time.h>
#include "easysetup_ble.h"
#include "JSON.h"
#include "iot_main.h"
#include "iot_bsp_random.h"
#include "iot_bsp_system.h"
#include "iot_easysetup.h"
#include "iot_internal.h"
#include "iot_nv_data.h"
#include "iot_util.h"
#include "iot_debug.h"
#include "security/iot_security_crypto.h"
#include "security/iot_security_ecdh.h"
#include "security/iot_security_helper.h"


#define PIN_SIZE	8
#define MAC_ADDR_BUFFER_SIZE	20
#define URL_BUFFER_SIZE 	64
#define WIFIINFO_BUFFER_SIZE	20
#define ES_CONFIRM_MAX_DELAY	100000
#define ES_CONFIRM_FAIL_TIMEOUT (10000)

#define AUTH_TYPE_NONE          (1 << 0)
#define AUTH_TYPE_WEP           (1 << 1)
#define AUTH_TYPE_WPA_PSK       (1 << 2)
#define AUTH_TYPE_WPA2_PSK      (1 << 3)
#define AUTH_TYPE_WPA_WPA2_PSK  (1 << 4)
#define AUTH_TYPE_EAP           (1 << 5)
#define AUTH_TYPE_WPA3          (1 << 6)

#define RANDOM_LEN              16
#define PREERR_STR_LEN          32
#define STR_DEFAULT_LEN         64


static unsigned char sec_random[RANDOM_LEN*2] = {0};

void st_conn_ownership_confirm(IOT_CTX *iot_ctx, bool confirm)
{
	struct iot_context *ctx = (struct iot_context*)iot_ctx;

	if (ctx->curr_otm_feature == OVF_BIT_BUTTON) {
		if (confirm == true) {
			IOT_INFO("button confirm asserted");
			IOT_ES_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_EASYSETUP_GET_OWNER_CONFIRM, 0);
			iot_os_eventgroup_set_bits(ctx->iot_events, IOT_EVENT_BIT_EASYSETUP_CONFIRM);
		} else if (confirm == false) {
			IOT_INFO("button confirm denied");
			IOT_ES_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_EASYSETUP_CONFIRM_DENIED, 0);
			iot_os_eventgroup_set_bits(ctx->iot_events, IOT_EVENT_BIT_EASYSETUP_CONFIRM_DENY);
		}
	}
}

STATIC_FUNCTION
char *_es_json_parse_string(JSON_H *json, const char *name)
{
	char *buf = NULL;
	JSON_H *recv = NULL;
	unsigned int buf_len;

	if (!json || !name) {
		IOT_ERROR("invalid args");
		return NULL;
	}

	if ((recv = JSON_GET_OBJECT_ITEM(json, name)) == NULL) {
		IOT_INFO("failed to find '%s'", name);
		return NULL;
	}
	buf_len = (strlen(recv->valuestring) + 1);

	IOT_DEBUG("'%s' (%d): %s",
			name, buf_len, recv->valuestring);

	if ((buf = (char *)iot_os_malloc(buf_len)) == NULL) {
		IOT_ERROR("failed to malloc for buf");
		return NULL;
	}
	memset(buf, 0, buf_len);
	memcpy(buf, recv->valuestring, strlen(recv->valuestring));

	return buf;
}

int trans_len = 0;

STATIC_FUNCTION
iot_error_t _encrypt_and_encode(iot_security_context_t *security_context, unsigned char *plain_msg, size_t plain_msg_len, char **out_msg)
{
	iot_error_t err;
	iot_security_buffer_t msg_buf = { 0 };
	iot_security_buffer_t encrypt_buf = { 0 };
	iot_security_buffer_t encrypt_b64url_buf = { 0 };

	if (!security_context || !plain_msg || plain_msg_len == 0) {
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INTERNAL_SERVER_ERROR, 0);
		return IOT_ERROR_EASYSETUP_INTERNAL_SERVER_ERROR;
	}

	msg_buf.p = plain_msg;
	msg_buf.len = plain_msg_len;

	err = iot_security_cipher_aes_encrypt(security_context, &msg_buf, &encrypt_buf);
	if (err != IOT_ERROR_NONE) {
		IOT_ERROR("aes encryption error 0x%x", err);
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_AES256_ENCRYPTION_ERROR, err);
		err = IOT_ERROR_EASYSETUP_AES256_ENCRYPTION_ERROR;
		goto enc_fail;
	}

	trans_len = encrypt_buf.len;

	*out_msg = (char *)encrypt_buf.p;
	return IOT_ERROR_NONE;

enc_fail:
	if (encrypt_buf.p) {
		iot_os_free(encrypt_buf.p);
	}
	if (encrypt_b64url_buf.p) {
		iot_os_free(encrypt_b64url_buf.p);
	}
	return err;
}

extern int recv_size;

STATIC_FUNCTION
iot_error_t _decode_and_decrypt(iot_security_context_t *security_context, unsigned char *encrypt_b64url_msg, size_t encrypt_b64url_msg_len, char **out_msg)
{
	iot_error_t err;
	iot_security_buffer_t decrypt_buf = {0 };
	iot_security_buffer_t plain_buf = { 0 };

	if (!security_context || !encrypt_b64url_msg || encrypt_b64url_msg_len == 0) {
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INTERNAL_SERVER_ERROR, 0);
		return IOT_ERROR_EASYSETUP_INTERNAL_SERVER_ERROR;
	}

	if ((decrypt_buf.p = iot_os_malloc(recv_size)) == NULL) {
		IOT_ERROR("failed to malloc for decode_buf");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_MEM_ALLOC_ERROR, 0);
		err = IOT_ERROR_EASYSETUP_MEM_ALLOC_ERROR;
		goto dec_fail;
	}


	decrypt_buf.len = recv_size;

	memcpy(decrypt_buf.p, encrypt_b64url_msg, decrypt_buf.len);

	err = iot_security_cipher_aes_decrypt(security_context, &decrypt_buf, &plain_buf);
	if (err != IOT_ERROR_NONE) {
		IOT_ERROR("aes decrypt error %d", err);
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_AES256_DECRYPTION_ERROR, err);
		err = IOT_ERROR_EASYSETUP_AES256_DECRYPTION_ERROR;
		goto dec_fail;
	}

	iot_os_free(decrypt_buf.p);
	*out_msg = (char *)plain_buf.p;
	return IOT_ERROR_NONE;

dec_fail:
	if (decrypt_buf.p) {
		iot_os_free(decrypt_buf.p);
	}
	if (plain_buf.p) {
		iot_os_free(plain_buf.p);
	}
	return err;
}

STATIC_FUNCTION
iot_error_t _es_time_set(unsigned char *time)
{
	char time_str[11] = {0,};
	iot_error_t err = IOT_ERROR_NONE;
	struct tm tm = { 0 };
	time_t now = 0;

	if (sscanf((char *)time, "%4d-%2d-%2dT%2d.%2d.%2d", &tm.tm_year, &tm.tm_mon, &tm.tm_mday, &tm.tm_hour, &tm.tm_min, &tm.tm_sec) != 6) {
		IOT_ERROR("Invalid UTC time!!");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_TIME, 0);
		err = IOT_ERROR_EASYSETUP_INVALID_TIME;
		return err;
	}

	/*
	This code is applied by the Year 2038 problem.
	The Year 2038 problem relates to representing time in many digital systems
	as the number of seconds passed since 00:00:00 UTC on 1 January 1970 and storing it as a signed 32-bit integer.
	Such implementations cannot encode times after 03:14:07 UTC on 19 January 2038.
	The Year 2038 problem is caused by insufficient capacity used to represent time.
	If it meet the problem, the time info will be updated by SNTP.
	*/
	if (sizeof(time_t) == 4) {
		if (tm.tm_year >= 2038) {
			IOT_ERROR("Not support time by year 2038 problem(Y2038 Problem)");
			IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_TIME, 0);
			return err;
		}
	}

	tm.tm_year -= 1900;
	tm.tm_mon -= 1;

	now = mktime(&tm);
	snprintf(time_str, sizeof(time_str), "%ld", now);

	err = iot_bsp_system_set_time_in_sec(time_str);
	if (err) {
		IOT_ERROR("Time set error!!");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_TIME, err);
		err = IOT_ERROR_EASYSETUP_INVALID_TIME;
	}
	return err;
}

STATIC_FUNCTION
char* _es_parse_input_data(iot_security_context_t *security_context, char *input_data)
{
	iot_error_t err = IOT_ERROR_NONE;
	char *in_payload = NULL;

	if (!input_data || !security_context) {
		IOT_ERROR("Invalid args");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_REQUEST, 0);
		return NULL;
	}

	err = _decode_and_decrypt(security_context, (unsigned char*) input_data, strlen(input_data), &in_payload);
	if (err != IOT_ERROR_NONE) {
		IOT_ERROR("decrypt and decode fail 0x%x", err);
		goto out;
	}

out:
	return in_payload;
}

STATIC_FUNCTION
char* _es_build_output_data(iot_security_context_t *security_context, char *out_payload)
{
	iot_error_t err = IOT_ERROR_NONE;
	char *encrypted_message = NULL;

	if (!out_payload || !security_context) {
		IOT_ERROR("Invalid args");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_REQUEST, 0);
		return NULL;
	}

	err = _encrypt_and_encode(security_context, (unsigned char*) out_payload, strlen(out_payload), &encrypted_message);
	if (err != IOT_ERROR_NONE) {
		IOT_ERROR("encrypt and encode fail 0x%x", err);
		goto out;
	}

out:
	return encrypted_message;
}

STATIC_FUNCTION
iot_error_t _es_deviceinfo_handler(struct iot_context *ctx, char *in_payload, char **out_payload)
{
	char *output_ptr = NULL;
	JSON_H *root = NULL;
	JSON_H *data = NULL;
	JSON_H *recv = NULL;
	JSON_H *recv_data = NULL;
	unsigned char crand[RANDOM_LEN] = {0};
	unsigned int crand_len = 0;
	unsigned char *crand_str = NULL;
	unsigned char srand[RANDOM_LEN] = {0};
	unsigned int srand_len = 0;
	unsigned char srand_str[STR_DEFAULT_LEN];
	iot_error_t err = IOT_ERROR_NONE;
	static iot_error_t pre_err;
	char *sn_buf = NULL;
	unsigned int sn_len = 0;
	unsigned char sn_str[STR_DEFAULT_LEN] = {0};
	unsigned int sn_str_len = 0;
	unsigned char *sub_cert = NULL;
	unsigned char *dev_cert = NULL;
	unsigned char *spub_key = NULL;
	unsigned char *signature = NULL;
	unsigned int orin_spub_key_len = 0;
	unsigned int orin_signature_len = 0;
     
	if (!ctx) {
		IOT_ERROR("invalid iot_context!!");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INTERNAL_SERVER_ERROR, 0);
		err = IOT_ERROR_EASYSETUP_INTERNAL_SERVER_ERROR;
		return err;
	}

	root = JSON_PARSE(in_payload);
	if (!root) {
		IOT_ERROR("Invalid json format of payload");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_REQUEST, 0);
		err = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto exit;
	}
    
	if ((recv = JSON_GET_OBJECT_ITEM(root, "data")) == NULL) {
		IOT_INFO("no data info");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_REQUEST, 0);
		err  = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto exit;
	}
    
	if ((recv_data = JSON_GET_OBJECT_ITEM(recv, "crand")) == NULL) {
		IOT_INFO("no crand info");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_REQUEST, 0);
		err = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto exit;
	}
	crand_str = (unsigned char *)JSON_GET_STRING_VALUE(recv_data);
	iot_security_base64_decode_urlsafe(crand_str, strlen((char*)crand_str), crand, RANDOM_LEN, &crand_len);
	memcpy(&sec_random[0], crand, RANDOM_LEN);
	JSON_DELETE(root);

	root = JSON_CREATE_OBJECT();
	if (!root) {
		IOT_ERROR("json create failed");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_JSON_CREATE_ERROR, 0);
		err = IOT_ERROR_EASYSETUP_JSON_CREATE_ERROR;
		return err;
	}

	data = JSON_CREATE_OBJECT();

	JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
	JSON_ADD_ITEM_TO_OBJECT(data, "protocolVersion", JSON_CREATE_STRING(STDK_D2D_PROTOCOL_VERSION));
	JSON_ADD_ITEM_TO_OBJECT(data, "firmwareVersion", JSON_CREATE_STRING(ctx->device_info.firmware_version));
	JSON_ADD_ITEM_TO_OBJECT(data, "hashedSn", JSON_CREATE_STRING((char *)ctx->devconf.hashed_sn));
	JSON_ADD_NUMBER_TO_OBJECT(data, "wifiSupportFrequency", (double) iot_bsp_wifi_get_freq());
	JSON_ADD_NUMBER_TO_OBJECT(data, "wifiSupportAuthType", (double)AUTH_TYPE_WPA2_PSK);    //TBD

	static char pre_err_str[PREERR_STR_LEN];
	itoa(pre_err, pre_err_str, 10);
	JSON_ADD_ITEM_TO_OBJECT(data, "prevErrorCode", JSON_CREATE_STRING(pre_err_str));

	unsigned int rnd;
	for (int i = 0; i < 4; i++) {
		rnd = iot_bsp_random();
		srand[i * 4 + 0] = (unsigned char)((rnd >> 0)  & 0x000000FF);
		srand[i * 4 + 1] = (unsigned char)((rnd >> 8)  & 0x000000FF);
		srand[i * 4 + 2] = (unsigned char)((rnd >> 16) & 0x000000FF);
		srand[i * 4 + 3] = (unsigned char)((rnd >> 24) & 0x000000FF);
	}

	memcpy(&sec_random[RANDOM_LEN], srand, RANDOM_LEN);

	iot_security_base64_encode_urlsafe(srand, RANDOM_LEN, srand_str, sizeof(srand_str), &srand_len);

	JSON_ADD_ITEM_TO_OBJECT(data, "srand", JSON_CREATE_STRING((char *)srand_str));

	err = iot_easysetup_ble_ecdh_init(&ctx->easysetup_security_context);
	if (err != IOT_ERROR_NONE) {
		IOT_ERROR("security setup fail 0x%x", err);
		err = IOT_ERROR_EASYSETUP_SHARED_KEY_INIT_FAIL;
		goto exit;
	}

       err = iot_easysetup_ble_ecdh_compute_shared_signature(&ctx->easysetup_security_context, sec_random,
				&dev_cert, &sub_cert, &spub_key, &orin_spub_key_len, &signature, &orin_signature_len);
	if (err != IOT_ERROR_NONE) {
		IOT_ERROR("shared signature creation fail 0x%x", err);
		err = IOT_ERROR_EASYSETUP_SHARED_SIGNATURE_CREATION_FAIL;
		goto exit;
	}

	unsigned char spub_key_str[128];
	unsigned int spub_key_len = 0;
	iot_security_base64_encode_urlsafe(spub_key,orin_spub_key_len,spub_key_str, sizeof(spub_key_str), &spub_key_len);

	unsigned char signature_str[128];
	unsigned int signature_len = 0;
	iot_security_base64_encode_urlsafe(signature,orin_signature_len,signature_str, sizeof(signature_str), &signature_len);

	JSON_ADD_ITEM_TO_OBJECT(data, "subCaCert", JSON_CREATE_STRING((char *)sub_cert));
	JSON_ADD_ITEM_TO_OBJECT(data, "deviceCert", JSON_CREATE_STRING((char *)dev_cert));
	JSON_ADD_ITEM_TO_OBJECT(data, "spubKey", JSON_CREATE_STRING((char *)spub_key_str));
	JSON_ADD_ITEM_TO_OBJECT(data, "signature", JSON_CREATE_STRING((char *)signature_str));

	JSON_ADD_ITEM_TO_OBJECT(data, "cloudlog", JSON_CREATE_STRING("NULL"));
	JSON_ADD_NUMBER_TO_OBJECT(root, "errorcode", 0);

	output_ptr = JSON_PRINT(root);
    
	*out_payload = output_ptr;
exit:
	if (root)
		JSON_DELETE(root);
	if (sn_buf)
		iot_os_free(sn_buf);
	if (sub_cert)
		iot_os_free(sub_cert);
	if (dev_cert)
		iot_os_free(dev_cert);
	if (spub_key)
		iot_os_free(spub_key);
	if (signature)
		iot_os_free(signature);
	pre_err = err;
		return err;
}

STATIC_FUNCTION
iot_error_t _es_keyinfo_handler(struct iot_context *ctx, char *input_data, char **output_data)
{
	JSON_H *recv = NULL;
	JSON_H *recv_data = NULL;
	JSON_H *root = NULL;
    JSON_H *data = NULL;
	JSON_H *array = NULL;
	unsigned int i;
	iot_error_t err = IOT_ERROR_NONE;
    iot_security_cipher_params_t cipher_set_params = { 0 };
	iot_security_ecdh_params_t ecdh_params = { 0 };
	iot_security_buffer_t secret_buf = { 0 };
	iot_security_buffer_t peer_pubkey_buf = { 0 };
	iot_security_buffer_t data_buf = { 0 };
	iot_security_buffer_t hash_buf = { 0 };
	iot_security_buffer_t iv = { 0 };
    unsigned char *p_cpubkey_str = NULL;
	unsigned char *p_datetime_str = NULL;
	unsigned char *p_regionaldatetime_str = NULL;
	unsigned char *p_timezoneid_str = NULL;
	char *out_payload = NULL;
    unsigned char secret[IOT_SECURITY_SECRET_LEN] = { 0 };
	unsigned char *decode_buf = NULL;
	size_t input_len = 0;
	size_t output_len = 0;
	size_t result_len = 0;
	size_t secret_len = 0;

	root = JSON_PARSE(input_data);
	if (!root) {
		IOT_ERROR("Invalid json format of payload");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_REQUEST, 0);
		err = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto exit;
	}

	if ((recv = JSON_GET_OBJECT_ITEM(root, "data")) == NULL) {
		IOT_ERROR("no data info");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_REQUEST, 0);
		err = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto exit;
	}

	if ((recv_data = JSON_GET_OBJECT_ITEM(recv, "cpubKey")) == NULL) {
		IOT_ERROR("no cpubKey info");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_REQUEST, 0);
		err  = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto exit;
	}
	p_cpubkey_str = (unsigned char *)JSON_GET_STRING_VALUE(recv_data);
	IOT_DEBUG("cpubKey: %s \r\n",p_cpubkey_str); // Stoage later


	input_len = (unsigned int)strlen((char*)p_cpubkey_str);
	output_len = IOT_SECURITY_B64_DECODE_LEN(input_len);
	if ((decode_buf = iot_os_malloc(output_len)) == NULL) {
		IOT_ERROR("failed to malloc for decode_buf");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_MEM_ALLOC_ERROR, 0);
		err = IOT_ERROR_EASYSETUP_MEM_ALLOC_ERROR;
		goto exit_secret;
	}
	memset(decode_buf, 0, output_len);

	err = iot_security_base64_decode_urlsafe((unsigned char *) p_cpubkey_str, input_len,
					decode_buf, output_len,
					&result_len);
	if (err) {
		IOT_ERROR("base64 decode error!! : %d", err);
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_BASE64_DECODE_ERROR, err);
		err = IOT_ERROR_EASYSETUP_BASE64_DECODE_ERROR;
		goto exit_secret;
	}

	peer_pubkey_buf.p = iot_os_malloc(65);
	memcpy(peer_pubkey_buf.p, decode_buf + 26, 65);

	ecdh_params.key_id = IOT_SECURITY_KEY_ID_EPHEMERAL;
	ecdh_params.c_pubkey.p = peer_pubkey_buf.p;
	ecdh_params.c_pubkey.len = 65;
	ecdh_params.salt.p = sec_random;
	ecdh_params.salt.len = 32;

	err = iot_security_ecdh_set_params(ctx->easysetup_security_context, &ecdh_params);
	if (err) {
		IOT_ERROR("iot_security_ecdh_set_params = %d", err);
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_SHARED_KEY_PARAMS_FAIL, err);
		err = IOT_ERROR_EASYSETUP_SHARED_KEY_PARAMS_FAIL;
		goto exit_ecdh_deinit;
	}

	err = iot_security_ecdh_compute_shared_secret(ctx->easysetup_security_context, &secret_buf);
	if (err) {
		IOT_ERROR("master secret generation failed %d", err);
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_SHARED_KEY_CREATION_FAIL, err);
		err = IOT_ERROR_EASYSETUP_SHARED_KEY_CREATION_FAIL;
		goto exit_ecdh_deinit;
	} else {
		IOT_INFO("master secret generation success");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_EASYSETUP_MASTER_SECRET_GENERATION_SUCCESS, 0);
	}

	memcpy(secret, secret_buf.p, secret_buf.len);

	secret_len = sizeof(secret);

	data_buf.len = secret_len + sizeof(sec_random);
	data_buf.p = (unsigned char *)iot_os_malloc(data_buf.len);
	memcpy(data_buf.p, secret, secret_len);
	memcpy(data_buf.p + secret_len, sec_random, sizeof(sec_random));

	hash_buf.len = IOT_SECURITY_SHA256_LEN;
	hash_buf.p = (unsigned char *)iot_os_malloc(hash_buf.len);

	err = iot_security_sha256(data_buf.p, data_buf.len, hash_buf.p, hash_buf.len);

	iv.len = IOT_SECURITY_IV_LEN;
	iv.p = (unsigned char *)iot_os_malloc(IOT_SECURITY_IV_LEN);

	memcpy(iv.p, hash_buf.p, IOT_SECURITY_IV_LEN);

	cipher_set_params.type = IOT_SECURITY_KEY_TYPE_AES256;
	cipher_set_params.iv = iv;

	err = iot_security_cipher_set_params(ctx->easysetup_security_context, &cipher_set_params);
	if (err != IOT_ERROR_NONE) {
		IOT_ERROR("failed to set cipher params");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_CIPHER_PARAMS_ERROR, 0);
		err = IOT_ERROR_EASYSETUP_CIPHER_PARAMS_ERROR;
		goto exit_ecdh_deinit;
	}

	if ((recv = JSON_GET_OBJECT_ITEM(root, "datetime")) == NULL) {
		IOT_INFO("no datetime info");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_REQUEST, 0);
		goto skip_time_set;
	}
	p_datetime_str = (unsigned char *)JSON_GET_STRING_VALUE(recv);

	input_len = (unsigned int)strlen((char*)p_datetime_str);
	output_len = IOT_SECURITY_B64_DECODE_LEN(input_len);
	if ((decode_buf = iot_os_malloc(output_len)) == NULL) {
		IOT_ERROR("failed to malloc for decode_buf");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_MEM_ALLOC_ERROR, 0);
		err = IOT_ERROR_EASYSETUP_MEM_ALLOC_ERROR;
		goto exit_secret;
	}
	memset(decode_buf, 0, output_len);

	err = iot_security_base64_decode_urlsafe((unsigned char *) p_datetime_str, input_len,
					decode_buf, output_len,
					&result_len);
	if (err) {
		IOT_ERROR("base64 decode error!! : %d", err);
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_BASE64_DECODE_ERROR, err);
		err = IOT_ERROR_EASYSETUP_BASE64_DECODE_ERROR;
		goto exit_secret;
	}

	IOT_DEBUG("datetime = %s", decode_buf);

	err = _es_time_set(decode_buf);
	if (err) {
		goto exit_secret;
	}
	iot_os_free(decode_buf);
	decode_buf = NULL;

	if ((recv = JSON_GET_OBJECT_ITEM(root, "regionaldatetime")) == NULL) {
		IOT_INFO("no regionaldatetime info");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_REQUEST, 0);
		err  = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto exit_secret;
	}
	p_regionaldatetime_str = (unsigned char *)JSON_GET_STRING_VALUE(recv);

	input_len = (unsigned int)strlen((char*)p_regionaldatetime_str);
	output_len = IOT_SECURITY_B64_DECODE_LEN(input_len);
	if ((decode_buf = iot_os_malloc(output_len)) == NULL) {
		IOT_ERROR("failed to malloc for decode_buf");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_MEM_ALLOC_ERROR, 0);
		err = IOT_ERROR_EASYSETUP_MEM_ALLOC_ERROR;
		goto exit_secret;
	}
	memset(decode_buf, 0, output_len);

	err = iot_security_base64_decode_urlsafe((unsigned char *) p_regionaldatetime_str, input_len,
					decode_buf, output_len,
					&result_len);
	if (err) {
		IOT_ERROR("base64 decode error!! : %d", err);
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_BASE64_DECODE_ERROR, err);
		err = IOT_ERROR_EASYSETUP_BASE64_DECODE_ERROR;
		goto exit_secret;
	}
	IOT_DEBUG("regionaldatetime = %s", decode_buf);
	iot_os_free(decode_buf); // TODO: how to use this value
	decode_buf = NULL;

	if ((recv = JSON_GET_OBJECT_ITEM(root, "timezoneid")) == NULL) {
		IOT_INFO("no timezoneid info");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_REQUEST, 0);
		err  = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto exit_secret;
	}
	p_timezoneid_str = (unsigned char *)JSON_GET_STRING_VALUE(recv);

	input_len = (unsigned int)strlen((char*)p_timezoneid_str);
	output_len = IOT_SECURITY_B64_DECODE_LEN(input_len);
	if ((decode_buf = iot_os_malloc(output_len)) == NULL) {
		IOT_ERROR("failed to malloc for decode_buf");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_MEM_ALLOC_ERROR, 0);
		err = IOT_ERROR_EASYSETUP_MEM_ALLOC_ERROR;
		goto exit_secret;
	}

	memset(decode_buf, 0, output_len);

	err = iot_security_base64_decode_urlsafe((unsigned char *) p_timezoneid_str, input_len,
					decode_buf, output_len,
					&result_len);
	if (err) {
		IOT_ERROR("base64 decode error!! : %d", err);
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_BASE64_DECODE_ERROR, err);
		err = IOT_ERROR_EASYSETUP_BASE64_DECODE_ERROR;
		goto exit_secret;
	}

	IOT_DEBUG("timezoneid = %s", decode_buf); // TODO: where to store

skip_time_set:

	JSON_DELETE(root);

	root = JSON_CREATE_OBJECT();
	if (!root) {
		IOT_ERROR("json create failed");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_MEM_ALLOC_ERROR, 0);
		err = IOT_ERROR_EASYSETUP_MEM_ALLOC_ERROR;
		goto exit_secret;
	}

	data = JSON_CREATE_OBJECT();

	JSON_ADD_ITEM_TO_OBJECT(root, "data", data);

	array = JSON_CREATE_ARRAY();
	if (!array) {
		IOT_ERROR("json create failed");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_MEM_ALLOC_ERROR, 0);
		err = IOT_ERROR_EASYSETUP_MEM_ALLOC_ERROR;
		goto exit_secret;
	}

	for (i = OVF_BIT_JUSTWORKS; i < OVF_BIT_MAX_FEATURE; i++) {
		if ((i == OVF_BIT_JUSTWORKS) && ctx->add_justworks) {
			JSON_ADD_ITEM_TO_ARRAY(array, JSON_CREATE_NUMBER(i));
		} else if (ctx->devconf.ownership_validation_type & (unsigned)(1 << i)) {
			JSON_ADD_ITEM_TO_ARRAY(array, JSON_CREATE_NUMBER(i));
		}
	}
	JSON_ADD_ITEM_TO_OBJECT(data, "otmSupportFeatures", array);
	JSON_ADD_NUMBER_TO_OBJECT(root, "errorcode", 0);

	out_payload = JSON_PRINT(root);
	*output_data = _es_build_output_data(ctx->easysetup_security_context, out_payload);

exit_secret:
	if (decode_buf) {
		free(decode_buf);
	}
	if (out_payload) {
		free(out_payload);
	}
	if (err && secret_buf.p) {
		free(secret_buf.p);
	}
exit_ecdh_deinit:
	iot_security_ecdh_deinit(ctx->easysetup_security_context);
exit:
	if (root) {
		JSON_DELETE(root);
	}
	return err;
}

STATIC_FUNCTION
iot_error_t _es_confirm_check_manager(struct iot_context *ctx, enum ownership_validation_feature confirm_feature, char *sn)
{
	char *dev_sn = NULL;
	unsigned char curr_event = 0;
	unsigned char is_qr = 0;
	size_t devsn_len;
	iot_error_t err = IOT_ERROR_NONE;
	struct iot_st_ecode st_ecode;

	iot_os_eventgroup_clear_bits(ctx->iot_events, IOT_EVENT_BIT_EASYSETUP_CONFIRM | IOT_EVENT_BIT_EASYSETUP_CONFIRM_DENY);
	ctx->curr_otm_feature = confirm_feature;

	IOT_REMARK("IOT_STATE_PROV_CONFIRMING");

	err = iot_state_update(ctx, IOT_STATE_PROV_CONFIRM,
			IOT_STATE_OPT_NEED_INTERACT);
	if (err != IOT_ERROR_NONE) {
		IOT_ERROR("failed handle cmd (%d): %d", IOT_STATE_PROV_CONFIRM, err);
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INTERNAL_SERVER_ERROR, err);
		err = IOT_ERROR_EASYSETUP_INTERNAL_SERVER_ERROR;
		goto out;
	}

	switch (confirm_feature)
	{
		case OVF_BIT_JUSTWORKS:
			IOT_INFO("There is no confirmation request. The check is skipped");
			IOT_ES_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_EASYSETUP_OTMTYPE_JUSTWORK, 0);
			break;
		case OVF_BIT_QR:
			is_qr = 1;
			// fall through
		case OVF_BIT_SERIAL_NUMBER:
			IOT_INFO("The %s confirmation is requested", is_qr ? "QR code" : "serial number");
			IOT_ES_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_EASYSETUP_OTMTYPE_QR, is_qr);
			if (sn == NULL) {
				IOT_ERROR("null serial number transferred");
				IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_QR, is_qr);
				err = IOT_ERROR_EASYSETUP_INVALID_QR;
				goto out;
			}

			err = iot_nv_get_serial_number(&dev_sn, &devsn_len);
			if (err != IOT_ERROR_NONE) {
				IOT_ERROR("failed to load serial number");
				IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_SERIAL_NOT_FOUND, err);
				err = IOT_ERROR_EASYSETUP_SERIAL_NOT_FOUND;
				goto out;
			}

			if (!strcmp(sn, dev_sn)) {
				IOT_INFO("confirm");
				IOT_ES_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_EASYSETUP_GET_OWNER_CONFIRM, 0);
			} else {
				IOT_ERROR("confirm fail");
				IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_SERIAL_NUMBER, is_qr);
				err = IOT_ERROR_EASYSETUP_INVALID_SERIAL_NUMBER;
				goto out;
			}
			break;
		case OVF_BIT_BUTTON:
			IOT_INFO("The button confirmation is requested");
			IOT_ES_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_EASYSETUP_OTMTYPE_BUTTON, 0);

			curr_event = iot_os_eventgroup_wait_bits(ctx->iot_events, IOT_EVENT_BIT_EASYSETUP_CONFIRM | IOT_EVENT_BIT_EASYSETUP_CONFIRM_DENY, false, ES_CONFIRM_MAX_DELAY);
			IOT_DEBUG("curr_event = 0x%x", curr_event);

			if (curr_event & IOT_EVENT_BIT_EASYSETUP_CONFIRM) {
				IOT_INFO("confirm");
				IOT_ES_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_EASYSETUP_GET_OWNER_CONFIRM, 0);
			} else {
				IOT_ERROR("confirm failed");
				IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_CONFIRM_DENIED, 0);
				iot_set_st_ecode(ctx, IOT_ST_ECODE_EE01);

				/* To report confirm failure to user, try to change iot-state timeout value shortly */
				if (iot_state_timeout_change(ctx, IOT_STATE_PROV_CONFIRM, ES_CONFIRM_FAIL_TIMEOUT) != IOT_ERROR_NONE) {
					IOT_ERROR("Can't update prov_confirm state timeout");
				}

				err = IOT_ERROR_EASYSETUP_CONFIRM_DENIED;
				goto out;
			}
			break;
		case OVF_BIT_PIN:
			IOT_INFO("The pin number confirmation is requested");
			IOT_ES_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_EASYSETUP_OTMTYPE_PIN, 0);
			return err;
		default:
			IOT_INFO("Not Supported confirmation type is requested");
			IOT_ES_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_EASYSETUP_OTMTYPE_NOT_SUPPORTED, 0);
			return err;
	}

out:
	if (dev_sn)
		free(dev_sn);
	return err;
}

STATIC_FUNCTION
iot_error_t _es_confirminfo_handler(struct iot_context *ctx, char *input_data, char **output_data)
{
	JSON_H *recv = NULL;
	JSON_H *root = NULL;
    JSON_H *recv_data = NULL;
	iot_error_t err = IOT_ERROR_NONE;
	char *in_payload = NULL;
	char *out_payload = NULL;

	if (!ctx || !input_data) {
		IOT_ERROR("Invalid data is reported");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INTERNAL_SERVER_ERROR, 0);
		err = IOT_ERROR_EASYSETUP_INTERNAL_SERVER_ERROR;
		return err;
	}

	in_payload = _es_parse_input_data(ctx->easysetup_security_context, input_data);
	if (!in_payload) {
		IOT_ERROR("Failed to get input payload");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_REQUEST, 0);
		err = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto out;
	}

   	root = JSON_PARSE(in_payload);
	if (!root) {
		IOT_ERROR("parse error");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_REQUEST, 0);
		goto out;
	}

	if ((recv_data = JSON_GET_OBJECT_ITEM(root, "data")) == NULL) {
		IOT_INFO("no data info");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_REQUEST, 0);
		err  = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto out;
	}

    if ((recv = JSON_GET_OBJECT_ITEM(recv_data, "otmSupportFeature")) == NULL) {
        IOT_ERROR("no otmsupportfeature info");
        IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_REQUEST, 0);
        err = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
        goto out;
    }

	IOT_INFO("otmSupportFeature = %d", recv->valueint);
	IOT_ES_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_EASYSETUP_REPORTED_OTMTYPE, recv->valueint);

	if ((recv->valueint >= OVF_BIT_JUSTWORKS) && (recv->valueint <= OVF_BIT_SERIAL_NUMBER)) {
		char *sn = NULL;

		if (recv->valueint == OVF_BIT_QR || recv->valueint == OVF_BIT_SERIAL_NUMBER)
			sn = _es_json_parse_string(root, "sn");

		err = _es_confirm_check_manager(ctx, recv->valueint, sn);

		if (sn) {
			iot_os_free(sn);
		}
		if (err != IOT_ERROR_NONE)
			goto out;
	} else {
		IOT_ERROR("Not supported otmsupportfeature : %d", recv->valueint);
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_CONFIRM_NOT_SUPPORT, recv->valueint);
		err = IOT_ERROR_EASYSETUP_CONFIRM_NOT_SUPPORT ;
		goto out;
	}
	JSON_DELETE(root);


	root = JSON_CREATE_OBJECT();
	if (!root) {
		IOT_ERROR("json create failed");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_JSON_CREATE_ERROR, 0);
		err = IOT_ERROR_EASYSETUP_JSON_CREATE_ERROR;
		goto out;
	}

    JSON_ADD_NUMBER_TO_OBJECT(root, "errorcode", 0);
	out_payload = JSON_PRINT(root);
	*output_data = _es_build_output_data(ctx->easysetup_security_context, out_payload);
out:
	if (out_payload) {
		iot_os_free(out_payload);
	}
	if (in_payload) {
		iot_os_free(in_payload);
	}
	if (root) {
		JSON_DELETE(root);
	}
	return err;
}

STATIC_FUNCTION
iot_error_t _es_confirm_handler(struct iot_context *ctx, char *input_data, char **output_data)
{
	bool validation = true;
	char pin[PIN_SIZE + 1];
	JSON_H *recv = NULL;
	JSON_H *root = NULL;
	int i;
	iot_error_t err = IOT_ERROR_NONE;
	char *out_payload = NULL;
	char *in_payload = NULL;

	if (!ctx || !ctx->pin) {
		IOT_ERROR("no pin from device app");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_PIN_NOT_FOUND, 0);
		err = IOT_ERROR_EASYSETUP_PIN_NOT_FOUND;
		return err;
	}

	if (ctx->curr_otm_feature != OVF_BIT_PIN) {
		IOT_ERROR("otm is not pin.");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_CMD, 0);
		err = IOT_ERROR_EASYSETUP_INVALID_CMD;
		return err;
	}

	in_payload = _es_parse_input_data(ctx->easysetup_security_context, input_data);
	if (!in_payload) {
		IOT_ERROR("Failed to get input payload");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_REQUEST, 0);
		err = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto out;
	}

	root = JSON_PARSE(in_payload);
	if (!root) {
		IOT_ERROR("Invalid payload json format");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_REQUEST, 0);
		err = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto out;
	}

	if ((recv = JSON_GET_OBJECT_ITEM(root, "pin")) == NULL) {
		IOT_ERROR("no pin info");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_REQUEST, 0);
		err = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto out;
	}

	if (strlen(JSON_GET_STRING_VALUE(recv)) != PIN_SIZE) {
		IOT_ERROR("pin size mistmatch");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_PIN, 0);
		err = IOT_ERROR_EASYSETUP_INVALID_PIN;
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

	if (!validation) {
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_PIN, 0);
		err = IOT_ERROR_EASYSETUP_INVALID_PIN;
		goto out;
	}

	for (i = 0; i < PIN_SIZE; i++) {
		if (ctx->pin->pin[i] != pin[i]) {
			IOT_ERROR("the reported pin number is not matched[%d]", i);
			validation = false;
			break;
		}
	}

	if (!validation) {
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_PIN_NOT_MATCHED, 0);
		err = IOT_ERROR_EASYSETUP_PIN_NOT_MATCHED;
		goto out;
	}
	JSON_DELETE(root);

	/*
	 * output payload
	 */
	root = JSON_CREATE_OBJECT();
	if (!root) {
		IOT_ERROR("json create failed");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_JSON_CREATE_ERROR, 0);
		err = IOT_ERROR_EASYSETUP_JSON_CREATE_ERROR;
		goto out;
	}
	out_payload = JSON_PRINT(root);
	*output_data = _es_build_output_data(ctx->easysetup_security_context, out_payload);
out:
	if (out_payload) {
		free(out_payload);
	}
	if (in_payload) {
		free(in_payload);
	}
	if (root) {
		JSON_DELETE(root);
	}
	return err;
}

STATIC_FUNCTION
iot_error_t _es_wifiscaninfo_handler(struct iot_context *ctx, char **output_data)
{
	char wifi_bssid[WIFIINFO_BUFFER_SIZE] = {0, };
	JSON_H *root = NULL;
	JSON_H *array = NULL;
	JSON_H *array_obj = NULL;
	int i;
	iot_error_t err = IOT_ERROR_NONE;
	char *out_payload = NULL;
    JSON_H *data = NULL;

	if (!ctx) {
		IOT_ERROR("invalid iot_context!!");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INTERNAL_SERVER_ERROR, 0);
		err = IOT_ERROR_EASYSETUP_INTERNAL_SERVER_ERROR;
		return err;
	}

	//optional : some chipsets don't support wifi scan mode during working AP mode
	err = iot_wifi_ctrl_request(ctx, IOT_WIFI_MODE_SCAN);
	if (err != IOT_ERROR_NONE) {
		IOT_INFO("Can't control WIFI mode scan.(%d)", err);
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_EASYSETUP_WIFI_SCAN_NOT_FOUND, err);
	}

	if (!ctx->scan_num) {
		IOT_ERROR("wifi AP isn't found!!");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_WIFI_SCAN_NOT_FOUND, ctx->scan_num);
		err = IOT_ERROR_EASYSETUP_WIFI_SCAN_NOT_FOUND;
		return err;
	}

	array = JSON_CREATE_ARRAY();
	if (!array) {
		IOT_ERROR("json_array create failed");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_JSON_CREATE_ERROR, 0);
		err = IOT_ERROR_EASYSETUP_JSON_CREATE_ERROR;
		return err;
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

		array_obj = JSON_CREATE_OBJECT();
		if (!array_obj) {
			IOT_ERROR("json create failed");
			if (array) {
				JSON_DELETE(array);
			}
			IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_JSON_CREATE_ERROR, 0);
			err = IOT_ERROR_EASYSETUP_JSON_CREATE_ERROR;
			goto out;
		}
		JSON_ADD_ITEM_TO_OBJECT(array_obj, "bssid", JSON_CREATE_STRING(wifi_bssid));
		JSON_ADD_ITEM_TO_OBJECT(array_obj, "ssid", JSON_CREATE_STRING((char*)ctx->scan_result[i].ssid));
		JSON_ADD_NUMBER_TO_OBJECT(array_obj, "rssi", (double) ctx->scan_result[i].rssi);
		JSON_ADD_NUMBER_TO_OBJECT(array_obj, "frequency", (double) ctx->scan_result[i].freq);
		JSON_ADD_NUMBER_TO_OBJECT(array_obj, "authType", ctx->scan_result[i].authmode);
		JSON_ADD_ITEM_TO_ARRAY(array, array_obj);
	}

	root = JSON_CREATE_OBJECT();
	if (!root) {
		IOT_ERROR("json create failed");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_JSON_CREATE_ERROR, 0);
		err = IOT_ERROR_EASYSETUP_JSON_CREATE_ERROR;
		if (array) {
			JSON_DELETE(array);
		}
		goto out;
	}

	data = JSON_CREATE_OBJECT();

	JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    
	JSON_ADD_ITEM_TO_OBJECT(data, "wifiScanInfo", array);
    JSON_ADD_NUMBER_TO_OBJECT(root, "errorcode", 0);

	out_payload = JSON_PRINT(root);
	*output_data = _es_build_output_data(ctx->easysetup_security_context, out_payload);
out:
	if (out_payload) {
		free(out_payload);
	}
	if (root) {
		JSON_DELETE(root);
	}
	return err;
}

STATIC_FUNCTION
iot_wifi_auth_mode_t _decide_wifi_auth_mode(const JSON_H *item, struct iot_wifi_prov_data *wifi_prov, const struct iot_context *ctx)
{
	iot_wifi_auth_mode_t auth_mode = IOT_WIFI_AUTH_WPA_WPA2_PSK;
	int i;

	if (!ctx || !wifi_prov) {
		return IOT_WIFI_AUTH_WPA_WPA2_PSK;
	}

	if (item == NULL) {
		IOT_INFO("no authType");
		for (i = 0; i < ctx->scan_num; i++) {
			if (!strcmp(wifi_prov->ssid, (char *)ctx->scan_result[i].ssid)) {
				auth_mode = ctx->scan_result[i].authmode;
				IOT_DEBUG("%s is type %d", wifi_prov->ssid, auth_mode);
				break;
			}
		}
		if (i == ctx->scan_num) {
			if (strlen(wifi_prov->password) == 0) {
				IOT_DEBUG("%s doesn't exist in scan list. So assume it as Open", wifi_prov->ssid);
				auth_mode = IOT_WIFI_AUTH_OPEN;
			} else {
				IOT_DEBUG("%s doesn't exist in scan list. So assume it as WPA", wifi_prov->ssid);
				auth_mode = IOT_WIFI_AUTH_WPA_WPA2_PSK;
			}
		}
	} else {
		for (i = 0; i < ctx->scan_num; i++) {
			if (!strcmp(wifi_prov->ssid, (char *)ctx->scan_result[i].ssid)) {
				if (item->valueint == ctx->scan_result[i].authmode) {
					auth_mode = item->valueint;
				} else {
					auth_mode = ctx->scan_result[i].authmode;
				}
				break;
			}
		}
		if (i == ctx->scan_num) {
			auth_mode = item->valueint;
		}
		IOT_DEBUG("%s is type %d", wifi_prov->ssid, auth_mode);
	}

	return auth_mode;
}

STATIC_FUNCTION
iot_error_t _es_wifi_prov_parse(struct iot_context *ctx, char *in_payload)
{
	struct iot_wifi_prov_data *wifi_prov = NULL;
	JSON_H *item = NULL;
	JSON_H *root = NULL;
    JSON_H *data = NULL;
	JSON_H *wifi_credential = NULL;
	iot_error_t err = IOT_ERROR_NONE;

	root = JSON_PARSE(in_payload);
	if (!root) {
		IOT_ERROR("Invalid args");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_REQUEST, 0);
		err = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto wifi_parse_out;
	}

	if ((data = JSON_GET_OBJECT_ITEM(root, "data")) == NULL) {
		IOT_INFO("no data info");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_REQUEST, 0);
		err  = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto wifi_parse_out;
	}

	if ((wifi_credential = JSON_GET_OBJECT_ITEM(data, "wifiCredential")) == NULL) {
		IOT_ERROR("failed to find wifiCredential");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_REQUEST, 0);
		err = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto wifi_parse_out;
	}

	if ((wifi_prov = (struct iot_wifi_prov_data *)malloc(sizeof(struct iot_wifi_prov_data))) == NULL) {
		IOT_ERROR("failed to malloc for wifi_prov_data");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_MEM_ALLOC_ERROR, 0);
		err = IOT_ERROR_EASYSETUP_MEM_ALLOC_ERROR;
		goto wifi_parse_out;
	}

	memset(wifi_prov, 0, sizeof(struct iot_wifi_prov_data));

	if ((item = JSON_GET_OBJECT_ITEM(wifi_credential, "ssid")) == NULL) {
		IOT_ERROR("failed to find ssid");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_REQUEST, 0);
		err = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto wifi_parse_out;
	}
	strncpy(wifi_prov->ssid, JSON_GET_STRING_VALUE(item), sizeof(wifi_prov->ssid) - 1);

	// password is optional.
	if ((item = JSON_GET_OBJECT_ITEM(wifi_credential, "password")) == NULL)
		IOT_INFO("No wifi password");
	else
		strncpy(wifi_prov->password, JSON_GET_STRING_VALUE(item), sizeof(wifi_prov->password) - 1);

	if ((item = JSON_GET_OBJECT_ITEM(wifi_credential, "macAddress")) == NULL) {
		IOT_INFO("no macAddress");
	} else {
		strncpy(wifi_prov->mac_str, JSON_GET_STRING_VALUE(item), sizeof(wifi_prov->mac_str));
		err = iot_util_convert_str_mac(wifi_prov->mac_str, &wifi_prov->bssid);
		if (err) {
			IOT_ERROR("Failed to convert str to mac address (error : %d) : %s", err, wifi_prov->mac_str);
			IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_MAC, err);
			err = IOT_ERROR_EASYSETUP_INVALID_MAC;
			goto wifi_parse_out;
		}
	}

	wifi_prov->security_type =
		_decide_wifi_auth_mode(JSON_GET_OBJECT_ITEM(wifi_credential, "authType"), wifi_prov, ctx);

	err = iot_nv_set_wifi_prov_data(wifi_prov);
	if (err) {
		IOT_ERROR("failed to set the cloud prov data");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_WIFI_DATA_WRITE_FAIL, err);
		err = IOT_ERROR_EASYSETUP_WIFI_DATA_WRITE_FAIL;
		goto wifi_parse_out;
	}

	IOT_INFO("ssid: %s", wifi_prov->ssid);
	IOT_DEBUG("password: %s", wifi_prov->password);
	IOT_INFO("mac addr: %s", wifi_prov->mac_str);

wifi_parse_out:
	if (wifi_prov)
		free(wifi_prov);
	if (root)
		JSON_DELETE(root);
	return err;
}

STATIC_FUNCTION
iot_error_t _es_cloud_prov_parse(struct iot_context *ctx, char *in_payload)
{
	struct iot_cloud_prov_data *cloud_prov = NULL;
	char *full_url = NULL;
	JSON_H *root = NULL;
    JSON_H *data = NULL;
	iot_error_t err = IOT_ERROR_NONE;
	url_parse_t url = { .protocol = NULL, .domain = NULL, .port = 0};

	root = JSON_PARSE(in_payload);
	if (!root) {
		IOT_ERROR("Invalid payload json format");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_REQUEST, 0);
		err = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto cloud_parse_out;
	}

	if ((data = JSON_GET_OBJECT_ITEM(root, "data")) == NULL) {
		IOT_INFO("no data info");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_REQUEST, 0);
		err  = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto cloud_parse_out;
	}

	if ((cloud_prov = (struct iot_cloud_prov_data *)malloc(sizeof(struct iot_cloud_prov_data))) == NULL) {
		IOT_ERROR("failed to alloc mem");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_MEM_ALLOC_ERROR, 0);
		err = IOT_ERROR_EASYSETUP_MEM_ALLOC_ERROR;
		goto cloud_parse_out;
	}

	memset(cloud_prov, 0, sizeof(struct iot_cloud_prov_data));

	if ((full_url = _es_json_parse_string(data, "brokerUrl")) == NULL) {
		IOT_ERROR("failed to find brokerUrl");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_REQUEST, 0);
		err = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto cloud_parse_out;
	}

	err = iot_util_url_parse(full_url, &url);
	if (err) {
		IOT_ERROR("failed to parse broker url");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_BROKER_URL, err);
		err = IOT_ERROR_EASYSETUP_INVALID_BROKER_URL;
		goto cloud_parse_out;
	}

	if ((cloud_prov->label = _es_json_parse_string(data, "deviceName")) == NULL) {
		IOT_INFO("No deviceName");
	}

	cloud_prov->broker_url = url.domain;
	cloud_prov->broker_port = url.port;

	err = iot_nv_set_cloud_prov_data(cloud_prov);
	if (err) {
		IOT_ERROR("failed to set the cloud prov data");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_CLOUD_DATA_WRITE_FAIL, err);
		cloud_prov->broker_port = 0;
		err = IOT_ERROR_EASYSETUP_CLOUD_DATA_WRITE_FAIL;
		goto cloud_prov_data_fail;
	}

	IOT_INFO("brokerUrl: %s:%d", cloud_prov->broker_url, cloud_prov->broker_port);
	IOT_INFO("deviceName : %s", cloud_prov->label);

cloud_prov_data_fail:
	if (cloud_prov->label) {
		iot_os_free(cloud_prov->label);
	}
cloud_parse_out:
	if (url.domain) {
		iot_os_free(url.domain);
	}
	if (url.protocol) {
		iot_os_free(url.protocol);
	}
	if (full_url) {
		iot_os_free(full_url);
	}
	if (cloud_prov) {
		iot_os_free(cloud_prov);
	}
	if (root) {
		JSON_DELETE(root);
	}
	return err;
}

STATIC_FUNCTION
iot_error_t _es_wifiprovisioninginfo_handler(struct iot_context *ctx, char *input_data, char **output_data)
{
	JSON_H *root = NULL;
    JSON_H *data = NULL;
	iot_error_t err = IOT_ERROR_NONE;
	char *in_payload = NULL;
	char *out_payload = NULL;

	in_payload = _es_parse_input_data(ctx->easysetup_security_context, input_data);

	err = _es_wifi_prov_parse(ctx, (char *)in_payload);
	if (err) {
		IOT_ERROR("failed to parse wifi_prov");
		goto out;
	}

	err = _es_cloud_prov_parse(ctx, (char *)in_payload);
	if (err) {
		IOT_ERROR("failed to parse cloud_prov");
		goto out;
	}

	if (ctx->lookup_id == NULL) {
		ctx->lookup_id = iot_os_malloc(IOT_REG_UUID_STR_LEN + 1);
	}

	err = iot_get_random_id_str(ctx->lookup_id,
			(IOT_REG_UUID_STR_LEN + 1));
	if (err != IOT_ERROR_NONE) {
		IOT_ERROR("failed to get new lookup_id(%d)", err);
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_LOOKUPID_GENERATE_FAIL, err);
		err = IOT_ERROR_EASYSETUP_LOOKUPID_GENERATE_FAIL;
		goto out;
	}

	IOT_DEBUG("lookupid = %s", ctx->lookup_id);

	root = JSON_CREATE_OBJECT();
	if (!root) {
		IOT_ERROR("json create failed");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_JSON_CREATE_ERROR, 0);
		err = IOT_ERROR_EASYSETUP_JSON_CREATE_ERROR;
		goto out;
	}
    data = JSON_CREATE_OBJECT();

	JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
	JSON_ADD_ITEM_TO_OBJECT(data, "lookupId", JSON_CREATE_STRING(ctx->lookup_id));
    JSON_ADD_NUMBER_TO_OBJECT(root, "errorcode", 0);

	out_payload = JSON_PRINT(root);
	*output_data = _es_build_output_data(ctx->easysetup_security_context, out_payload);

	/* Now we allow D2D process reentrant and prov_data could be loaded
	 * at the init state or previous D2D, so free it first to avoid memory-leak
	 */
	iot_api_prov_data_mem_free(&ctx->prov_data);
	err = iot_nv_get_prov_data(&ctx->prov_data);
	if (err) {
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_WIFI_DATA_READ_FAIL, err);
		err = IOT_ERROR_EASYSETUP_WIFI_DATA_READ_FAIL;
		IOT_WARN("No provisining from nv");
	} else {
		IOT_INFO("provisioning success");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_EASYSETUP_PROVISIONING_SUCCESS, 0);
	}
out:
	if (in_payload) {
		iot_os_free(in_payload);
	}
	if (out_payload) {
		iot_os_free(out_payload);
	}
	if (root) {
		JSON_DELETE(root);
	}
	return err;
}

STATIC_FUNCTION
iot_error_t _es_setupcomplete_handler(struct iot_context *ctx, char *input_data, char **output_data)
{
	JSON_H *root = NULL;
	iot_error_t err = IOT_ERROR_NONE;
	char *out_payload = NULL;

    IOT_INFO("_es_setupcomplete_handler");

	root = JSON_CREATE_OBJECT();
	if (!root) {
		IOT_ERROR("json create failed");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_JSON_CREATE_ERROR, 0);
		err = IOT_ERROR_EASYSETUP_JSON_CREATE_ERROR;
		goto out;
	}

    JSON_ADD_NUMBER_TO_OBJECT(root, "errorcode", 0);

	out_payload = JSON_PRINT(root);
	*output_data = _es_build_output_data(ctx->easysetup_security_context, out_payload);
    //iot_easysetup_ble_ecdh_teardown(&ctx->easysetup_security_context);
out:
	if (out_payload) {
		iot_os_free(out_payload);
	}
	if (root) {
		JSON_DELETE(root);
	}
	return err;
}

static iot_error_t _es_log_systeminfo_handler(struct iot_context *ctx, char **out_payload)
{
	char *output_ptr = NULL;
	JSON_H *root = NULL;
	iot_error_t err = IOT_ERROR_NONE;

	root = JSON_CREATE_OBJECT();
	if (!root) {
		IOT_ERROR("json create failed");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_JSON_CREATE_ERROR, 0);
		err = IOT_ERROR_EASYSETUP_JSON_CREATE_ERROR;
		goto out;
	}

	JSON_ADD_ITEM_TO_OBJECT(root, "version", JSON_CREATE_STRING("1.0"));

	output_ptr = JSON_PRINT(root);

	*out_payload = output_ptr;

out:
	if (root)
		JSON_DELETE(root);
	return err;
}

static iot_error_t _es_log_create_dump_handler(struct iot_context *ctx, char *in_payload, char **out_payload)
{
	char *output_ptr = NULL;
	JSON_H *root = NULL;
	iot_error_t err = IOT_ERROR_NONE;

	root = JSON_CREATE_OBJECT();
	if (!root) {
		IOT_ERROR("json create failed");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_JSON_CREATE_ERROR, 0);
		err = IOT_ERROR_EASYSETUP_JSON_CREATE_ERROR;
		goto out;
	}

	output_ptr = JSON_PRINT(root);

	*out_payload = output_ptr;

out:
	if (root)
		JSON_DELETE(root);
	return err;
}

static iot_error_t _es_log_get_dump_handler(struct iot_context *ctx, char **out_payload)
{
	char *log_dump = NULL;
	char *output_ptr = NULL;
	JSON_H *item = NULL;
	JSON_H *root = NULL;
	iot_error_t err = IOT_ERROR_NONE;
#if !defined(CONFIG_STDK_IOT_CORE_EASYSETUP_LOG_SUPPORT_NO_USE_LOGFILE)
	char *sumo_dump = NULL;
	size_t log_dump_size = 2048;
	size_t sumo_dump_size = 200;
	size_t written_size = 0;
#endif

	item = JSON_CREATE_OBJECT();
	if (!item) {
		IOT_ERROR("json create failed");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_JSON_CREATE_ERROR, 0);
		err = IOT_ERROR_EASYSETUP_JSON_CREATE_ERROR;
		goto out;
	}

#if defined(CONFIG_STDK_IOT_CORE_EASYSETUP_LOG_SUPPORT_NO_USE_LOGFILE)
	log_dump = iot_debug_get_log();
#else
	err = st_create_log_dump((IOT_CTX *)ctx, &log_dump, log_dump_size, &written_size, IOT_DUMP_MODE_NEED_BASE64 | IOT_DUMP_MODE_NEED_DUMP_STATE);
	if (err < 0) {
		IOT_ERROR("Fail to get log dump!\n");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_CREATE_LOGDUMP_FAIL, 0);
		goto out;
	}
	err = st_create_log_dump((IOT_CTX *)ctx, &sumo_dump, sumo_dump_size, &written_size, IOT_DUMP_MODE_NEED_BASE64);
	if (err < 0) {
		IOT_ERROR("Fail to get sumo dump!\n");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_CREATE_SUMODUMP_FAIL, 0);
		goto out;
	}
#endif

	JSON_ADD_NUMBER_TO_OBJECT(item, "code", 1);
	JSON_ADD_ITEM_TO_OBJECT(item, "message", JSON_CREATE_STRING(log_dump));
#if !defined(CONFIG_STDK_IOT_CORE_EASYSETUP_LOG_SUPPORT_NO_USE_LOGFILE)
	JSON_ADD_ITEM_TO_OBJECT(item, "sumomessage", JSON_CREATE_STRING(sumo_dump));
#endif

	root = JSON_CREATE_OBJECT();
	if (!root) {
		IOT_ERROR("json create failed");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_JSON_CREATE_ERROR, 0);
		err = IOT_ERROR_EASYSETUP_MEM_ALLOC_ERROR;
		if (item) {
			JSON_DELETE(item);
		}
		goto out;
	}

	JSON_ADD_ITEM_TO_OBJECT(root, "error", item);

	output_ptr = JSON_PRINT(root);

	*out_payload = output_ptr;
out:
#if !defined(CONFIG_STDK_IOT_CORE_EASYSETUP_LOG_SUPPORT_NO_USE_LOGFILE)
	if (log_dump)
		free(log_dump);
	if (sumo_dump)
		free(sumo_dump);
#endif
	if (root)
		JSON_DELETE(root);
	return err;
}

iot_error_t iot_easysetup_request_handler(struct iot_context *ctx, struct iot_easysetup_payload request)
{
	iot_error_t err = IOT_ERROR_NONE;
	struct iot_easysetup_payload response;

	if (!ctx)
		return IOT_ERROR_EASYSETUP_INTERNAL_SERVER_ERROR;

	response.step = request.step;
	response.payload = NULL;

	switch (request.step) {
	case IOT_EASYSETUP_STEP_DEVICEINFO:
		err = _es_deviceinfo_handler(ctx, request.payload, &response.payload);
		break;
	case IOT_EASYSETUP_STEP_WIFISCANINFO:
		err = _es_wifiscaninfo_handler(ctx, &response.payload);
		break;
	case IOT_EASYSETUP_STEP_KEYINFO:
		err = _es_keyinfo_handler(ctx, request.payload, &response.payload);
		break;
	case IOT_EASYSETUP_STEP_CONFIRMINFO:
		err = _es_confirminfo_handler(ctx, request.payload, &response.payload);
		break;
	case IOT_EASYSETUP_STEP_CONFIRM:
		err = _es_confirm_handler(ctx, request.payload, &response.payload);
		break;
	case IOT_EASYSETUP_STEP_WIFIPROVIONINGINFO:
		err = _es_wifiprovisioninginfo_handler(ctx, request.payload, &response.payload);
		break;
	case IOT_EASYSETUP_STEP_SETUPCOMPLETE:
		err = _es_setupcomplete_handler(ctx, request.payload, &response.payload);
		break;
	case IOT_EASYSETUP_STEP_LOG_SYSTEMINFO:
		err = _es_log_systeminfo_handler(ctx, &response.payload);
		break;
	case IOT_EASYSETUP_STEP_LOG_CREATE_DUMP:
		err = _es_log_create_dump_handler(ctx, request.payload, &response.payload);
		break;
	case IOT_EASYSETUP_STEP_LOG_GET_DUMP:
		err = _es_log_get_dump_handler(ctx, &response.payload);
		break;
	default:
		err = IOT_ERROR_EASYSETUP_INTERNAL_SERVER_ERROR;
		break;
	}
	if (err) {
		IOT_ERROR("failed to handle step %d (%d)", request.step, err);
	}

	response.err = err;

	if (ctx->easysetup_resp_queue) {
		err = iot_util_queue_send(ctx->easysetup_resp_queue, &response);
		if (err != IOT_ERROR_NONE) {
			IOT_ERROR("Cannot put the response into easysetup_resp_queue");
			err = IOT_ERROR_EASYSETUP_QUEUE_SEND_ERROR;
		} else {
			iot_os_eventgroup_set_bits(ctx->iot_events,
				IOT_EVENT_BIT_EASYSETUP_RESP);
			err = IOT_ERROR_NONE;
		}
	} else {
		IOT_ERROR("easysetup_resp_queue is deleted");
		err = IOT_ERROR_EASYSETUP_INTERNAL_SERVER_ERROR;
	}

	return err;
}
