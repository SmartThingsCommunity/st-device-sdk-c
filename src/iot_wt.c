/* ***************************************************************************
 *
 * Copyright 2020 Samsung Electronics All Rights Reserved.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#include "iot_internal.h"
#include "iot_debug.h"
#include "iot_error.h"
#include "iot_crypto.h"
#include "iot_wt.h"
#include "iot_util.h"

#include "cJSON.h"

static char * _iot_jwt_alloc_b64_buffer(size_t plain_len, size_t *out_len)
{
	char *b64_buf;
	size_t b64_len;

	b64_len = IOT_CRYPTO_CAL_B64_LEN(plain_len);

	b64_buf = (char *)malloc(b64_len);
	if (!b64_buf) {
		IOT_ERROR("malloc returned NULL");
		return NULL;
	}

	*out_len = b64_len;

	return b64_buf;
}

static char * _iot_jwt_header_rs256(const char *sn)
{
	cJSON *object;
	char *object_str;

	object = cJSON_CreateObject();
	if (!object) {
		IOT_ERROR("cJSON_CreateObject returned NULL");
		return NULL;
	}

	cJSON_AddItemToObject(object, "alg", cJSON_CreateString("RS256"));
	cJSON_AddItemToObject(object, "kty", cJSON_CreateString("RSA"));
	cJSON_AddItemToObject(object, "crv", cJSON_CreateString(""));
	cJSON_AddItemToObject(object, "typ", cJSON_CreateString("JWT"));
	cJSON_AddItemToObject(object, "ver", cJSON_CreateString("0.0.1"));
	cJSON_AddItemToObject(object, "kid", cJSON_CreateString(sn));

	object_str = cJSON_PrintUnformatted(object);
	if (!object_str) {
		IOT_ERROR("cJSON_PrintUnformatted returned NULL");
		cJSON_Delete(object);
		return NULL;
	}

	cJSON_Delete(object);

	return object_str;
}

static char * _iot_jwt_header_ed25519(const char *sn)
{
	cJSON *object;
	char *object_str;

	object = cJSON_CreateObject();
	if (!object) {
		IOT_ERROR("cJSON_CreateObject returned NULL");
		return NULL;
	}

	cJSON_AddItemToObject(object, "alg", cJSON_CreateString("EdDSA"));
	cJSON_AddItemToObject(object, "kty", cJSON_CreateString("OKP"));
	cJSON_AddItemToObject(object, "crv", cJSON_CreateString("Ed25519"));
	cJSON_AddItemToObject(object, "typ", cJSON_CreateString("JWT"));
	cJSON_AddItemToObject(object, "ver", cJSON_CreateString("0.0.1"));
	cJSON_AddItemToObject(object, "kid", cJSON_CreateString(sn));

	object_str = cJSON_PrintUnformatted(object);
	if (!object_str) {
		IOT_ERROR("cJSON_PrintUnformatted returned NULL");
		cJSON_Delete(object);
		return NULL;
	}

	cJSON_Delete(object);

	return object_str;
}


static char * _iot_jwt_create_header(const char *sn, iot_crypto_pk_type_t pk_type)
{
	char *object_str;

	switch(pk_type) {
	case IOT_CRYPTO_PK_RSA:
		object_str = _iot_jwt_header_rs256(sn);
		break;
	case IOT_CRYPTO_PK_ED25519:
		object_str = _iot_jwt_header_ed25519(sn);
		break;
	default:
		IOT_ERROR("pubkey type (%d) is not supported", pk_type);
		object_str = NULL;
		break;
	}

	return object_str;
}

static iot_error_t _iot_jwt_create_b64h(char **buf, size_t *out_len,
				const char *sn, iot_crypto_pk_type_t pk_type)
{
	iot_error_t err;
	char *hdr;
	char *b64_buf;
	size_t hdr_len;
	size_t b64_len;

	hdr = _iot_jwt_create_header(sn, pk_type);
	if (!hdr) {
		IOT_ERROR("_iot_jwt_create_header returned NULL");
		err = IOT_ERROR_WEBTOKEN_FAIL;
		goto exit;
	}

	hdr_len = strlen(hdr);

	b64_buf = _iot_jwt_alloc_b64_buffer(hdr_len, &b64_len);
	if (!b64_buf) {
		IOT_ERROR("_iot_jwt_alloc_b64_buffer returned NULL");
		err = IOT_ERROR_MEM_ALLOC;
		goto exit_hdr;
	}

	err = iot_crypto_base64_encode((unsigned char *)hdr, hdr_len, (unsigned char *)b64_buf, b64_len, out_len);
	if (err) {
		IOT_ERROR("iot_crypto_base64_encode returned error : %d", err);
		goto exit_b64_buf;
	}

	*buf = b64_buf;
	goto exit_hdr;

exit_b64_buf:
	free(b64_buf);
exit_hdr:
	free(hdr);
exit:
	return err;
}

static char * _iot_jwt_create_payload(void)
{
	iot_error_t err;
	cJSON *object;
	char *object_str;
	char time_in_sec[16]; /* 1559347200 is '2019-06-01 00:00:00 UTC' */
	char uuid_str[40];    /* 4066c24f-cd48-4e92-a538-362e74337c7f */
	struct iot_uuid uuid;

	err = iot_get_time_in_sec(time_in_sec, sizeof(time_in_sec));
	if (err) {
		IOT_ERROR("_iot_get_time_in_sec returned error : %d", err);
		return NULL;
	}

	err = iot_util_get_random_uuid(&uuid);
	if (err) {
		IOT_ERROR("iot_util_get_random_uuid returned error : %d", err);
		return NULL;
	}

	err = iot_util_convert_uuid_str(&uuid, uuid_str, sizeof(uuid_str));
	if (err) {
		IOT_ERROR("iot_util_convert_uuid_str returned error : %d", err);
		return NULL;
	}


	object = cJSON_CreateObject();
	if (!object) {
		IOT_ERROR("cJSON_CreateObject returned NULL");
		return NULL;
	}

	cJSON_AddItemToObject(object, "iat", cJSON_CreateString(time_in_sec));
	cJSON_AddItemToObject(object, "jti", cJSON_CreateString(uuid_str));

	object_str = cJSON_PrintUnformatted(object);
	if (!object_str) {
		IOT_ERROR("cJSON_PrintUnformatted returned NULL");
		cJSON_Delete(object);
		return NULL;
	}

	cJSON_Delete(object);

	return object_str;
}

static iot_error_t _iot_jwt_create_b64p(char **buf, size_t *out_len)
{
	iot_error_t err;
	char *payload;
	char *b64_buf;
	size_t payload_len;
	size_t b64_len;

	payload = _iot_jwt_create_payload();
	if (!payload) {
		IOT_ERROR("_iot_jwt_create_payload returned NULL");
		err = IOT_ERROR_WEBTOKEN_FAIL;
		goto exit;
	}

	payload_len = strlen(payload);

	b64_buf = _iot_jwt_alloc_b64_buffer(payload_len, &b64_len);
	if (!b64_buf) {
		IOT_ERROR("_iot_jwt_alloc_b64_buffer returned NULL");
		err = IOT_ERROR_MEM_ALLOC;
		goto exit_payload;
	}

	err = iot_crypto_base64_encode((unsigned char *)payload, payload_len, (unsigned char *)b64_buf, b64_len, out_len);
	if (err) {
		IOT_ERROR("iot_crypto_base64_encode returned error : %d", err);
		goto exit_b64_buf;
	}

	*buf = b64_buf;
	goto exit_payload;

exit_b64_buf:
	free(b64_buf);
exit_payload:
	free(payload);
exit:
	return err;
}

static iot_error_t _iot_jwt_create_b64s(char **buf, size_t *out_len,
                                        char *b64hp, size_t hp_len,
					iot_crypto_pk_info_t *pk_info)
{
	iot_error_t err;
	iot_crypto_pk_context_t pk_ctx;
	char *sig;
	char *b64_buf;
	size_t sig_len;
	size_t b64_len;

	sig = (char *)malloc(IOT_CRYPTO_SIGNATURE_LEN);
	if (!sig) {
		IOT_ERROR("malloc returned NULL");
		err = IOT_ERROR_MEM_ALLOC;
		goto exit;
	}

	err = iot_crypto_pk_init(&pk_ctx, pk_info);
	if (err) {
		IOT_ERROR("iot_crypto_pk_init returned error : %d", err);
		goto exit_sig;
	}

	err = iot_crypto_pk_sign(&pk_ctx, (unsigned char *)b64hp, hp_len,
	                            (unsigned char *)sig, &sig_len);
	if (err) {
		IOT_ERROR("iot_crypto_pk_sign returned error : %d", err);
		iot_crypto_pk_free(&pk_ctx);
		goto exit_sig;
	}

	iot_crypto_pk_free(&pk_ctx);

	b64_buf = _iot_jwt_alloc_b64_buffer(sig_len, &b64_len);
	if (!b64_buf) {
		IOT_ERROR("_iot_jwt_alloc_b64_buffer returned NULL");
		err = IOT_ERROR_MEM_ALLOC;
		goto exit_sig;
	}

	err = iot_crypto_base64_encode((unsigned char *)sig, sig_len, (unsigned char *)b64_buf, b64_len, out_len);
	if (err) {
		IOT_ERROR("iot_crypto_base64_encode returned error : %d", err);
		goto exit_b64_buf;
	}

	*buf = b64_buf;
	goto exit_sig;

exit_b64_buf:
	free(b64_buf);
exit_sig:
	free(sig);
exit:
	return err;
}

iot_error_t iot_wt_create(char **token, const char *sn, iot_crypto_pk_info_t *pk_info)
{
	iot_error_t err;
	char *b64h;
	char *b64p;
	char *b64s;
	char *tmp;
	size_t b64h_len;
	size_t b64p_len;
	size_t b64s_len;
	size_t token_len;
	size_t written = 0;

	/* b64h = b64(header) */

	err = _iot_jwt_create_b64h(&b64h, &b64h_len, sn, pk_info->type);
	if (err) {
		IOT_ERROR("_iot_jwt_create_b64h returned error : %d", err);
		goto exit;
	}

	/* b64p = b64(payload) */

	err = _iot_jwt_create_b64p(&b64p, &b64p_len);
	if (err) {
		IOT_ERROR("_iot_jwt_create_b64p returned error : %d", err);
		goto exit_header;
	}

	/* b64h.b64 */

	token_len = b64h_len + b64p_len + IOT_CRYPTO_CAL_B64_LEN(IOT_CRYPTO_SIGNATURE_LEN) + 3;

	tmp = (char *)malloc(token_len);
	if (tmp == NULL) {
		IOT_ERROR("malloc returned NULL");
		err = IOT_ERROR_MEM_ALLOC;
		goto exit_payload;
	}

	memcpy(tmp, b64h, b64h_len);
	written += b64h_len;

	tmp[written++] = '.';

	memcpy(tmp + written, b64p, b64p_len);
	written += b64p_len;

	/* b64s = b64(sign(sha256(b64h.b64p))) */

	err = _iot_jwt_create_b64s(&b64s, &b64s_len, tmp, written, pk_info);
	if (err) {
		IOT_ERROR("_iot_jwt_create_b64s returned error : %d", err);
		free(tmp);
		goto exit_payload;
	}

	/* token = b64h.b64p.b64s */

	tmp[written++] = '.';

	memcpy(tmp + written, b64s, b64s_len);
	written += b64s_len;

	tmp[written] = '\0';

	IOT_DEBUG("token: %s (%d)", tmp, written);

	*token = tmp;
	err = IOT_ERROR_NONE;
	goto exit_signature;

exit_signature:
	free(b64s);
exit_payload:
	free(b64p);
exit_header:
	free(b64h);
exit:
	return err;
}

