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

static char * _iot_wt_alloc_b64_buffer(size_t plain_len, size_t *out_len)
{
	char *b64_buf;
	size_t b64_len;

	b64_len = IOT_CRYPTO_CAL_B64_LEN(plain_len);

	b64_buf = (char *)malloc(b64_len);
	if (!b64_buf) {
		IOT_ERROR("malloc failed for base64 token");
		return NULL;
	}

	*out_len = b64_len;

	return b64_buf;
}

#if defined(STDK_IOT_CORE_WEBTOKEN_CBOR)

#include <cbor.h>

/*
 * https://tools.ietf.org/html/rfc8152#section-3.1
 */
enum {
	COSE_HEADER_ALG = 1,
	COSE_HEADER_KID = 4,
};

/*
 * https://tools.ietf.org/html/rfc8152#section-13
 */
enum {
	COSE_KEY_TYPE_OKP = 1,
	COSE_KEY_TYPE_EC2 = 2,
	COSE_KEY_TYPE_SYMMETRIC = 4,
};

enum {
	COSE_ALGORITHM_EdDSA = -8,
};

/*
 * https://tools.ietf.org/html/rfc8392#section-3.1
 */
enum {
	CWT_CLAIMS_ISS = 1,
	CWT_CLAIMS_SUB = 2,
	CWT_CLAIMS_AUD = 3,
	CWT_CLAIMS_EXP = 4,
	CWT_CLAIMS_NBF = 5,
	CWT_CLAIMS_IAT = 6,
	CWT_CLAIMS_CTI = 7,
};

struct cwt_tobesign_info {
	unsigned char *protected;
	size_t protected_len;
	unsigned char *payload;
	size_t payload_len;
};

#define COSE_MAP_ALLOC_LEN(x)	(1 + (x * 2))

static iot_error_t _iot_cwt_create_protected(
		unsigned char **protected, size_t *protected_len,
		iot_crypto_pk_type_t pk_type)
{
	CborEncoder root = {0};
	CborEncoder map = {0};
	int entry_num;
	unsigned char *cborbuf;
	unsigned char *tmp;
	size_t buflen = 32;
	size_t olen;

	if (!protected || !protected_len) {
		IOT_ERROR("invalid args");
		return IOT_ERROR_INVALID_ARGS;
	}

retry:
	buflen += 32;

	cborbuf = (unsigned char *)malloc(buflen);
	if (cborbuf == NULL) {
		IOT_ERROR("failed to malloc for cwt");
		return IOT_ERROR_MEM_ALLOC;
	}

	memset(cborbuf, 0, buflen);

	cbor_encoder_init(&root, cborbuf, buflen, 0);

	entry_num = 1;

	cbor_encoder_create_map(&root, &map, entry_num);

	switch (pk_type) {
	case IOT_CRYPTO_PK_ED25519:
		cbor_encode_int(&map, COSE_HEADER_ALG);
		cbor_encode_negative_int(&map, -COSE_ALGORITHM_EdDSA);
		break;
	default:
		IOT_ERROR("'%d' not yet supported", pk_type);
		free(cborbuf);
		return IOT_ERROR_WEBTOKEN_FAIL;
	}

	cbor_encoder_close_container_checked(&root, &map);

	olen = cbor_encoder_get_buffer_size(&root, cborbuf);
	if (olen < buflen) {
		tmp = (unsigned char *)realloc(cborbuf, olen + 1);
		if (tmp) {
			cborbuf = tmp;
			cborbuf[olen] = 0;
		}
	} else {
		IOT_ERROR("allocated size is not enough (%d < %d)",
				(int)buflen, (int)olen);
		free(cborbuf);
		if (buflen < IOT_CBOR_MAX_BUF_LEN) {
			goto retry;
		} else {
			return IOT_ERROR_WEBTOKEN_FAIL;
		}
	}

	*protected = cborbuf;
	*protected_len = olen;

	return IOT_ERROR_NONE;
}

static iot_error_t _iot_cwt_create_unprotected(CborEncoder *root, const char *sn)
{
	CborEncoder map;
	int entry_num = 1;

	cbor_encoder_create_map(root, &map, entry_num);
	cbor_encode_int(&map, COSE_HEADER_KID);
	cbor_encode_byte_string(&map, (const unsigned char *)sn, strlen(sn));
	cbor_encoder_close_container_checked(root, &map);

	return IOT_ERROR_NONE;
}

static iot_error_t _iot_cwt_create_payload(
		unsigned char **payload, size_t *payload_len)
{
	iot_error_t err;
	CborEncoder root = {0};
	CborEncoder map = {0};
	int entry_num;
	unsigned char *cborbuf;
	unsigned char *tmp;
	size_t buflen = 128;
	size_t olen;

	long time_in_sec;	/* 1559347200 is '2019-06-01 00:00:00 UTC' */
	struct iot_uuid uuid;	/* 16 bytes */
	const char *aud = "mqtts://greatgate.smartthings.com";

	if (!payload || !payload_len) {
		IOT_ERROR("invalid args");
		return IOT_ERROR_INVALID_ARGS;
	}

	err = iot_get_time_in_sec_by_long(&time_in_sec);
	if (err) {
		IOT_ERROR("_iot_get_time_in_sec_by_long returned error : %d", err);
		return err;
	}

	err = iot_util_get_random_uuid(&uuid);
	if (err) {
		IOT_ERROR("iot_util_get_random_uuid returned error : %d", err);
		return err;
	}

retry:
	buflen += 128;

	cborbuf = (unsigned char *)malloc(buflen);
	if (cborbuf == NULL) {
		IOT_ERROR("failed to malloc for cwt");
		return IOT_ERROR_MEM_ALLOC;
	}

	memset(cborbuf, 0, buflen);

	cbor_encoder_init(&root, cborbuf, buflen, 0);

	entry_num = 3;

	cbor_encoder_create_map(&root, &map, entry_num);

	/* iat */
	cbor_encode_int(&map, CWT_CLAIMS_IAT);
	cbor_encode_uint(&map, time_in_sec);
	/* cti */
	cbor_encode_int(&map, CWT_CLAIMS_CTI);
	cbor_encode_byte_string(&map, uuid.id, sizeof(uuid.id));
	/* aud : optional */
	cbor_encode_int(&map, CWT_CLAIMS_AUD);
	cbor_encode_text_string(&map, aud, strlen(aud));

	cbor_encoder_close_container_checked(&root, &map);

	olen = cbor_encoder_get_buffer_size(&root, cborbuf);
	if (olen < buflen) {
		tmp = (unsigned char *)realloc(cborbuf, olen + 1);
		if (tmp) {
			cborbuf = tmp;
			cborbuf[olen] = 0;
		}
	} else {
		IOT_ERROR("allocated size is not enough (%d < %d)",
				(int)buflen, (int)olen);
		free(cborbuf);
		if (buflen < IOT_CBOR_MAX_BUF_LEN) {
			goto retry;
		} else {
			return IOT_ERROR_WEBTOKEN_FAIL;
		}
	}

	*payload = cborbuf;
	*payload_len = olen;

	return IOT_ERROR_NONE;
}

static iot_error_t _iot_cwt_create_signature(
		unsigned char **sig, size_t *sig_len,
		struct cwt_tobesign_info *tbs_info,
		iot_crypto_pk_info_t *pk_info)
{
	iot_error_t err;
	CborEncoder root = {0};
	CborEncoder array = {0};
	int array_num = 4;
	unsigned char *cborbuf;
	unsigned char *tmp;
	size_t buflen = 128;
	size_t olen;

	iot_crypto_pk_context_t pk_ctx;
	unsigned char *sigbuf;
	size_t sigbuflen;
	const char *context = "Signature1";

	if (!sig || !sig_len || !tbs_info || !pk_info) {
		IOT_ERROR("invalid args");
		return IOT_ERROR_INVALID_ARGS;
	}

	if (!tbs_info->protected || (tbs_info->protected_len == 0) ||
	    !tbs_info->payload || (tbs_info->payload_len == 0)) {
		IOT_ERROR("invalid args");
		return IOT_ERROR_INVALID_ARGS;
	}

	sigbuf = (unsigned char *)malloc(IOT_CRYPTO_SIGNATURE_LEN);
	if (!sigbuf) {
		IOT_ERROR("malloc failed for cwt");
		return IOT_ERROR_MEM_ALLOC;
	}

	err = iot_crypto_pk_init(&pk_ctx, pk_info);
	if (err) {
		IOT_ERROR("iot_crypto_pk_init returned error : %d", err);
		goto exit_sig;
	}

retry:
	buflen += 128;

	cborbuf = (unsigned char *)malloc(buflen);
	if (cborbuf == NULL) {
		IOT_ERROR("failed to malloc for cwt");
		goto exit_pk;
	}

	memset(cborbuf, 0, buflen);

	cbor_encoder_init(&root, cborbuf, buflen, 0);

	cbor_encoder_create_array(&root, &array, array_num);

	cbor_encode_text_string(&array, context, strlen(context));
	cbor_encode_byte_string(&array, tbs_info->protected, tbs_info->protected_len);
	cbor_encode_byte_string(&array, NULL, 0);
	cbor_encode_byte_string(&array, tbs_info->payload, tbs_info->payload_len);

	cbor_encoder_close_container_checked(&root, &array);

	olen = cbor_encoder_get_buffer_size(&root, cborbuf);
	if (olen < buflen) {
		tmp = (unsigned char *)realloc(cborbuf, olen + 1);
		if (tmp) {
			cborbuf = tmp;
			cborbuf[olen] = 0;
		}
	} else {
		IOT_ERROR("allocated size is not enough (%d < %d)",
				(int)buflen, (int)olen);
		free(cborbuf);
		if (buflen < IOT_CBOR_MAX_BUF_LEN) {
			goto retry;
		} else {
			goto exit_pk;
		}
	}

	err = iot_crypto_pk_sign(&pk_ctx, cborbuf, olen, sigbuf, &sigbuflen);
	if (err) {
		IOT_ERROR("iot_crypto_pk_sign returned error : %d", err);
		goto exit_cborbuf;
	}

	free(cborbuf);
	iot_crypto_pk_free(&pk_ctx);

	*sig = sigbuf;
	*sig_len = sigbuflen;

	return IOT_ERROR_NONE;

exit_cborbuf:
	free(cborbuf);
exit_pk:
	iot_crypto_pk_free(&pk_ctx);
exit_sig:
	free(sigbuf);

	return err;
}

static iot_error_t _iot_cwt_create(char **token, const char *sn, iot_crypto_pk_info_t *pk_info)
{
	iot_error_t err;
	CborEncoder root = {0};
	CborEncoder array = {0};
	int array_num = 4;
	unsigned char *cborbuf = NULL;
	unsigned char *protected = NULL;
	unsigned char *payload = NULL;
	unsigned char *signature = NULL;
	unsigned char *tmp = NULL;
	char *cborbuf_b64 = NULL;
	size_t olen;
	size_t cbor_len;
	size_t protected_len;
	size_t payload_len;
	size_t buflen = 128;
	size_t b64_len;
	struct cwt_tobesign_info tbs_info;

	if (!token || !sn || !pk_info) {
		return IOT_ERROR_INVALID_ARGS;
	}

retry:
	buflen += 128;

	cborbuf = (unsigned char *)malloc(buflen);
	if (cborbuf == NULL) {
		IOT_ERROR("failed to malloc for cbor");
		return IOT_ERROR_MEM_ALLOC;
	}

	memset(cborbuf, 0, buflen);

	/*
	 * https://tools.ietf.org/html/rfc8152#section-4.2
	 */
	cbor_encoder_init(&root, cborbuf, buflen, 0);

	cbor_encode_tag(&root, CborCOSE_Sign1Tag);

	cbor_encoder_create_array(&root, &array, array_num);

	/* protected */
	err = _iot_cwt_create_protected(&protected, &protected_len, pk_info->type);
	if (err)
		goto exit_cborbuf;

	cbor_encode_byte_string(&array, protected, protected_len);

	/* unprotected */
	err = _iot_cwt_create_unprotected(&array, sn);
	if (err)
		goto exit_protected;

	/* payload */
	err = _iot_cwt_create_payload(&payload, &payload_len);
	if (err)
		goto exit_unprotected;

	cbor_encode_byte_string(&array, payload, payload_len);

	/* signature */
	tbs_info.protected = protected;
	tbs_info.protected_len = protected_len;
	tbs_info.payload = payload;
	tbs_info.payload_len = payload_len;
	err = _iot_cwt_create_signature(&signature, &olen, &tbs_info, pk_info);
	if (err)
		goto exit_payload;

	cbor_encode_byte_string(&array, signature, olen);

	cbor_encoder_close_container_checked(&root, &array);

	olen = cbor_encoder_get_buffer_size(&root, cborbuf);
	if (olen < buflen) {
		tmp = (unsigned char *)realloc(cborbuf, olen + 1);
		if (tmp) {
			cborbuf = tmp;
			cborbuf[olen] = 0;
			cbor_len = olen;
		} else {
			IOT_WARN("realloc failed for cwt");
			cbor_len = buflen;
		}
	} else {
		IOT_ERROR("allocated size is not enough (%d < %d)",
				(int)buflen, (int)olen);
		free(cborbuf);
		if (buflen < IOT_CBOR_MAX_BUF_LEN) {
			goto retry;
		} else {
			goto exit_signature;
		}
	}

	cborbuf_b64 = (char *)_iot_wt_alloc_b64_buffer(cbor_len , &b64_len);
	if (!cborbuf_b64) {
		err = IOT_ERROR_MEM_ALLOC;
		goto exit_failed;
	}

	err = iot_crypto_base64_encode(cborbuf, cbor_len, (unsigned char *)cborbuf_b64, b64_len, &olen);
	if (err) {
		IOT_ERROR("iot_crypto_base64_encode returned error : %d", err);
		free(cborbuf_b64);
		goto exit_failed;
	}

	*token = cborbuf_b64;

	IOT_DEBUG("CWT(%d) : '%s'", olen, cborbuf_b64);

	err = IOT_ERROR_NONE;

exit_failed:
	free(cborbuf);
exit_signature:
	free(signature);
exit_payload:
	free(payload);
exit_unprotected:
exit_protected:
	free(protected);
exit_cborbuf:
	free(cborbuf);

	return err;
}

#else /* !STDK_IOT_CORE_WEBTOKEN_CBOR */

#include <cJSON.h>

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

	b64_buf = _iot_wt_alloc_b64_buffer(hdr_len, &b64_len);
	if (!b64_buf) {
		IOT_ERROR("_iot_wt_alloc_b64_buffer returned NULL");
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

	b64_buf = _iot_wt_alloc_b64_buffer(payload_len, &b64_len);
	if (!b64_buf) {
		IOT_ERROR("_iot_wt_alloc_b64_buffer returned NULL");
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

	b64_buf = _iot_wt_alloc_b64_buffer(sig_len, &b64_len);
	if (!b64_buf) {
		IOT_ERROR("_iot_wt_alloc_b64_buffer returned NULL");
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

static iot_error_t _iot_jwt_create(char **token, const char *sn, iot_crypto_pk_info_t *pk_info)
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

	if (!token || !sn || !pk_info) {
		return IOT_ERROR_INVALID_ARGS;
	}

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

#endif /* STDK_IOT_CORE_WEBTOKEN_CBOR */

iot_error_t iot_wt_create(char **token, const char *sn, iot_crypto_pk_info_t *pk_info)
{
#if defined(STDK_IOT_CORE_WEBTOKEN_CBOR)
	return _iot_cwt_create(token, sn, pk_info);
#else
	return _iot_jwt_create(token, sn, pk_info);
#endif
}
