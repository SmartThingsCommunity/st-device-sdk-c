/* ***************************************************************************
 *
 * Copyright (c) 2020 Samsung Electronics All Rights Reserved.
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

#ifndef _IOT_SECURITY_HELPER_H_
#define _IOT_SECURITY_HELPER_H_

#include "iot_security_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define IOT_SECURITY_B64_ALIGN_LEN(x)	(((x) + 3) & ~3u)
#define IOT_SECURITY_B64_ENCODE_LEN(x)	((((x) + 2) / 3) * 4 + 1)
#define IOT_SECURITY_B64_DECODE_LEN(x)	(IOT_SECURITY_B64_ALIGN_LEN(x) / 4 * 3 + 1)

/**
 * @brief	Encode a string as a base64 string
 * @param[in]	src a pointer to a buffer to encode
 * @param[in]	src_len the size of buffer pointed by src in bytes
 * @param[out]	dst a pointer to a buffer to store base64 string
 * @param[in]	dst_len the size of buffer pointed by dst in bytes
 * @param[out]	out_len the bytes written to dst
 * @retval	IOT_ERROR_NONE success
 * @retval	IOT_ERROR_INVALID_ARGS input parameter is invalid
 * @retval	IOT_ERROR_SECURITY_BASE64_ENCODE failed to encode the string
 */
iot_error_t iot_security_base64_encode(const unsigned char *src, size_t src_len, unsigned char *dst, size_t dst_len, size_t *out_len);

/**
 * @brief	Decode a base64 string as a string
 * @param[in]	src a pointer to a buffer to decode
 * @param[in]	src_len the size of buffer pointed by src in bytes
 * @param[out]	dst a pointer to a buffer to store base64 string
 * @param[in]	dst_len the size of buffer pointed by dst in bytes
 * @param[out]	out_len the bytes written to dst
 * @retval	IOT_ERROR_NONE success
 * @retval	IOT_ERROR_INVALID_ARGS input parameter is invalid
 * @retval	IOT_ERROR_SECURITY_BASE64_DECODE failed to decode the string
 */
iot_error_t iot_security_base64_decode(const unsigned char *src, size_t src_len, unsigned char *dst, size_t dst_len, size_t *out_len);

/**
 * @brief	Encode a string as a urlsafe base64 string
 * @details	This function replaces url unsafe characters ('+', '/') to
 *		url safe character ('-', '_')
 * @param[in]	src a pointer to a buffer to encode
 * @param[in]	src_len the size of buffer pointed by src in bytes
 * @param[out]	dst a pointer to a buffer to store base64 string
 * @param[in]	dst_len the size of buffer pointed by dst in bytes
 * @param[out]	out_len the bytes written to dst
 * @retval	IOT_ERROR_NONE success
 * @retval	IOT_ERROR_INVALID_ARGS input parameter is invalid
 * @retval	IOT_ERROR_SECURITY_BASE64_URL_ENCODE failed to encode the string as urlsafe
 */
iot_error_t iot_security_base64_encode_urlsafe(const unsigned char *src, size_t src_len, unsigned char *dst, size_t dst_len, size_t *out_len);

/**
 * @brief	Decode a urlsafe base64 string as a string
 * @param[in]	src a pointer to a buffer to decode
 * @param[in]	src_len the size of buffer pointed by src in bytes
 * @param[out]	dst a pointer to a buffer to store base64 string
 * @param[in]	dst_len the size of buffer pointed by dst in bytes
 * @param[out]	out_len the bytes written to dst
 * @retval	IOT_ERROR_NONE success
 * @retval	IOT_ERROR_INVALID_ARGS input parameter is invalid
 * @retval	IOT_ERROR_MEM_ALLOC memory allocation for align buffer is failed
 * @retval	IOT_ERROR_SECURITY_BASE64_URL_DECODE failed to encode the string as urlsafe
 */
iot_error_t iot_security_base64_decode_urlsafe(const unsigned char *src, size_t src_len, unsigned char *dst, size_t dst_len, size_t *out_len);

/**
 * @brief	Generate a digest by sha256 hash
 * @param[in]	src a pointer to a buffer to generate a digest
 * @param[in]	src_len the size of buffer pointed by src in bytes
 * @param[out]	dst a pointer to a buffer to store a digest
 * @retval	IOT_ERROR_NONE success
 * @retval	IOT_ERROR_INVALID_ARGS input parameter is invalid
 * @retval	IOT_ERROR_SECURITY_SHA256 failed to generate a digest
 */
iot_error_t iot_security_sha256(const unsigned char *input, size_t input_len, unsigned char *output, size_t output_len);

/**
 * @brief	Converts an ed25519 public key to an x25519 public key
 * @param[in]	ed25519_key a pointer to a public key buffer
 * @param[out]	curve25519_key a pointer to a buffer to store converted x25519 public key
 * @retval	IOT_ERROR_NONE success
 * @retval	IOT_ERROR_INVALID_ARGS input parameter is invalid
 * @retval	IOT_ERROR_CRYPTO_ED_KEY_CONVERT failed to convert to x25519
 */
iot_error_t iot_security_ed25519_convert_pubkey(unsigned char *ed25519_key, unsigned char *curve25519_key);

/**
 * @brief	Converts an ed25519 secret key to an x25519 secret key
 * @param[in]	ed25519_key a pointer to a secret key buffer
 * @param[out]	curve25519_key a pointer to a buffer to store converted x25519 secret key
 * @retval	IOT_ERROR_NONE success
 * @retval	IOT_ERROR_INVALID_ARGS input parameter is invalid
 * @retval	IOT_ERROR_CRYPTO_ED_KEY_CONVERT failed to convert to x25519
 */
iot_error_t iot_security_ed25519_convert_seckey(unsigned char *ed25519_key, unsigned char *curve25519_key);

#ifdef __cplusplus
}
#endif

#endif /* _IOT_SECURITY_HELPER_H_ */
