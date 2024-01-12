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

#ifndef _PORT_CRYPTO_H_
#define _PORT_CRYPTO_H_

#include "security/iot_security_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief	Generate a digest by sha512 hash
 * @param[in]	src a pointer to a buffer to generate a digest
 * @param[in]	src_len the size of buffer pointed by src in bytes
 * @param[out]	dst a pointer to a buffer to store a digest
 * @retval	IOT_ERROR_NONE success
 * @retval	IOT_ERROR_INVALID_ARGS input parameter is invalid
 * @retval	IOT_ERROR_SECURITY_SHA256 failed to generate a digest
 */
iot_error_t port_crypto_sha512(const unsigned char *input, size_t input_len, unsigned char *output, size_t output_len);

/**
 * @brief	Generate a digest by sha256 hash
 * @param[in]	src a pointer to a buffer to generate a digest
 * @param[in]	src_len the size of buffer pointed by src in bytes
 * @param[out]	dst a pointer to a buffer to store a digest
 * @retval	IOT_ERROR_NONE success
 * @retval	IOT_ERROR_INVALID_ARGS input parameter is invalid
 * @retval	IOT_ERROR_SECURITY_SHA256 failed to generate a digest
 */
iot_error_t port_crypto_sha256(const unsigned char *input, size_t input_len, unsigned char *output, size_t output_len);

/**
 * @brief	Generate a key-pair for requested type
 * @param[in]	key type to be generated
 * @param[out]	generated secret key
 * @param[out]  generated public key
 * @retval	IOT_ERROR_NONE success
 * @retval	IOT_ERROR_INVALID_ARGS input parameter is invalid
 */
iot_error_t port_crypto_generate_key(iot_security_key_id_t key_type, iot_security_buffer_t *seckey_buf, iot_security_buffer_t *pubkey_buf);

/**
 * @brief	Create a signature
 * @param[in]	key parameters
 * @param[in]	signature input buffer
 * @param[out]  signature output buffer
 * @retval	IOT_ERROR_NONE success
 * @retval	IOT_ERROR_INVALID_ARGS input parameter is invalid
 */
iot_error_t port_crypto_pk_sign(iot_security_pk_params_t *pk_params, iot_security_buffer_t *input_buf, iot_security_buffer_t *sig_buf);

/**
 * @brief	Verify a signature
 * @param[in]	key parameters
 * @param[in]	signature input buffer
 * @param[in]  signature output buffer
 * @retval	IOT_ERROR_NONE success
 * @retval	IOT_ERROR_INVALID_ARGS input parameter is invalid
 */
iot_error_t port_crypto_pk_verify(iot_security_pk_params_t *pk_params, iot_security_buffer_t *input_buf, iot_security_buffer_t *sig_buf);

/**
 * @brief	Encrypt input data
 * @param[in]	key parameters
 * @param[in]	input buffer
 * @param[out]  output buffer
 * @retval	IOT_ERROR_NONE success
 * @retval	IOT_ERROR_INVALID_ARGS input parameter is invalid
 */
iot_error_t port_crypto_cipher_encrypt(iot_security_cipher_params_t *cipher_params, iot_security_buffer_t *input_buf, iot_security_buffer_t *output_buf);

/**
 * @brief	Decrypt input data
 * @param[in]	key parameters
 * @param[in]	input buffer
 * @param[out]  output buffer
 * @retval	IOT_ERROR_NONE success
 * @retval	IOT_ERROR_INVALID_ARGS input parameter is invalid
 */
iot_error_t port_crypto_cipher_decrypt(iot_security_cipher_params_t *cipher_params, iot_security_buffer_t *input_buf, iot_security_buffer_t *output_buf);

/**
 * @brief	Compute share key
 * @param[in]	key type
 * @param[in]   local private/public key
 * @param[in]	peer public key
 * @param[out]  sahred key
 * @retval	IOT_ERROR_NONE success
 * @retval	IOT_ERROR_INVALID_ARGS input parameter is invalid
 */
iot_error_t port_crypto_compute_ecdh_shared(iot_security_key_type_t key_type, iot_security_buffer_t *t_seckey_buf, iot_security_buffer_t *c_pubkey_buf, iot_security_buffer_t *output_buf);

#ifdef __cplusplus
}
#endif

#endif /* _PORT_CRYPTO_H_ */
