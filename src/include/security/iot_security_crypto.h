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

#ifndef _IOT_SECURITY_CRYPTO_H_
#define _IOT_SECURITY_CRYPTO_H_

#include "iot_security_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Types of cipher operation
 */
enum iot_security_cipher_mode {
	IOT_SECURITY_CIPHER_DECRYPT = 1,
	IOT_SECURITY_CIPHER_ENCRYPT,
};

/**
 * @brief Algorithm types of key
 */
enum iot_security_key_type {
	IOT_SECURITY_KEY_TYPE_UNKNOWN = 0,
	IOT_SECURITY_KEY_TYPE_ED25519,
	IOT_SECURITY_KEY_TYPE_RSA2048,
	IOT_SECURITY_KEY_TYPE_AES256 = 3,       /* must be 3 because referenced in ss.lib */
	IOT_SECURITY_KEY_TYPE_MAX,
};

/**
 * @brief Contains information of public key pair
 */
struct iot_security_pk_params {
	iot_security_key_type_t type;           /** @brief type of key pair */
	iot_security_buffer_t pubkey;           /** @brief public key buffer structure of key pair */
	iot_security_buffer_t seckey;           /** @brief private key buffer structure of key pair  */
};

/**
 * @brief Contains cipher information
 */
struct iot_security_cipher_params {
	iot_security_key_type_t type;           /** @brief algorithm type of cipher */
	iot_security_buffer_t key;              /** @brief a pointer to a shared key buffer structure */
	iot_security_buffer_t iv;               /** @brief a pointer to a IV buffer for AES cipher structure */
};

/**
 * @brief	Initialize a pubkey module in crypto sub system
 * @details	Create a required parameter holder for pubkey module and init the backend module
 * @retval	IOT_ERROR_NONE success
 * @retval	IOT_ERROR_MEM_ALLOC not enough heap memory
 * @retval	IOT_ERROR_SECURITY_CONTEXT_NULL security context parameter is null
 * @retval	IOT_ERROR_SECURITY_PK_INIT failed to init the pubkey in backend
 */
iot_error_t iot_security_pk_init(iot_security_context_t *context);

/**
 * @brief	De-initialize a pubkey module in crypto sub system
 * @details	De-initialize the initialized pubkey module and free the parameter holder
 * @retval	IOT_ERROR_NONE success
 * @retval	IOT_ERROR_SECURITY_CONTEXT_NULL security context parameter is null
 * @retval	IOT_ERROR_SECURITY_PK_DEINIT failed to de-init the pubkey in backend
 */
iot_error_t iot_security_pk_deinit(iot_security_context_t *context);

/**
 * @brief	Get a signature size
 * @param[in]	pk_type a type of signature algorithm
 * @retval	return a signature size of current context's signature algorithm
 */
size_t iot_security_pk_get_signature_len(iot_security_key_type_t pk_type);

/**
 * @brief	Get a algorithm type of key
 * @param[in]	context reference to the security context
 * @param[out]	key_type a type of key algorithm
 * @retval	IOT_ERROR_NONE success
 * @retval	IOT_ERROR_INVALID_ARGS input parameter is invalid
 * @retval	IOT_ERROR_SECURITY_PK_KEY_TYPE pubkey system does not initialized
 */
iot_error_t iot_security_pk_get_key_type(iot_security_context_t *context, iot_security_key_type_t *key_type);

/**
 * @brief	Calculate a signature
 * @details	Calculate a signature with input_buf then return the signature to sig_buf
 * @param[in]	context reference to the security context
 * @param[in]	input_buf a pointer to a buffer to data for signature
 * @param[out]	sig_buf a pointer to a buffer to store the signature
 * @retval	IOT_ERROR_NONE success
 * @retval	IOT_ERROR_INVALID_ARGS input parameter is invalid
 * @retval	IOT_ERROR_MEM_ALLOC not enough heap memory
 * @retval	IOT_ERROR_SECURITY_CONTEXT_NULL security context is null
 * @retval	IOT_ERROR_SECURITY_BE_CONTEXT_NULL backend context is null
 * @retval	IOT_ERROR_SECURITY_BE_FUNC_NULL a pointer to a read function of backend is null
 * @retval	IOT_ERROR_SECURITY_PK_PARAMS_NULL pubkey parameter is null or has invalid data
 * @retval	IOT_ERROR_SECURITY_PK_INVALID_PUBKEY the public key used to sign is invalid
 * @retval	IOT_ERROR_SECURITY_PK_INVALID_SECKEY the private key used to sign is invalid
 * @retval	IOT_ERROR_SECURITY_PK_SIGN failed to calculate a signature
 * @retval	IOT_ERROR_SECURITY_PK_KEY_LEN a size of signature is not a expected size
 */
iot_error_t iot_security_pk_sign(iot_security_context_t *context, iot_security_buffer_t *input_buf, iot_security_buffer_t *sig_buf);

/**
 * @brief	Verify the signature
 * @details	Verify the signature for input_buf with sig_buf
 * @param[in]	context reference to the security context
 * @param[in]	input_buf a pointer to a buffer to data for signature
 * @param[out]	sig_buf a pointer to a buffer to the signature
 * @retval	IOT_ERROR_NONE success
 * @retval	IOT_ERROR_INVALID_ARGS input parameter is invalid
 * @retval	IOT_ERROR_MEM_ALLOC not enough heap memory
 * @retval	IOT_ERROR_SECURITY_CONTEXT_NULL security context is null
 * @retval	IOT_ERROR_SECURITY_BE_CONTEXT_NULL backend context is null
 * @retval	IOT_ERROR_SECURITY_BE_FUNC_NULL a pointer to a read function of backend is null
 * @retval	IOT_ERROR_SECURITY_PK_PARAMS_NULL pubkey parameter is null or has invalid data
 * @retval	IOT_ERROR_SECURITY_PK_INVALID_PUBKEY the public key used for verify is invalid
 * @retval	IOT_ERROR_SECURITY_PK_KEY_LEN a size of signature is not a expected size
 * @retval	IOT_ERROR_SECURITY_PK_VERIFY the signature is mismatch
 */
iot_error_t iot_security_pk_verify(iot_security_context_t *context, iot_security_buffer_t *input_buf, iot_security_buffer_t *sig_buf);

/**
 * @brief	Initialize a cipher module in crypto sub system
 * @details	Create a required parameter holder for cipher module and init the backend module
 * @retval	IOT_ERROR_NONE success
 * @retval	IOT_ERROR_MEM_ALLOC not enough heap memory
 * @retval	IOT_ERROR_SECURITY_CONTEXT_NULL security context parameter is null
 * @retval	IOT_ERROR_SECURITY_CIPHER_INIT failed to init the cipher in backend
 */
iot_error_t iot_security_cipher_init(iot_security_context_t *context);

/**
 * @brief	De-initialize a cipher module in crypto sub system
 * @details	De-initialize the initialized cipher module and free the parameter holder
 * @retval	IOT_ERROR_NONE success
 * @retval	IOT_ERROR_SECURITY_CONTEXT_NULL security context parameter is null
 * @retval	IOT_ERROR_SECURITY_CIPHER_DEINIT failed to de-init the cipher in backend
 */
iot_error_t iot_security_cipher_deinit(iot_security_context_t *context);

/**
 * @brief	Generate a digest by sha256 hash
 * @param[in]	key_type a algorithm type for cipher operation
 * @param[in]	data_size the size of data for cipher operation
 * @retval	return calculated align size for request key type
 * 		return zero size if failed to calculate align size
 */
size_t iot_security_cipher_get_align_size(iot_security_key_type_t key_type, size_t data_size);

/**
 * @brief	Set the parameter for cipher operation
 * @details	Set the cipher algorithm, Key and IV
 * @param[in]	context reference to the security context
 * @param[in]	cipher_set_params cipher parameter want to set
 * @retval	IOT_ERROR_NONE success
 * @retval	IOT_ERROR_INVALID_ARGS input parameter is invalid
 * @retval	IOT_ERROR_MEM_ALLOC not enough heap memory
 * @retval	IOT_ERROR_SECURITY_CONTEXT_NULL security context is null
 * @retval	IOT_ERROR_SECURITY_BE_CONTEXT_NULL backend context is null
 * @retval	IOT_ERROR_SECURITY_BE_FUNC_NULL a pointer to a read function of backend is null
 * @retval	IOT_ERROR_SECURITY_CIPHER_PARAMS_NULL cipher parameter is null or has invalid data
 */
iot_error_t iot_security_cipher_set_params(iot_security_context_t *context, iot_security_cipher_params_t *cipher_set_params);

/**
 * @brief	Encrypt the data based on AES
 * @details	Supported cipher algorithm is AES-256-CBC mode
 * @param[in]	context reference to the security context
 * @param[in]	input_buf a pointer to a buffer to encrypt
 * @param[out]	output_buf a pointer to a buffer to store the result
 * @retval	IOT_ERROR_NONE success
 * @retval	IOT_ERROR_INVALID_ARGS input parameter is invalid
 * @retval	IOT_ERROR_MEM_ALLOC not enough heap memory
 * @retval	IOT_ERROR_SECURITY_CONTEXT_NULL security context is null
 * @retval	IOT_ERROR_SECURITY_BE_CONTEXT_NULL backend context is null
 * @retval	IOT_ERROR_SECURITY_BE_FUNC_NULL a pointer to a read function of backend is null
 * @retval	IOT_ERROR_SECURITY_CIPHER_PARAMS_NULL cipher parameter is null or has invalid data
 * @retval	IOT_ERROR_SECURITY_CIPHER_INVALID_MODE a not supported cipher mode is requested
 * @retval	IOT_ERROR_SECURITY_CIPHER_INVALID_ALGO a not supported cipher algorithm is requested
 * @retval	IOT_ERROR_SECURITY_CIPHER_INVALID_KEY a key information in parameter is invalid
 * @retval	IOT_ERROR_SECURITY_CIPHER_INVALID_IV a IV information in parameter is invalid
 * @retval	IOT_ERROR_SECURITY_CIPHER_LIBRARY an error occurred in 3rd party library
 * @retval	IOT_ERROR_SECURITY_CIPHER_BUF_OVERFLOW the output buffer is not enough to store the result
 */
iot_error_t iot_security_cipher_aes_encrypt(iot_security_context_t *context, iot_security_buffer_t *input_buf, iot_security_buffer_t *output_buf);

/**
 * @brief	Decrypt the data based on AES
 * @details	Supported cipher algorithm is AES-256-CBC mode
 * @param[in]	context reference to the security context
 * @param[in]	input_buf a pointer to a buffer to decrypt
 * @param[out]	output_buf a pointer to a buffer to store the result
 * @retval	IOT_ERROR_NONE success
 * @retval	IOT_ERROR_INVALID_ARGS input parameter is invalid
 * @retval	IOT_ERROR_MEM_ALLOC not enough heap memory
 * @retval	IOT_ERROR_SECURITY_CONTEXT_NULL security context is null
 * @retval	IOT_ERROR_SECURITY_BE_CONTEXT_NULL backend context is null
 * @retval	IOT_ERROR_SECURITY_BE_FUNC_NULL a pointer to a read function of backend is null
 * @retval	IOT_ERROR_SECURITY_CIPHER_PARAMS_NULL cipher parameter is null or has invalid data
 * @retval	IOT_ERROR_SECURITY_CIPHER_INVALID_MODE a not supported cipher mode is requested
 * @retval	IOT_ERROR_SECURITY_CIPHER_INVALID_ALGO a not supported cipher algorithm is requested
 * @retval	IOT_ERROR_SECURITY_CIPHER_INVALID_KEY a key information in parameter is invalid
 * @retval	IOT_ERROR_SECURITY_CIPHER_INVALID_IV a IV information in parameter is invalid
 * @retval	IOT_ERROR_SECURITY_CIPHER_LIBRARY an error occurred in 3rd party library
 * @retval	IOT_ERROR_SECURITY_CIPHER_BUF_OVERFLOW the output buffer is not enough to store the result
 */
iot_error_t iot_security_cipher_aes_decrypt(iot_security_context_t *context, iot_security_buffer_t *input_buf, iot_security_buffer_t *output_buf);

#ifdef __cplusplus
}
#endif

#endif /* _IOT_SECURITY_CRYPTO_H_ */
