/* ***************************************************************************
 *
 * Copyright (c) 2022 Samsung Electronics All Rights Reserved.
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

#include "security/iot_security_error.h"
#include "security/iot_security_storage.h"

/**
 * @brief	Load key pair info and store to context
 * @details	Load public key(65 bytes raw type) and key type and store to security context
 * @param[in]	context reference to the security context
 * @retval	IOT_ERROR_NONE success
 */
iot_error_t iot_security_be_hardware_se_pk_load(iot_security_context_t *context);

/**
 * @brief	Calculate a signature
 * @details	Calculate 64bytes raw type ecdsa signature using device private key
 * @param[in]	context reference to the security context
 * @param[in]	input_buf a pointer to a buffer to data for signature
 * @param[out]	sig_buf a pointer to a buffer to store the signature
 * @retval	IOT_ERROR_NONE success
 */
iot_error_t iot_security_be_hardware_se_pk_sign(iot_security_context_t *context, iot_security_buffer_t *input_buf, iot_security_buffer_t *sig_buf);

/**
 * @brief	Verify the signature
 * @details	Verify the signature for input_buf with sig_buf
 * @param[in]	context reference to the security context
 * @param[in]	input_buf a pointer to a buffer to data for signature
 * @param[in]	sig_buf a pointer to a buffer to the signature
 * @retval	IOT_ERROR_NONE success
 */
iot_error_t iot_security_be_hardware_se_pk_verify(iot_security_context_t *context, iot_security_buffer_t *input_buf, iot_security_buffer_t *sig_buf);

/**
 * @brief	Encrypt the data based on AES
 * @details	Supported cipher algorithm is AES-256-CBC mode
 * @param[in]	context reference to the security context
 * @param[in]	input_buf a pointer to a buffer to encrypt
 * @param[out]	output_buf a pointer to a buffer to store the result
 * @retval	IOT_ERROR_NONE success
 */
iot_error_t iot_security_be_hardware_se_cipher_aes_encrypt(iot_security_context_t *context, iot_security_buffer_t *input_buf, iot_security_buffer_t *output_buf);

/**
 * @brief	Decrypt the data based on AES
 * @details	Supported cipher algorithm is AES-256-CBC mode
 * @param[in]	context reference to the security context
 * @param[in]	input_buf a pointer to a buffer to decrypt
 * @param[out]	output_buf a pointer to a buffer to store the result
 * @retval	IOT_ERROR_NONE success
 */
iot_error_t iot_security_be_hardware_se_cipher_aes_decrypt(iot_security_context_t *context, iot_security_buffer_t *input_buf, iot_security_buffer_t *output_buf);

/**
 * @brief	Compute a shared secret
 * @details	Compute a shared secret with peer public key
 * @param[in]	context reference to the security context
 * @param[in]	input_buf a pointer to a buffer to peer public key(65bytes raw type)
 * @param[out]	output_buf a pointer to a buffer to store the shared secret
 * @retval	IOT_ERROR_NONE success
 */
iot_error_t iot_security_be_hardware_se_ecdh_compute_shared_secret(iot_security_context_t *context, iot_security_buffer_t *input_buf, iot_security_buffer_t *output_buf);

/**
 * @brief	Generate a ephemeral key pair
 * @details	Generate a key pair based on elliptic curve
 * @param[in]	context reference to the security context
 * @param[in]	key_id key identity to specific a ephemeral key pair
 * @retval	IOT_ERROR_NONE success
 */
iot_error_t iot_security_be_hardware_se_manager_generate_key(iot_security_context_t *context, iot_security_key_id_t key_id);

/**
 * @brief	Remove the generated ephemeral key pair
 * @param[in]	context reference to the security context
 * @param[in]	key_id key identity to specific a ephemeral key pair
 * @retval	IOT_ERROR_NONE success
 */
iot_error_t iot_security_be_hardware_se_manager_remove_key(iot_security_context_t *context, iot_security_key_id_t key_id);

/**
 * @brief	Set the key for signature or encryption
 * @details	Set the key for signature or encryption operation
 * @param[in]	context reference to the security context
 * @param[in]	key_id key identity want to get
 * @retval	IOT_ERROR_NONE success
 */
iot_error_t iot_security_be_hardware_se_manager_set_key(iot_security_context_t *context, iot_security_key_id_t key_id);

/**
 * @brief	Get the key for signature or encryption
 * @details	Get the parameter required for signature or encryption operation
 * @param[in]	context reference to the security context
 * @param[in]	key_id key identity want to get
 * @param[out]	key_buf a pointer to a buffer to store the key (64bytes raw type, need to fix 65bytes)
 * @retval	IOT_ERROR_NONE success
 */
iot_error_t iot_security_be_hardware_se_manager_get_key(iot_security_context_t *context, iot_security_key_id_t key_id, iot_security_buffer_t *key_buf);

/**
 * @brief	Get the certificate
 * @details	Get the certificate from static, factory or eSE
 * @param[in]	context reference to the security context
 * @param[in]	cert_id certificate identity want to get
 * @param[out]	cert_buf a pointer to a buffer to store the raw type certificate
 * @retval	IOT_ERROR_NONE success
 */
iot_error_t iot_security_be_hardware_se_manager_get_certificate(iot_security_context_t *context, iot_security_cert_id_t cert_id, iot_security_buffer_t *cert_buf);

/**
 * @brief	Read data from storage
 * @details	a pointer to a function to read the data from storage
 * @param[in]	context reference to the security context
 * @param[in]	storage_id file identity of target to read
 * @param[out]	data_buf a pointer to a security buffer for read data
 * @retval	IOT_ERROR_NONE success
 */
iot_error_t iot_security_be_hardware_se_storage_read(iot_security_context_t *context, iot_security_storage_id_t storage_id, iot_security_buffer_t *data_buf);

/**
 * @brief	Write data to storage
 * @details	a pointer to a function to write the data to storage
 * @param[in]	context reference to the security context
 * @param[in]	storage_id file identity of target to write
 * @param[in]	data_buf a pointer to a security buffer for write data
 * @retval	IOT_ERROR_NONE success
 */
iot_error_t iot_security_be_hardware_se_storage_write(iot_security_context_t *context, iot_security_storage_id_t storage_id, iot_security_buffer_t *data_buf);

/**
 * @brief	Remove data from storage
 * @details	a pointer to a function to remove the data from storage
 * @param[in]	context reference to the security context
 * @param[in]	storage_id file identity of target to remove
 * @retval	IOT_ERROR_NONE success
 */
iot_error_t iot_security_be_hardware_se_storage_remove(iot_security_context_t *context, iot_security_storage_id_t storage_id);

/**
 * @brief Generates a user-specified number of random bytes and returns it in a new buffer.
 * @details	Supports random number based on True Random Number Generator.
 * @param [in]  len the number of random bytes
 * @param [out] random a generated random bytes
 * @return IOT_ERROR_NONE if successful
 */
iot_error_t iot_security_be_hardware_se_generate_random(unsigned int len, unsigned char *random);
