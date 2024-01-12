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

#ifndef _IOT_SECURITY_SS_H_
#define _IOT_SECURITY_SS_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief	Encryption of the input data
 * @details	The encryption key is generated from device unique value
 * @param[in]	input	a pointer to a buffer to encrypt
 * @param[in]	ilen	the size of buffer pointed by input in bytes
 * @param[out]	output	a pointer of pointer to a buffer to store the
 *		encrypted data
 * @param[out]	olen	the bytes written to output buffer
 * @retval	IOT_ERROR_NONE encryption is success
 * @retval	IOT_ERROR_MEM_ALLOC mem alloc failed for output buffer
 * @retval	IOT_ERROR_CRYPTO_CIPHER_ALIGN failed to get align size
 *		of the input size for output buffer
 * @retval	IOT_ERROR_CRYPTO_CIPHER cipher operation is failed
 * @retval	IOT_ERROR_CRYPTO_SS_KDF failed during derivate the key
 */
iot_error_t iot_security_ss_encrypt(unsigned char *input, size_t ilen,
				unsigned char **output, size_t *olen);

/**
 * @brief	Decryption of the input data
 * @details	The decryption key is generated from device unique value
 * @param[in]	input	a pointer to a buffer to decrypt
 * @param[in]	ilen	the size of buffer pointed by input in bytes
 * @param[out]	output	a pointer of pointer to a buffer to store the
 *		decrypted data
 * @param[out]	olen	the bytes written to output buffer
 * @retval	IOT_ERROR_NONE decryption is success
 * @retval	IOT_ERROR_MEM_ALLOC mem alloc failed for output buffer
 * @retval	IOT_ERROR_CRYPTO_CIPHER_ALIGN failed to get align size
 *		of the input size for output buffer
 * @retval	IOT_ERROR_CRYPTO_CIPHER_UNKNOWN_TYPE cipher is requested
 *		with not supported algorithm
 * @retval	IOT_ERROR_CRYPTO_CIPHER cipher operation is failed
 * @retval	IOT_ERROR_CRYPTO_SS_KDF failed during derivate the key
 */
iot_error_t iot_security_ss_decrypt(unsigned char *input, size_t ilen,
				unsigned char **output, size_t *olen);

#ifdef __cplusplus
}
#endif

#endif /* _IOT_SECURITY_SS_H_ */
