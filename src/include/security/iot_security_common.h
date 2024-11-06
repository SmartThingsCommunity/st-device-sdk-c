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

#ifndef _IOT_SECURITY_COMMON_H_
#define _IOT_SECURITY_COMMON_H_

#include <string.h>
#include <stdbool.h>
#include "iot_security_error.h"
#include "iot_os_util.h"

#ifdef __cplusplus
extern "C" {
#endif

#define IOT_SECURITY_ED25519_LEN                32
#define IOT_SECURITY_SECRET_LEN                 32
#define IOT_SECURITY_IV_LEN                     16
#define IOT_SECURITY_SHA256_LEN                 32
#define IOT_SECURITY_SHA512_LEN                 64

#define IOT_SECURITY_EC_SECKEY_LEN              32
#define IOT_SECURITY_EC_PUBKEY_LEN              64

#define IOT_SECURITY_SIGNATURE_ED25519_LEN      64
#define IOT_SECURITY_SIGNATURE_RSA2048_LEN      256
#define IOT_SECURITY_SIGNATURE_ECCP256_LEN      1024    /* MBEDTLS_MPI_MAX_SIZE */
#define IOT_SECURITY_SIGNATURE_UNKNOWN_LEN      0

typedef struct iot_security_storage_params iot_security_storage_params_t;
typedef struct iot_security_be_context iot_security_be_context_t;

/**
* @brief Contains a buffer information
*/
typedef struct iot_security_buffer {
	size_t len;                                     /**< @brief length of buffer */
	unsigned char *p;                               /**< @brief pointer of buffer */
} iot_security_buffer_t;

static inline void iot_security_buffer_free(iot_security_buffer_t *buffer)
{
	if (buffer) {
		if (buffer->p && buffer->len) {
			memset(buffer->p, 0, buffer->len);
			iot_os_free(buffer->p);
		}
		memset(buffer, 0, sizeof(iot_security_buffer_t));
	}
}

/**
 * @brief Algorithm types of key
 */
typedef enum iot_security_key_type {
	IOT_SECURITY_KEY_TYPE_UNKNOWN = 0,
	IOT_SECURITY_KEY_TYPE_ED25519,
	IOT_SECURITY_KEY_TYPE_RSA2048,
	IOT_SECURITY_KEY_TYPE_ECCP256,
	IOT_SECURITY_KEY_TYPE_AES256 = 3,               /* must be 3 because referenced in ss.lib */
	IOT_SECURITY_KEY_TYPE_MAX,
} iot_security_key_type_t;

typedef enum iot_security_key_id {
	IOT_SECURITY_KEY_ID_UNKNOWN = 0,
	IOT_SECURITY_KEY_ID_DEVICE_PUBLIC,
	IOT_SECURITY_KEY_ID_DEVICE_PRIVATE,
	IOT_SECURITY_KEY_ID_SHARED_SECRET,
	IOT_SECURITY_KEY_ID_EPHEMERAL,
	IOT_SECURITY_KEY_ID_MAX,
} iot_security_key_id_t;

typedef enum iot_security_cert_id {
	IOT_SECURITY_CERT_ID_UNKNOWN = 0,
	IOT_SECURITY_CERT_ID_ROOT_CA,
	IOT_SECURITY_CERT_ID_SUB_CA,
	IOT_SECURITY_CERT_ID_DEVICE,
	IOT_SECURITY_CERT_ID_MAX,
} iot_security_cert_id_t;

typedef enum iot_security_pk_sign_type {
	IOT_SECURITY_PK_SIGN_TYPE_UNKNOWN = 0,
	IOT_SECURITY_PK_SIGN_TYPE_DER,
	IOT_SECURITY_PK_SIGN_TYPE_RAW,
} iot_security_pk_sign_type_t;

/**
 * @brief Contains information of public key pair
 */
typedef struct iot_security_pk_params {
	iot_security_key_type_t type;                   /** @brief type of key pair */
	iot_security_buffer_t pubkey;                   /** @brief public key buffer structure of key pair */
	iot_security_buffer_t seckey;                   /** @brief private key buffer structure of key pair  */
	iot_security_pk_sign_type_t pk_sign_type;		/** @brief private key signature type */
} iot_security_pk_params_t;

/**
 * @brief Contains information for cipher operation
 */
typedef struct iot_security_cipher_params {
	iot_security_key_type_t type;                   /** @brief algorithm type of cipher */
	iot_security_buffer_t key;                      /** @brief a pointer to a shared key buffer structure */
	iot_security_buffer_t iv;                       /** @brief a pointer to a IV buffer for AES cipher structure */
} iot_security_cipher_params_t;

/**
 * @brief Contains key information
 */
typedef struct iot_security_key_params {
	iot_security_key_id_t key_id;
	union {
		iot_security_pk_params_t pk;            /** @brief for signature */
		iot_security_cipher_params_t cipher;	/** @brief for encryption */
	} params;
} iot_security_key_params_t;

/**
* @brief Contains ecdh information
*/
typedef struct iot_security_ecdh_params {
	iot_security_key_id_t key_id;                   /** @brief a key identity of own key pair */
	iot_security_buffer_t t_seckey;                 /** @brief a pointer to a things secret key based on curve25519 (software backend only) */
	iot_security_buffer_t c_pubkey;                 /** @brief a pointer to a server public key based on curve25519 */
	iot_security_buffer_t salt;                     /** @brief a pointer to a random token as a salt */
} iot_security_ecdh_params_t;

/**
 * @brief A handle of security context
 */
typedef unsigned int security_handle;

/**
 * @brief Indicate a sub system is initialized
 */
typedef enum iot_security_sub_system {
	IOT_SECURITY_SUB_NONE    = 0,
	IOT_SECURITY_SUB_PK      = (1 << 0),
	IOT_SECURITY_SUB_CIPHER  = (1 << 1),
	IOT_SECURITY_SUB_ECDH    = (1 << 2),
	IOT_SECURITY_SUB_MANAGER = (1 << 3),
	IOT_SECURITY_SUB_STORAGE = (1 << 4),
} iot_security_sub_system_t;

/**
 * @brief Contains a security context data
 */
typedef struct iot_security_context {
	security_handle handle;                         /**< @brief handle of context */
	iot_security_sub_system_t sub_system;           /**< @brief flag to know whether the sub system has been initialized */

	iot_security_pk_params_t *pk_params;            /**< @brief contains parameter for pk system */
	iot_security_cipher_params_t *cipher_params;    /**< @brief contains parameter for cipher system */
	iot_security_ecdh_params_t *ecdh_params;        /**< @brief contains parameter for ecdh system */
	iot_security_storage_params_t *storage_params;  /**< @brief contains parameter for storage system */

	iot_security_be_context_t *be_context;          /**< @brief reference to the backend context */
} iot_security_context_t;

/**
 * @brief	Check the reference to the security context
 * @details	Check the reference to security context is valid or null in sub systems
 * @param[in]	context reference to the security context
 * @retval	IOT_ERROR_NONE security context is valid
 * @retval	IOT_ERROR_SECURITY_CONTEXT_NULL security context is invalid
 */
iot_error_t iot_security_check_context_is_valid(iot_security_context_t *context);

/**
 * @brief	Check the function lists of backend by reference to the security context
 * @details	Check the function lists of backend context is valid or null
 * @param[in]	context reference to the security context
 * @retval	IOT_ERROR_NONE functions lists of backend context is valid
 * @retval	IOT_ERROR_SECURITY_CONTEXT_NULL security context is invalid
 * @retval	IOT_ERROR_SECURITY_BE_CONTEXT_NULL backend context is invalid
 * @retval	IOT_ERROR_SECURITY_BE_FUNCS_ENTRY_NULL function lists of backend context is invalid
 */
iot_error_t iot_security_check_backend_funcs_entry_is_valid(iot_security_context_t *context);

/**
 * @brief	Initialize a security context
 * @details	Create a context for sub system and init the backend module
 * @return	a pointer to the created security context or null if failed to create
 */
iot_security_context_t *iot_security_init(void);

/**
 * @brief	De-initialize a security context
 * @details	De-initialize the initialized sub system and free the context
 * @param[in]	context reference to the security context
 * @retval	IOT_ERROR_NONE success
 * @retval	IOT_ERROR_INVALID_ARGS context is null or deinit failed in sub system
 */
iot_error_t iot_security_deinit(iot_security_context_t *context);

#ifdef __cplusplus
}
#endif

#endif /* _IOT_SECURITY_COMMON_H_ */
