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

#ifndef _IOT_SECURITY_BE_COMMON_H_
#define _IOT_SECURITY_BE_COMMON_H_

#include "security/backend/iot_security_be_bsp.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct iot_security_be_funcs {
	/**
	 * @brief a pointer to a function to initialize a cipher module
	 */
	iot_error_t (*cipher_init)(iot_security_context_t *);
	/**
	 * @brief a pointer to a function to deinitialize cipher module
	 */
	iot_error_t (*cipher_deinit)(iot_security_context_t *);
	/**
	 * @brief a pointer to a function to set the params for cipher operation
	 */
	iot_error_t (*cipher_set_params)(iot_security_context_t *, iot_security_cipher_params_t *);
	/**
	 * @brief a pointer to a function to encrypt based on AES
	 */
	iot_error_t (*cipher_aes_encrypt)(iot_security_context_t *, iot_security_buffer_t *, iot_security_buffer_t *);
	/**
	 * @brief a pointer to a function to decrypt based on AES
	 */
	iot_error_t (*cipher_aes_decrypt)(iot_security_context_t *, iot_security_buffer_t *, iot_security_buffer_t *);

	/**
	 * @brief a pointer to a function to initialize a manager module
	 */
	iot_error_t (*manager_init)(iot_security_context_t *);
	/**
	 * @brief a pointer to a function to deinitialize a manager module
	 */
	iot_error_t (*manager_deinit)(iot_security_context_t *);
	/**
	 * @brief a pointer to a function to get the security key
	 */
	iot_error_t (*manager_get_key)(iot_security_context_t *, iot_security_key_id_t, iot_security_buffer_t *);
	/**
	 * @brief a pointer to a function to set the security key
	 */
	iot_error_t (*manager_set_key)(iot_security_context_t *, iot_security_key_params_t *);
	/**
	 * @brief a pointer to a function to get the certificate
	 */
	iot_error_t (*manager_get_certificate)(iot_security_context_t *, iot_security_cert_id_t, iot_security_buffer_t *);

	/**
	 * @brief a pointer to a function to initialize a secure storage
	 */
	iot_error_t (*storage_init)(iot_security_context_t *);
	/**
	 * @brief a pointer to a function to deinitialize secure storage
	 */
	iot_error_t (*storage_deinit)(iot_security_context_t *);
	/**
	 * @brief a pointer to a function to read data from secure storage
	 */
	iot_error_t (*storage_read)(iot_security_context_t *, iot_security_buffer_t *);
	/**
	 * @brief a pointer to a function to write data into secure storage
	 */
	iot_error_t (*storage_write)(iot_security_context_t *, iot_security_buffer_t *);
	/**
	 * @brief a pointer to a function to remove data from secure storage
	 */
	iot_error_t (*storage_remove)(iot_security_context_t *);
} iot_security_be_funcs_t;

/**
 * @brief Callback function to get nv data from core
 */
typedef iot_error_t (*external_nv_callback)(iot_nvd_t nv_id, iot_security_buffer_t *output_buf);

struct iot_security_be_context {
	/**
	 * @brief string name to know this
	 */
	const char *name;
	/**
	 * @brief a pointer to a function lists
	 */
	const iot_security_be_funcs_t *fn;
	/**
	 * @brief a pointer to a function lists for bsp layer
	 */
	const iot_security_be_bsp_funcs_t *bsp_fn;
	/**
	 * @brief a pointer to a function to get nv data from device info file
	 */
	external_nv_callback external_device_info_cb;
};

/**
 * @brief	Initialize a security backend context
 * @details	Create a backend context and set the backend module
 * @param[in]	external_nv_cb a pointer to a function to get nv data from core
 * @return	a pointer to the created security context or null if failed to create
 */
iot_security_be_context_t *iot_security_be_init(external_nv_callback external_nv_cb);

/**
 * @brief	De-initialize a security backend context
 * @details	De-initialize the initialized backend module and free the backend context
 * @param[in]	be_context reference to the security backend context
 * @retval	IOT_ERROR_NONE success
 * @retval	IOT_ERROR_INVALID_ARGS be_context is null or deinit failed
 */
iot_error_t iot_security_be_deinit(iot_security_be_context_t *be_context);

#ifdef __cplusplus
}
#endif

#endif /* _IOT_SECURITY_BE_COMMON_H_ */
