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

#ifndef _IOT_SECURITY_MANAGER_H_
#define _IOT_SECURITY_MANAGER_H_

#include "iot_security_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief	Initialize a manager sub system
 * @details	Create a required parameter holder for manager system (can be null)
 * @retval	IOT_ERROR_NONE success
 * @retval	IOT_ERROR_SECURITY_CONTEXT_NULL security context parameter is null
 * @retval	IOT_ERROR_SECURITY_MANAGER_INIT failed to init the manager system
 */
iot_error_t iot_security_manager_init(iot_security_context_t *context);

/**
 * @brief	De-initialize a manager sub system
 * @details	De-initialize the initialized manager system
 * @retval	IOT_ERROR_NONE success
 * @retval	IOT_ERROR_SECURITY_CONTEXT_NULL security context parameter is null
 * @retval	IOT_ERROR_SECURITY_MANAGER_DEINIT failed to de-init the manager system
 */
iot_error_t iot_security_manager_deinit(iot_security_context_t *context);

/**
 * @brief	Generate a ephemeral key pair
 * @details	Generate a key pair based on elliptic curve
 * @param[in]	context reference to the security context
 * @param[in]	key_id key identity to specific a ephemeral key pair
 * @retval	IOT_ERROR_NONE success
 * @retval	IOT_ERROR_INVALID_ARGS input parameter is invalid
 * @retval	IOT_ERROR_MEM_ALLOC not enough heap memory
 * @retval	IOT_ERROR_SECURITY_CONTEXT_NULL security context is null
 * @retval	IOT_ERROR_SECURITY_BE_CONTEXT_NULL backend context is null
 * @retval	IOT_ERROR_SECURITY_BE_FUNC_NULL a pointer to a read function of backend is null
 * @retval	IOT_ERROR_SECURITY_KEY_INVALID_ID key identity in key_params is not a supported
 * @retval	IOT_ERROR_SECURITY_MANAGER_KEY_GENERATE failed to generate key pair
 */
iot_error_t iot_security_manager_generate_key(iot_security_context_t *context, iot_security_key_id_t key_id);

/**
 * @brief	Remove the generated ephemeral key pair
 * @param[in]	context reference to the security context
 * @param[in]	key_id key identity to specific a ephemeral key pair
 * @retval	IOT_ERROR_NONE success
 * @retval	IOT_ERROR_INVALID_ARGS input parameter is invalid
 * @retval	IOT_ERROR_MEM_ALLOC not enough heap memory
 * @retval	IOT_ERROR_SECURITY_CONTEXT_NULL security context is null
 * @retval	IOT_ERROR_SECURITY_BE_CONTEXT_NULL backend context is null
 * @retval	IOT_ERROR_SECURITY_BE_FUNC_NULL a pointer to a read function of backend is null
 * @retval	IOT_ERROR_SECURITY_KEY_INVALID_ID key identity in key_params is not a supported
 * @retval	IOT_ERROR_SECURITY_MANAGER_KEY_REMOVE failed to remove key pair
 */
iot_error_t iot_security_manager_remove_key(iot_security_context_t *context, iot_security_key_id_t key_id);

/**
 * @brief	Set the key for signature or encryption
 * @details	Set the parameter required for signature or encryption operation
 * @param[in]	context reference to the security context
 * @param[in]	key_params key parameter want to set
 * @retval	IOT_ERROR_NONE success
 * @retval	IOT_ERROR_INVALID_ARGS input parameter is invalid
 * @retval	IOT_ERROR_MEM_ALLOC not enough heap memory
 * @retval	IOT_ERROR_SECURITY_CONTEXT_NULL security context is null
 * @retval	IOT_ERROR_SECURITY_BE_CONTEXT_NULL backend context is null
 * @retval	IOT_ERROR_SECURITY_BE_FUNC_NULL a pointer to a read function of backend is null
 * @retval	IOT_ERROR_SECURITY_CIPHER_PARAMS_NULL cipher parameter is null
 * @retval	IOT_ERROR_SECURITY_PK_PARAMS_NULL pubkey parameter is null
 * @retval	IOT_ERROR_SECURITY_KEY_INVALID_ID key identity in key_params is not a supported
 * @retval	IOT_ERROR_SECURITY_MANAGER_KEY_SET failed to set key
 */
iot_error_t iot_security_manager_set_key(iot_security_context_t *context, iot_security_key_params_t *key_params);

/**
 * @brief	Set the key for signature or encryption
 * @details	Set the parameter required for signature or encryption operation
 * @param[in]	context reference to the security context
 * @param[in]	key_id key identity want to get
 * @param[out]	key_buf a pointer to a buffer to store the key
 * @retval	IOT_ERROR_NONE success
 * @retval	IOT_ERROR_INVALID_ARGS input parameter is invalid
 * @retval	IOT_ERROR_MEM_ALLOC not enough heap memory
 * @retval	IOT_ERROR_SECURITY_CONTEXT_NULL security context is null
 * @retval	IOT_ERROR_SECURITY_BE_CONTEXT_NULL backend context is null
 * @retval	IOT_ERROR_SECURITY_BE_FUNC_NULL a pointer to a read function of backend is null
 * @retval	IOT_ERROR_SECURITY_CIPHER_PARAMS_NULL cipher parameter is null
 * @retval	IOT_ERROR_SECURITY_PK_PARAMS_NULL pubkey parameter is null
 * @retval	IOT_ERROR_SECURITY_KEY_INVALID_ID key identity in key_params is not a supported
 * @retval	IOT_ERROR_SECURITY_KEY_NOT_FOUND not found key requested by key_id
 * @retval	IOT_ERROR_SECURITY_KEY_NO_PERMISSION can not get key because do not have permission
 * @retval	IOT_ERROR_SECURITY_MANAGER_KEY_GET failed to get key
 */
iot_error_t iot_security_manager_get_key(iot_security_context_t *context, iot_security_key_id_t key_id, iot_security_buffer_t *key_buf);

/**
 * @brief	Get the certificate
 * @details	Get the certificate from static, factory or eSE
 * @param[in]	context reference to the security context
 * @param[in]	cert_id certificate identity want to get
 * @param[out]	cert_buf a pointer to a buffer to store the certificate
 * @retval	IOT_ERROR_NONE success
 * @retval	IOT_ERROR_INVALID_ARGS input parameter is invalid
 * @retval	IOT_ERROR_MEM_ALLOC not enough heap memory
 * @retval	IOT_ERROR_SECURITY_CONTEXT_NULL security context is null
 * @retval	IOT_ERROR_SECURITY_BE_CONTEXT_NULL backend context is null
 * @retval	IOT_ERROR_SECURITY_BE_FUNC_NULL a pointer to a read function of backend is null
 * @retval	IOT_ERROR_SECURITY_BSP_FN_LOAD_NULL fs bsp functions is null when software based
 * @retval	IOT_ERROR_SECURITY_CERT_INVALID_ID cert_id is not a supported target
 * @retval	IOT_ERROR_SECURITY_MANAGER_CERT_GET failed to get certificate
 * @retval	IOT_ERROR_NV_DATA_ERROR cert_id is not a supported static certificate
 */
iot_error_t iot_security_manager_get_certificate(iot_security_context_t *context, iot_security_cert_id_t cert_id, iot_security_buffer_t *cert_buf);

#ifdef __cplusplus
}
#endif

#endif /* _IOT_SECURITY_MANAGER_H_ */
