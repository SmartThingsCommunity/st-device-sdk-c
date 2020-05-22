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

#ifndef _IOT_SECURITY_KEY_MANAGER_H_
#define _IOT_SECURITY_KEY_MANAGER_H_

#include "iot_security_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
* @brief Contains information for ecdh
*/
struct iot_security_ecdh_params {
	/**
	 * @brief a pointer to a things secret key based on curve25519 (software backend only)
	 */
	iot_security_buffer_t t_seckey;
	/**
	 * @brief a pointer to a server public key based on curve25519
	 */
	iot_security_buffer_t c_pubkey;
	/**
	 * @brief a pointer to a random token as a salt
	 */
	iot_security_buffer_t salt;
};

/**
 * @brief	Initialize a ecdh sub system
 * @details	Create a required parameter holder for ecdh system and init the backend module
 * @retval	IOT_ERROR_NONE success
 * @retval	IOT_ERROR_MEM_ALLOC not enough heap memory
 * @retval	IOT_ERROR_SECURITY_CONTEXT_NULL security context parameter is null
 * @retval	IOT_ERROR_SECURITY_ECDH_INIT failed to init the ecdh of backend
 */
iot_error_t iot_security_ecdh_init(iot_security_context_t *context);

/**
 * @brief	De-initialize a ecdh sub system
 * @details	De-initialize the initialized ecdh system and free the parameter holder
 * @retval	IOT_ERROR_NONE success
 * @retval	IOT_ERROR_SECURITY_CONTEXT_NULL security context parameter is null
 * @retval	IOT_ERROR_SECURITY_STORAGE_DEINIT failed to de-init the ecdh of backend
 */
iot_error_t iot_security_ecdh_deinit(iot_security_context_t *context);

/**
 * @brief	Set the parameter for ecdh operation
 * @details	Set the ecdh algorithm, Key and IV
 * @param[in]	context reference to the security context
 * @param[in]	ecdh_set_params ecdh parameter want to set
 * @retval	IOT_ERROR_NONE success
 * @retval	IOT_ERROR_INVALID_ARGS input parameter is invalid
 * @retval	IOT_ERROR_MEM_ALLOC not enough heap memory
 * @retval	IOT_ERROR_SECURITY_CONTEXT_NULL security context is null
 * @retval	IOT_ERROR_SECURITY_BE_CONTEXT_NULL backend context is null
 * @retval	IOT_ERROR_SECURITY_BE_FUNC_NULL a pointer to a read function of backend is null
 * @retval	IOT_ERROR_SECURITY_ECDH_PARAMS_NULL ecdh parameter is null or has invalid data
 * @retval	IOT_ERROR_SECURITY_ECDH_SET_PARAMS failed to set the parameter
 */
iot_error_t iot_security_ecdh_set_params(iot_security_context_t *context, iot_security_ecdh_params_t *ecdh_set_params);

/**
 * @brief	Compute a shared secret
 * @details	Compute a shared secret with device private key and peer public key
 * @param[in]	context reference to the security context
 * @param[out]	secret_buf a pointer to a buffer to store the shared secret
 * @retval	IOT_ERROR_NONE success
 * @retval	IOT_ERROR_INVALID_ARGS input parameter is invalid
 * @retval	IOT_ERROR_MEM_ALLOC not enough heap memory
 * @retval	IOT_ERROR_SECURITY_CONTEXT_NULL security context is null
 * @retval	IOT_ERROR_SECURITY_BE_CONTEXT_NULL backend context is null
 * @retval	IOT_ERROR_SECURITY_BE_FUNC_NULL a pointer to a read function of backend is null
 * @retval	IOT_ERROR_SECURITY_ECDH_PARAMS_NULL ecdh parameter is null or has invalid data
 * @retval	IOT_ERROR_SECURITY_ECDH_INVALID_PUBKEY public key of peer is invalid
 * @retval	IOT_ERROR_SECURITY_ECDH_INVALID_SECKEY private key of device is invalid
 * @retval	IOT_ERROR_SECURITY_ECDH_LIBRARY an error occurred in 3rd party library
 */
iot_error_t iot_security_ecdh_compute_shared_secret(iot_security_context_t *context, iot_security_buffer_t *secret_buf);

#ifdef __cplusplus
}
#endif

#endif /* _IOT_SECURITY_KEY_MANAGER_H_ */
