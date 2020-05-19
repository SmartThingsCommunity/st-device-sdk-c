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

} iot_security_be_funcs_t;

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
};

/**
 * @brief	Initialize a security backend context
 * @details	Create a backend context and set the backend module
 * @return	a pointer to the created security context or null if failed to create
 */
iot_security_be_context_t *iot_security_be_init(void);

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
