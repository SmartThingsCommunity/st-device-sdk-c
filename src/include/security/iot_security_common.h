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

#include <stdbool.h>
#include "iot_security_error.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct iot_security_be_context iot_security_be_context_t;

/**
 * @brief A handle of security context
 */
typedef unsigned int security_handle;

/**
 * @brief Indicate a sub system is initialized
 */
typedef enum iot_security_sub_system {
	IOT_SECURITY_SUB_NONE    = 0,
} iot_security_sub_system_t;

/**
 * @brief Contains a buffer information
 */
typedef struct iot_security_buffer {
	size_t len;                                     /**< @brief length of buffer */
	unsigned char *p;                               /**< @brief pointer of buffer */
} iot_security_buffer_t;

/**
 * @brief Contains a security context data
 */
typedef struct iot_security_context {
	security_handle handle;                         /**< @brief handle of context */
	iot_security_sub_system_t sub_system;           /**< @brief flag to know whether the sub system has been initialized */

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
