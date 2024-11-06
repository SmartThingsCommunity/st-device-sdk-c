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

#ifndef _IOT_SECURITY_BE_BSP_H_
#define _IOT_SECURITY_BE_BSP_H_

#include "security/iot_security_storage.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct iot_security_be_bsp_funcs {
	/**
	 * @brief a pointer to a function to load data from bsp layer
	 */
	iot_error_t (*bsp_fs_load)(iot_security_be_context_t *, iot_security_storage_id_t , iot_security_buffer_t *);
	/**
	 * @brief a pointer to a function to store data into bsp layer
	 */
	iot_error_t (*bsp_fs_store)(iot_security_be_context_t *, iot_security_storage_id_t, iot_security_buffer_t *);
	/**
	 * @brief a pointer to a function to remove data from bsp layer
	 */
	iot_error_t (*bsp_fs_remove)(iot_security_be_context_t *, iot_security_storage_id_t);
} iot_security_be_bsp_funcs_t;

/**
 * @brief	Initialize a bsp layer for software backend module
 * @details	Set a bsp layer to access the file system in backend module
 * @param[in]	context reference to the security backend context
 * @retval	IOT_ERROR_NONE success
 * @retval	IOT_ERROR_SECURITY_BE_CONTEXT_NULL be context is null
 */
iot_error_t iot_security_be_bsp_init(iot_security_be_context_t *be_context);

#ifdef __cplusplus
}
#endif

#endif /* _IOT_SECURITY_BE_BSP_H_ */
