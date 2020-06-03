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

#ifndef _IOT_SECURITY_SECURE_STORAGE_H_
#define _IOT_SECURITY_SECURE_STORAGE_H_

#include "iot_nv_data.h"
#include "iot_security_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define IOT_SECURITY_STORAGE_BUF_MAX_LEN	2048
#define IOT_SECURITY_STORAGE_FILENAME_MAX_LEN	64

/**
 * @brief	File identity referencing iot_nvd_t
 */
typedef iot_nvd_t iot_security_storage_id_t;

/**
 * @brief	Target attribute of storage
 * @details	'NV' means a dynamic file created at runtime.
 * 		'FACTORY' means a file injected from factory.
 */
typedef enum {
	IOT_SECURITY_STORAGE_TARGET_UNKNOWN = 0,
	IOT_SECURITY_STORAGE_TARGET_NV,
	IOT_SECURITY_STORAGE_TARGET_FACTORY,
	IOT_SECURITY_STORAGE_TARGET_DI,
	IOT_SECURITY_STORAGE_TARGET_STATIC,
	IOT_SECURITY_STORAGE_TARGET_INVALID,
} iot_security_storage_target_t;

/**
 * @brief	Used file identity in current context
 */
struct iot_security_storage_params {
	iot_security_storage_id_t storage_id;
};

/**
 * @brief	Initialize a storage sub system
 * @details	Create a required parameter holder for storage system and init the backend module
 * @retval	IOT_ERROR_NONE success
 * @retval	IOT_ERROR_MEM_ALLOC not enough heap memory
 * @retval	IOT_ERROR_SECURITY_CONTEXT_NULL security context parameter is null
 * @retval	IOT_ERROR_SECURITY_STORAGE_INIT failed to init the storage of backend
 */
iot_error_t iot_security_storage_init(iot_security_context_t *context);

/**
 * @brief	De-initialize a storage sub system
 * @details	De-initialize the initialized storage system and free the parameter holder
 * @retval	IOT_ERROR_NONE success
 * @retval	IOT_ERROR_SECURITY_CONTEXT_NULL security context parameter is null
 * @retval	IOT_ERROR_SECURITY_STORAGE_DEINIT failed to de-init the storage of backend
 */
iot_error_t iot_security_storage_deinit(iot_security_context_t *context);

/**
 * @brief	Read data from storage
 * @details	a pointer to a function to read the data from storage
 * @param[in]	context reference to the security context
 * @param[in]	storage_id file identity of target to read
 * @param[out]	output_buf a pointer to a security buffer for read data
 * @retval	IOT_ERROR_NONE success
 * @retval	IOT_ERROR_INVALID_ARGS output_buf is null
 * @retval	IOT_ERROR_MEM_ALLOC not enough heap memory
 * @retval	IOT_ERROR_SECURITY_CONTEXT_NULL security context is null
 * @retval	IOT_ERROR_SECURITY_BE_CONTEXT_NULL backend context is null
 * @retval	IOT_ERROR_SECURITY_BE_FUNCS_ENTRY_NULL function lists of backend context is null
 * @retval	IOT_ERROR_SECURITY_STORAGE_PARAMS_NULL storage parameter holder is null
 * @retval	IOT_ERROR_SECURITY_STORAGE_INVALID_ID storage_id is a invalid identity
 * @retval	IOT_ERROR_SECURITY_BE_FUNC_NULL a pointer to a read function of backend is null
 * @retval	IOT_ERROR_SECURITY_FS_UNKNOWN_TARGET target attribute referenced by file identity is unknown
 * @retval	IOT_ERROR_SECURITY_FS_INVALID_ARGS parameter is invalid in bsp layer
 * @retval	IOT_ERROR_SECURITY_FS_BUFFER not enough buffer to get filename from file identity
 * @retval	IOT_ERROR_SECURITY_FS_OPEN failed to open file to read the data in bsp layer
 * @retval	IOT_ERROR_SECURITY_FS_READ failed to read from file in bsp layer
 * @retval	IOT_ERROR_SECURITY_FS_CLOSE failed to close file after read the data in bsp layer
 * @retval	IOT_ERROR_SECURITY_FS_NOT_FOUND file does not exist in bsp layer
 */
iot_error_t iot_security_storage_read(iot_security_context_t *context, iot_security_storage_id_t storage_id, iot_security_buffer_t *output_buf);

/**
 * @brief	Write data to storage
 * @details	a pointer to a function to write the data to storage
 * @param[in]	context reference to the security context
 * @param[in]	storage_id file identity of target to write
 * @param[in]	input_buf a pointer to a security buffer for write data
 * @retval	IOT_ERROR_NONE success
 * @retval	IOT_ERROR_INVALID_ARGS output_buf is null
 * @retval	IOT_ERROR_MEM_ALLOC not enough heap memory
 * @retval	IOT_ERROR_SECURITY_CONTEXT_NULL security context is null
 * @retval	IOT_ERROR_SECURITY_BE_CONTEXT_NULL backend context is null
 * @retval	IOT_ERROR_SECURITY_BE_FUNCS_ENTRY_NULL function lists of backend context is null
 * @retval	IOT_ERROR_SECURITY_STORAGE_PARAMS_NULL storage parameter holder is null
 * @retval	IOT_ERROR_SECURITY_STORAGE_INVALID_ID storage_id is a invalid identity
 * @retval	IOT_ERROR_SECURITY_BE_FUNC_NULL a pointer to a read function of backend is null
 * @retval	IOT_ERROR_SECURITY_FS_INVALID_TARGET not allowed to write the data referenced by file identity
 * @retval	IOT_ERROR_SECURITY_FS_UNKNOWN_TARGET target attribute referenced by file identity is unknown
 * @retval	IOT_ERROR_SECURITY_FS_INVALID_ARGS parameter is invalid in bsp layer
 * @retval	IOT_ERROR_SECURITY_FS_BUFFER not enough buffer to get filename from file identity
 * @retval	IOT_ERROR_SECURITY_FS_OPEN failed to open file to write the data in bsp layer
 * @retval	IOT_ERROR_SECURITY_FS_WRITE failed to write to file in bsp layer
 * @retval	IOT_ERROR_SECURITY_FS_CLOSE failed to close file after write the data in bsp layer
 * @retval	IOT_ERROR_SECURITY_FS_NOT_FOUND file does not exist in bsp layer
 */
iot_error_t iot_security_storage_write(iot_security_context_t *context, iot_security_storage_id_t storage_id, iot_security_buffer_t *input_buf);

/**
 * @brief	Remove data from storage
 * @details	a pointer to a function to remove the data from storage
 * @param[in]	context reference to the security context
 * @param[in]	storage_id file identity of target to remove
 * @retval	IOT_ERROR_NONE success
 * @retval	IOT_ERROR_INVALID_ARGS output_buf is null
 * @retval	IOT_ERROR_MEM_ALLOC not enough heap memory
 * @retval	IOT_ERROR_SECURITY_CONTEXT_NULL security context is null
 * @retval	IOT_ERROR_SECURITY_BE_CONTEXT_NULL backend context is null
 * @retval	IOT_ERROR_SECURITY_BE_FUNCS_ENTRY_NULL function lists of backend context is null
 * @retval	IOT_ERROR_SECURITY_STORAGE_PARAMS_NULL storage parameter holder is null
 * @retval	IOT_ERROR_SECURITY_STORAGE_INVALID_ID storage_id is a invalid identity
 * @retval	IOT_ERROR_SECURITY_BE_FUNC_NULL a pointer to a read function of backend is null
 * @retval	IOT_ERROR_SECURITY_FS_INVALID_TARGET not allowed to remove the data referenced by file identity
 * @retval	IOT_ERROR_SECURITY_FS_UNKNOWN_TARGET target attribute referenced by file identity is unknown
 * @retval	IOT_ERROR_SECURITY_FS_INVALID_ARGS parameter is invalid in bsp layer
 * @retval	IOT_ERROR_SECURITY_FS_BUFFER not enough buffer to get filename from file identity
 * @retval	IOT_ERROR_SECURITY_FS_OPEN failed to open file to read the data in bsp layer
 * @retval	IOT_ERROR_SECURITY_FS_REMOVE failed to remove from file in bsp layer
 * @retval	IOT_ERROR_SECURITY_FS_CLOSE failed to close file after read the data in bsp layer
 * @retval	IOT_ERROR_SECURITY_FS_NOT_FOUND file does not exist in bsp layer
 */
iot_error_t iot_security_storage_remove(iot_security_context_t *context, iot_security_storage_id_t storage_id);

#ifdef __cplusplus
}
#endif

#endif /* _IOT_SECURITY_SECURE_STORAGE_H_ */
