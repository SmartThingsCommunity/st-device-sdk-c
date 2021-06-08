/* ***************************************************************************
 *
 * Copyright 2019 Samsung Electronics All Rights Reserved.
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

#ifndef _IOT_BSP_FS_H_
#define _IOT_BSP_FS_H_

#include <stddef.h>
#include "iot_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @name iot_bsp_fs_handle_t
 * @brief file system handle.
 */
typedef struct {
	int fd;
	char filename[128];
} iot_bsp_fs_handle_t;

/**
 * @name iot_bsp_fs_open_mode_t
 * @brief file system open mode.
 */
typedef enum {
	FS_READONLY,
	FS_READWRITE
} iot_bsp_fs_open_mode_t;

/**
 * @brief Initialize a file system.
 *
 * @details This function initializes the file-system of the device.
 * You must call this function before using file-management function (open, read, write, etc.)
 * @retval IOT_ERROR_NONE File-system init successful.
 * @retval IOT_ERROR_INIT_FAIL File-system init failed.
 */
iot_error_t iot_bsp_fs_init();

/**
 * @brief Deinitialize a file system.
 *
 * @retval IOT_ERROR_NONE File-system deinit successful.
 * @retval IOT_ERROR_DEINIT_FAIL File-system deinit failed.
 */
iot_error_t iot_bsp_fs_deinit();

/**
 * @brief Open a file
 *
 * @param[in] filename File name.
 * @param[in] mode File open mode. FS_READONLY or FS_READWRITE.
 * @param[out] handle A pointer to the file handle.
 * @retval IOT_ERROR_NONE File open successful.
 * @retval IOT_ERROR_FS_NO_FILE No file.
 * @retval IOT_ERROR_FS_OPEN_FAIL File open failed.
 */
iot_error_t iot_bsp_fs_open(const char* filename, iot_bsp_fs_open_mode_t mode, iot_bsp_fs_handle_t* handle);

/**
 * @brief Open a file from stnv partition
 *
 * @details This function will return the read-only file-system handle.
 * You can access the stnv partition's file though this handle.
 * @param[in] filename File name.
 * @param[out] handle A pointer to the file handle.
 * @retval IOT_ERROR_NONE File open successful.
 * @retval IOT_ERROR_FS_NO_FILE No file.
 * @retval IOT_ERROR_FS_OPEN_FAIL File open failed.
 */
iot_error_t iot_bsp_fs_open_from_stnv(const char* filename, iot_bsp_fs_handle_t* handle);

/**
 * @brief Read a file
 *
 * @param[in] handle  This is iot_bsp_fs_handle_t handle from iot_bsp_fs_open().
 * @param[out] buffer A pointer to buffer array to store the read data from the file.
 * @param[in/out] length The size of buffer and this will be set to the actual length of the value read
 * @retval IOT_ERROR_NONE File read successful.
 * @retval IOT_ERROR_FS_READ_FAIL File read failed.
 * @retval IOT_ERROR_FS_NO_FILE No file.
 */
iot_error_t iot_bsp_fs_read(iot_bsp_fs_handle_t handle, char* buffer, size_t *length);

/**
 * @brief Write a file
 *
 * @param[in] handle This is iot_bsp_fs_handle_t handle from iot_bsp_fs_open().
 * @param[in] data A pointer to data array to write to the file.
 * @param[in] length The size of data.
 * @retval IOT_ERROR_NONE File write successful.
 * @retval IOT_ERROR_FS_WRITE_FAIL File write failed.
 */
iot_error_t iot_bsp_fs_write(iot_bsp_fs_handle_t handle, const char* data, size_t length);

/**
 * @brief Close a file
 *
 * @param[in] handle This is iot_bsp_fs_handle_t handle from iot_bsp_fs_open().
 * @retval IOT_ERROR_NONE File close successful.
 */
iot_error_t iot_bsp_fs_close(iot_bsp_fs_handle_t handle);

/**
 * @brief Remove a file
 *
 * @param[in] filename File name.
 * @retval IOT_ERROR_NONE File remove successful.
 * @retval IOT_ERROR_INVALID_ARGS Invalid filename
 * @retval IOT_ERROR_FS_REMOVE_FAIL File remove failed.
 */
iot_error_t iot_bsp_fs_remove(const char* filename);

#ifdef __cplusplus
}
#endif

#endif /* _IOT_BSP_DEBUG_H_ */
