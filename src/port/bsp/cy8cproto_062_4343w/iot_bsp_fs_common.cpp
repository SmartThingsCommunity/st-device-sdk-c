/* ***************************************************************************
 *
 * Copyright 2019-2020 Samsung Electronics All Rights Reserved.
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

#include <stdio.h>
#include <string.h>
#include "iot_bsp_fs.h"
#include "iot_bsp_debug.h"

iot_error_t iot_bsp_fs_init()
{
	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_deinit()
{
	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_open(const char *filename, iot_bsp_fs_open_mode_t mode, iot_bsp_fs_handle_t *handle)
{
	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_open_from_stnv(const char *filename, iot_bsp_fs_handle_t *handle)
{
	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_read(iot_bsp_fs_handle_t handle, char *buffer, unsigned int length)
{
	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_write(iot_bsp_fs_handle_t handle, const char *data, unsigned int length)
{
	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_close(iot_bsp_fs_handle_t handle)
{
	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_remove(const char *filename)
{
	return IOT_ERROR_NONE;
}
