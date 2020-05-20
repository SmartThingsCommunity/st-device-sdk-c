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

#include <string.h>

#include "iot_main.h"
#include "iot_debug.h"
#include "security/iot_security_storage.h"
#include "security/backend/iot_security_be.h"

STATIC_FUNCTION
iot_error_t _iot_security_be_check_context_and_params_is_valid(iot_security_context_t *context, iot_security_sub_system_t sub_system)
{
	if (!context) {
		IOT_ERROR("context is null");
		return IOT_ERROR_SECURITY_CONTEXT_NULL;
	}

	if (sub_system & IOT_SECURITY_SUB_STORAGE) {
		if (!context->storage_params) {
			IOT_ERROR("storage params is null");
			return IOT_ERROR_SECURITY_STORAGE_PARAMS_NULL;
		}
	}

	return IOT_ERROR_NONE;
}

STATIC_FUNCTION
iot_error_t _iot_security_be_software_bsp_fs_load(iot_security_context_t *context, iot_security_storage_id_t storage_id, iot_security_buffer_t *output_buf)
{
	iot_error_t err;
	const iot_security_be_bsp_funcs_t *bsp_fn;

	if (!context) {
		return IOT_ERROR_SECURITY_CONTEXT_NULL;
	}

	if (!context->be_context) {
		return IOT_ERROR_SECURITY_BE_CONTEXT_NULL;
	}

	bsp_fn = context->be_context->bsp_fn;

	if (!bsp_fn || !bsp_fn->bsp_fs_load) {
		return IOT_ERROR_SECURITY_BSP_FN_LOAD_NULL;
	}

	err = bsp_fn->bsp_fs_load(context->be_context, storage_id, output_buf);
	if (err) {
		return err;
	}

	return IOT_ERROR_NONE;
};

STATIC_FUNCTION
iot_error_t _iot_security_be_software_storage_read(iot_security_context_t *context, iot_security_buffer_t *data_buf)
{
	iot_error_t err;
	iot_security_storage_params_t *storage_params;

	err = _iot_security_be_check_context_and_params_is_valid(context, IOT_SECURITY_SUB_STORAGE);
	if (err) {
		return err;
	}

	storage_params = context->storage_params;

	err = _iot_security_be_software_bsp_fs_load(context, storage_params->storage_id, data_buf);
	if (err) {
		return err;
	}

	return IOT_ERROR_NONE;
}

STATIC_FUNCTION
iot_error_t _iot_security_be_software_storage_write(iot_security_context_t *context, iot_security_buffer_t *data_buf)
{
	iot_error_t err;
	iot_security_storage_params_t *storage_params;

	err = _iot_security_be_check_context_and_params_is_valid(context, IOT_SECURITY_SUB_STORAGE);
	if (err) {
		return err;
	}

	storage_params = context->storage_params;

	if (!context->be_context->bsp_fn ||
		!context->be_context->bsp_fn->bsp_fs_store) {
		return IOT_ERROR_SECURITY_BSP_FN_STORE_NULL;
	}

	err = context->be_context->bsp_fn->bsp_fs_store(context->be_context, storage_params->storage_id, data_buf);
	if (err) {
		return err;
	}

	return IOT_ERROR_NONE;
}

STATIC_FUNCTION
iot_error_t _iot_security_be_software_storage_remove(iot_security_context_t *context)
{
	iot_error_t err;
	iot_security_storage_params_t *storage_params;

	err = _iot_security_be_check_context_and_params_is_valid(context, IOT_SECURITY_SUB_STORAGE);
	if (err) {
		return err;
	}

	storage_params = context->storage_params;

	if (!context->be_context->bsp_fn ||
		!context->be_context->bsp_fn->bsp_fs_remove) {
		return IOT_ERROR_SECURITY_BSP_FN_REMOVE_NULL;
	}

	err = context->be_context->bsp_fn->bsp_fs_remove(context->be_context, storage_params->storage_id);
	if (err) {
		if (err != IOT_ERROR_SECURITY_FS_NOT_FOUND) {
		}
		return err;
	}

	return IOT_ERROR_NONE;
}

const iot_security_be_funcs_t iot_security_be_software_funcs = {
	.storage_init = NULL,
	.storage_deinit = NULL,
	.storage_read = _iot_security_be_software_storage_read,
	.storage_write = _iot_security_be_software_storage_write,
	.storage_remove = _iot_security_be_software_storage_remove,
};

iot_security_be_context_t *iot_security_be_init(external_nv_callback external_nv_cb)
{
	iot_error_t err;
	iot_security_be_context_t *be_context;

	be_context = (iot_security_be_context_t *)iot_os_malloc(sizeof(iot_security_be_context_t));
	if (!be_context) {
		IOT_ERROR("failed to malloc for context");
		return NULL;
	}

	memset(be_context, 0, sizeof(iot_security_be_context_t));

	be_context->name = "software";
	be_context->fn = &iot_security_be_software_funcs;
	be_context->external_device_info_cb = external_nv_cb;

	err = iot_security_be_bsp_init(be_context);
	if (err) {
		IOT_ERROR("iot_security_be_bsp_init = %d", err);
		iot_os_free(be_context);
		return NULL;
	}

	IOT_DEBUG("security backend is '%s'", be_context->name);

	return be_context;
}

iot_error_t iot_security_be_deinit(iot_security_be_context_t *be_context)
{
	if (!be_context) {
		IOT_ERROR("backend context is null");
		return IOT_ERROR_INVALID_ARGS;
	}

	memset(be_context, 0, sizeof(iot_security_be_context_t));

	iot_os_free(be_context);

	return IOT_ERROR_NONE;
}
