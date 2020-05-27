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
iot_error_t _iot_security_storage_set_storage_id(iot_security_context_t *context, iot_security_storage_id_t storage_id)
{
	if (!context) {
		return IOT_ERROR_SECURITY_CONTEXT_NULL;
	}

	if (!context->storage_params) {
		return IOT_ERROR_SECURITY_STORAGE_PARAMS_NULL;
	}

	if ((storage_id <= IOT_NVD_UNKNOWN) || (storage_id >= IOT_NVD_MAX)) {
		IOT_ERROR("'%d' is invalid id", storage_id);
		return IOT_ERROR_SECURITY_STORAGE_INVALID_ID;
	}

	context->storage_params->storage_id = storage_id;

	return IOT_ERROR_NONE;
}

iot_error_t iot_security_storage_init(iot_security_context_t *context)
{
	iot_error_t err;
	iot_security_storage_params_t *storage_params;

	if (!context) {
		return IOT_ERROR_SECURITY_CONTEXT_NULL;
	}

	storage_params = (iot_security_storage_params_t *)iot_os_malloc(sizeof(iot_security_storage_params_t));
	if (!storage_params) {
		IOT_ERROR("failed to malloc for storage params");
		return IOT_ERROR_MEM_ALLOC;
	}

	memset(storage_params, 0, sizeof(iot_security_storage_params_t));

	context->storage_params = storage_params;

	if (context->be_context &&
		context->be_context->fn &&
		context->be_context->fn->storage_init) {
		err = context->be_context->fn->storage_init(context);
		if (err) {
			iot_os_free(context->storage_params);
			context->storage_params = NULL;
			return err;
		}
	}

	context->sub_system |= IOT_SECURITY_SUB_STORAGE;

	return IOT_ERROR_NONE;
}

iot_error_t iot_security_storage_deinit(iot_security_context_t *context)
{
	iot_error_t err;

	if (!context) {
		return IOT_ERROR_SECURITY_CONTEXT_NULL;
	}

	if (context->be_context &&
		context->be_context->fn &&
		context->be_context->fn->storage_deinit) {
		err = context->be_context->fn->storage_deinit(context);
		if (err) {
			return err;
		}
	}

	if (context->storage_params) {
		memset(context->storage_params, 0, sizeof(iot_security_storage_params_t));
		iot_os_free(context->storage_params);
		context->storage_params = NULL;
	}

	context->sub_system &= ~IOT_SECURITY_SUB_STORAGE;

	return IOT_ERROR_NONE;
}

iot_error_t iot_security_storage_read(iot_security_context_t *context, iot_security_storage_id_t storage_id, iot_security_buffer_t *output_buf)
{
	iot_error_t err;

	IOT_DEBUG("id:%d", storage_id);

	err = iot_security_check_backend_funcs_entry_is_valid(context);
	if (err) {
		return err;
	}

	err = _iot_security_storage_set_storage_id(context, storage_id);
	if (err) {
		return err;
	}

	if (!output_buf) {
		IOT_ERROR("output buf is invalid");
		return IOT_ERROR_INVALID_ARGS;
	}

	memset(output_buf, 0, sizeof(iot_security_buffer_t));

	if (!context->be_context->fn->storage_read) {
		IOT_ERROR("be->fn->storage_read is null");
		return IOT_ERROR_SECURITY_BE_FUNC_NULL;
	}

	err = context->be_context->fn->storage_read(context, output_buf);
	if (err) {
		if (err == IOT_ERROR_SECURITY_FS_NOT_FOUND) {
			IOT_WARN("id:%d not found", context->storage_params->storage_id);
		}
		return err;
	}

	IOT_DEBUG("id:%d read %d@%p", context->storage_params->storage_id, (int)output_buf->len, output_buf->p);

	return IOT_ERROR_NONE;
}

iot_error_t iot_security_storage_write(iot_security_context_t *context, iot_security_storage_id_t storage_id, iot_security_buffer_t *input_buf)
{
	iot_error_t err;

	IOT_DEBUG("id:%d", storage_id);

	err = iot_security_check_backend_funcs_entry_is_valid(context);
	if (err) {
		return err;
	}

	err = _iot_security_storage_set_storage_id(context, storage_id);
	if (err) {
		return err;
	}

	if (!input_buf || !input_buf->p || (input_buf->len == 0)) {
		IOT_ERROR("input buf is invalid");
		return IOT_ERROR_INVALID_ARGS;
	}

	if (!context->be_context->fn->storage_write) {
		IOT_ERROR("be->fn->storage_write is null");
		return IOT_ERROR_SECURITY_BE_FUNC_NULL;
	}

	err = context->be_context->fn->storage_write(context, input_buf);
	if (err) {
		return err;
	}

	IOT_DEBUG("id:%d written %d@%p", context->storage_params->storage_id, (int)input_buf->len, input_buf->p);

	return IOT_ERROR_NONE;
}

iot_error_t iot_security_storage_remove(iot_security_context_t *context, iot_security_storage_id_t storage_id)
{
	iot_error_t err;

	IOT_DEBUG("id:%d", storage_id);

	err = iot_security_check_backend_funcs_entry_is_valid(context);
	if (err) {
		return err;
	}

	err = _iot_security_storage_set_storage_id(context, storage_id);
	if (err) {
		return err;
	}

	if (!context->be_context->fn->storage_remove) {
		IOT_ERROR("be->fn->storage_remove is null");
		return IOT_ERROR_SECURITY_BE_FUNC_NULL;
	}

	err = context->be_context->fn->storage_remove(context);
	if (err) {
		if (err == IOT_ERROR_SECURITY_FS_NOT_FOUND) {
			IOT_WARN("id:%d not found", context->storage_params->storage_id);
		}
		return err;
	}

	IOT_DEBUG("id:%d removed", context->storage_params->storage_id);

	return IOT_ERROR_NONE;
}