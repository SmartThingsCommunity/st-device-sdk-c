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
#include "security/iot_security_ecdh.h"
#include "security/backend/iot_security_be.h"

iot_error_t iot_security_ecdh_init(iot_security_context_t *context)
{
	iot_error_t err;
	iot_security_ecdh_params_t *ecdh_params;

	if (!context) {
		return IOT_ERROR_SECURITY_CONTEXT_NULL;
	}

	ecdh_params = (iot_security_ecdh_params_t *)iot_os_malloc(sizeof(iot_security_ecdh_params_t));
	if (!ecdh_params) {
		IOT_ERROR("failed to malloc for ecdh params");
		return IOT_ERROR_MEM_ALLOC;
	}

	memset((void *)ecdh_params, 0, sizeof(iot_security_ecdh_params_t));

	context->ecdh_params = ecdh_params;

	if (context->be_context &&
		context->be_context->fn &&
		context->be_context->fn->ecdh_init) {
		err = context->be_context->fn->ecdh_init(context);
		if (err) {
			iot_os_free(context->ecdh_params);
			context->ecdh_params = NULL;
			return err;
		}
	}

	context->sub_system |= IOT_SECURITY_SUB_ECDH;

	return IOT_ERROR_NONE;
}

iot_error_t iot_security_ecdh_deinit(iot_security_context_t *context)
{
	iot_error_t err;

	if (!context) {
		return IOT_ERROR_SECURITY_CONTEXT_NULL;
	}

	if (context->be_context &&
		context->be_context->fn &&
		context->be_context->fn->ecdh_deinit) {
		err = context->be_context->fn->ecdh_deinit(context);
		if (err) {
			return err;
		}
	}

	if (context->ecdh_params) {
		memset((void *)context->ecdh_params, 0, sizeof(iot_security_ecdh_params_t));
		iot_os_free((void *)context->ecdh_params);
		context->ecdh_params = NULL;
	}

	context->sub_system &= ~IOT_SECURITY_SUB_ECDH;

	return IOT_ERROR_NONE;
}

iot_error_t iot_security_ecdh_set_params(iot_security_context_t *context, iot_security_ecdh_params_t *ecdh_set_params)
{
	iot_error_t err;

	err = iot_security_check_backend_funcs_entry_is_valid(context);
	if (err) {
		return err;
	}

	if (!ecdh_set_params) {
		IOT_ERROR("ecdh set params is null");
		return IOT_ERROR_INVALID_ARGS;
	}

	if (!context->be_context->fn->ecdh_set_params) {
		IOT_ERROR("be->fn->ecdh_set_params is null");
		return IOT_ERROR_SECURITY_BE_FUNC_NULL;
	}

	err = context->be_context->fn->ecdh_set_params(context, ecdh_set_params);
	if (err) {
		return err;
	}

	return IOT_ERROR_NONE;
}

iot_error_t iot_security_ecdh_compute_shared_secret(iot_security_context_t *context, iot_security_buffer_t *secret_buf)
{
	iot_error_t err;

	err = iot_security_check_backend_funcs_entry_is_valid(context);
	if (err) {
		return err;
	}

	/*
	 * secret_buf can be null
	 */

	if (!context->be_context->fn->ecdh_compute_shared_secret) {
		IOT_ERROR("be->fn->ecdh_compute_shared_secret is null");
		return IOT_ERROR_SECURITY_BE_FUNC_NULL;
	}

	err = context->be_context->fn->ecdh_compute_shared_secret(context, secret_buf);
	if (err) {
		return err;
	}

	return IOT_ERROR_NONE;
}