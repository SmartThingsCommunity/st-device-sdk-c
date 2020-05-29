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
#include "security/iot_security_common.h"
#include "security/backend/iot_security_be.h"

iot_error_t iot_security_check_context_is_valid(iot_security_context_t *context)
{
	if (!context) {
		return IOT_ERROR_SECURITY_CONTEXT_NULL;
	}

	return IOT_ERROR_NONE;
}

iot_error_t iot_security_check_backend_funcs_entry_is_valid(iot_security_context_t *context)
{
	if (!context) {
		return IOT_ERROR_SECURITY_CONTEXT_NULL;
	}

	if (!context->be_context) {
		return IOT_ERROR_SECURITY_BE_CONTEXT_NULL;
	}

	if (!context->be_context->fn) {
		return IOT_ERROR_SECURITY_BE_FUNCS_ENTRY_NULL;
	}

	return IOT_ERROR_NONE;
}

iot_security_context_t *iot_security_init(void)
{
	iot_security_context_t *context;
	iot_security_be_context_t *be_context;
#if defined(CONFIG_STDK_IOT_CORE_SUPPORT_STNV_PARTITION)
	external_nv_callback external_nv_cb = NULL;
#else
	external_nv_callback external_nv_cb = iot_nv_get_data_from_device_info;
#endif

	context = (iot_security_context_t *)iot_os_malloc(sizeof(iot_security_context_t));
	if (!context) {
		IOT_ERROR("failed to malloc for context");
		return NULL;
	}

	memset(context, 0, sizeof(iot_security_context_t));

	be_context = iot_security_be_init(external_nv_cb);
	if (!be_context) {
		IOT_ERROR("failed to malloc for backend context");
		iot_os_free(context);
		return NULL;
	}

	context->be_context = be_context;

	return context;
}

iot_error_t iot_security_deinit(iot_security_context_t *context)
{
	iot_error_t err;

	err = iot_security_check_context_is_valid(context);
	if (err) {
		return err;
	}

	err = iot_security_be_deinit(context->be_context);
	if (err) {
		IOT_ERROR("iot_security_be_deinit = %d", err);
		return err;
	}

	memset(context, 0, sizeof(iot_security_context_t));

	iot_os_free(context);

	return IOT_ERROR_NONE;
}
