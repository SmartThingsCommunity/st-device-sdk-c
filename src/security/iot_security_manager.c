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
#include "security/iot_security_manager.h"
#include "security/backend/iot_security_be.h"

iot_error_t iot_security_manager_init(iot_security_context_t *context)
{
	iot_error_t err;

	if (!context) {
		IOT_ERROR_DUMP_AND_RETURN(CONTEXT_NULL, 0);
	}

	if (context->be_context &&
		context->be_context->fn &&
		context->be_context->fn->manager_init) {
		err = context->be_context->fn->manager_init(context);
		if (err) {
			return err;
		}
	}

	context->sub_system |= IOT_SECURITY_SUB_MANAGER;

	return IOT_ERROR_NONE;
}

iot_error_t iot_security_manager_deinit(iot_security_context_t *context)
{
	iot_error_t err;

	if (!context) {
		IOT_ERROR_DUMP_AND_RETURN(CONTEXT_NULL, 0);
	}

	if (context->be_context &&
		context->be_context->fn &&
		context->be_context->fn->manager_deinit) {
		err = context->be_context->fn->manager_deinit(context);
		if (err) {
			return err;
		}
	}

	context->sub_system &= ~IOT_SECURITY_SUB_MANAGER;

	return IOT_ERROR_NONE;
}

iot_error_t iot_security_manager_generate_key(iot_security_context_t *context, iot_security_key_id_t key_id)
{
	iot_error_t err;

	err = iot_security_check_backend_funcs_entry_is_valid(context);
	if (err) {
		return err;
	}

	if (key_id != IOT_SECURITY_KEY_ID_EPHEMERAL) {
		IOT_ERROR("key id %d is invalid", key_id);
		IOT_ERROR_DUMP_AND_RETURN(KEY_INVALID_ID, 0);
	}

	if (!context->be_context->fn->manager_generate_key) {
		IOT_ERROR("be->fn->manager_generate_key is null");
		IOT_ERROR_DUMP_AND_RETURN(BE_FUNC_NULL, 0);
	}

	err = context->be_context->fn->manager_generate_key(context, key_id);
	if (err) {
		IOT_ERROR("be->fn->manager_generate_key = %d", err);
		return err;
	}

	return IOT_ERROR_NONE;
}

iot_error_t iot_security_manager_remove_key(iot_security_context_t *context, iot_security_key_id_t key_id)
{
	iot_error_t err;

	err = iot_security_check_backend_funcs_entry_is_valid(context);
	if (err) {
		return err;
	}

	if (key_id != IOT_SECURITY_KEY_ID_EPHEMERAL) {
		IOT_ERROR("key id %d is invalid", key_id);
		IOT_ERROR_DUMP_AND_RETURN(KEY_INVALID_ID, 0);
	}

	if (!context->be_context->fn->manager_remove_key) {
		IOT_ERROR("be->fn->manager_remove_key is null");
		IOT_ERROR_DUMP_AND_RETURN(BE_FUNC_NULL, 0);
	}

	err = context->be_context->fn->manager_remove_key(context, key_id);
	if (err) {
		IOT_ERROR("be->fn->manager_remove_key = %d", err);
		return err;
	}

	return IOT_ERROR_NONE;
}

iot_error_t iot_security_manager_set_key(iot_security_context_t *context, iot_security_key_params_t *key_params)
{
	iot_error_t err;

	err = iot_security_check_backend_funcs_entry_is_valid(context);
	if (err) {
		return err;
	}

	if (!key_params) {
		IOT_ERROR("key params is null");
		IOT_ERROR_DUMP_AND_RETURN(INVALID_ARGS, 0);
	}

	if (!context->be_context->fn->manager_set_key) {
		IOT_ERROR("be->fn->manager_set_key is null");
		IOT_ERROR_DUMP_AND_RETURN(BE_FUNC_NULL, 0);
	}

	IOT_DEBUG("key id = %d", key_params->key_id);

	err = context->be_context->fn->manager_set_key(context, key_params);
	if (err) {
		IOT_ERROR("be->fn->manager_set_key = %d", err);
		return err;
	}

	return IOT_ERROR_NONE;
}

iot_error_t iot_security_manager_get_key(iot_security_context_t *context, iot_security_key_id_t key_id, iot_security_buffer_t *key_buf)
{
	iot_error_t err;

	IOT_DEBUG("key id = %d", key_id);

	err = iot_security_check_backend_funcs_entry_is_valid(context);
	if (err) {
		return err;
	}

	if ((key_id <= IOT_SECURITY_KEY_ID_UNKNOWN) || (key_id >= IOT_SECURITY_KEY_ID_MAX)) {
		IOT_ERROR("'%d' is invalid", key_id);
		IOT_ERROR_DUMP_AND_RETURN(KEY_INVALID_ID, 0);
	}

	if (!key_buf) {
		IOT_ERROR("key buffer is null");
		IOT_ERROR_DUMP_AND_RETURN(INVALID_ARGS, 0);
	}

	memset(key_buf, 0, sizeof(iot_security_buffer_t));

	if (!context->be_context->fn->manager_get_key) {
		IOT_ERROR("be->fn->manager_get_key is null");
		IOT_ERROR_DUMP_AND_RETURN(BE_FUNC_NULL, 0);
	}

	err = context->be_context->fn->manager_get_key(context, key_id, key_buf);
	if (err) {
		IOT_ERROR("be->fn->manager_get_key = %d", err);
		return err;
	}

	return IOT_ERROR_NONE;
}

STATIC_FUNCTION
iot_security_storage_target_t _iot_security_manager_check_certificate_target(iot_security_cert_id_t cert_id)
{
	switch (cert_id) {
	case IOT_SECURITY_CERT_ID_ROOT_CA:
		return IOT_SECURITY_STORAGE_TARGET_STATIC;
	default:
		return IOT_SECURITY_STORAGE_TARGET_NV;
	}
}

iot_error_t iot_security_manager_get_certificate(iot_security_context_t *context, iot_security_cert_id_t cert_id, iot_security_buffer_t *cert_buf)
{
	iot_error_t err;
	iot_security_storage_target_t storage_target;

	IOT_DEBUG("cert id = %d", cert_id);

	err = iot_security_check_backend_funcs_entry_is_valid(context);
	if (err) {
		return err;
	}

	if ((cert_id <= IOT_SECURITY_CERT_ID_UNKNOWN) || (cert_id >= IOT_SECURITY_CERT_ID_MAX)) {
		IOT_ERROR("'%d' is invalid", cert_id);
		IOT_ERROR_DUMP_AND_RETURN(CERT_INVALID_ID, 0);
	}

	if (!cert_buf) {
		IOT_ERROR("cert buffer is null");
		IOT_ERROR_DUMP_AND_RETURN(INVALID_ARGS, 0);
	}

	memset(cert_buf, 0, sizeof(iot_security_buffer_t));

	storage_target = _iot_security_manager_check_certificate_target(cert_id);
	if (storage_target == IOT_SECURITY_STORAGE_TARGET_STATIC) {
		return iot_nv_get_static_certificate(cert_id, cert_buf);
	}

	if (!context->be_context->fn->manager_get_certificate) {
		IOT_ERROR("be->fn->manager_get_certificate is null");
		IOT_ERROR_DUMP_AND_RETURN(BE_FUNC_NULL, 0);
	}

	err = context->be_context->fn->manager_get_certificate(context, cert_id, cert_buf);
	if (err) {
		IOT_ERROR("be->fn->manager_get_certificate = %d", err);
		return err;
	}

	return IOT_ERROR_NONE;
}