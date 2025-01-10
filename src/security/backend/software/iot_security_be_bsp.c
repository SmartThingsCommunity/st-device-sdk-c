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

#include <stdio.h>
#include <string.h>

#include "iot_main.h"
#include "iot_debug.h"
#include "iot_bsp_fs.h"
#include "iot_bsp_nv_data.h"
#include "security/iot_security_storage.h"
#include "security/backend/iot_security_be.h"

#if defined(CONFIG_STDK_IOT_CORE_OS_SUPPORT_POSIX)
#define IOT_SECURITY_STORAGE_EXTRA_PATH	"."
#else
#define IOT_SECURITY_STORAGE_EXTRA_PATH	NULL
#endif

STATIC_FUNCTION
iot_security_storage_target_t _iot_security_be_bsp_fs_storage_id2target(iot_security_storage_id_t storage_id)
{
	if (storage_id == IOT_NVD_UNKNOWN) {
		return IOT_SECURITY_STORAGE_TARGET_UNKNOWN;
	}

	if (storage_id < IOT_NVD_FACTORY) {
		return IOT_SECURITY_STORAGE_TARGET_NV;
	}

	if (storage_id < IOT_NVD_MAX) {
#if defined(CONFIG_STDK_IOT_CORE_SUPPORT_STNV_PARTITION)
		return IOT_SECURITY_STORAGE_TARGET_FACTORY;
#else
		return IOT_SECURITY_STORAGE_TARGET_DI;
#endif
	}

	return IOT_SECURITY_STORAGE_TARGET_UNKNOWN;
}

STATIC_FUNCTION
iot_error_t _iot_security_be_bsp_fs_storage_id2filename(iot_security_storage_id_t storage_id, char *filename, size_t filename_len)
{
	const char *storage_file;
	const char *extra_path = (const char *)IOT_SECURITY_STORAGE_EXTRA_PATH;
	int c = 0;

	if (!filename || (filename_len == 0)) {
		IOT_ERROR("filename is invalid");
		IOT_ERROR_DUMP_AND_RETURN(FS_INVALID_ARGS, 0);
	}

	storage_file = iot_bsp_nv_get_data_path(storage_id);
	if (!storage_file) {
		IOT_ERROR("not found file for id = %d", storage_id);
		IOT_ERROR_DUMP_AND_RETURN(STORAGE_INVALID_ID, storage_id);
	}

	if (extra_path) {
		c = snprintf(filename, filename_len, "%s/", extra_path);
	}

	if (filename_len < strlen(storage_file) + c) {
		IOT_ERROR("length is not enough (%d < (%d + %d)", (int)filename_len, strlen(storage_file), c);
		IOT_ERROR_DUMP_AND_RETURN(FS_BUFFER, filename_len);
	}

	snprintf(filename + c, filename_len - c, "%s", storage_file);

	IOT_DEBUG("storage file = '%s'", filename);

	return IOT_ERROR_NONE;
}

STATIC_FUNCTION
iot_error_t _iot_security_be_bsp_fs_load_from_nv(iot_security_storage_id_t storage_id, iot_security_buffer_t *output_buf)
{
	iot_error_t err;
	iot_bsp_fs_handle_t handle;
	char filename[IOT_SECURITY_STORAGE_FILENAME_MAX_LEN];
	char *fs_buf;
	size_t fs_buf_len;
	unsigned char *realloc_buf;

	IOT_DEBUG("id = %d", storage_id);

	err = _iot_security_be_bsp_fs_storage_id2filename(storage_id, filename, sizeof(filename));
	if (err) {
		return err;
	}

	if (storage_id >= IOT_NVD_FACTORY) {
#if defined(CONFIG_STDK_IOT_CORE_SUPPORT_STNV_PARTITION)
		err = iot_bsp_fs_open_from_stnv(filename, &handle);
		if (err) {
			if (err == IOT_ERROR_FS_NO_FILE) {
				err = IOT_ERROR_SECURITY_FS_NOT_FOUND;
				IOT_ERROR("iot_bsp_fs_open_from_stnv(%s) = %d", filename, err);
				IOT_ERROR_DUMP_AND_RETURN(FS_NOT_FOUND, err);
			} else {
				IOT_ERROR("iot_bsp_fs_open_from_stnv(%s) = %d", filename, err);
				IOT_ERROR_DUMP_AND_RETURN(FS_OPEN, err);
			}
		}
#else
		IOT_ERROR("not defined factory partition");
		IOT_ERROR_DUMP_AND_RETURN(FS_OPEN, 0);
#endif
	} else {
		err = iot_bsp_fs_open(filename, FS_READONLY, &handle);
		if (err) {
			if (err == IOT_ERROR_FS_NO_FILE) {
				err = IOT_ERROR_SECURITY_FS_NOT_FOUND;
				IOT_ERROR("iot_bsp_fs_open(%s) = %d", filename, err);
				IOT_ERROR_DUMP_AND_RETURN(FS_NOT_FOUND, err);
			} else {
				IOT_ERROR("iot_bsp_fs_open(%s) = %d", filename, err);
				IOT_ERROR_DUMP_AND_RETURN(FS_OPEN, err);
			}
		}
	}

	fs_buf_len = IOT_SECURITY_STORAGE_BUF_MAX_LEN;
	fs_buf = (char *)iot_os_malloc(fs_buf_len);
	if (!fs_buf) {
		IOT_ERROR("failed to malloc for fs buf");
		IOT_ERROR_DUMP_AND_RETURN(MEM_ALLOC, 0);
	}

	err = iot_bsp_fs_read(handle, fs_buf, &fs_buf_len);
	if (err) {
		if (err == IOT_ERROR_FS_NO_FILE) {
			err = IOT_ERROR_SECURITY_FS_NOT_FOUND;
		} else {
			IOT_ERROR("iot_bsp_fs_read = %d", err);
			err = IOT_ERROR_SECURITY_FS_READ;
			IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, err, __LINE__, 0);
		}

		iot_os_free(fs_buf);
		(void)iot_bsp_fs_close(handle);

		return err;
	}

	realloc_buf = (unsigned char *)iot_os_realloc(fs_buf, fs_buf_len + 1);
	if (realloc_buf) {
		realloc_buf[fs_buf_len] = '\0';
		output_buf->p = realloc_buf;
		output_buf->len = fs_buf_len;
	} else {
		IOT_ERROR("failed to realloc for buf");
		iot_os_free(fs_buf);
		(void)iot_bsp_fs_close(handle);
		IOT_ERROR_DUMP_AND_RETURN(MEM_ALLOC, 0);
	}

	err = iot_bsp_fs_close(handle);
	if (err) {
		IOT_ERROR("iot_bsp_fs_close = %d", err);
		IOT_ERROR_DUMP_AND_RETURN(FS_CLOSE, err);
	}

	return IOT_ERROR_NONE;
}

STATIC_FUNCTION
iot_error_t _iot_security_be_bsp_fs_load(iot_security_be_context_t *be_context, iot_security_storage_id_t storage_id, iot_security_buffer_t *output_buf)
{
	iot_security_storage_target_t storage_target;

	IOT_DEBUG("id = %d", storage_id);

	if (!be_context) {
		IOT_ERROR_DUMP_AND_RETURN(BE_CONTEXT_NULL, 0);
	}

	if (!output_buf) {
		IOT_ERROR("output buffer is invalid");
		IOT_ERROR_DUMP_AND_RETURN(FS_INVALID_ARGS, 0);
	}

	memset(output_buf, 0, sizeof(iot_security_buffer_t));

	storage_target = _iot_security_be_bsp_fs_storage_id2target(storage_id);

	switch (storage_target) {
	case IOT_SECURITY_STORAGE_TARGET_NV:
	case IOT_SECURITY_STORAGE_TARGET_FACTORY:
		return _iot_security_be_bsp_fs_load_from_nv(storage_id, output_buf);
	case IOT_SECURITY_STORAGE_TARGET_DI:
		if (!be_context->external_device_info_cb) {
			IOT_ERROR_DUMP_AND_RETURN(BE_EXTERNAL_NULL, 0);
		}
		return be_context->external_device_info_cb(storage_id, output_buf);
	default:
		IOT_ERROR("cannot found target for id = %d", storage_id);
		IOT_ERROR_DUMP_AND_RETURN(FS_UNKNOWN_TARGET, 0);
	}
}

STATIC_FUNCTION
iot_error_t _iot_security_be_bsp_fs_store_to_nv(iot_security_storage_id_t storage_id, iot_security_buffer_t *input_buf)
{
	iot_error_t err;
	iot_bsp_fs_handle_t handle;
	char filename[IOT_SECURITY_STORAGE_FILENAME_MAX_LEN];

	err = _iot_security_be_bsp_fs_storage_id2filename(storage_id, filename, sizeof(filename));
	if (err) {
		return err;
	}

	err = iot_bsp_fs_open(filename, FS_READWRITE, &handle);
	if (err) {
		IOT_ERROR("iot_bsp_fs_open(%s) = %d", filename, err);
		IOT_ERROR_DUMP_AND_RETURN(FS_OPEN, err);
	}

	err = iot_bsp_fs_write(handle, (const char *)input_buf->p, (unsigned int)input_buf->len);
	if (err) {
		IOT_ERROR("iot_bsp_fs_write = %d", err);
		(void)iot_bsp_fs_close(handle);
		IOT_ERROR_DUMP_AND_RETURN(FS_WRITE, err);
	}

	err = iot_bsp_fs_close(handle);
	if (err) {
		IOT_ERROR("iot_bsp_fs_close = %d", err);
		IOT_ERROR_DUMP_AND_RETURN(FS_CLOSE, err);
	}

	return IOT_ERROR_NONE;
}

STATIC_FUNCTION
iot_error_t _iot_security_be_bsp_fs_store(iot_security_be_context_t *be_context, iot_security_storage_id_t storage_id, iot_security_buffer_t *input_buf)
{
	iot_security_storage_target_t storage_target;

	IOT_DEBUG("id = %d", storage_id);

	if (!input_buf || !input_buf->p || (input_buf->len == 0)) {
		IOT_ERROR("input buffer is invalid");
		IOT_ERROR_DUMP_AND_RETURN(FS_INVALID_ARGS, 0);
	}

	storage_target = _iot_security_be_bsp_fs_storage_id2target(storage_id);

	switch (storage_target) {
	case IOT_SECURITY_STORAGE_TARGET_NV:
		return _iot_security_be_bsp_fs_store_to_nv(storage_id, input_buf);
	case IOT_SECURITY_STORAGE_TARGET_FACTORY:
		IOT_ERROR("cannot update factory nv for id = %d", storage_id);
		IOT_ERROR_DUMP_AND_RETURN(FS_INVALID_TARGET, storage_id);
	case IOT_SECURITY_STORAGE_TARGET_DI:
		IOT_ERROR("cannot update device info nv for id = %d", storage_id);
		IOT_ERROR_DUMP_AND_RETURN(FS_INVALID_TARGET, storage_id);
	default:
		IOT_ERROR("cannot found target for id = %d", storage_id);
		IOT_ERROR_DUMP_AND_RETURN(FS_UNKNOWN_TARGET, storage_id);
	}
}

STATIC_FUNCTION
iot_error_t _iot_security_be_bsp_fs_remove_from_nv(iot_security_storage_id_t storage_id)
{
	iot_error_t err;
	char filename[IOT_SECURITY_STORAGE_FILENAME_MAX_LEN];

	err = _iot_security_be_bsp_fs_storage_id2filename(storage_id, filename, sizeof(filename));
	if (err) {
		return err;
	}

	err = iot_bsp_fs_remove(filename);
	if (err) {
		if (err == IOT_ERROR_FS_NO_FILE) {
			IOT_ERROR_DUMP_AND_RETURN(FS_NOT_FOUND, 0);
		} else {
			IOT_ERROR("iot_bsp_fs_remove = %d", err);
			IOT_ERROR_DUMP_AND_RETURN(FS_REMOVE, err);
		}
	}

	return IOT_ERROR_NONE;
}

STATIC_FUNCTION
iot_error_t _iot_security_be_bsp_fs_remove(iot_security_be_context_t *be_context, iot_security_storage_id_t storage_id)
{
	iot_security_storage_target_t storage_target;

	IOT_DEBUG("id = %d", storage_id);

	storage_target = _iot_security_be_bsp_fs_storage_id2target(storage_id);

	switch (storage_target) {
	case IOT_SECURITY_STORAGE_TARGET_NV:
		return _iot_security_be_bsp_fs_remove_from_nv(storage_id);
	case IOT_SECURITY_STORAGE_TARGET_FACTORY:
		IOT_ERROR("cannot remove factory nv for id = %d", storage_id);
		IOT_ERROR_DUMP_AND_RETURN(FS_INVALID_TARGET, storage_id);
	case IOT_SECURITY_STORAGE_TARGET_DI:
		IOT_ERROR("cannot remove device info nv for id = %d", storage_id);
		IOT_ERROR_DUMP_AND_RETURN(FS_INVALID_TARGET, storage_id);
	default:
		IOT_ERROR("cannot found target for id = %d", storage_id);
		IOT_ERROR_DUMP_AND_RETURN(FS_UNKNOWN_TARGET, storage_id);
	}
}

const iot_security_be_bsp_funcs_t iot_security_be_software_bsp_funcs = {
	.bsp_fs_load = _iot_security_be_bsp_fs_load,
	.bsp_fs_store = _iot_security_be_bsp_fs_store,
	.bsp_fs_remove = _iot_security_be_bsp_fs_remove,
};

iot_error_t iot_security_be_bsp_init(iot_security_be_context_t *be_context)
{
	if (!be_context) {
		IOT_ERROR_DUMP_AND_RETURN(BE_CONTEXT_NULL, 0);
	}

	be_context->bsp_fn = &iot_security_be_software_bsp_funcs;

	return IOT_ERROR_NONE;
}
