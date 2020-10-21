/* ***************************************************************************
 *
 * Copyright 2020 Samsung Electronics All Rights Reserved.
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
#include <time.h>
#include <sys/time.h>
#include "iot_debug.h"
#include "st_dev_version.h"
#include "iot_internal.h"

#include "iot_os_util.h"
#include "iot_bsp_system.h"
#include "security/iot_security_helper.h"
#ifdef CONFIG_STDK_IOT_CORE_LOG_FILE
#include "iot_log_file.h"
#endif

#define GET_LARGEST_MULTIPLE(x, n) (((x)/(n))*(n))
#define COPY_STR_TO_BYTE(dest, src, len) memcpy(dest, src, (len < strlen(src) ? len : strlen(src)))

static struct iot_dump_state* _iot_dump_create_dump_state(struct iot_context *iot_ctx)
{
    struct iot_dump_state* dump_state;
    struct timeval time;

    IOT_INFO("log version : %x", IOT_DUMP_LOG_VERSION);

    dump_state = iot_os_malloc(sizeof(struct iot_dump_state));
    if (!dump_state) {
        IOT_ERROR("failed to malloc for evt_data");
        return NULL;
    }
    memset(dump_state, 0, sizeof(struct iot_dump_state));

    dump_state->stdk_version_code = STDK_VERSION_CODE;
    dump_state->clock_time = clock();
    COPY_STR_TO_BYTE(dump_state->os_name, iot_os_get_os_name(), sizeof(dump_state->os_name));
    COPY_STR_TO_BYTE(dump_state->os_version, iot_os_get_os_version_string(), sizeof(dump_state->os_version));
    COPY_STR_TO_BYTE(dump_state->bsp_name, iot_bsp_get_bsp_name(), sizeof(dump_state->bsp_name));
    COPY_STR_TO_BYTE(dump_state->bsp_version, iot_bsp_get_bsp_version_string(), sizeof(dump_state->bsp_version));

    gettimeofday(&time, NULL);
    dump_state->log_time = time.tv_sec;

    if (iot_ctx) {
        dump_state->sequence_number = iot_ctx->event_sequence_num;

        COPY_STR_TO_BYTE(dump_state->device_id, iot_ctx->iot_reg_data.deviceId,
                sizeof(dump_state->device_id));

        if (iot_ctx->devconf.dip) {
            memcpy(dump_state->dip_id, iot_ctx->devconf.dip->dip_id.id,
                    sizeof(dump_state->dip_id));

            dump_state->dip_version =
                    ((iot_ctx->devconf.dip->dip_major_version & 0xffff) << 16)
                            | (iot_ctx->devconf.dip->dip_minor_version & 0xffff);
        }
        if (iot_ctx->device_info.firmware_version) {
            COPY_STR_TO_BYTE(dump_state->firmware_version, iot_ctx->device_info.firmware_version,
                    sizeof(dump_state->firmware_version));
        }
        if (iot_ctx->device_info.model_number) {
            COPY_STR_TO_BYTE(dump_state->model_number, iot_ctx->device_info.model_number,
                    sizeof(dump_state->model_number));
        }
        if (iot_ctx->device_info.manufacturer_name) {
            COPY_STR_TO_BYTE(dump_state->manufacturer_name, iot_ctx->device_info.manufacturer_name,
                    sizeof(dump_state->manufacturer_name));
        }

        dump_state->mqtt_connection_success_count = iot_ctx->mqtt_connection_success_count;
        dump_state->mqtt_connection_try_count = iot_ctx->mqtt_connection_try_count;
    }
    return dump_state;
}

static struct iot_dump_header* _iot_dump_create_header()
{
    struct iot_dump_header* header;
    header = iot_os_malloc(sizeof(struct iot_dump_header));
    if (!header) {
        IOT_ERROR("failed to malloc for header_line of dump");
        return NULL;
    }
    memset(header, 0, sizeof(struct iot_dump_header));

    header->magic_number = IOT_DUMP_MAGIC_NUMBER;
    header->log_version = IOT_DUMP_LOG_VERSION;
    header->dump_state_size = sizeof(struct iot_dump_state);

    return header;
}

static iot_error_t _iot_dump_copy_memory(void *dest, int dest_size, const void *src, int src_size,
        void *buf, int buf_size, int *remain_number, int *written_len, int need_base64)
{
    size_t pre_out_len = 0;
    size_t main_out_len = 0;
    size_t pre_copy_len = 0;
    size_t main_copy_len = 0;
    iot_error_t iot_err = IOT_ERROR_NONE;

    if ((!written_len) || (!dest) || (!src) || (dest_size <= 0) || (src_size <= 0) || (buf_size < 3))
        return IOT_ERROR_BAD_REQ;

    *written_len = 0;

    if (src_size > dest_size)
        src_size = dest_size;

    if (!need_base64) {
        memcpy(dest, src, src_size);
        *written_len = src_size;
        return IOT_ERROR_NONE;
    }
    //Step1: old 'remain' bytes and new (3-'remain') bytes are combined to 3bytes, and converted to base64
    if (*remain_number > 0) {
        pre_copy_len = 3 - *remain_number;
        memcpy(buf + *remain_number, src, pre_copy_len);
        iot_err = iot_security_base64_encode(buf, 3, dest, dest_size, &pre_out_len);
        if (iot_err < 0) {
            return iot_err;
        }
        memset(buf, 0, 3);
        *written_len = pre_out_len;
    }
    //Step2: convert multiples of 3 bytes
    *remain_number = (src_size - pre_copy_len) % 3;
    main_copy_len = GET_LARGEST_MULTIPLE(src_size - pre_copy_len, 3);
    if (main_copy_len > 0) {
        iot_err = iot_security_base64_encode(src + pre_copy_len, main_copy_len, dest + pre_out_len,
                                             dest_size - pre_out_len, &main_out_len);
        if (iot_err < 0) {
            return iot_err;
        }
    }
    //Step3: save unconverted remain bytes to buf
    memcpy(buf, src + pre_copy_len + main_copy_len, *remain_number);
    *written_len = pre_out_len + main_out_len;
    return iot_err;
}

int st_create_log_dump(IOT_CTX *iot_ctx, char **log_dump_output, size_t max_log_dump_size, size_t *allocated_size, int log_mode)
{
    struct iot_dump_header* header;
    struct iot_dump_state* dump_state;
    struct iot_context *ctx = (struct iot_context*)iot_ctx;

    char temp_buf[IOT_DUMP_BUFFER_SIZE] = "";
    char *all_log_dump;
    int remain_number = 0;
    int written_len = 0;

    size_t max_msg_size = 0;
    size_t min_log_size = 0;
    size_t output_log_size = 0;
    size_t stored_log_size = 0;
    size_t curr_size = 0;

    int need_base64 = log_mode & IOT_DUMP_MODE_NEED_BASE64;
    int need_dump_state = log_mode & IOT_DUMP_MODE_NEED_DUMP_STATE;

    size_t iot_dump_state_size = sizeof(struct iot_dump_state);

    iot_error_t iot_err = IOT_ERROR_NONE;
#ifdef CONFIG_STDK_IOT_CORE_LOG_FILE
    size_t msg_size;
    iot_log_file_handle_t *logfile;
#endif

    if (!need_dump_state) {
        iot_dump_state_size = 0;
    }

    if (need_base64) {
        min_log_size = IOT_SECURITY_B64_ENCODE_LEN(sizeof(struct iot_dump_header) + iot_dump_state_size);
    } else {
        min_log_size = sizeof(struct iot_dump_header) + iot_dump_state_size;
    }
    if (max_log_dump_size < min_log_size) {
        IOT_ERROR("input log size is smaller than minimum log size");
        return IOT_ERROR_BAD_REQ;
    }

#ifdef CONFIG_STDK_IOT_CORE_LOG_FILE
#if defined(CONFIG_STDK_IOT_CORE_LOG_FILE_RAM_ONLY)
    logfile = iot_log_file_open(&stored_log_size, RAM_ONLY);
#elif defined(CONFIG_STDK_IOT_CORE_LOG_FILE_FLASH_WITH_RAM)
    logfile = iot_log_file_open(&stored_log_size, FLASH_WITH_RAM);
#else
#error "Need to choice STDK_IOT_CORE_LOG_FILE_TYPE first"
#endif
    if (!logfile) {
        IOT_ERROR("fail to open log file");
        return IOT_ERROR_BAD_REQ;
    }
#endif

    if (need_base64) {
        max_msg_size = (max_log_dump_size - 1) / 4 * 3 - sizeof(struct iot_dump_header) - iot_dump_state_size;
    } else {
        max_msg_size = max_log_dump_size - sizeof(struct iot_dump_header) - iot_dump_state_size;
    }
    if (max_msg_size > stored_log_size)
        max_msg_size = stored_log_size;
    max_msg_size = GET_LARGEST_MULTIPLE(max_msg_size, IOT_DUMP_LOG_MSG_LINE_LENGTH);

    if (need_base64) {
        output_log_size = IOT_SECURITY_B64_ENCODE_LEN(max_msg_size + sizeof(struct iot_dump_header) + iot_dump_state_size);
    } else {
        output_log_size = max_msg_size + sizeof(struct iot_dump_header) + iot_dump_state_size;
    }

    all_log_dump = iot_os_malloc(output_log_size);
    if (!all_log_dump) {
        IOT_ERROR("failed to malloc for all_log_dump");
        iot_err = IOT_ERROR_MEM_ALLOC;
        goto end;
    }
    memset(all_log_dump, 0, output_log_size);

    header = _iot_dump_create_header();
    if (!need_dump_state) {
        header->dump_state_size = 0;
    }
    iot_err = _iot_dump_copy_memory(all_log_dump + curr_size, output_log_size - curr_size,
                header, sizeof(struct iot_dump_header), temp_buf, sizeof(temp_buf), &remain_number, &written_len, need_base64);
    iot_os_free(header);
    if (iot_err < 0) {
        IOT_ERROR("failed to get header for all_log_dump : ret %d", iot_err);
        goto end;
    }
    curr_size += written_len;

    if (need_dump_state) {
        dump_state = _iot_dump_create_dump_state(ctx);
        iot_err = _iot_dump_copy_memory(all_log_dump + curr_size, output_log_size - curr_size,
                    dump_state, sizeof(struct iot_dump_state), temp_buf, sizeof(temp_buf), &remain_number, &written_len, need_base64);
        iot_os_free(dump_state);
        if (iot_err < 0) {
            IOT_ERROR("failed to get dump_state for all_log_dump : ret %d", iot_err);
            goto end;
        }
        curr_size += written_len;
    }

#ifdef CONFIG_STDK_IOT_CORE_LOG_FILE
    if (logfile) {
        iot_log_file_seek(logfile, 0 - max_msg_size, logfile->tail_addr);

        while (max_msg_size) {
            msg_size = sizeof(temp_buf) - remain_number;
            if (msg_size > max_msg_size)
                msg_size = max_msg_size;

            iot_log_file_read(logfile, temp_buf + remain_number, msg_size, &msg_size);

            max_msg_size -= msg_size;
            msg_size += remain_number;
            remain_number = 0;

            iot_err = _iot_dump_copy_memory(all_log_dump + curr_size, output_log_size - curr_size,
                    temp_buf, msg_size, temp_buf, sizeof(temp_buf), &remain_number, &written_len, need_base64);
            if (iot_err < 0) {
                IOT_ERROR("failed to get log msg for all_log_dump : ret %d", iot_err);
                goto end;
            }
            curr_size += written_len;
        }
        iot_log_file_close(logfile);
    }
#endif

    if (remain_number) {
        memset(temp_buf + remain_number, 0, 3 - remain_number);
        iot_err = _iot_dump_copy_memory(all_log_dump + curr_size, output_log_size - curr_size,
                temp_buf, 3 - remain_number, temp_buf, sizeof(temp_buf), &remain_number, &written_len, need_base64);
        if (iot_err < 0) {
            IOT_ERROR("failed to get remain character for all_log_dump : ret %d", iot_err);
            goto end;
        }
        curr_size += written_len;
    }

    if (allocated_size)
        *allocated_size = output_log_size;
    *log_dump_output = all_log_dump;
    return iot_err;

end:
#ifdef CONFIG_STDK_IOT_CORE_LOG_FILE
    if (logfile) {
        iot_log_file_close(logfile);
    }
#endif
    if (all_log_dump)
        iot_os_free(all_log_dump);
    if (allocated_size)
        *allocated_size = 0;
    *log_dump_output = NULL;
    return iot_err;
}

#ifdef CONFIG_STDK_IOT_CORE_LOG_FILE
void iot_dump_log(iot_debug_level_t level, dump_log_id_t log_id, int arg1, int arg2)
{
    int msg[4] = {0,};
    struct timeval time;

#ifndef CONFIG_STDK_IOT_CORE_LOG_LEVEL_ERROR
    if (level == IOT_DEBUG_LEVEL_ERROR) return;
#endif
#ifndef CONFIG_STDK_IOT_CORE_LOG_LEVEL_WARN
    if (level == IOT_DEBUG_LEVEL_WARN) return;
#endif
#ifndef CONFIG_STDK_IOT_CORE_LOG_LEVEL_INFO
    if (level == IOT_DEBUG_LEVEL_INFO) return;
#endif
#ifndef CONFIG_STDK_IOT_CORE_LOG_LEVEL_DEBUG
    if (level == IOT_DEBUG_LEVEL_DEBUG) return;
#endif

    gettimeofday(&time, NULL);

    msg[0] = ((level & 0xf) << 28) | (log_id & 0xffff);
    msg[1] = time.tv_sec;
    msg[2] = arg1;
    msg[3] = arg2;

    IOT_DEBUG("LOG : %08x %08x %08x %08x" , msg[0], msg[1], msg[2], msg[3]);

    iot_log_file_store((const char *)msg, sizeof(msg));
}
#else
void iot_dump_log(iot_debug_level_t level, dump_log_id_t log_id, int arg1, int arg2)
{
    return;
}
#endif
