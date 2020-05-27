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

#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include "iot_debug.h"
#include "st_dev_version.h"
#include "iot_internal.h"

#include "iot_os_util.h"
#include "iot_bsp_system.h"
#include "iot_crypto.h"
#ifdef CONFIG_STDK_IOT_CORE_LOG_FILE
#include "iot_log_file.h"
#endif
static struct iot_dump_state* _iot_dump_create_dump_state()
{
    struct iot_dump_state* dump_state;

    printf("log version : %x\n", IOT_DUMP_LOG_VERSION);

    dump_state = iot_os_malloc(sizeof(struct iot_dump_state));
    if (!dump_state) {
        IOT_ERROR("failed to malloc for evt_data");
        return NULL;
    }
    memset(dump_state, 0, sizeof(struct iot_dump_state));

    dump_state->stdk_version_code = STDK_VERSION_CODE;
    dump_state->clock_time = clock();
    dump_state->sequence_number = iot_cap_get_sqnum();
    strncpy(dump_state->os_name, iot_os_get_os_name(), sizeof(dump_state->os_name));
    strncpy(dump_state->os_version, iot_os_get_os_version_string(), sizeof(dump_state->os_version));
    strncpy(dump_state->bsp_name, iot_bsp_get_bsp_name(), sizeof(dump_state->bsp_name));
    strncpy(dump_state->bsp_version, iot_bsp_get_bsp_version_string(), sizeof(dump_state->bsp_version));

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

    header->magic_number = MAGIC_NUMBER;
    header->log_version = IOT_DUMP_LOG_VERSION;
    header->dump_state_size = sizeof(struct iot_dump_state);

    return header;
}

static int _iot_dump_copy_memory(void *dest, int dest_size, const void *src, int src_size,
        void *buf, int buf_size, int *remain_number, int need_base64)
{
    unsigned int out_len1 = 0;
    unsigned int out_len2 = 0;
    unsigned int copy_len1 = 0;
    unsigned int copy_len2 = 0;
    int ret;

    if ((dest_size <= 0) || (src_size <= 0) || (buf_size < 3))
        return IOT_ERROR_BAD_REQ;
    if (src_size > dest_size)
        src_size = dest_size;

    if (!need_base64) {
        memcpy(dest, src, src_size);
        return src_size;
    }
    //Step1: old 'remain' bytes and new (3-'remain') bytes are combined to 3bytes, and converted to base64
    if (*remain_number > 0) {
        copy_len1 = 3 - *remain_number;
        memcpy(buf + *remain_number, src, copy_len1);
        ret = iot_crypto_base64_encode(buf, 3, dest, dest_size, &out_len1);
        if (ret < 0) {
            return ret;
        }
        memset(buf, 0, 3);
    }
    //Step2: convert multiples of 3 bytes
    *remain_number = (src_size - copy_len1) % 3;
    copy_len2 = ((src_size - copy_len1) / 3) * 3;
    ret = iot_crypto_base64_encode(src + copy_len1, copy_len2, dest + out_len1, dest_size - out_len1, &out_len2);
    if (ret < 0) {
        return ret;
    }
    //Step3: save unconverted remain bytes to buf
    memcpy(buf, src + copy_len1 + copy_len2, *remain_number);
    return out_len1 + out_len2;
}

char* iot_dump_create_all_log_dump(int all_log_dump_size, int need_base64)
{
    char* all_log_dump;
    struct iot_dump_header* header;
    struct iot_dump_state* dump_state;

    char temp_buf[48] = "";
    int remain_number = 0;

    unsigned int curr_size = 0;
    int ret;

    all_log_dump = iot_os_malloc(all_log_dump_size);
    if (!all_log_dump) {
        IOT_ERROR("failed to malloc for all_log_dump");
        return NULL;
    }
    memset(all_log_dump, 0, all_log_dump_size);
    header = _iot_dump_create_header();
    ret = _iot_dump_copy_memory(all_log_dump + curr_size, all_log_dump_size - curr_size,
                header, sizeof(struct iot_dump_header), temp_buf, sizeof(temp_buf), &remain_number, need_base64);
    iot_os_free(header);
    if (ret < 0) {
        IOT_ERROR("failed to get all_log_dump : ret %d, line %d", ret, __LINE__);
        iot_os_free(all_log_dump);
        return NULL;
    }
    curr_size += ret;

    dump_state = _iot_dump_create_dump_state();
    ret = _iot_dump_copy_memory(all_log_dump + curr_size, all_log_dump_size - curr_size,
                dump_state, sizeof(struct iot_dump_state), temp_buf, sizeof(temp_buf), &remain_number, need_base64);
    iot_os_free(dump_state);
    if (ret < 0) {
        IOT_ERROR("failed to get all_log_dump : ret %d, line %d", ret, __LINE__);
        iot_os_free(all_log_dump);
        return NULL;
    }
    curr_size += ret;

#ifdef CONFIG_STDK_IOT_CORE_LOG_FILE
    iot_log_file_handle_t *logfile;
    unsigned int log_buf_size = 0;
    unsigned int maximum_msg_size, msg_size;

    if (need_base64) {
        maximum_msg_size = (all_log_dump_size - 1) / 4 * 3 - sizeof(struct iot_dump_header) - sizeof(struct iot_dump_state);
    } else {
        maximum_msg_size = all_log_dump_size - sizeof(struct iot_dump_header) - sizeof(struct iot_dump_state);
    }

    logfile = iot_log_file_open(&log_buf_size, RAM_ONLY);
    if (maximum_msg_size > log_buf_size)
        maximum_msg_size = log_buf_size;
    while (maximum_msg_size) {
        msg_size = sizeof(temp_buf) - remain_number;
        if (msg_size > maximum_msg_size)
            msg_size = maximum_msg_size;

        iot_log_file_read(logfile, temp_buf + remain_number, msg_size, &msg_size);

        maximum_msg_size -= msg_size;
        msg_size += remain_number;
        remain_number = 0;

        ret = _iot_dump_copy_memory(all_log_dump + curr_size, all_log_dump_size - curr_size,
                temp_buf, msg_size, temp_buf, sizeof(temp_buf), &remain_number, need_base64);
        if (ret < 0) {
            IOT_ERROR("failed to get all_log_dump : ret %d, line %d", ret, __LINE__);
            iot_os_free(all_log_dump);
            return NULL;
        }
        curr_size += ret;
    }
    iot_log_file_close(logfile);
#endif

    if (remain_number) {
        memset(temp_buf + remain_number, 0, 3 - remain_number);
        _iot_dump_copy_memory(all_log_dump + curr_size, all_log_dump_size - curr_size,
                temp_buf, 3 - remain_number, temp_buf, sizeof(temp_buf), &remain_number, need_base64);
    }


    return all_log_dump;
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

    printf("%08x %08x %08x %08x\n" , msg[0], msg[1], msg[2], msg[3]);

    iot_log_file_store((const char *)msg, sizeof(msg));
}
#else
void iot_dump_log(iot_debug_level_t level, dump_log_id_t log_id, int arg1, int arg2)
{
    return;
}
#endif
