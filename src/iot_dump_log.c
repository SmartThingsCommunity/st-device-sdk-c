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
#include <sys/time.h>
#include "iot_debug.h"
#include "st_dev_version.h"
#include "iot_internal.h"

#include "iot_os_util.h"
#include "iot_log_file.h"

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
    //TODO : replace hard coded string
    strncpy(dump_state->os_name, "FreeRTOS", sizeof(dump_state->os_name));
    strncpy(dump_state->os_version, "v10.0.1", sizeof(dump_state->os_version));
    strncpy(dump_state->bsp_name, "esp8266", sizeof(dump_state->bsp_name));
    strncpy(dump_state->bsp_version, "UNKNOWN", sizeof(dump_state->bsp_version));

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

static void _iot_dump_copy_memory(void *dest, int *curr_size, const void *src, int size)
{
    if (size <= 0)
        return;

    memcpy(dest + *curr_size, src, size);
    *curr_size += size;
}

char* iot_dump_create_all_log_dump(int all_log_dump_size)
{
    char* all_log_dump;
    struct iot_dump_header* header;
    struct iot_dump_state* dump_state;
    iot_log_file_handle_t *logfile;

    unsigned int log_buf_size = 0;

    int maximum_msg_size = all_log_dump_size - sizeof(struct iot_dump_header) - sizeof(struct iot_dump_state);
    int curr_size = 0;

    all_log_dump = iot_os_malloc(all_log_dump_size);
    if (!all_log_dump) {
        IOT_ERROR("failed to malloc for all_log_dump");
        return NULL;
    }
    memset(all_log_dump, 0, all_log_dump_size);

    header = _iot_dump_create_header();
    _iot_dump_copy_memory(all_log_dump, &curr_size, header, sizeof(struct iot_dump_header));
    iot_os_free(header);

    dump_state = _iot_dump_create_dump_state();
    _iot_dump_copy_memory(all_log_dump, &curr_size, dump_state, sizeof(struct iot_dump_state));
    iot_os_free(dump_state);

    logfile = iot_log_file_open(&log_buf_size, RAM_ONLY);
    if (maximum_msg_size > log_buf_size)
        maximum_msg_size = log_buf_size;
    iot_log_file_read(logfile, all_log_dump + curr_size, maximum_msg_size, &log_buf_size);
    iot_log_file_close(logfile);

    return all_log_dump;
}

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