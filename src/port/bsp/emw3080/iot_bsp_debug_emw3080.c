/******************************************************************
 *
 * Copyright 2020 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************/
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include "iot_bsp_debug.h"
#include "mico.h"

#define LOG_COLOR_HEAD      "\033[0;%dm"
#define LOG_COLOR_END       "\033[0m"

static const uint32_t s_log_color[IOT_DEBUG_LEVEL_MAX] = {
    0,  //  IOT_DEBUG_LEVEL_NONE
    31, //  IOT_DEBUG_LEVEL_ERROR
    33, //  IOT_DEBUG_LEVEL_WARN
    32, //  IOT_DEBUG_LEVEL_INFO
    0,  //  IOT_DEBUG_LEVEL_DEBUG
};

void iot_bsp_debug(iot_debug_level_t level, const char* tag, const char* fmt, ...)
{
	va_list ap;
	uint32_t time;
	uint32_t color = s_log_color[level];

	if (level == IOT_DEBUG_LEVEL_ERROR) {
		printf("E: %s ", tag);
	} else if (level == IOT_DEBUG_LEVEL_WARN) {
		printf("W: %s ", tag);
	} else if (level == IOT_DEBUG_LEVEL_INFO) {
		printf("I: %s ", tag);
	} else if (level == IOT_DEBUG_LEVEL_DEBUG) {
		printf("D: %s ", tag);
	} else {
		printf("D: %s ", tag);
	}

	time = mico_rtos_get_time();
	printf("[%u] ", time);

	if (color)
		printf(LOG_COLOR_HEAD, color);
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);

	if (color)
		printf(LOG_COLOR_END);
	printf("\r\n");
}

void iot_bsp_debug_check_heap(const char* tag, const char* func, const int line, const char* fmt, ...)
{
	static int count = 0;
	micoMemInfo_t *meminfo = mico_memory_info();

	if (count == 0) {
		printf("%s: %s(%d) > [MEMCHK][%d] Heap total size : %d\r\n", tag, func, line, count, meminfo->total_memory);
	}

	printf("%s: %s(%d) > [MEMCHK][%d] allocated(used):%d, freed:%d, total memory:%d, number of chunks:%d\r\n",tag, func, line, ++count,
			meminfo->allocted_memory,
			meminfo->free_memory,
			meminfo->total_memory,
			meminfo->num_of_chunks);
}
