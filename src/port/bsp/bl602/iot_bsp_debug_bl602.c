/* ***************************************************************************
 *
 * Copyright 2019 Samsung Electronics All Rights Reserved.
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
#include <stdlib.h>
#include <stdarg.h>
#include <blog.h>
#include "FreeRTOS.h"
#include "iot_bsp_debug.h"

#define INFO_LOG_COLOR_HEAD      "\033[32m"
#define INFO_LOG_COLOR_END       "\033[0m"
#define WARN_LOG_COLOR_HEAD      "\033[33m"
#define WARN_LOG_COLOR_END       "\033[0m"
#define ERROR_LOG_COLOR_HEAD      "\033[31m"
#define ERROR_LOG_COLOR_END       "\033[0m"
#define DEBUG_LOG_COLOR_HEAD      "\033[0m"
#define DEBUG_LOG_COLOR_END       "\033[0m"


#define PRINT_ST_INFO_LOG(TAG, M, ...)     do {__blog_printf(INFO_LOG_COLOR_HEAD "I (%u) %s : %s" INFO_LOG_COLOR_END "\r\n",\
            (xPortIsInsideInterrupt())?(xTaskGetTickCountFromISR()):(xTaskGetTickCount()), \
            TAG, M, ##__VA_ARGS__);\
        } while(0==1)

#define PRINT_ST_WARN_LOG(TAG, M, ...)     do {__blog_printf(WARN_LOG_COLOR_HEAD "W (%u) %s : %s" WARN_LOG_COLOR_END "\r\n",\
            (xPortIsInsideInterrupt())?(xTaskGetTickCountFromISR()):(xTaskGetTickCount()), \
            TAG, M, ##__VA_ARGS__);\
        } while(0==1)

#define PRINT_ST_ERROR_LOG(TAG, M, ...)     do {__blog_printf(ERROR_LOG_COLOR_HEAD "E (%u) %s : %s" ERROR_LOG_COLOR_END "\r\n",\
            (xPortIsInsideInterrupt())?(xTaskGetTickCountFromISR()):(xTaskGetTickCount()), \
            TAG, M, ##__VA_ARGS__);\
        } while(0==1)

#define PRINT_ST_DEBUG_LOG(TAG, M, ...)     do {__blog_printf(DEBUG_LOG_COLOR_HEAD "D (%u) %s : %s" DEBUG_LOG_COLOR_END "\r\n",\
            (xPortIsInsideInterrupt())?(xTaskGetTickCountFromISR()):(xTaskGetTickCount()), \
            TAG, M, ##__VA_ARGS__);\
        } while(0==1)


void iot_bsp_debug(iot_debug_level_t level, const char* tag, const char* fmt, ...)
{
    char* buf;
	int ret;
	va_list va;

	va_start(va, fmt);
	ret = vasiprintf(&buf, fmt, va);
	va_end(va);

	if (level == IOT_DEBUG_LEVEL_ERROR) {
		PRINT_ST_ERROR_LOG(tag, buf);
	} else if (level == IOT_DEBUG_LEVEL_WARN) {
		PRINT_ST_WARN_LOG(tag, buf);
	} else if (level == IOT_DEBUG_LEVEL_INFO) {
		PRINT_ST_INFO_LOG(tag, buf);
	} else if (level == IOT_DEBUG_LEVEL_DEBUG) {
		PRINT_ST_DEBUG_LOG(tag, buf);
	} else {
		PRINT_ST_DEBUG_LOG(tag, buf);
	}

	if (ret >= 0) {
		free(buf);
	}
}

static unsigned int _iot_bsp_debug_get_free_heap_size(void)
{
	return xPortGetFreeHeapSize();
}

static unsigned int _iot_bsp_debug_get_minimum_free_heap_size(void)
{
	return xPortGetMinimumEverFreeHeapSize();
}

static unsigned int _iot_bsp_debug_get_maximum_heap_size(void)
{
	return configTOTAL_HEAP_SIZE;
}

void iot_bsp_debug_check_heap(const char* tag, const char* func, const int line, const char* fmt, ...)
{
	static int count = 0;
	char* buf;
	int ret;
	va_list va;

	va_start(va, fmt);
	ret = vasprintf(&buf, fmt, va);
	va_end(va);

	if (count == 0) {
        iot_bsp_debug(IOT_DEBUG_LEVEL_WARN, tag, "%s(%d) > [MEMCHK][%d] Heap total size : %d", func, line, count, _iot_bsp_debug_get_maximum_heap_size());
	}

	iot_bsp_debug(IOT_DEBUG_LEVEL_WARN, tag, "%s(%d) > [MEMCHK][%d][%s] CU:%d, CR:%d, PU:%d, PR:%d", func, line, ++count, buf,
			_iot_bsp_debug_get_maximum_heap_size() - _iot_bsp_debug_get_free_heap_size(),
			_iot_bsp_debug_get_free_heap_size(),
			_iot_bsp_debug_get_maximum_heap_size() - _iot_bsp_debug_get_minimum_free_heap_size(),
			_iot_bsp_debug_get_minimum_free_heap_size());

	if (ret >= 0) {
		free(buf);
	}
}
