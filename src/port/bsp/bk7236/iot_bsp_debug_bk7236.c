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
#include <stdint.h>
#include <stdarg.h>
#include <time.h>
#include <sys/time.h>
#include <driver/aon_rtc.h>
#include <string.h>
#include "iot_bsp_debug.h"
#include "FreeRTOS.h"

#define LOG_COLOR_HEAD "\033[0;%dm"
#define LOG_COLOR_END  "\033[0m"
#define BUF_SIZE 512

static const uint32_t s_log_color [IOT_DEBUG_LEVEL_MAX]= {
	0,  //IOT_DEBUG_LEVEL_NONE
	31, //IOT_DEBUG_LEVEL_ERROR
	33, //IOT_DEBUG_LEVEL_WARN
	32, //IOT_DEBUG_LEVEL_INFO
	0,  //IOT_DEBUG_LEVEL_DEBUG
};

static void get_current_time_in_s(time_t *vTime)
{
	struct timeval tv = {0,0};
	bk_rtc_gettimeofday(&tv, 0);
	*vTime = tv.tv_sec;
}

void iot_bsp_debug(iot_debug_level_t level, const char* tag, const char* fmt, ...)
{
	va_list va;
	char buf[BUF_SIZE] = {0,};
	char buffer[64] = {0};
	time_t bkTime = 0;
	uint32_t color = s_log_color[level];

	va_start(va, fmt);
	vsnprintf(buf, BUF_SIZE, fmt, va);
	va_end(va);
	
	
	get_current_time_in_s(&bkTime);
	ctime_r(&bkTime, buffer);
	char date[64] = {0};
	strncpy(date, buffer, strlen(buffer)-1);

	if (level == IOT_DEBUG_LEVEL_ERROR) {
		printf(LOG_COLOR_HEAD"E: %s [%s] %s"LOG_COLOR_END "\r\n", color, tag, date, buf);
	} else if (level == IOT_DEBUG_LEVEL_WARN) {
		printf(LOG_COLOR_HEAD"W: %s [%s] %s"LOG_COLOR_END "\r\n", color, tag, date, buf);
	} else if (level == IOT_DEBUG_LEVEL_INFO) {
		printf(LOG_COLOR_HEAD"I: %s [%s] %s"LOG_COLOR_END "\r\n", color, tag, date, buf);
	} else if (level == IOT_DEBUG_LEVEL_DEBUG) {
		printf(LOG_COLOR_HEAD"D: %s [%s] %s"LOG_COLOR_END "\r\n", color, tag, date, buf);
	} else {
		printf(LOG_COLOR_HEAD"D: %s [%s] %s"LOG_COLOR_END "\r\n", color, tag, date, buf);
	}
	printf("\r\n");
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
	char buf[BUF_SIZE] = {0,};
	va_list va;

	va_start(va, fmt);
	vsnprintf(buf, BUF_SIZE, fmt, va);
	va_end(va);

	if (count == 0) {
		iot_bsp_debug(IOT_DEBUG_LEVEL_WARN, tag, "%s(%d) > [MEMCHK][%d] Heap total size : %d", func, line, count, _iot_bsp_debug_get_maximum_heap_size());
	}

	iot_bsp_debug(IOT_DEBUG_LEVEL_WARN, tag, "%s(%d) > [MEMCHK][%d][%s] CU:%d, CR:%d, PU:%d, PR:%d", func, line, ++count, buf,
			_iot_bsp_debug_get_maximum_heap_size() - _iot_bsp_debug_get_free_heap_size(),
			_iot_bsp_debug_get_free_heap_size(),
			_iot_bsp_debug_get_maximum_heap_size() - _iot_bsp_debug_get_minimum_free_heap_size(),
			_iot_bsp_debug_get_minimum_free_heap_size());
}
