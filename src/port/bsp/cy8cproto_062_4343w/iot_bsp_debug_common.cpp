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

#include "iot_bsp_debug.h"
#include "mbed.h"
#include "platform/mbed_assert.h"
#include "platform/mbed_debug.h"
#include "platform/mbed_error.h"
#include "platform/mbed_stats.h"

#define COLOR_RED "\x1b[31m"
#define COLOR_GREEN "\x1b[32m"
#define COLOR_YELLOW "\x1b[33m"
#define COLOR_RESET "\x1b[0m"
#define BUF_SIZE 512
#define MAX_THREAD_INFO 10

Mutex mutex;
mbed_stats_heap_t heap_info;
mbed_stats_stack_t stack_info[ MAX_THREAD_INFO ];

void iot_bsp_dump(char* buf)
{
	/* TODO: implement dump */
}

void iot_bsp_debug(iot_debug_level_t level, const char* tag, const char* fmt, ...)
{
	char buf[BUF_SIZE] = {0,};
	int ret;
	va_list va;

	va_start(va, fmt);
	ret = vsnprintf(buf, BUF_SIZE, fmt, va);
	va_end(va);

	iot_bsp_dump(buf);
	mutex.lock();
	if (level == IOT_DEBUG_LEVEL_ERROR) {
		printf(COLOR_RED "E %s: %s\n" COLOR_RESET, tag, buf);
	} else if (level == IOT_DEBUG_LEVEL_WARN) {
		printf(COLOR_YELLOW "W %s: %s\n" COLOR_RESET, tag, buf);
	} else if (level == IOT_DEBUG_LEVEL_INFO) {
		printf(COLOR_GREEN "I %s: %s\n" COLOR_RESET, tag, buf);
	} else if (level == IOT_DEBUG_LEVEL_DEBUG) {
		printf("D %s: %s\n", tag, buf);
	} else {
		printf("D %s: %s\n", tag, buf);
	}
	mutex.unlock();
}

/* TODO: get proper values of heap */
static unsigned int _iot_bsp_debug_get_free_heap_size(void)
{
	mbed_stats_heap_get(&heap_info);
	return (heap_info.total_size - heap_info.current_size);
}

static unsigned int _iot_bsp_debug_get_minimum_free_heap_size(void)
{
	mbed_stats_heap_get(&heap_info);
	return (heap_info.total_size - heap_info.current_size);
}

static unsigned int _iot_bsp_debug_get_maximum_heap_size(void)
{
	mbed_stats_heap_get(&heap_info);
	return (heap_info.total_size);
}

void iot_bsp_debug_check_heap(const char* tag, const char* func, const int line, const char* fmt, ...)
{
	static int count = 0;
	char buf[BUF_SIZE] = {0,};
	int ret;
	va_list va;

	va_start(va, fmt);
	ret = vsnprintf(buf, BUF_SIZE, fmt, va);
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

#if 0
int test_debug_mbed()
{
	debug("\nThis message is from debug function");
	debug_if(1,"\nThis message is from debug_if function");
	debug_if(0,"\nSOMETHING WRONG!!! This message from debug_if function shouldn't show on bash");

	printf("\nMemoryStats:");
	mbed_stats_heap_get( &heap_info );
	printf("\n\tBytes allocated currently: %d", heap_info.current_size);
	printf("\n\tMax bytes allocated at a given time: %d", heap_info.max_size);
	printf("\n\tCumulative sum of bytes ever allocated: %d", heap_info.total_size);
	printf("\n\tCurrent number of bytes allocated for the heap: %d", heap_info.reserved_size);
	printf("\n\tCurrent number of allocations: %d", heap_info.alloc_cnt);
	printf("\n\tNumber of failed allocations: %d", heap_info.alloc_fail_cnt);

	mbed_stats_stack_get( &stack_info[0] );
	printf("\nCumulative Stack Info:");
	printf("\n\tMaximum number of bytes used on the stack: %d", stack_info[0].max_size);
	printf("\n\tCurrent number of bytes allocated for the stack: %d", stack_info[0].reserved_size);
	printf("\n\tNumber of stacks stats accumulated in the structure: %d", stack_info[0].stack_cnt);

	mbed_stats_stack_get_each( stack_info, MAX_THREAD_INFO );
	printf("\nThread Stack Info:");
	for(int i=0;i < MAX_THREAD_INFO; i++) {
		if(stack_info[i].thread_id != 0) {
			printf("\n\tThread: %d", i);
			printf("\n\t\tThread Id: 0x%08X", stack_info[i].thread_id);
			printf("\n\t\tMaximum number of bytes used on the stack: %d", stack_info[i].max_size);
			printf("\n\t\tCurrent number of bytes allocated for the stack: %d", stack_info[i].reserved_size);
			printf("\n\t\tNumber of stacks stats accumulated in the structure: %d", stack_info[i].stack_cnt);
		}
	}

	printf("\nDone...\n\n");
}
#endif
