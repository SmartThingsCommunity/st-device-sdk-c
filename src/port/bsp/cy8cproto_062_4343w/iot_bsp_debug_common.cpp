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

#define BUF_SIZE 512

void iot_bsp_dump(char* buf)
{

}

void iot_bsp_debug(iot_debug_level_t level, const char* tag, const char* fmt, ...)
{

}

static unsigned int _iot_bsp_debug_get_free_heap_size(void)
{
	return 0;
}

static unsigned int _iot_bsp_debug_get_minimum_free_heap_size(void)
{
	return 0;
}

static unsigned int _iot_bsp_debug_get_maximum_heap_size(void)
{
	return 0;
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

