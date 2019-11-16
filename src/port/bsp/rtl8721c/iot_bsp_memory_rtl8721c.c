/******************************************************************
 *
 * Copyright 2019 Samsung Electronics All Rights Reserved.
 *
 *
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
#include "FreeRTOS.h"
#include "platform_stdlib_rtl8721d.h"

static unsigned int _iot_bsp_mem_get_free_heap_size(void)
{
	return xPortGetFreeHeapSize();
}

static unsigned int _iot_bsp_mem_get_minimum_free_heap_size(void)
{
	return xPortGetMinimumEverFreeHeapSize();
}

static unsigned int _iot_bsp_mem_get_maximum_heap_size(void)
{
	return configTOTAL_HEAP_SIZE;
}

void iot_bsp_mem_check_heap(const char* tag, const char* func, const int line, const char* fmt, ...)
{
	static int count = 0;
	va_list va;

	va_start(va, fmt);
	rtl_vprintf(fmt, va);
	va_end(va);

	if (count == 0) {
		printf("%s: %s(%d) > [MEMCHK][%d] Heap total size : %d", tag, func, line, count, _iot_bsp_mem_get_maximum_heap_size());
	}

	printf("%s: %s(%d) > [MEMCHK][%d] CU:%d, CR:%d, PU:%d, PR:%d\n", tag, func, line, ++count,
			_iot_bsp_mem_get_maximum_heap_size() - _iot_bsp_mem_get_free_heap_size(),
			_iot_bsp_mem_get_free_heap_size(),
			_iot_bsp_mem_get_maximum_heap_size() - _iot_bsp_mem_get_minimum_free_heap_size(),
			_iot_bsp_mem_get_minimum_free_heap_size());
}
