/* ***************************************************************************
 *
 * Copyright 2019-2020 Samsung Electronics All Rights Reserved.
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
#include <esp_log.h>
#include <esp_system.h>
#include <esp_heap_caps.h>
#include "iot_bsp_debug.h"

void iot_bsp_debug(iot_debug_level_t level, const char* tag, const char* fmt, ...)
{
	char* buf;
	int ret;
	va_list va;

	va_start(va, fmt);
	ret = vasprintf(&buf, fmt, va);
	va_end(va);

#if defined(CONFIG_STDK_IOT_CORE_EASYSETUP_LOG_SUPPORT_NO_USE_LOGFILE)
	iot_debug_save_log(buf);
#endif

	if (level == IOT_DEBUG_LEVEL_ERROR) {
		ESP_LOGE(tag, "%s", buf);
	} else if (level == IOT_DEBUG_LEVEL_WARN) {
		ESP_LOGW(tag, "%s", buf);
	} else if (level == IOT_DEBUG_LEVEL_INFO) {
		ESP_LOGI(tag, "%s", buf);
	} else if (level == IOT_DEBUG_LEVEL_DEBUG) {
		ESP_LOGD(tag, "%s", buf);
	} else {
		ESP_LOGD(tag, "%s", buf);
	}

	if (ret >= 0) {
		free(buf);
	}
}

static unsigned int _iot_bsp_debug_get_free_heap_size(void)
{
	return esp_get_free_heap_size();
}

static unsigned int _iot_bsp_debug_get_minimum_free_heap_size(void)
{
	return esp_get_minimum_free_heap_size();
}

static unsigned int _iot_bsp_debug_get_maximum_heap_size(void)
{
	static size_t bytes = 0;
	multi_heap_info_t info;

	if (bytes == 0) {
		heap_caps_get_info(&info, MALLOC_CAP_DEFAULT);
		bytes = info.total_allocated_bytes + info.total_free_bytes;
	}

	return bytes;
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
		ESP_LOGW(tag, "%s(%d) > [MEMCHK][%d] Heap total size : %d", func, line, count, _iot_bsp_debug_get_maximum_heap_size());
	}

	ESP_LOGW(tag, "%s(%d) > [MEMCHK][%d][%s] CU:%d, CR:%d, PU:%d, PR:%d", func, line, ++count, buf,
			_iot_bsp_debug_get_maximum_heap_size() - _iot_bsp_debug_get_free_heap_size(),
			_iot_bsp_debug_get_free_heap_size(),
			_iot_bsp_debug_get_maximum_heap_size() - _iot_bsp_debug_get_minimum_free_heap_size(),
			_iot_bsp_debug_get_minimum_free_heap_size());

	if (ret >= 0) {
		free(buf);
	}
}
