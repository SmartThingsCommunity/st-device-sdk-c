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
#include <string.h>
#include <esp_log.h>
#include <esp_system.h>
#include <esp_heap_caps.h>
#if defined(CONFIG_STDK_IOT_CORE_LOG_FILE)
#include <esp_spi_flash.h>
#endif

#include "iot_bsp_debug.h"

#if defined(CONFIG_STDK_IOT_CORE_LOG_FILE)
#include "iot_log_file.h"
#endif

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
		ESP_LOGE(tag, buf);
	} else if (level == IOT_DEBUG_LEVEL_WARN) {
		ESP_LOGW(tag, buf);
	} else if (level == IOT_DEBUG_LEVEL_INFO) {
		ESP_LOGI(tag, buf);
	} else if (level == IOT_DEBUG_LEVEL_DEBUG) {
		ESP_LOGD(tag, buf);
	} else {
		ESP_LOGD(tag, buf);
	}

	if (ret >= 0) {
		free(buf);
	}
}

extern heap_region_t g_heap_region[HEAP_REGIONS_MAX];

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

	if (bytes == 0) {
		for (int i = 0; i < HEAP_REGIONS_MAX; i++) {
			bytes += g_heap_region[i].total_size;
		}
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
		for (int i = 0; i < HEAP_REGIONS_MAX; i++) {
			ESP_LOGW(tag, "%s(%d) > [MEMCHK][%d] Heap_%d total size : %d", func, line, count, i, g_heap_region[i].total_size);
		}
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

#if defined(CONFIG_STDK_IOT_CORE_LOG_FILE_FLASH_WITH_RAM)
iot_error_t iot_log_read_flash(unsigned int src_addr, void *des_addr, unsigned int size)
{
	iot_error_t iot_err = IOT_ERROR_NONE;
	esp_err_t esp_err = ESP_OK;

	IOT_LOG_FILE_DEBUG("[%s] src_addr=0x%x des_addr=0x%p size=0x%x\n", __FUNCTION__, src_addr, des_addr, size);

	esp_err = spi_flash_read(src_addr, des_addr, size);
	if (esp_err != IOT_ERROR_NONE) {
		IOT_LOG_FILE_ERROR("%s IOT_ERROR_READ_FAIL\n", __FUNCTION__);
		iot_err = IOT_ERROR_READ_FAIL;
	}

	IOT_LOG_FILE_DEBUG("[%s] end\n", __FUNCTION__);

	return iot_err;
}

iot_error_t iot_log_write_flash(unsigned int des_addr, void *src_addr, unsigned int size)
{
	iot_error_t iot_err = IOT_ERROR_NONE;
	esp_err_t esp_err = ESP_OK;

	IOT_LOG_FILE_DEBUG("[%s] des_addr=0x%x src_addr=0x%p size=0x%x\n", __FUNCTION__, des_addr, src_addr, size);

	esp_err = spi_flash_write(des_addr, src_addr, size);
	if (esp_err != IOT_ERROR_NONE) {
		IOT_LOG_FILE_ERROR("%s IOT_ERROR_WRITE_FAIL\n", __FUNCTION__);
		iot_err = IOT_ERROR_WRITE_FAIL;
	}

	IOT_LOG_FILE_DEBUG("[%s] end\n", __FUNCTION__);

	return iot_err;
}

iot_error_t iot_log_erase_sector(unsigned int sector_num)
{
	iot_error_t iot_err = IOT_ERROR_NONE;
	esp_err_t esp_err = ESP_OK;

	IOT_LOG_FILE_DEBUG("[%s] sector_num=%d\n", __FUNCTION__, sector_num);

	esp_err = spi_flash_erase_sector(sector_num);
	if (esp_err != IOT_ERROR_NONE) {
		IOT_LOG_FILE_ERROR("%s _iot_log_erase_sector\n", __FUNCTION__);
		iot_err = IOT_ERROR_BAD_REQ;
	}

	IOT_LOG_FILE_DEBUG("[%s] end\n", __FUNCTION__);

	return iot_err;
}
#endif
