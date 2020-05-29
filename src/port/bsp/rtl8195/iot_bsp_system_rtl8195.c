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

#include "iot_bsp_system.h"
#include "iot_debug.h"
#include "FreeRTOS.h"
#include "task.h"
#include "osdep_service.h"

#include <reent.h>
#include <sys/time.h>

const char* iot_bsp_get_bsp_name()
{
       return "rtl8195";
}

const char* iot_bsp_get_bsp_version_string()
{
       return "";
}

static uint64_t s_boot_time;

static inline void set_boot_time(uint64_t time_ms)
{
	taskENTER_CRITICAL();
	s_boot_time = time_ms;
	taskEXIT_CRITICAL();
}

static inline uint64_t get_boot_time()
{
    uint64_t result;

    taskENTER_CRITICAL();
    result = s_boot_time;
    taskEXIT_CRITICAL();

    return result;
}

int _gettimeofday_r(struct _reent* r, struct timeval* tv, void* tz)
{
	uint64_t msec;

	(void) tz;

	if (tv) {
		msec =  get_boot_time()  + (uint64_t)rtw_systime_to_ms(rtw_get_current_time());
		tv->tv_sec = msec / 1000;
		tv->tv_usec = (msec  % 1000) * 1000;
	}

	return 0;
}

int settimeofday(const struct timeval* tv, const struct timezone* tz)
{
	(void) tz;

	if (tv) {
		uint64_t now = ((uint64_t) tv->tv_sec) * 1000000LL + tv->tv_usec;
		now =  now /1000;
		uint64_t since_boot = (uint64_t)rtw_systime_to_ms(rtw_get_current_time());
		set_boot_time(now - since_boot);
	}

	return 0;
}

void iot_bsp_system_reboot()
{
	sys_reset();
}

void iot_bsp_system_poweroff()
{

}

iot_error_t iot_bsp_system_get_time_in_sec(char* buf, unsigned int buf_len)
{
	IOT_ERROR_CHECK(buf == NULL, IOT_ERROR_INVALID_ARGS, "buffer for time is NULL");

	struct timeval tv = {0,};

	gettimeofday(&tv, NULL);
	snprintf(buf, buf_len, "%ld", tv.tv_sec);

	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_system_set_time_in_sec(const char* time_in_sec)
{
	IOT_ERROR_CHECK(time_in_sec == NULL, IOT_ERROR_INVALID_ARGS, "time data is NULL");

	struct timeval tv = {0,};

	sscanf(time_in_sec, "%ld", &tv.tv_sec);
	settimeofday(&tv, NULL);

	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_system_get_uniqueid(unsigned char **uid, size_t *olen)
{
	return IOT_ERROR_NOT_IMPLEMENTED;
}
