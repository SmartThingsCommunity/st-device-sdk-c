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
#include <components/system.h>
#include <driver/aon_rtc.h>
#include "iot_bsp_system.h"
#include "iot_debug.h"


const char* iot_bsp_get_bsp_name()
{
    return "BK7236";
}

const char* iot_bsp_get_bsp_version_string()
{
	return "";
}

void iot_bsp_system_reboot()
{
    // Disable scheduler on this core.
	bk_reboot();
}

void iot_bsp_system_poweroff()
{
	iot_bsp_system_reboot(); // no poweroff feature.
}


iot_error_t iot_bsp_system_get_time_in_sec(time_t *time_in_sec)
{
	struct timeval tv = {0,};
	bk_rtc_gettimeofday(&tv, NULL);
	*time_in_sec = tv.tv_sec;
	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_system_set_time_in_sec(time_t time_in_sec)
{
	struct timeval tv = {0,};
	tv.tv_sec = time_in_sec;
	bk_rtc_settimeofday(&tv,NULL);
	return IOT_ERROR_NONE;
}

int __wrap_gettimeofday(struct timeval *tv, struct timezone *tz)
{
	return bk_rtc_gettimeofday(tv, tz);
}

__attribute__((alias("__wrap_gettimeofday")))
int gettimeofday(struct timeval*, void*);
