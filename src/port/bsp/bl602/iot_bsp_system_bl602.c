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
#include <sys/time.h>
#include <FreeRTOS.h>
#include <task.h>
#include "hal_sys.h"
#include "bl_timer.h"
#include "iot_bsp_system.h"
#include "iot_debug.h"


const char* iot_bsp_get_bsp_name()
{
       return "bl602";
}

const char* iot_bsp_get_bsp_version_string()
{
    setenv("CONFIG_CHIP_NAME", "BL602", 1);
	getenv("BL_SDK_VER");
	return BL_SDK_VER;
}

void iot_bsp_system_reboot()
{
    // Disable scheduler on this core.
    vTaskSuspendAll();
	hal_sys_reset();	
}

void iot_bsp_system_poweroff()
{
	iot_bsp_system_reboot(); // no poweroff feature.
}

iot_error_t iot_bsp_system_get_time_in_sec(time_t *time_in_sec)
{
	struct timeval tv = {0,};

	gettimeofday(&tv, NULL);
	*time_in_sec = tv.tv_sec;

	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_system_set_time_in_sec(time_t time_in_sec)
{
	IOT_WARN_CHECK(time_in_sec == NULL, IOT_ERROR_INVALID_ARGS, "time data is NULL");

	struct timeval tv = {0,};

	tv.tv_sec = time_in_sec;
	settimeofday(&tv, NULL);

	return IOT_ERROR_NONE;
}

clock_t clock()
{
	return bl_timer_now_us();
}
