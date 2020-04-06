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
#include <time.h>
#include "platform/mbed_rtc_time.h"
#include "iot_bsp_system.h"
#include "iot_debug.h"
#include "mbed.h"

void iot_bsp_system_reboot()
{
	//TODO: implement API
	NVIC_SystemReset();
}

void iot_bsp_system_poweroff()
{
	//TODO: implement API
	exit(0);
}

iot_error_t iot_bsp_system_get_time_in_sec(char* buf, unsigned int buf_len)
{
	IOT_WARN_CHECK(buf == NULL, IOT_ERROR_INVALID_ARGS, "buffer for time is NULL");

	time_t seconds = time(NULL);

	snprintf(buf, buf_len, "%lld", seconds);

	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_system_set_time_in_sec(const char* time_in_sec)
{
	IOT_WARN_CHECK(time_in_sec == NULL, IOT_ERROR_INVALID_ARGS, "time data is NULL");

	time_t seconds;

	sscanf(time_in_sec, "%lld", &seconds);
	set_time(seconds);

	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_system_get_uniqueid(unsigned char **uid, size_t *olen)
{
	//TODO: implement API
	return IOT_ERROR_NONE;
}
