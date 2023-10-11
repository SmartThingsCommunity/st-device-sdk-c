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
#include <sys/time.h>
#include "esp_system.h"
#include "soc/efuse_reg.h"

#include "iot_bsp_system.h"
#include "iot_debug.h"

const char* iot_bsp_get_bsp_name()
{
       return "esp32";
}

const char* iot_bsp_get_bsp_version_string()
{
       return esp_get_idf_version();
}

void iot_bsp_system_reboot()
{
	esp_restart();
}

void iot_bsp_system_poweroff()
{
	esp_restart(); // no poweroff feature.
}

iot_error_t iot_bsp_system_get_time_in_sec(char* buf, unsigned int buf_len)
{
	IOT_WARN_CHECK(buf == NULL, IOT_ERROR_INVALID_ARGS, "buffer for time is NULL");

	struct timeval tv = {0,};

	gettimeofday(&tv, NULL);
	snprintf(buf, buf_len, "%lld", tv.tv_sec);

	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_system_set_time_in_sec(const char* time_in_sec)
{
	IOT_WARN_CHECK(time_in_sec == NULL, IOT_ERROR_INVALID_ARGS, "time data is NULL");

	struct timeval tv = {0,};

	sscanf(time_in_sec, "%lld", &tv.tv_sec);
	settimeofday(&tv, NULL);

	return IOT_ERROR_NONE;
}
