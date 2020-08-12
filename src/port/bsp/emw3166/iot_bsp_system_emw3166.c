/* ***************************************************************************
 *
 * Copyright 2020 Samsung Electronics All Rights Reserved.
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

#include "iot_bsp_system.h"
#include <mico_platform.h>
#include <mico_system.h>

const char* iot_bsp_get_bsp_name()
{
	return "emw3166";
}

const char* iot_bsp_get_bsp_version_string()
{
	return "";
}

void iot_bsp_system_reboot()
{
	mico_system_reboot();
}

void iot_bsp_system_poweroff()
{
	mico_system_reboot();
}

iot_error_t iot_bsp_system_get_time_in_sec(char* buf, unsigned int buf_len)
{
	mico_utc_time_ms_t current_utc_time_ms = 0;
	uint32_t current_time_s;
	mico_time_get_utc_time_ms( &current_utc_time_ms );

	current_time_s = current_utc_time_ms / 1000;
	snprintf(buf, buf_len, "%ld", current_time_s);

	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_system_set_time_in_sec(const char* time_in_sec)
{
	mico_utc_time_ms_t current_utc_time_ms = 0;
	uint32_t current_time_s;

	sscanf(time_in_sec, "%ld", &current_time_s);
	current_utc_time_ms = (mico_utc_time_ms_t)current_time_s * 1000;

	mico_time_set_utc_time_ms(&current_utc_time_ms);

	return IOT_ERROR_NONE;
}
