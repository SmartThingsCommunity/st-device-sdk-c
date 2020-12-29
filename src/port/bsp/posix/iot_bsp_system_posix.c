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
#include <unistd.h>
#include "iot_bsp_system.h"
#include "iot_debug.h"

const char* iot_bsp_get_bsp_name()
{
       return "posix";
}

const char* iot_bsp_get_bsp_version_string()
{
       return "";
}

void iot_bsp_system_reboot()
{
	exit(0);
}

void iot_bsp_system_poweroff()
{
	exit(0);
}

iot_error_t iot_bsp_system_get_time_in_sec(char* buf, unsigned int buf_len)
{
	IOT_WARN_CHECK(buf == NULL, IOT_ERROR_INVALID_ARGS, "buffer for time is NULL");

	struct timespec ts = {0,};

	clock_gettime(CLOCK_REALTIME, &ts);
	snprintf(buf, buf_len, "%ld", ts.tv_sec);

	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_system_set_time_in_sec(const char* time_in_sec)
{
	IOT_WARN_CHECK(time_in_sec == NULL, IOT_ERROR_INVALID_ARGS, "time data is NULL");

	struct timespec ts = {0,};
	int ret;

	sscanf(time_in_sec, "%ld", &ts.tv_sec);
	ret = clock_settime(CLOCK_REALTIME, &ts);
	if (ret == -1)
		return IOT_ERROR_INVALID_ARGS;

	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_system_get_uniqueid(unsigned char **uid, size_t *olen)
{
	unsigned long hostid = gethostid();
	unsigned char *id;

	id = (unsigned char*) malloc(4);
	if (!id) {
		return IOT_ERROR_MEM_ALLOC;
	}

	for (int i = 0; i < 4; i++) {
		id[i] = (unsigned char) hostid;
		hostid = hostid >> 8u;
	}

	*uid = id;
	*olen = 4;

	return IOT_ERROR_NONE;
}
