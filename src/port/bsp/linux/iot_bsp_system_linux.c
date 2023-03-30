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

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/utsname.h>
#include "iot_bsp_system.h"
#include "iot_debug.h"

#define MACHINE_ID_FILE "/etc/machine-id"
#define MACHINE_ID_LEN_BYTES 16

static struct utsname uname_data;

const char* iot_bsp_get_bsp_name(void)
{
	uname(&uname_data);
	return uname_data.sysname;
}

const char* iot_bsp_get_bsp_version_string(void)
{
	uname(&uname_data);
	return uname_data.version;
}

void iot_bsp_system_reboot(void)
{
	exit(0);
}

void iot_bsp_system_poweroff(void)
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

	sscanf(time_in_sec, "%ld", &ts.tv_sec);
	clock_settime(CLOCK_REALTIME, &ts);

	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_system_get_uniqueid(unsigned char **uid, size_t *olen)
{
	FILE *fp = NULL;
	unsigned char *machine_id;
	int pos;

	machine_id = (unsigned char*)malloc(MACHINE_ID_LEN_BYTES);
	if (!machine_id)
		return IOT_ERROR_MEM_ALLOC;

	fp = fopen(MACHINE_ID_FILE, "r");
	if (!fp) {
		printf("could not open the file: %s", MACHINE_ID_FILE);
		return IOT_ERROR_READ_FAIL;
	}

	for (pos = 0; pos < MACHINE_ID_LEN_BYTES && !feof(fp); pos++)
		fscanf(fp, "%2hhx", &machine_id[pos]);

	fclose(fp);
	*uid = machine_id;
	*olen = MACHINE_ID_LEN_BYTES;

	return IOT_ERROR_NONE;
}
