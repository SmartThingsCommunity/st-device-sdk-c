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

#ifndef _IOT_CAPS_HELPER_ALARM_
#define _IOT_CAPS_HELPER_ALARM_

#include "iot_caps_helper.h"

enum {
	CAPS_HELPER_ALARM_VALUE_BOTH = 0,
	CAPS_HELPER_ALARM_VALUE_OFF,
	CAPS_HELPER_ALARM_VALUE_SIREN,
	CAPS_HELPER_ALARM_VALUE_STROBE,
	CAPS_HELPER_ALARM_VALUE_MAX
};

const static struct iot_caps_alarm {
	const char *id;
	const struct alarm_attr_alarm {
		const char *name;
		const unsigned char property;
		const char *values[CAPS_HELPER_ALARM_VALUE_MAX];
	} attr_alarm;
	const struct alarm_cmd_both { const char *name; } cmd_both;
	const struct alarm_cmd_off { const char *name; } cmd_off;
	const struct alarm_cmd_siren { const char *name; } cmd_siren;
	const struct alarm_cmd_strobe { const char *name; } cmd_strobe;
} caps_helper_alarm = {
	.id = "alarm",
	.attr_alarm = {
		.name = "alarm",
		.property = ATTR_SET_VALUE_REQUIRED,
		.values = { "both", "off", "siren", "strobe" },
	},
	.cmd_both = { .name = "both"},
	.cmd_off = { .name = "off"},
	.cmd_siren = { .name = "siren"},
	.cmd_strobe = { .name = "strobe"},
};

#endif /* _IOT_CAPS_HELPER_ALARM_ */
