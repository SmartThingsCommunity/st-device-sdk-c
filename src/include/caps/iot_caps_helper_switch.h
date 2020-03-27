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

#ifndef _IOT_CAPS_HELPER_SWITCH_
#define _IOT_CAPS_HELPER_SWITCH_

#include "iot_caps_helper.h"

enum {
	CAPS_HELPER_SWITCH_VALUE_OFF = 0,
	CAPS_HELPER_SWITCH_VALUE_ON,
	CAPS_HELPER_SWITCH_VALUE_MAX
};

const static struct iot_caps_switch {
	const char *id;
	const struct switch_attr_switch {
		const char *name;
		const unsigned char property;
		const char *values[CAPS_HELPER_SWITCH_VALUE_MAX];
	} attr_switch;
	const struct switch_cmd_off { const char *name; } cmd_off;
	const struct switch_cmd_on { const char *name; } cmd_on;
} caps_helper_switch = {
	.id = "switch",
	.attr_switch = {
		.name = "switch",
		.property = ATTR_SET_VALUE_REQUIRED,
		.values = { "off", "on" },
	},
	.cmd_off = { .name = "off" },
	.cmd_on = { .name = "on" },
};

#endif /* _IOT_CAPS_HELPER_SWITCH_ */
