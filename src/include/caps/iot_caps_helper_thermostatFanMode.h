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

#ifndef _IOT_CAPS_HELPER_THERMOSTAT_FAN_MODE_
#define _IOT_CAPS_HELPER_THERMOSTAT_FAN_MODE_

#include "iot_caps_helper.h"

enum {
	CAPS_HELPER_THERMOSTAT_FAN_MODE_VALUE_AUTO = 0,
	CAPS_HELPER_THERMOSTAT_FAN_MODE_VALUE_CIRCULATE,
	CAPS_HELPER_THERMOSTAT_FAN_MODE_VALUE_FOLLOWSCHEDULE,
	CAPS_HELPER_THERMOSTAT_FAN_MODE_VALUE_ON,
	CAPS_HELPER_THERMOSTAT_FAN_MODE_VALUE_MAX
};

const static struct iot_caps_thermostatFanMode {
	const char *id;
	const struct thermostatFanMode_attr_thermostatFanMode {
		const char *name;
		const unsigned char property;
		const char *values[CAPS_HELPER_THERMOSTAT_FAN_MODE_VALUE_MAX];
	} attr_thermostatFanMode;
	const struct thermostatFanMode_attr_supported_thermostatFanModes {
		const char *name;
		const unsigned char property;
		const char *values[CAPS_HELPER_THERMOSTAT_FAN_MODE_VALUE_MAX];
	} attr_supportedThermostatFanModes;
	const struct thermostatFanMode_cmd_fanAuto { const char *name; } cmd_fanAuto;
	const struct thermostatFanMode_cmd_fanCirculate { const char *name; } cmd_fanCirculate;
	const struct thermostatFanMode_cmd_fanOn { const char *name; } cmd_fanOn;
	const struct thermostatFanMode_cmd_setThermostatFanMode { const char *name; } cmd_setThermostatFanMode;
} caps_helper_thermostatFanMode = {
	.id = "thermostatFanMode",
	.attr_thermostatFanMode = {
		.name = "thermostatFanMode",
		.property = ATTR_SET_VALUE_REQUIRED,
		.values = { "auto", "circulate", "followschedule", "on" },
	},
	.attr_supportedThermostatFanModes = {
		.name = "supportedThermostatFanModes",
		.property = ATTR_SET_VALUE_REQUIRED,
		.values = { "auto", "circulate", "followschedule", "on" },
	},
	.cmd_fanAuto = { .name = "fanAuto" },
	.cmd_fanCirculate = { .name = "fanCirculate" },
	.cmd_fanOn = { .name = "fanOn" },
	.cmd_setThermostatFanMode = { .name = "setThermostatFanMode" },
};

#endif /* _IOT_CAPS_HELPER_THERMOSTAT_FAN_MODE_ */
