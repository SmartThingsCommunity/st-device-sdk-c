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

#ifndef _IOT_CAPS_HELPER_THERMOSTAT_MODE_
#define _IOT_CAPS_HELPER_THERMOSTAT_MODE_

#include "iot_caps_helper.h"

enum {
	CAPS_HELPER_THERMOSTAT_MODE_VALUE_AUTO = 0,
	CAPS_HELPER_THERMOSTAT_MODE_VALUE_COOL,
	CAPS_HELPER_THERMOSTAT_MODE_VALUE_ECO,
	CAPS_HELPER_THERMOSTAT_MODE_VALUE_RUSH_HOUR,
	CAPS_HELPER_THERMOSTAT_MODE_VALUE_EMERGENCY_HEAT,
	CAPS_HELPER_THERMOSTAT_MODE_VALUE_HEAT,
	CAPS_HELPER_THERMOSTAT_MODE_VALUE_OFF,
	CAPS_HELPER_THERMOSTAT_MODE_VALUE_MAX
};

const static struct iot_caps_thermostatMode {
	const char *id;
	const struct thermostatMode_attr_thermostatMode {
		const char *name;
		const unsigned char property;
		const char *values[CAPS_HELPER_THERMOSTAT_MODE_VALUE_MAX];
	} attr_thermostatMode;
	const struct thermostatMode_attr_supported_thermostatModes {
		const char *name;
		const unsigned char property;
		const char *values[CAPS_HELPER_THERMOSTAT_MODE_VALUE_MAX];
	} attr_supportedThermostatModes;
	const struct thermostatMode_cmd_auto { const char *name; } cmd_auto;
	const struct thermostatMode_cmd_cool { const char *name; } cmd_cool;
	const struct thermostatMode_cmd_emergencyHeat { const char *name; } cmd_emergencyHeat;
	const struct thermostatMode_cmd_heat { const char *name; } cmd_heat;
	const struct thermostatMode_cmd_off { const char *name; } cmd_off;
	const struct thermostatMode_cmd_setThermostatMode { const char *name; } cmd_setThermostatMode;
} caps_helper_thermostatMode = {
	.id = "thermostatMode",
	.attr_thermostatMode = {
		.name = "thermostatMode",
		.property = ATTR_SET_VALUE_REQUIRED,
		.values = { "auto", "cool", "eco", "rush hour", "emergency heat", "heat", "off" },
	},
	.attr_supportedThermostatModes = {
		.name = "supportedThermostatModes",
		.property = ATTR_SET_VALUE_REQUIRED,
		.values = { "auto", "cool", "eco", "rush hour", "emergency heat", "heat", "off" },
	},
	.cmd_auto = { .name = "auto" },
	.cmd_cool = { .name = "cool" },
	.cmd_emergencyHeat = { .name = "emergencyHeat" },
	.cmd_heat = { .name = "heat" },
	.cmd_off = { .name = "off" },
	.cmd_setThermostatMode = { .name = "setThermostatMode" },
};

#endif /* _IOT_CAPS_HELPER_THERMOSTAT_MODE_ */
