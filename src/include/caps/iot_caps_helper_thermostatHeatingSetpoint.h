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

#ifndef _IOT_CAPS_HELPER_THERMOSTAT_HEATING_SETPOINT_
#define _IOT_CAPS_HELPER_THERMOSTAT_HEATING_SETPOINT_

#include "iot_caps_helper.h"

enum {
	CAPS_HELPER_THERMOSTAT_HEATING_SETPOINT_UNIT_F = 0,
	CAPS_HELPER_THERMOSTAT_HEATING_SETPOINT_UNIT_C,
	CAPS_HELPER_THERMOSTAT_HEATING_SETPOINT_UNIT_MAX
};

const static struct iot_caps_thermostatHeatingSetpoint {
	const char *id;
	const struct thermostatHeatingSetpoint_attr_heatingSetpoint {
		const char *name;
		const double min, max;
		const unsigned char property;
		const char *units[CAPS_HELPER_THERMOSTAT_HEATING_SETPOINT_UNIT_MAX];
	} attr_heatingSetpoint;
	const struct thermostatHeatingSetpoint_cmd_setHeatingSetpoint { const char *name; } cmd_setHeatingSetpoint;
} caps_helper_thermostatHeatingSetpoint = {
	.id = "thermostatHeatingSetpoint",
	.attr_heatingSetpoint = {
		.name = "heatingSetpoint",
		.min = -460,
		.max = 10000,
		.property = ATTR_SET_VALUE_MIN | ATTR_SET_VALUE_MAX \
			| ATTR_SET_VALUE_REQUIRED | ATTR_SET_UNIT_REQUIRED,
		.units = { "F", "C" },
	},
	.cmd_setHeatingSetpoint = { .name = "setHeatingSetpoint" },
};

#endif /* _IOT_CAPS_HELPER_THERMOSTAT_HEATING_SETPOINT_ */
