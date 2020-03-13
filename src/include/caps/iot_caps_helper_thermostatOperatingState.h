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

#ifndef _IOT_CAPS_HELPER_THERMOSTAT_OPERATING_STATE_
#define _IOT_CAPS_HELPER_THERMOSTAT_OPERATING_STATE_

#include "iot_caps_helper.h"

enum {
	CAPS_HELPER_THERMOSTAT_OPERATING_STATE_VALUE_COOLING = 0,
	CAPS_HELPER_THERMOSTAT_OPERATING_STATE_VALUE_FAN_ONLY,
	CAPS_HELPER_THERMOSTAT_OPERATING_STATE_VALUE_HEATING,
	CAPS_HELPER_THERMOSTAT_OPERATING_STATE_VALUE_IDLE,
	CAPS_HELPER_THERMOSTAT_OPERATING_STATE_VALUE_PENDING_COOL,
	CAPS_HELPER_THERMOSTAT_OPERATING_STATE_VALUE_PENDING_HEAT,
	CAPS_HELPER_THERMOSTAT_OPERATING_STATE_VALUE_VENT_ECONOMIZER,
	CAPS_HELPER_THERMOSTAT_OPERATING_STATE_VALUE_MAX
};

const static struct iot_caps_thermostatOperatingState {
	const char *id;
	const struct thermostatOperatingState_attr_thermostatOperatingState {
		const char *name;
		const unsigned char property;
		const char *values[CAPS_HELPER_THERMOSTAT_OPERATING_STATE_VALUE_MAX];
	} attr_thermostatOperatingState;
} caps_helper_thermostatOperatingState = {
	.id = "thermostatOperatingState",
	.attr_thermostatOperatingState = {
		.name = "thermostatOperatingState",
		.property = ATTR_SET_VALUE_REQUIRED,
		.values = { "cooling", "fan only", "heating", "idle", "pending cool", "pending heat", "vent economizer" },
	},
};

#endif /* _IOT_CAPS_HELPER_THERMOSTAT_OPERATING_STATE_ */
