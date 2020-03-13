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

#ifndef _IOT_CAPS_HELPER_ACCELERATION_SENSOR_
#define _IOT_CAPS_HELPER_ACCELERATION_SENSOR_

#include "iot_caps_helper.h"

enum {
	CAPS_HELPER_ACCELERATION_SENSOR_VALUE_ACTIVE = 0,
	CAPS_HELPER_ACCELERATION_SENSOR_VALUE_INACTIVE,
	CAPS_HELPER_ACCELERATION_SENSOR_VALUE_MAX
};

const static struct iot_caps_accelerationSensor {
	const char *id;
	const struct accelerationSensor_attr_acceleration {
		const char *name;
		const unsigned char property;
		const char *values[CAPS_HELPER_ACCELERATION_SENSOR_VALUE_MAX];
	} attr_acceleration;
} caps_helper_accelerationSensor = {
	.id = "accelerationSensor",
	.attr_acceleration = {
		.name = "acceleration",
		.property = ATTR_SET_VALUE_REQUIRED,
		.values = { "active", "inactive" },
	}
};

#endif /* _IOT_CAPS_HELPER_ACCELERATION_SENSOR_ */
