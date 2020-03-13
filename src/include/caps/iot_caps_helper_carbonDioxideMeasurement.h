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

#ifndef _IOT_CAPS_HELPER_CARBON_DIOXIDE_MEASUREMENT_
#define _IOT_CAPS_HELPER_CARBON_DIOXIDE_MEASUREMENT_

#include "iot_caps_helper.h"

enum {
	CAPS_HELPER_CARBON_DIOXIDE_MEASUREMENT_UNIT_PPM = 0,
	CAPS_HELPER_CARBON_DIOXIDE_MEASUREMENT_UNIT_MAX
};

const static struct iot_caps_carbonDioxideMeasurement {
	const char *id;
	struct carbonDioxideMeasurement_attr_carbonDioxide {
		const char *name;
		const int min, max;
		const unsigned char property;
		const char *units[CAPS_HELPER_CARBON_DIOXIDE_MEASUREMENT_UNIT_MAX];
	} attr_carbonDioxide;
} caps_helper_carbonDioxideMeasurement = {
	.id = "carbonDioxideMeasurement",
	.attr_carbonDioxide = {
		.name = "carbonDioxide",
		.min = 0,
		.max = 1000000,
		.property = ATTR_SET_VALUE_MIN | ATTR_SET_VALUE_MAX | ATTR_SET_VALUE_REQUIRED,
		.units = { "ppm" },
	},
};

#endif /* _IOT_CAPS_HELPER_CARBON_DIOXIDE_MEASUREMENT_ */
