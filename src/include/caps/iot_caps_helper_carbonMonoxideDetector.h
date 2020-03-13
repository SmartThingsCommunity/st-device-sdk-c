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

#ifndef _IOT_CAPS_HELPER_CARBON_MONOXIDE_DETECTOR_
#define _IOT_CAPS_HELPER_CARBON_MONOXIDE_DETECTOR_

#include "iot_caps_helper.h"

enum {
	CAPS_HELPER_CARBON_MONOXIDE_DETECTOR_VALUE_CLEAR = 0,
	CAPS_HELPER_CARBON_MONOXIDE_DETECTOR_VALUE_DETECTED,
	CAPS_HELPER_CARBON_MONOXIDE_DETECTOR_VALUE_TESTED,
	CAPS_HELPER_CARBON_MONOXIDE_DETECTOR_VALUE_MAX
};

const static struct iot_caps_carbonMonoxideDetector {
	const char *id;
	const struct carbonMonoxideDetector_attr_carbonMonoxide {
		const char *name;
		const unsigned char property;
		const char *values[CAPS_HELPER_CARBON_MONOXIDE_DETECTOR_VALUE_MAX];
	} attr_carbonMonoxide;
} caps_helper_carbonMonoxideDetector = {
	.id = "carbonMonoxideDetector",
	.attr_carbonMonoxide = {
		.name = "carbonMonoxide",
		.property = ATTR_SET_VALUE_REQUIRED,
		.values = { "clear", "detected", "tested" },
	}
};

#endif /* _IOT_CAPS_HELPER_CARBON_MONOXIDE_DETECTOR_ */
