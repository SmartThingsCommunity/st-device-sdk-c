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

#ifndef _IOT_CAPS_HELPER_BUTTON_
#define _IOT_CAPS_HELPER_BUTTON_

#include "iot_caps_helper.h"

enum {
	CAPS_HELPER_BUTTON_VALUE_PUSHED,
	CAPS_HELPER_BUTTON_VALUE_HELD,
	CAPS_HELPER_BUTTON_VALUE_DOUBLE,
	CAPS_HELPER_BUTTON_VALUE_PUSHED_2X,
	CAPS_HELPER_BUTTON_VALUE_PUSHED_3X,
	CAPS_HELPER_BUTTON_VALUE_PUSHED_4X,
	CAPS_HELPER_BUTTON_VALUE_PUSHED_5X,
	CAPS_HELPER_BUTTON_VALUE_PUSHED_6X,
	CAPS_HELPER_BUTTON_VALUE_DOWN,
	CAPS_HELPER_BUTTON_VALUE_DOWN_2X,
	CAPS_HELPER_BUTTON_VALUE_DOWN_3X,
	CAPS_HELPER_BUTTON_VALUE_DOWN_4X,
	CAPS_HELPER_BUTTON_VALUE_DOWN_5X,
	CAPS_HELPER_BUTTON_VALUE_DOWN_6X,
	CAPS_HELPER_BUTTON_VALUE_DOWN_HOLD,
	CAPS_HELPER_BUTTON_VALUE_UP,
	CAPS_HELPER_BUTTON_VALUE_UP_2X,
	CAPS_HELPER_BUTTON_VALUE_UP_3X,
	CAPS_HELPER_BUTTON_VALUE_UP_4X,
	CAPS_HELPER_BUTTON_VALUE_UP_5X,
	CAPS_HELPER_BUTTON_VALUE_UP_6X,
	CAPS_HELPER_BUTTON_VALUE_UP_HOLD,
	CAPS_HELPER_BUTTON_VALUE_MAX
};

const static struct iot_caps_button {
	const char *id;
	const struct button_attr_button {
		const char *name;
		const unsigned char property;
		const char *values[CAPS_HELPER_BUTTON_VALUE_MAX];
	} attr_button;
	const struct button_attr_numberOfButtons {
		const char *name;
		const int min;
		const unsigned char property;
	} attr_numberOfButtons;
	const struct button_attr_supportedButtonValues {
		const char *name;
		const unsigned char property;
		const char *values[CAPS_HELPER_BUTTON_VALUE_MAX];
	} attr_supportedButtonValues;
} caps_helper_button = {
	.id = "button",
	.attr_button = {
		.name = "button",
		.property = ATTR_SET_VALUE_REQUIRED,
		.values = {
			"pushed",
			"held",
			"double",
			"pushed_2x",
			"pushed_3x",
			"pushed_4x",
			"pushed_5x",
			"pushed_6x",
			"down",
			"down_2x",
			"down_3x",
			"down_4x",
			"down_5x",
			"down_6x",
			"down_hold",
			"up",
			"up_2x",
			"up_3x",
			"up_4x",
			"up_5x",
			"up_6x",
			"up_hold"
		},
	},
	.attr_numberOfButtons = {
		.name = "numberOfButtons",
		.min = 0,
		.property = ATTR_SET_VALUE_MIN | ATTR_SET_VALUE_REQUIRED
	},
	.attr_supportedButtonValues = {
		.name = "supportedButtonValues",
		.property = 0,
		.values = {
			"pushed",
			"held",
			"double",
			"pushed_2x",
			"pushed_3x",
			"pushed_4x",
			"pushed_5x",
			"pushed_6x",
			"down",
			"down_2x",
			"down_3x",
			"down_4x",
			"down_5x",
			"down_6x",
			"down_hold",
			"up",
			"up_2x",
			"up_3x",
			"up_4x",
			"up_5x",
			"up_6x",
			"up_hold"
		}
	}
};

#endif /* _IOT_CAPS_HELPER_BUTTON_ */