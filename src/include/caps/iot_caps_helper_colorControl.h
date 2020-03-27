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

#ifndef _IOT_CAPS_HELPER_COLOR_CONTROL_
#define _IOT_CAPS_HELPER_COLOR_CONTROL_


#include "iot_caps_helper.h"

const static struct iot_caps_colorControl {
	const char *id;
	const struct colorControl_attr_color {
		const char *name;
		const unsigned int max_length;
		const unsigned char property;
	} attr_color;
	const struct colorControl_attr_int {
		const char *name;
		const int min;
		const unsigned char property;
	} attr_hue, attr_saturation;
	const struct colorControl_cmd_setColor { const char *name; } cmd_setColor;
	const struct colorControl_cmd_setHue { const char *name; } cmd_setHue;
	const struct colorControl_cmd_setSaturation { const char *name; } cmd_setSaturation;
} caps_helper_colorControl = {
	.id = "colorControl",
	.attr_color = {
		.name = "color",
		.max_length = 255,
		.property = ATTR_SET_MAX_LENGTH,
	},
	.attr_hue = {
		.name = "hue",
		.min = 0,
		.property = ATTR_SET_VALUE_MIN,
	},
	.attr_saturation = {
		.name = "saturation",
		.min = 0,
		.property = ATTR_SET_VALUE_MIN,
	},
	.cmd_setColor = { .name = "setColor" },
	.cmd_setHue = { .name = "setHue" },
	.cmd_setSaturation = { .name = "setSaturation" },
};

#endif /* _IOT_CAPS_HELPER_COLOR_CONTROL_ */
