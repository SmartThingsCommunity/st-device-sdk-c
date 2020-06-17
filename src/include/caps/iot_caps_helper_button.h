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

#ifdef __cplusplus
extern "C" {
#endif

#define CAP_ENUM_BUTTON_SUPPORTEDBUTTONVALUES_VALUE_MAX 22
enum {
    CAP_ENUM_BUTTON_BUTTON_VALUE_PUSHED,
    CAP_ENUM_BUTTON_BUTTON_VALUE_HELD,
    CAP_ENUM_BUTTON_BUTTON_VALUE_DOUBLE,
    CAP_ENUM_BUTTON_BUTTON_VALUE_PUSHED_2X,
    CAP_ENUM_BUTTON_BUTTON_VALUE_PUSHED_3X,
    CAP_ENUM_BUTTON_BUTTON_VALUE_PUSHED_4X,
    CAP_ENUM_BUTTON_BUTTON_VALUE_PUSHED_5X,
    CAP_ENUM_BUTTON_BUTTON_VALUE_PUSHED_6X,
    CAP_ENUM_BUTTON_BUTTON_VALUE_DOWN,
    CAP_ENUM_BUTTON_BUTTON_VALUE_DOWN_2X,
    CAP_ENUM_BUTTON_BUTTON_VALUE_DOWN_3X,
    CAP_ENUM_BUTTON_BUTTON_VALUE_DOWN_4X,
    CAP_ENUM_BUTTON_BUTTON_VALUE_DOWN_5X,
    CAP_ENUM_BUTTON_BUTTON_VALUE_DOWN_6X,
    CAP_ENUM_BUTTON_BUTTON_VALUE_DOWN_HOLD,
    CAP_ENUM_BUTTON_BUTTON_VALUE_UP,
    CAP_ENUM_BUTTON_BUTTON_VALUE_UP_2X,
    CAP_ENUM_BUTTON_BUTTON_VALUE_UP_3X,
    CAP_ENUM_BUTTON_BUTTON_VALUE_UP_4X,
    CAP_ENUM_BUTTON_BUTTON_VALUE_UP_5X,
    CAP_ENUM_BUTTON_BUTTON_VALUE_UP_6X,
    CAP_ENUM_BUTTON_BUTTON_VALUE_UP_HOLD,
    CAP_ENUM_BUTTON_BUTTON_VALUE_MAX
};

const static struct iot_caps_button {
    const char *id;
    const struct button_attr_supportedButtonValues {
        const char *name;
        const unsigned char property;
        const unsigned char value_type;
        const char *values[CAP_ENUM_BUTTON_SUPPORTEDBUTTONVALUES_VALUE_MAX];
    } attr_supportedButtonValues;
    const struct button_attr_button {
        const char *name;
        const unsigned char property;
        const unsigned char value_type;
        const char *values[CAP_ENUM_BUTTON_BUTTON_VALUE_MAX];
    } attr_button;
    const struct button_attr_numberOfButtons {
        const char *name;
        const unsigned char property;
        const unsigned char value_type;
        const int min;
    } attr_numberOfButtons;
} caps_helper_button = {
    .id = "button",
    .attr_supportedButtonValues = {
        .name = "supportedButtonValues",
        .property = ATTR_SET_VALUE_ARRAY,
        .value_type = VALUE_TYPE_STRING,
        .values = {"pushed", "held", "double", "pushed_2x", "pushed_3x", "pushed_4x", "pushed_5x", "pushed_6x", "down", "down_2x", "down_3x", "down_4x", "down_5x", "down_6x", "down_hold", "up", "up_2x", "up_3x", "up_4x", "up_5x", "up_6x", "up_hold"},
    },
    .attr_button = {
        .name = "button",
        .property = ATTR_SET_VALUE_REQUIRED,
        .value_type = VALUE_TYPE_STRING,
        .values = {"pushed", "held", "double", "pushed_2x", "pushed_3x", "pushed_4x", "pushed_5x", "pushed_6x", "down", "down_2x", "down_3x", "down_4x", "down_5x", "down_6x", "down_hold", "up", "up_2x", "up_3x", "up_4x", "up_5x", "up_6x", "up_hold"},
    },
    .attr_numberOfButtons = {
        .name = "numberOfButtons",
        .property = ATTR_SET_VALUE_MIN | ATTR_SET_VALUE_REQUIRED,
        .value_type = VALUE_TYPE_INTEGER,
        .min = 0,
    },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_BUTTON_ */
