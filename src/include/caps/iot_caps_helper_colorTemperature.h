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

#ifndef _IOT_CAPS_HELPER_COLOR_TEMPERATURE_
#define _IOT_CAPS_HELPER_COLOR_TEMPERATURE_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_COLORTEMPERATURE_COLORTEMPERATURE_UNIT_K,
    CAP_ENUM_COLORTEMPERATURE_COLORTEMPERATURE_UNIT_MAX
};

const static struct iot_caps_colorTemperature {
    const char *id;
    const struct colorTemperature_attr_colorTemperature {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *units[CAP_ENUM_COLORTEMPERATURE_COLORTEMPERATURE_UNIT_MAX];
        const char *unit_K;
        const int min;
        const int max;
    } attr_colorTemperature;
    const struct colorTemperature_cmd_setColorTemperature { const char* name; } cmd_setColorTemperature;
} caps_helper_colorTemperature = {
    .id = "colorTemperature",
    .attr_colorTemperature = {
        .name = "colorTemperature",
        .property = ATTR_SET_VALUE_MIN | ATTR_SET_VALUE_MAX | ATTR_SET_VALUE_REQUIRED,
        .valueType = VALUE_TYPE_INTEGER,
        .units = {"K"},
        .unit_K = "K",
        .min = 1,
        .max = 30000,
    },
    .cmd_setColorTemperature = { .name = "setColorTemperature" }, // arguments: temperature(integer) 
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_COLOR_TEMPERATURE_ */
