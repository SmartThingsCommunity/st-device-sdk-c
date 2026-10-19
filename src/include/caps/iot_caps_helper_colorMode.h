/* ***************************************************************************
 *
 * Copyright 2019-2026 Samsung Electronics All Rights Reserved.
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

#ifndef _IOT_CAPS_HELPER_COLOR_MODE_
#define _IOT_CAPS_HELPER_COLOR_MODE_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_COLORMODE_COLORMODE_VALUE_COLOR,
    CAP_ENUM_COLORMODE_COLORMODE_VALUE_COLORTEMPERATURE,
    CAP_ENUM_COLORMODE_COLORMODE_VALUE_OTHER,
    CAP_ENUM_COLORMODE_COLORMODE_VALUE_MAX
};

const static struct iot_caps_colorMode {
    const char *id;
    const struct colorMode_attr_colorMode {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_COLORMODE_COLORMODE_VALUE_MAX];
        const char *value_color;
        const char *value_colorTemperature;
        const char *value_other;
    } attr_colorMode;
} caps_helper_colorMode = {
    .id = "colorMode",
    .attr_colorMode =
        {
            .name = "colorMode",
            .property = 0,
            .valueType = VALUE_TYPE_STRING,
            .values = {"color", "colorTemperature", "other"},
            .value_color = "color",
            .value_colorTemperature = "colorTemperature",
            .value_other = "other",
        },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_COLOR_MODE_ */
