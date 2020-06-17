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

#ifndef _IOT_CAPS_HELPER_FAN_OSCILLATION_MODE_
#define _IOT_CAPS_HELPER_FAN_OSCILLATION_MODE_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_FANOSCILLATIONMODE_FANOSCILLATIONMODE_VALUE_FIXED,
    CAP_ENUM_FANOSCILLATIONMODE_FANOSCILLATIONMODE_VALUE_VERTICAL,
    CAP_ENUM_FANOSCILLATIONMODE_FANOSCILLATIONMODE_VALUE_HORIZONTAL,
    CAP_ENUM_FANOSCILLATIONMODE_FANOSCILLATIONMODE_VALUE_ALL,
    CAP_ENUM_FANOSCILLATIONMODE_FANOSCILLATIONMODE_VALUE_INDIRECT,
    CAP_ENUM_FANOSCILLATIONMODE_FANOSCILLATIONMODE_VALUE_DIRECT,
    CAP_ENUM_FANOSCILLATIONMODE_FANOSCILLATIONMODE_VALUE_FIXEDCENTER,
    CAP_ENUM_FANOSCILLATIONMODE_FANOSCILLATIONMODE_VALUE_FIXEDLEFT,
    CAP_ENUM_FANOSCILLATIONMODE_FANOSCILLATIONMODE_VALUE_FIXEDRIGHT,
    CAP_ENUM_FANOSCILLATIONMODE_FANOSCILLATIONMODE_VALUE_FAR,
    CAP_ENUM_FANOSCILLATIONMODE_FANOSCILLATIONMODE_VALUE_MAX
};

const static struct iot_caps_fanOscillationMode {
    const char *id;
    const struct fanOscillationMode_attr_fanOscillationMode {
        const char *name;
        const unsigned char property;
        const unsigned char value_type;
        const char *values[CAP_ENUM_FANOSCILLATIONMODE_FANOSCILLATIONMODE_VALUE_MAX];
    } attr_fanOscillationMode;
    const struct fanOscillationMode_cmd_setFanOscillationMode { const char* name; } cmd_setFanOscillationMode;
} caps_helper_fanOscillationMode = {
    .id = "fanOscillationMode",
    .attr_fanOscillationMode = {
        .name = "fanOscillationMode",
        .property = NULL,
        .value_type = VALUE_TYPE_STRING,
        .values = {"fixed", "vertical", "horizontal", "all", "indirect", "direct", "fixedCenter", "fixedLeft", "fixedRight", "far"},
    },
    .cmd_setFanOscillationMode = { .name = "setFanOscillationMode" }, // arguments: fanOscillationMode(string) 
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_FAN_OSCILLATION_MODE_ */
