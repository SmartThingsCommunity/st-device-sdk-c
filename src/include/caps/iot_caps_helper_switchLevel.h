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

#ifndef _IOT_CAPS_HELPER_SWITCH_LEVEL_
#define _IOT_CAPS_HELPER_SWITCH_LEVEL_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_SWITCHLEVEL_LEVEL_UNIT_PERCENT,
    CAP_ENUM_SWITCHLEVEL_LEVEL_UNIT_MAX
};

const static struct iot_caps_switchLevel {
    const char *id;
    const struct switchLevel_attr_level {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *units[CAP_ENUM_SWITCHLEVEL_LEVEL_UNIT_MAX];
        const char *unit_percent;
        const int min;
        const int max;
    } attr_level;
    const struct switchLevel_cmd_setLevel { const char* name; } cmd_setLevel;
} caps_helper_switchLevel = {
    .id = "switchLevel",
    .attr_level = {
        .name = "level",
        .property = ATTR_SET_VALUE_MIN | ATTR_SET_VALUE_MAX | ATTR_SET_VALUE_REQUIRED,
        .valueType = VALUE_TYPE_INTEGER,
        .units = {"%"},
        .unit_percent = "%",
        .min = 0,
        .max = 100,
    },
    .cmd_setLevel = { .name = "setLevel" }, // arguments: level(integer) rate(integer) 
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_SWITCH_LEVEL_ */
