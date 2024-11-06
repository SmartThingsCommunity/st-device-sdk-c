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

#ifndef _IOT_CAPS_HELPER_RAPID_COOLING_
#define _IOT_CAPS_HELPER_RAPID_COOLING_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_RAPIDCOOLING_RAPIDCOOLING_VALUE_OFF,
    CAP_ENUM_RAPIDCOOLING_RAPIDCOOLING_VALUE_ON,
    CAP_ENUM_RAPIDCOOLING_RAPIDCOOLING_VALUE_MAX
};

const static struct iot_caps_rapidCooling {
    const char *id;
    const struct rapidCooling_attr_rapidCooling {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_RAPIDCOOLING_RAPIDCOOLING_VALUE_MAX];
        const char *value_off;
        const char *value_on;
    } attr_rapidCooling;
    const struct rapidCooling_cmd_setRapidCooling { const char* name; } cmd_setRapidCooling;
} caps_helper_rapidCooling = {
    .id = "rapidCooling",
    .attr_rapidCooling = {
        .name = "rapidCooling",
        .property = ATTR_SET_VALUE_REQUIRED,
        .valueType = VALUE_TYPE_STRING,
        .values = {"off", "on"},
        .value_off = "off",
        .value_on = "on",
    },
    .cmd_setRapidCooling = { .name = "setRapidCooling" }, // arguments: rapidCooling(string) 
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_RAPID_COOLING_ */
