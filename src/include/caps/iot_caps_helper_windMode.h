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

#ifndef _IOT_CAPS_HELPER_WIND_MODE_
#define _IOT_CAPS_HELPER_WIND_MODE_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_WINDMODE_WINDMODE_VALUE_NOWIND,
    CAP_ENUM_WINDMODE_WINDMODE_VALUE_SLEEPWIND,
    CAP_ENUM_WINDMODE_WINDMODE_VALUE_NATURALWIND,
    CAP_ENUM_WINDMODE_WINDMODE_VALUE_MAX
};

#define CAP_ENUM_WINDMODE_SUPPORTEDWINDMODES_VALUE_MAX CAP_ENUM_WINDMODE_WINDMODE_VALUE_MAX

const static struct iot_caps_windMode {
    const char *id;
    const struct windMode_attr_supportedWindModes {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_WINDMODE_SUPPORTEDWINDMODES_VALUE_MAX];
        const char *value_noWind;
        const char *value_sleepWind;
        const char *value_naturalWind;
    } attr_supportedWindModes;
    const struct windMode_attr_windMode {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_WINDMODE_WINDMODE_VALUE_MAX];
        const char *value_noWind;
        const char *value_sleepWind;
        const char *value_naturalWind;
    } attr_windMode;
    const struct windMode_cmd_setWindMode {
        const char *name;
    } cmd_setWindMode;
} caps_helper_windMode = {
    .id = "windMode",
    .attr_supportedWindModes =
        {
            .name = "supportedWindModes",
            .property = ATTR_SET_VALUE_ARRAY,
            .valueType = VALUE_TYPE_STRING,
            .values = {"noWind", "sleepWind", "naturalWind"},
            .value_noWind = "noWind",
            .value_sleepWind = "sleepWind",
            .value_naturalWind = "naturalWind",
        },
    .attr_windMode =
        {
            .name = "windMode",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"noWind", "sleepWind", "naturalWind"},
            .value_noWind = "noWind",
            .value_sleepWind = "sleepWind",
            .value_naturalWind = "naturalWind",
        },
    .cmd_setWindMode = {.name = "setWindMode"},  // arguments: windMode(string)
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_WIND_MODE_ */
