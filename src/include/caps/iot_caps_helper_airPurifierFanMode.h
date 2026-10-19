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

#ifndef _IOT_CAPS_HELPER_AIR_PURIFIER_FAN_MODE_
#define _IOT_CAPS_HELPER_AIR_PURIFIER_FAN_MODE_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_AIRPURIFIERFANMODE_AIRPURIFIERFANMODE_VALUE_AUTO,
    CAP_ENUM_AIRPURIFIERFANMODE_AIRPURIFIERFANMODE_VALUE_SLEEP,
    CAP_ENUM_AIRPURIFIERFANMODE_AIRPURIFIERFANMODE_VALUE_LOW,
    CAP_ENUM_AIRPURIFIERFANMODE_AIRPURIFIERFANMODE_VALUE_MEDIUM,
    CAP_ENUM_AIRPURIFIERFANMODE_AIRPURIFIERFANMODE_VALUE_HIGH,
    CAP_ENUM_AIRPURIFIERFANMODE_AIRPURIFIERFANMODE_VALUE_QUIET,
    CAP_ENUM_AIRPURIFIERFANMODE_AIRPURIFIERFANMODE_VALUE_WINDFREE,
    CAP_ENUM_AIRPURIFIERFANMODE_AIRPURIFIERFANMODE_VALUE_OFF,
    CAP_ENUM_AIRPURIFIERFANMODE_AIRPURIFIERFANMODE_VALUE_MAX
};

#define CAP_ENUM_AIRPURIFIERFANMODE_SUPPORTEDAIRPURIFIERFANMODES_VALUE_MAX \
    CAP_ENUM_AIRPURIFIERFANMODE_AIRPURIFIERFANMODE_VALUE_MAX

const static struct iot_caps_airPurifierFanMode {
    const char *id;
    const struct airPurifierFanMode_attr_supportedAirPurifierFanModes {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_AIRPURIFIERFANMODE_SUPPORTEDAIRPURIFIERFANMODES_VALUE_MAX];
        const char *value_auto;
        const char *value_sleep;
        const char *value_low;
        const char *value_medium;
        const char *value_high;
        const char *value_quiet;
        const char *value_windFree;
        const char *value_off;
    } attr_supportedAirPurifierFanModes;
    const struct airPurifierFanMode_attr_airPurifierFanMode {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_AIRPURIFIERFANMODE_AIRPURIFIERFANMODE_VALUE_MAX];
        const char *value_auto;
        const char *value_sleep;
        const char *value_low;
        const char *value_medium;
        const char *value_high;
        const char *value_quiet;
        const char *value_windFree;
        const char *value_off;
    } attr_airPurifierFanMode;
    const struct airPurifierFanMode_cmd_setAirPurifierFanMode {
        const char *name;
    } cmd_setAirPurifierFanMode;
} caps_helper_airPurifierFanMode = {
    .id = "airPurifierFanMode",
    .attr_supportedAirPurifierFanModes =
        {
            .name = "supportedAirPurifierFanModes",
            .property = ATTR_SET_VALUE_ARRAY,
            .valueType = VALUE_TYPE_STRING,
            .values = {"auto", "sleep", "low", "medium", "high", "quiet", "windFree", "off"},
            .value_auto = "auto",
            .value_sleep = "sleep",
            .value_low = "low",
            .value_medium = "medium",
            .value_high = "high",
            .value_quiet = "quiet",
            .value_windFree = "windFree",
            .value_off = "off",
        },
    .attr_airPurifierFanMode =
        {
            .name = "airPurifierFanMode",
            .property = 0,
            .valueType = VALUE_TYPE_STRING,
            .values = {"auto", "sleep", "low", "medium", "high", "quiet", "windFree", "off"},
            .value_auto = "auto",
            .value_sleep = "sleep",
            .value_low = "low",
            .value_medium = "medium",
            .value_high = "high",
            .value_quiet = "quiet",
            .value_windFree = "windFree",
            .value_off = "off",
        },
    .cmd_setAirPurifierFanMode = {.name = "setAirPurifierFanMode"},  // arguments: airPurifierFanMode(string)
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_AIR_PURIFIER_FAN_MODE_ */
