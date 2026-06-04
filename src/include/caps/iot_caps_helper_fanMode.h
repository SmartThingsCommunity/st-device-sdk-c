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

#ifndef _IOT_CAPS_HELPER_FAN_MODE_
#define _IOT_CAPS_HELPER_FAN_MODE_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_FANMODE_FANMODE_VALUE_AUTO,
    CAP_ENUM_FANMODE_FANMODE_VALUE_LOW,
    CAP_ENUM_FANMODE_FANMODE_VALUE_MEDIUM,
    CAP_ENUM_FANMODE_FANMODE_VALUE_HIGH,
    CAP_ENUM_FANMODE_FANMODE_VALUE_OFF,
    CAP_ENUM_FANMODE_FANMODE_VALUE_TURBO,
    CAP_ENUM_FANMODE_FANMODE_VALUE_MAX
};

enum {
    CAP_ENUM_FANMODE_SUPPORTEDFANMODES_VALUE_AUTO,
    CAP_ENUM_FANMODE_SUPPORTEDFANMODES_VALUE_LOW,
    CAP_ENUM_FANMODE_SUPPORTEDFANMODES_VALUE_MEDIUM,
    CAP_ENUM_FANMODE_SUPPORTEDFANMODES_VALUE_HIGH,
    CAP_ENUM_FANMODE_SUPPORTEDFANMODES_VALUE_OFF,
    CAP_ENUM_FANMODE_SUPPORTEDFANMODES_VALUE_TURBO,
    CAP_ENUM_FANMODE_SUPPORTEDFANMODES_VALUE_MAX
};

const static struct iot_caps_fanMode {
    const char *id;
    const struct fanMode_attr_fanMode {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_FANMODE_FANMODE_VALUE_MAX];
        const char *value_auto;
        const char *value_low;
        const char *value_medium;
        const char *value_high;
        const char *value_off;
        const char *value_turbo;
    } attr_fanMode;
    const struct fanMode_attr_supportedFanModes {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_FANMODE_SUPPORTEDFANMODES_VALUE_MAX];
        const char *value_auto;
        const char *value_low;
        const char *value_medium;
        const char *value_high;
        const char *value_off;
        const char *value_turbo;
    } attr_supportedFanModes;
    const struct fanMode_cmd_setFanMode {
        const char *name;
    } cmd_setFanMode;
} caps_helper_fanMode = {
    .id = "fanMode",
    .attr_fanMode =
        {
            .name = "fanMode",
            .property = 0,
            .valueType = VALUE_TYPE_STRING,
            .values = {"auto", "low", "medium", "high", "off", "turbo"},
            .value_auto = "auto",
            .value_low = "low",
            .value_medium = "medium",
            .value_high = "high",
            .value_off = "off",
            .value_turbo = "turbo",
        },
    .attr_supportedFanModes =
        {
            .name = "supportedFanModes",
            .property = ATTR_SET_VALUE_ARRAY,
            .valueType = VALUE_TYPE_STRING,
            .values = {"auto", "low", "medium", "high", "off", "turbo"},
            .value_auto = "auto",
            .value_low = "low",
            .value_medium = "medium",
            .value_high = "high",
            .value_off = "off",
            .value_turbo = "turbo",
        },
    .cmd_setFanMode = {.name = "setFanMode"},  // arguments: fanMode(string)
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_FAN_MODE_ */
