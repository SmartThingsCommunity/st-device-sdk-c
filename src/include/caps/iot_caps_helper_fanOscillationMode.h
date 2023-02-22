/* ***************************************************************************
 *
 * Copyright 2019-2021 Samsung Electronics All Rights Reserved.
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

#define CAP_ENUM_FANOSCILLATIONMODE_SUPPORTEDFANOSCILLATIONMODES_VALUE_MAX 16
enum {
    CAP_ENUM_FANOSCILLATIONMODE_FANOSCILLATIONMODE_VALUE_OFF,
    CAP_ENUM_FANOSCILLATIONMODE_FANOSCILLATIONMODE_VALUE_INDIVIDUAL,
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
    CAP_ENUM_FANOSCILLATIONMODE_FANOSCILLATIONMODE_VALUE_WIDE,
    CAP_ENUM_FANOSCILLATIONMODE_FANOSCILLATIONMODE_VALUE_MID,
    CAP_ENUM_FANOSCILLATIONMODE_FANOSCILLATIONMODE_VALUE_SPOT,
    CAP_ENUM_FANOSCILLATIONMODE_FANOSCILLATIONMODE_VALUE_SWING,
    CAP_ENUM_FANOSCILLATIONMODE_FANOSCILLATIONMODE_VALUE_MAX
};

const static struct iot_caps_fanOscillationMode {
    const char *id;
    const struct fanOscillationMode_attr_supportedFanOscillationModes {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_FANOSCILLATIONMODE_SUPPORTEDFANOSCILLATIONMODES_VALUE_MAX];
        const char *value_off;
        const char *value_individual;
        const char *value_fixed;
        const char *value_vertical;
        const char *value_horizontal;
        const char *value_all;
        const char *value_indirect;
        const char *value_direct;
        const char *value_fixedCenter;
        const char *value_fixedLeft;
        const char *value_fixedRight;
        const char *value_far;
        const char *value_wide;
        const char *value_mid;
        const char *value_spot;
        const char *value_swing;
    } attr_supportedFanOscillationModes;
    const struct fanOscillationMode_attr_fanOscillationMode {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_FANOSCILLATIONMODE_FANOSCILLATIONMODE_VALUE_MAX];
        const char *value_off;
        const char *value_individual;
        const char *value_fixed;
        const char *value_vertical;
        const char *value_horizontal;
        const char *value_all;
        const char *value_indirect;
        const char *value_direct;
        const char *value_fixedCenter;
        const char *value_fixedLeft;
        const char *value_fixedRight;
        const char *value_far;
        const char *value_wide;
        const char *value_mid;
        const char *value_spot;
        const char *value_swing;
    } attr_fanOscillationMode;
    const struct fanOscillationMode_cmd_setFanOscillationMode { const char* name; } cmd_setFanOscillationMode;
} caps_helper_fanOscillationMode = {
    .id = "fanOscillationMode",
    .attr_supportedFanOscillationModes = {
        .name = "supportedFanOscillationModes",
        .property = ATTR_SET_VALUE_REQUIRED | ATTR_SET_VALUE_ARRAY,
        .valueType = VALUE_TYPE_STRING,
        .values = {"'off'", "individual", "fixed", "vertical", "horizontal", "all", "indirect", "direct", "fixedCenter", "fixedLeft", "fixedRight", "far", "wide", "mid", "spot", "swing"},
        .value_off = "'off'",
        .value_individual = "individual",
        .value_fixed = "fixed",
        .value_vertical = "vertical",
        .value_horizontal = "horizontal",
        .value_all = "all",
        .value_indirect = "indirect",
        .value_direct = "direct",
        .value_fixedCenter = "fixedCenter",
        .value_fixedLeft = "fixedLeft",
        .value_fixedRight = "fixedRight",
        .value_far = "far",
        .value_wide = "wide",
        .value_mid = "mid",
        .value_spot = "spot",
        .value_swing = "swing",
    },
    .attr_fanOscillationMode = {
        .name = "fanOscillationMode",
        .property = 0,
        .valueType = VALUE_TYPE_STRING,
        .values = {"'off'", "individual", "fixed", "vertical", "horizontal", "all", "indirect", "direct", "fixedCenter", "fixedLeft", "fixedRight", "far", "wide", "mid", "spot", "swing"},
        .value_off = "'off'",
        .value_individual = "individual",
        .value_fixed = "fixed",
        .value_vertical = "vertical",
        .value_horizontal = "horizontal",
        .value_all = "all",
        .value_indirect = "indirect",
        .value_direct = "direct",
        .value_fixedCenter = "fixedCenter",
        .value_fixedLeft = "fixedLeft",
        .value_fixedRight = "fixedRight",
        .value_far = "far",
        .value_wide = "wide",
        .value_mid = "mid",
        .value_spot = "spot",
        .value_swing = "swing",
    },
    .cmd_setFanOscillationMode = { .name = "setFanOscillationMode" }, // arguments: fanOscillationMode(string) 
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_FAN_OSCILLATION_MODE_ */
