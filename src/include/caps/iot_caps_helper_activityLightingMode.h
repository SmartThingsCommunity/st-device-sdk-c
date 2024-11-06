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

#ifndef _IOT_CAPS_HELPER_ACTIVITY_LIGHTING_MODE_
#define _IOT_CAPS_HELPER_ACTIVITY_LIGHTING_MODE_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_ACTIVITYLIGHTINGMODE_LIGHTINGMODE_VALUE_READING,
    CAP_ENUM_ACTIVITYLIGHTINGMODE_LIGHTINGMODE_VALUE_WRITING,
    CAP_ENUM_ACTIVITYLIGHTINGMODE_LIGHTINGMODE_VALUE_COMPUTER,
    CAP_ENUM_ACTIVITYLIGHTINGMODE_LIGHTINGMODE_VALUE_NIGHT,
    CAP_ENUM_ACTIVITYLIGHTINGMODE_LIGHTINGMODE_VALUE_SLEEPPREPARATION,
    CAP_ENUM_ACTIVITYLIGHTINGMODE_LIGHTINGMODE_VALUE_DAY,
    CAP_ENUM_ACTIVITYLIGHTINGMODE_LIGHTINGMODE_VALUE_COZY,
    CAP_ENUM_ACTIVITYLIGHTINGMODE_LIGHTINGMODE_VALUE_SOFT,
    CAP_ENUM_ACTIVITYLIGHTINGMODE_LIGHTINGMODE_VALUE_MAX
};

const static struct iot_caps_activityLightingMode {
    const char *id;
    const struct activityLightingMode_attr_lightingMode {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_ACTIVITYLIGHTINGMODE_LIGHTINGMODE_VALUE_MAX];
        const char *value_reading;
        const char *value_writing;
        const char *value_computer;
        const char *value_night;
        const char *value_sleepPreparation;
        const char *value_day;
        const char *value_cozy;
        const char *value_soft;
    } attr_lightingMode;
    const struct activityLightingMode_cmd_setLightingMode { const char* name; } cmd_setLightingMode;
} caps_helper_activityLightingMode = {
    .id = "activityLightingMode",
    .attr_lightingMode = {
        .name = "lightingMode",
        .property = ATTR_SET_VALUE_REQUIRED,
        .valueType = VALUE_TYPE_STRING,
        .values = {"reading", "writing", "computer", "night", "sleepPreparation", "day", "cozy", "soft"},
        .value_reading = "reading",
        .value_writing = "writing",
        .value_computer = "computer",
        .value_night = "night",
        .value_sleepPreparation = "sleepPreparation",
        .value_day = "day",
        .value_cozy = "cozy",
        .value_soft = "soft",
    },
    .cmd_setLightingMode = { .name = "setLightingMode" }, // arguments: lightingMode(string) 
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_ACTIVITY_LIGHTING_MODE_ */
