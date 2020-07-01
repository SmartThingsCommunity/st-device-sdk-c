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

#ifndef _IOT_CAPS_HELPER_ROBOT_CLEANER_TURBO_MODE_
#define _IOT_CAPS_HELPER_ROBOT_CLEANER_TURBO_MODE_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_ROBOTCLEANERTURBOMODE_ROBOTCLEANERTURBOMODE_VALUE_ON,
    CAP_ENUM_ROBOTCLEANERTURBOMODE_ROBOTCLEANERTURBOMODE_VALUE_OFF,
    CAP_ENUM_ROBOTCLEANERTURBOMODE_ROBOTCLEANERTURBOMODE_VALUE_SILENCE,
    CAP_ENUM_ROBOTCLEANERTURBOMODE_ROBOTCLEANERTURBOMODE_VALUE_MAX
};

const static struct iot_caps_robotCleanerTurboMode {
    const char *id;
    const struct robotCleanerTurboMode_attr_robotCleanerTurboMode {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_ROBOTCLEANERTURBOMODE_ROBOTCLEANERTURBOMODE_VALUE_MAX];
        const char *value_on;
        const char *value_off;
        const char *value_silence;
    } attr_robotCleanerTurboMode;
    const struct robotCleanerTurboMode_cmd_setRobotCleanerTurboMode { const char* name; } cmd_setRobotCleanerTurboMode;
} caps_helper_robotCleanerTurboMode = {
    .id = "robotCleanerTurboMode",
    .attr_robotCleanerTurboMode = {
        .name = "robotCleanerTurboMode",
        .property = ATTR_SET_VALUE_REQUIRED,
        .valueType = VALUE_TYPE_STRING,
        .values = {"on", "off", "silence"},
        .value_on = "on",
        .value_off = "off",
        .value_silence = "silence",
    },
    .cmd_setRobotCleanerTurboMode = { .name = "setRobotCleanerTurboMode" }, // arguments: mode(string) 
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_ROBOT_CLEANER_TURBO_MODE_ */
