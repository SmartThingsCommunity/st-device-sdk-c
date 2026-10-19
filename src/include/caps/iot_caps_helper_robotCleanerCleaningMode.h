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

#ifndef _IOT_CAPS_HELPER_ROBOT_CLEANER_CLEANING_MODE_
#define _IOT_CAPS_HELPER_ROBOT_CLEANER_CLEANING_MODE_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_ROBOTCLEANERCLEANINGMODE_ROBOTCLEANERCLEANINGMODE_VALUE_AUTO,
    CAP_ENUM_ROBOTCLEANERCLEANINGMODE_ROBOTCLEANERCLEANINGMODE_VALUE_PART,
    CAP_ENUM_ROBOTCLEANERCLEANINGMODE_ROBOTCLEANERCLEANINGMODE_VALUE_REPEAT,
    CAP_ENUM_ROBOTCLEANERCLEANINGMODE_ROBOTCLEANERCLEANINGMODE_VALUE_MANUAL,
    CAP_ENUM_ROBOTCLEANERCLEANINGMODE_ROBOTCLEANERCLEANINGMODE_VALUE_STOP,
    CAP_ENUM_ROBOTCLEANERCLEANINGMODE_ROBOTCLEANERCLEANINGMODE_VALUE_MAP,
    CAP_ENUM_ROBOTCLEANERCLEANINGMODE_ROBOTCLEANERCLEANINGMODE_VALUE_MAX
};

const static struct iot_caps_robotCleanerCleaningMode {
    const char *id;
    const struct robotCleanerCleaningMode_attr_robotCleanerCleaningMode {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_ROBOTCLEANERCLEANINGMODE_ROBOTCLEANERCLEANINGMODE_VALUE_MAX];
        const char *value_auto;
        const char *value_part;
        const char *value_repeat;
        const char *value_manual;
        const char *value_stop;
        const char *value_map;
    } attr_robotCleanerCleaningMode;
    const struct robotCleanerCleaningMode_cmd_setRobotCleanerCleaningMode {
        const char *name;
    } cmd_setRobotCleanerCleaningMode;
} caps_helper_robotCleanerCleaningMode = {
    .id = "robotCleanerCleaningMode",
    .attr_robotCleanerCleaningMode =
        {
            .name = "robotCleanerCleaningMode",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"auto", "part", "repeat", "manual", "stop", "map"},
            .value_auto = "auto",
            .value_part = "part",
            .value_repeat = "repeat",
            .value_manual = "manual",
            .value_stop = "stop",
            .value_map = "map",
        },
    .cmd_setRobotCleanerCleaningMode = {.name = "setRobotCleanerCleaningMode"},  // arguments: mode(string)
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_ROBOT_CLEANER_CLEANING_MODE_ */
