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

#ifndef _IOT_CAPS_HELPER_ROBOT_CLEANER_MOVEMENT_
#define _IOT_CAPS_HELPER_ROBOT_CLEANER_MOVEMENT_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_ROBOTCLEANERMOVEMENT_ROBOTCLEANERMOVEMENT_VALUE_HOMING,
    CAP_ENUM_ROBOTCLEANERMOVEMENT_ROBOTCLEANERMOVEMENT_VALUE_IDLE,
    CAP_ENUM_ROBOTCLEANERMOVEMENT_ROBOTCLEANERMOVEMENT_VALUE_CHARGING,
    CAP_ENUM_ROBOTCLEANERMOVEMENT_ROBOTCLEANERMOVEMENT_VALUE_ALARM,
    CAP_ENUM_ROBOTCLEANERMOVEMENT_ROBOTCLEANERMOVEMENT_VALUE_POWEROFF,
    CAP_ENUM_ROBOTCLEANERMOVEMENT_ROBOTCLEANERMOVEMENT_VALUE_RESERVE,
    CAP_ENUM_ROBOTCLEANERMOVEMENT_ROBOTCLEANERMOVEMENT_VALUE_POINT,
    CAP_ENUM_ROBOTCLEANERMOVEMENT_ROBOTCLEANERMOVEMENT_VALUE_AFTER,
    CAP_ENUM_ROBOTCLEANERMOVEMENT_ROBOTCLEANERMOVEMENT_VALUE_CLEANING,
    CAP_ENUM_ROBOTCLEANERMOVEMENT_ROBOTCLEANERMOVEMENT_VALUE_PAUSE,
    CAP_ENUM_ROBOTCLEANERMOVEMENT_ROBOTCLEANERMOVEMENT_VALUE_MAX
};

const static struct iot_caps_robotCleanerMovement {
    const char *id;
    const struct robotCleanerMovement_attr_robotCleanerMovement {
        const char *name;
        const unsigned char property;
        const unsigned char value_type;
        const char *values[CAP_ENUM_ROBOTCLEANERMOVEMENT_ROBOTCLEANERMOVEMENT_VALUE_MAX];
    } attr_robotCleanerMovement;
    const struct robotCleanerMovement_cmd_setRobotCleanerMovement { const char* name; } cmd_setRobotCleanerMovement;
} caps_helper_robotCleanerMovement = {
    .id = "robotCleanerMovement",
    .attr_robotCleanerMovement = {
        .name = "robotCleanerMovement",
        .property = ATTR_SET_VALUE_REQUIRED,
        .value_type = VALUE_TYPE_STRING,
        .values = {"homing", "idle", "charging", "alarm", "powerOff", "reserve", "point", "after", "cleaning", "pause"},
    },
    .cmd_setRobotCleanerMovement = { .name = "setRobotCleanerMovement" }, // arguments: mode(string) 
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_ROBOT_CLEANER_MOVEMENT_ */
