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

#ifndef _IOT_CAPS_HELPER_SECURITY_SYSTEM_
#define _IOT_CAPS_HELPER_SECURITY_SYSTEM_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_SECURITYSYSTEM_SECURITYSYSTEMSTATUS_VALUE_ARMEDAWAY,
    CAP_ENUM_SECURITYSYSTEM_SECURITYSYSTEMSTATUS_VALUE_ARMEDSTAY,
    CAP_ENUM_SECURITYSYSTEM_SECURITYSYSTEMSTATUS_VALUE_DISARMED,
    CAP_ENUM_SECURITYSYSTEM_SECURITYSYSTEMSTATUS_VALUE_MAX
};

const static struct iot_caps_securitySystem {
    const char *id;
    const struct securitySystem_attr_alarm {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const unsigned int max_length;
    } attr_alarm;
    const struct securitySystem_attr_securitySystemStatus {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_SECURITYSYSTEM_SECURITYSYSTEMSTATUS_VALUE_MAX];
        const char *value_armedAway;
        const char *value_armedStay;
        const char *value_disarmed;
    } attr_securitySystemStatus;
    const struct securitySystem_cmd_armStay { const char* name; } cmd_armStay;
    const struct securitySystem_cmd_disarm { const char* name; } cmd_disarm;
    const struct securitySystem_cmd_armAway { const char* name; } cmd_armAway;
} caps_helper_securitySystem = {
    .id = "securitySystem",
    .attr_alarm = {
        .name = "alarm",
        .property = ATTR_SET_VALUE_REQUIRED | ATTR_SET_MAX_LENGTH,
        .valueType = VALUE_TYPE_STRING,
        .max_length = 255,
    },
    .attr_securitySystemStatus = {
        .name = "securitySystemStatus",
        .property = ATTR_SET_VALUE_REQUIRED,
        .valueType = VALUE_TYPE_STRING,
        .values = {"armedAway", "armedStay", "disarmed"},
        .value_armedAway = "armedAway",
        .value_armedStay = "armedStay",
        .value_disarmed = "disarmed",
    },
    .cmd_armStay = { .name = "armStay" }, // arguments: bypassAll(boolean) 
    .cmd_disarm = { .name = "disarm" },
    .cmd_armAway = { .name = "armAway" }, // arguments: bypassAll(boolean) 
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_SECURITY_SYSTEM_ */
