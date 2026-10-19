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

#ifndef _IOT_CAPS_HELPER_ELEVATOR_CALL_
#define _IOT_CAPS_HELPER_ELEVATOR_CALL_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_ELEVATORCALL_CALLSTATUS_VALUE_CALLED,
    CAP_ENUM_ELEVATORCALL_CALLSTATUS_VALUE_STANDBY,
    CAP_ENUM_ELEVATORCALL_CALLSTATUS_VALUE_UNKNOWN,
    CAP_ENUM_ELEVATORCALL_CALLSTATUS_VALUE_MAX
};

const static struct iot_caps_elevatorCall {
    const char *id;
    const struct elevatorCall_attr_callStatus {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_ELEVATORCALL_CALLSTATUS_VALUE_MAX];
        const char *value_called;
        const char *value_standby;
        const char *value_unknown;
    } attr_callStatus;
    const struct elevatorCall_cmd_call {
        const char *name;
    } cmd_call;
} caps_helper_elevatorCall = {
    .id = "elevatorCall",
    .attr_callStatus =
        {
            .name = "callStatus",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"called", "standby", "unknown"},
            .value_called = "called",
            .value_standby = "standby",
            .value_unknown = "unknown",
        },
    .cmd_call = {.name = "call"},
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_ELEVATOR_CALL_ */
