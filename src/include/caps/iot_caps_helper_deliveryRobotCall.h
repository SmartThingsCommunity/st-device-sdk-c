/* ***************************************************************************
 *
 * Copyright 2026 Samsung Electronics All Rights Reserved.
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

#ifndef _IOT_CAPS_HELPER_DELIVERY_ROBOT_CALL_
#define _IOT_CAPS_HELPER_DELIVERY_ROBOT_CALL_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_DELIVERYROBOTCALL_ROBOTSTATE_VALUE_AVAILABLE,
    CAP_ENUM_DELIVERYROBOTCALL_ROBOTSTATE_VALUE_USING,
    CAP_ENUM_DELIVERYROBOTCALL_ROBOTSTATE_VALUE_ERROR,
    CAP_ENUM_DELIVERYROBOTCALL_ROBOTSTATE_VALUE_CALLED,
    CAP_ENUM_DELIVERYROBOTCALL_ROBOTSTATE_VALUE_CALLFAILED,
    CAP_ENUM_DELIVERYROBOTCALL_ROBOTSTATE_VALUE_MAX
};

enum {
    CAP_ENUM_DELIVERYROBOTCALL_SUPPORTEDROBOTSTATES_VALUE_AVAILABLE,
    CAP_ENUM_DELIVERYROBOTCALL_SUPPORTEDROBOTSTATES_VALUE_USING,
    CAP_ENUM_DELIVERYROBOTCALL_SUPPORTEDROBOTSTATES_VALUE_ERROR,
    CAP_ENUM_DELIVERYROBOTCALL_SUPPORTEDROBOTSTATES_VALUE_CALLED,
    CAP_ENUM_DELIVERYROBOTCALL_SUPPORTEDROBOTSTATES_VALUE_CALLFAILED,
    CAP_ENUM_DELIVERYROBOTCALL_SUPPORTEDROBOTSTATES_VALUE_MAX
};

enum {
    CAP_ENUM_DELIVERYROBOTCALL_SUPPORTEDROBOTCOMMANDS_VALUE_CALL,
    CAP_ENUM_DELIVERYROBOTCALL_SUPPORTEDROBOTCOMMANDS_VALUE_CANCEL,
    CAP_ENUM_DELIVERYROBOTCALL_SUPPORTEDROBOTCOMMANDS_VALUE_MAX
};

const static struct iot_caps_deliveryRobotCall {
    const char *id;
    const struct deliveryRobotCall_attr_robotState {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_DELIVERYROBOTCALL_ROBOTSTATE_VALUE_MAX];
        const char *value_available;
        const char *value_using;
        const char *value_error;
        const char *value_called;
        const char *value_callFailed;
    } attr_robotState;
    const struct deliveryRobotCall_attr_supportedRobotStates {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_DELIVERYROBOTCALL_SUPPORTEDROBOTSTATES_VALUE_MAX];
        const char *value_available;
        const char *value_using;
        const char *value_error;
        const char *value_called;
        const char *value_callFailed;
    } attr_supportedRobotStates;
    const struct deliveryRobotCall_attr_supportedRobotCommands {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_DELIVERYROBOTCALL_SUPPORTEDROBOTCOMMANDS_VALUE_MAX];
        const char *value_call;
        const char *value_cancel;
    } attr_supportedRobotCommands;
    const struct deliveryRobotCall_cmd_call {
        const char *name;
    } cmd_call;
    const struct deliveryRobotCall_cmd_cancel {
        const char *name;
    } cmd_cancel;
} caps_helper_deliveryRobotCall = {
    .id = "deliveryRobotCall",
    .attr_robotState =
        {
            .name = "robotState",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"available", "using", "error", "called", "callFailed"},
            .value_available = "available",
            .value_using = "using",
            .value_error = "error",
            .value_called = "called",
            .value_callFailed = "callFailed",
        },
    .attr_supportedRobotStates =
        {
            .name = "supportedRobotStates",
            .property = ATTR_SET_VALUE_ARRAY,
            .valueType = VALUE_TYPE_STRING,
            .values = {"available", "using", "error", "called", "callFailed"},
            .value_available = "available",
            .value_using = "using",
            .value_error = "error",
            .value_called = "called",
            .value_callFailed = "callFailed",
        },
    .attr_supportedRobotCommands =
        {
            .name = "supportedRobotCommands",
            .property = ATTR_SET_VALUE_ARRAY,
            .valueType = VALUE_TYPE_STRING,
            .values = {"call", "cancel"},
            .value_call = "call",
            .value_cancel = "cancel",
        },
    .cmd_call = {.name = "call"},
    .cmd_cancel = {.name = "cancel"},
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_DELIVERY_ROBOT_CALL_ */
