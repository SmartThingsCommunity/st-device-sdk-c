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

#ifndef _IOT_CAPS_HELPER_DISHWASHER_OPERATING_STATE_
#define _IOT_CAPS_HELPER_DISHWASHER_OPERATING_STATE_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CAP_ENUM_DISHWASHEROPERATINGSTATE_SUPPORTEDMACHINESTATES_VALUE_MAX 3
enum {
    CAP_ENUM_DISHWASHEROPERATINGSTATE_MACHINESTATE_VALUE_PAUSE,
    CAP_ENUM_DISHWASHEROPERATINGSTATE_MACHINESTATE_VALUE_RUN,
    CAP_ENUM_DISHWASHEROPERATINGSTATE_MACHINESTATE_VALUE_STOP,
    CAP_ENUM_DISHWASHEROPERATINGSTATE_MACHINESTATE_VALUE_MAX
};

enum {
    CAP_ENUM_DISHWASHEROPERATINGSTATE_DISHWASHERJOBSTATE_VALUE_AIRWASH,
    CAP_ENUM_DISHWASHEROPERATINGSTATE_DISHWASHERJOBSTATE_VALUE_COOLING,
    CAP_ENUM_DISHWASHEROPERATINGSTATE_DISHWASHERJOBSTATE_VALUE_DRYING,
    CAP_ENUM_DISHWASHEROPERATINGSTATE_DISHWASHERJOBSTATE_VALUE_FINISH,
    CAP_ENUM_DISHWASHEROPERATINGSTATE_DISHWASHERJOBSTATE_VALUE_PREDRAIN,
    CAP_ENUM_DISHWASHEROPERATINGSTATE_DISHWASHERJOBSTATE_VALUE_PREWASH,
    CAP_ENUM_DISHWASHEROPERATINGSTATE_DISHWASHERJOBSTATE_VALUE_RINSE,
    CAP_ENUM_DISHWASHEROPERATINGSTATE_DISHWASHERJOBSTATE_VALUE_SPIN,
    CAP_ENUM_DISHWASHEROPERATINGSTATE_DISHWASHERJOBSTATE_VALUE_UNKNOWN,
    CAP_ENUM_DISHWASHEROPERATINGSTATE_DISHWASHERJOBSTATE_VALUE_WASH,
    CAP_ENUM_DISHWASHEROPERATINGSTATE_DISHWASHERJOBSTATE_VALUE_WRINKLEPREVENT,
    CAP_ENUM_DISHWASHEROPERATINGSTATE_DISHWASHERJOBSTATE_VALUE_MAX
};

const static struct iot_caps_dishwasherOperatingState {
    const char *id;
    const struct dishwasherOperatingState_attr_completionTime {
        const char *name;
        const unsigned char property;
        const unsigned char value_type;
    } attr_completionTime;
    const struct dishwasherOperatingState_attr_supportedMachineStates {
        const char *name;
        const unsigned char property;
        const unsigned char value_type;
        const char *values[CAP_ENUM_DISHWASHEROPERATINGSTATE_SUPPORTEDMACHINESTATES_VALUE_MAX];
    } attr_supportedMachineStates;
    const struct dishwasherOperatingState_attr_machineState {
        const char *name;
        const unsigned char property;
        const unsigned char value_type;
        const char *values[CAP_ENUM_DISHWASHEROPERATINGSTATE_MACHINESTATE_VALUE_MAX];
    } attr_machineState;
    const struct dishwasherOperatingState_attr_dishwasherJobState {
        const char *name;
        const unsigned char property;
        const unsigned char value_type;
        const char *values[CAP_ENUM_DISHWASHEROPERATINGSTATE_DISHWASHERJOBSTATE_VALUE_MAX];
    } attr_dishwasherJobState;
    const struct dishwasherOperatingState_cmd_setMachineState { const char* name; } cmd_setMachineState;
} caps_helper_dishwasherOperatingState = {
    .id = "dishwasherOperatingState",
    .attr_completionTime = {
        .name = "completionTime",
        .property = ATTR_SET_VALUE_REQUIRED,
        .value_type = VALUE_TYPE_STRING,
    },
    .attr_supportedMachineStates = {
        .name = "supportedMachineStates",
        .property = ATTR_SET_VALUE_REQUIRED | ATTR_SET_VALUE_ARRAY,
        .value_type = VALUE_TYPE_STRING,
        .values = {"pause", "run", "stop"},
    },
    .attr_machineState = {
        .name = "machineState",
        .property = ATTR_SET_VALUE_REQUIRED,
        .value_type = VALUE_TYPE_STRING,
        .values = {"pause", "run", "stop"},
    },
    .attr_dishwasherJobState = {
        .name = "dishwasherJobState",
        .property = ATTR_SET_VALUE_REQUIRED,
        .value_type = VALUE_TYPE_STRING,
        .values = {"airwash", "cooling", "drying", "finish", "preDrain", "prewash", "rinse", "spin", "unknown", "wash", "wrinklePrevent"},
    },
    .cmd_setMachineState = { .name = "setMachineState" }, // arguments: state(string) 
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_DISHWASHER_OPERATING_STATE_ */
