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

#ifndef _IOT_CAPS_HELPER_OPERATING_STATE_
#define _IOT_CAPS_HELPER_OPERATING_STATE_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CAP_ENUM_OPERATINGSTATE_SUPPORTEDMACHINESTATES_VALUE_MAX 3
enum {
    CAP_ENUM_OPERATINGSTATE_MACHINESTATE_VALUE_PAUSED,
    CAP_ENUM_OPERATINGSTATE_MACHINESTATE_VALUE_RUNNING,
    CAP_ENUM_OPERATINGSTATE_MACHINESTATE_VALUE_READY,
    CAP_ENUM_OPERATINGSTATE_MACHINESTATE_VALUE_MAX
};

const static struct iot_caps_operatingState {
    const char *id;
    const struct operatingState_attr_supportedMachineStates {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_OPERATINGSTATE_SUPPORTEDMACHINESTATES_VALUE_MAX];
        const char *value_paused;
        const char *value_running;
        const char *value_ready;
    } attr_supportedMachineStates;
    const struct operatingState_attr_machineState {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_OPERATINGSTATE_MACHINESTATE_VALUE_MAX];
        const char *value_paused;
        const char *value_running;
        const char *value_ready;
    } attr_machineState;
    const struct operatingState_cmd_setMachineState { const char* name; } cmd_setMachineState;
} caps_helper_operatingState = {
    .id = "operatingState",
    .attr_supportedMachineStates = {
        .name = "supportedMachineStates",
        .property = ATTR_SET_VALUE_REQUIRED | ATTR_SET_VALUE_ARRAY,
        .valueType = VALUE_TYPE_STRING,
        .values = {"paused", "running", "ready"},
        .value_paused = "paused",
        .value_running = "running",
        .value_ready = "ready",
    },
    .attr_machineState = {
        .name = "machineState",
        .property = ATTR_SET_VALUE_REQUIRED,
        .valueType = VALUE_TYPE_STRING,
        .values = {"paused", "running", "ready"},
        .value_paused = "paused",
        .value_running = "running",
        .value_ready = "ready",
    },
    .cmd_setMachineState = { .name = "setMachineState" }, // arguments: state(string) 
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_OPERATING_STATE_ */
