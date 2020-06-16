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

#ifndef _IOT_CAPS_HELPER_DRYER_OPERATING_STATE_
#define _IOT_CAPS_HELPER_DRYER_OPERATING_STATE_

#include "iot_caps_helper.h"

#define CAP_ENUM_DRYEROPERATINGSTATE_SUPPORTEDMACHINESTATES_VALUE_MAX 3
enum {
    CAP_ENUM_DRYEROPERATINGSTATE_MACHINESTATE_VALUE_PAUSE,
    CAP_ENUM_DRYEROPERATINGSTATE_MACHINESTATE_VALUE_RUN,
    CAP_ENUM_DRYEROPERATINGSTATE_MACHINESTATE_VALUE_STOP,
    CAP_ENUM_DRYEROPERATINGSTATE_MACHINESTATE_VALUE_MAX
};

enum {
    CAP_ENUM_DRYEROPERATINGSTATE_DRYERJOBSTATE_VALUE_COOLING,
    CAP_ENUM_DRYEROPERATINGSTATE_DRYERJOBSTATE_VALUE_DELAYWASH,
    CAP_ENUM_DRYEROPERATINGSTATE_DRYERJOBSTATE_VALUE_DRYING,
    CAP_ENUM_DRYEROPERATINGSTATE_DRYERJOBSTATE_VALUE_FINISHED,
    CAP_ENUM_DRYEROPERATINGSTATE_DRYERJOBSTATE_VALUE_NONE,
    CAP_ENUM_DRYEROPERATINGSTATE_DRYERJOBSTATE_VALUE_WEIGHTSENSING,
    CAP_ENUM_DRYEROPERATINGSTATE_DRYERJOBSTATE_VALUE_WRINKLEPREVENT,
    CAP_ENUM_DRYEROPERATINGSTATE_DRYERJOBSTATE_VALUE_MAX
};

const static struct iot_caps_dryerOperatingState {
    const char *id;
    const struct dryerOperatingState_attr_completionTime {
        const char *name;
        const unsigned char property;
        const unsigned char value_type;
    } attr_completionTime;
    const struct dryerOperatingState_attr_supportedMachineStates {
        const char *name;
        const unsigned char property;
        const unsigned char value_type;
        const char *values[CAP_ENUM_DRYEROPERATINGSTATE_SUPPORTEDMACHINESTATES_VALUE_MAX];
    } attr_supportedMachineStates;
    const struct dryerOperatingState_attr_machineState {
        const char *name;
        const unsigned char property;
        const unsigned char value_type;
        const char *values[CAP_ENUM_DRYEROPERATINGSTATE_MACHINESTATE_VALUE_MAX];
    } attr_machineState;
    const struct dryerOperatingState_attr_dryerJobState {
        const char *name;
        const unsigned char property;
        const unsigned char value_type;
        const char *values[CAP_ENUM_DRYEROPERATINGSTATE_DRYERJOBSTATE_VALUE_MAX];
    } attr_dryerJobState;
    const struct dryerOperatingState_cmd_setMachineState { const char* name; } cmd_setMachineState;
} caps_helper_dryerOperatingState = {
    .id = "dryerOperatingState",
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
    .attr_dryerJobState = {
        .name = "dryerJobState",
        .property = ATTR_SET_VALUE_REQUIRED,
        .value_type = VALUE_TYPE_STRING,
        .values = {"cooling", "delayWash", "drying", "finished", "none", "weightSensing", "wrinklePrevent"},
    },
    .cmd_setMachineState = { .name = "setMachineState" }, // arguments: state(string) 
};

#endif /* _IOT_CAPS_HERLPER_DRYER_OPERATING_STATE_ */
