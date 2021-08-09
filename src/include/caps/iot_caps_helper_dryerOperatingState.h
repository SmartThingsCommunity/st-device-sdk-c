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

#ifndef _IOT_CAPS_HELPER_DRYER_OPERATING_STATE_
#define _IOT_CAPS_HELPER_DRYER_OPERATING_STATE_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

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
    CAP_ENUM_DRYEROPERATINGSTATE_DRYERJOBSTATE_VALUE_REFRESHING,
    CAP_ENUM_DRYEROPERATINGSTATE_DRYERJOBSTATE_VALUE_WEIGHTSENSING,
    CAP_ENUM_DRYEROPERATINGSTATE_DRYERJOBSTATE_VALUE_WRINKLEPREVENT,
    CAP_ENUM_DRYEROPERATINGSTATE_DRYERJOBSTATE_VALUE_DEHUMIDIFYING,
    CAP_ENUM_DRYEROPERATINGSTATE_DRYERJOBSTATE_VALUE_AIDRYING,
    CAP_ENUM_DRYEROPERATINGSTATE_DRYERJOBSTATE_VALUE_SANITIZING,
    CAP_ENUM_DRYEROPERATINGSTATE_DRYERJOBSTATE_VALUE_INTERNALCARE,
    CAP_ENUM_DRYEROPERATINGSTATE_DRYERJOBSTATE_VALUE_MAX
};

const static struct iot_caps_dryerOperatingState {
    const char *id;
    const struct dryerOperatingState_attr_completionTime {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
    } attr_completionTime;
    const struct dryerOperatingState_attr_supportedMachineStates {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_DRYEROPERATINGSTATE_SUPPORTEDMACHINESTATES_VALUE_MAX];
        const char *value_pause;
        const char *value_run;
        const char *value_stop;
    } attr_supportedMachineStates;
    const struct dryerOperatingState_attr_machineState {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_DRYEROPERATINGSTATE_MACHINESTATE_VALUE_MAX];
        const char *value_pause;
        const char *value_run;
        const char *value_stop;
    } attr_machineState;
    const struct dryerOperatingState_attr_dryerJobState {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_DRYEROPERATINGSTATE_DRYERJOBSTATE_VALUE_MAX];
        const char *value_cooling;
        const char *value_delayWash;
        const char *value_drying;
        const char *value_finished;
        const char *value_none;
        const char *value_refreshing;
        const char *value_weightSensing;
        const char *value_wrinklePrevent;
        const char *value_dehumidifying;
        const char *value_aIDrying;
        const char *value_sanitizing;
        const char *value_internalCare;
    } attr_dryerJobState;
    const struct dryerOperatingState_cmd_setMachineState { const char* name; } cmd_setMachineState;
} caps_helper_dryerOperatingState = {
    .id = "dryerOperatingState",
    .attr_completionTime = {
        .name = "completionTime",
        .property = ATTR_SET_VALUE_REQUIRED,
        .valueType = VALUE_TYPE_STRING,
    },
    .attr_supportedMachineStates = {
        .name = "supportedMachineStates",
        .property = ATTR_SET_VALUE_REQUIRED | ATTR_SET_VALUE_ARRAY,
        .valueType = VALUE_TYPE_STRING,
        .values = {"pause", "run", "stop"},
        .value_pause = "pause",
        .value_run = "run",
        .value_stop = "stop",
    },
    .attr_machineState = {
        .name = "machineState",
        .property = ATTR_SET_VALUE_REQUIRED,
        .valueType = VALUE_TYPE_STRING,
        .values = {"pause", "run", "stop"},
        .value_pause = "pause",
        .value_run = "run",
        .value_stop = "stop",
    },
    .attr_dryerJobState = {
        .name = "dryerJobState",
        .property = ATTR_SET_VALUE_REQUIRED,
        .valueType = VALUE_TYPE_STRING,
        .values = {"cooling", "delayWash", "drying", "finished", "none", "refreshing", "weightSensing", "wrinklePrevent", "dehumidifying", "aIDrying", "sanitizing", "internalCare"},
        .value_cooling = "cooling",
        .value_delayWash = "delayWash",
        .value_drying = "drying",
        .value_finished = "finished",
        .value_none = "none",
        .value_refreshing = "refreshing",
        .value_weightSensing = "weightSensing",
        .value_wrinklePrevent = "wrinklePrevent",
        .value_dehumidifying = "dehumidifying",
        .value_aIDrying = "aIDrying",
        .value_sanitizing = "sanitizing",
        .value_internalCare = "internalCare",
    },
    .cmd_setMachineState = { .name = "setMachineState" }, // arguments: state(string) 
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_DRYER_OPERATING_STATE_ */
