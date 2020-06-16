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

#ifndef _IOT_CAPS_HELPER_OVEN_OPERATING_STATE_
#define _IOT_CAPS_HELPER_OVEN_OPERATING_STATE_

#include "iot_caps_helper.h"

enum {
    CAP_ENUM_OVENOPERATINGSTATE_OVENJOBSTATE_VALUE_CLEANING,
    CAP_ENUM_OVENOPERATINGSTATE_OVENJOBSTATE_VALUE_COOKING,
    CAP_ENUM_OVENOPERATINGSTATE_OVENJOBSTATE_VALUE_COOLING,
    CAP_ENUM_OVENOPERATINGSTATE_OVENJOBSTATE_VALUE_DRAINING,
    CAP_ENUM_OVENOPERATINGSTATE_OVENJOBSTATE_VALUE_PREHEAT,
    CAP_ENUM_OVENOPERATINGSTATE_OVENJOBSTATE_VALUE_READY,
    CAP_ENUM_OVENOPERATINGSTATE_OVENJOBSTATE_VALUE_RINSING,
    CAP_ENUM_OVENOPERATINGSTATE_OVENJOBSTATE_VALUE_MAX
};

#define CAP_ENUM_OVENOPERATINGSTATE_SUPPORTEDMACHINESTATES_VALUE_MAX 3
enum {
    CAP_ENUM_OVENOPERATINGSTATE_MACHINESTATE_VALUE_READY,
    CAP_ENUM_OVENOPERATINGSTATE_MACHINESTATE_VALUE_RUNNING,
    CAP_ENUM_OVENOPERATINGSTATE_MACHINESTATE_VALUE_PAUSED,
    CAP_ENUM_OVENOPERATINGSTATE_MACHINESTATE_VALUE_MAX
};

enum {
    CAP_ENUM_OVENOPERATINGSTATE_PROGRESS_UNIT_PERCENT,
    CAP_ENUM_OVENOPERATINGSTATE_PROGRESS_UNIT_MAX
};

const static struct iot_caps_ovenOperatingState {
    const char *id;
    const struct ovenOperatingState_attr_ovenJobState {
        const char *name;
        const unsigned char property;
        const unsigned char value_type;
        const char *values[CAP_ENUM_OVENOPERATINGSTATE_OVENJOBSTATE_VALUE_MAX];
    } attr_ovenJobState;
    const struct ovenOperatingState_attr_completionTime {
        const char *name;
        const unsigned char property;
        const unsigned char value_type;
    } attr_completionTime;
    const struct ovenOperatingState_attr_supportedMachineStates {
        const char *name;
        const unsigned char property;
        const unsigned char value_type;
        const char *values[CAP_ENUM_OVENOPERATINGSTATE_SUPPORTEDMACHINESTATES_VALUE_MAX];
    } attr_supportedMachineStates;
    const struct ovenOperatingState_attr_progress {
        const char *name;
        const unsigned char property;
        const unsigned char value_type;
        const char *units[CAP_ENUM_OVENOPERATINGSTATE_PROGRESS_UNIT_MAX];
        const int min;
        const int max;
    } attr_progress;
    const struct ovenOperatingState_attr_operationTime {
        const char *name;
        const unsigned char property;
        const unsigned char value_type;
        const int min;
    } attr_operationTime;
    const struct ovenOperatingState_attr_machineState {
        const char *name;
        const unsigned char property;
        const unsigned char value_type;
        const char *values[CAP_ENUM_OVENOPERATINGSTATE_MACHINESTATE_VALUE_MAX];
    } attr_machineState;
    const struct ovenOperatingState_cmd_start { const char* name; } cmd_start;
    const struct ovenOperatingState_cmd_stop { const char* name; } cmd_stop;
    const struct ovenOperatingState_cmd_setMachineState { const char* name; } cmd_setMachineState;
} caps_helper_ovenOperatingState = {
    .id = "ovenOperatingState",
    .attr_ovenJobState = {
        .name = "ovenJobState",
        .property = NULL,
        .value_type = VALUE_TYPE_STRING,
        .values = {"cleaning", "cooking", "cooling", "draining", "preheat", "ready", "rinsing"},
    },
    .attr_completionTime = {
        .name = "completionTime",
        .property = ATTR_SET_VALUE_REQUIRED,
        .value_type = VALUE_TYPE_STRING,
    },
    .attr_supportedMachineStates = {
        .name = "supportedMachineStates",
        .property = ATTR_SET_VALUE_ARRAY,
        .value_type = VALUE_TYPE_STRING,
        .values = {"ready", "running", "paused"},
    },
    .attr_progress = {
        .name = "progress",
        .property = ATTR_SET_VALUE_MIN | ATTR_SET_VALUE_MAX | ATTR_SET_VALUE_REQUIRED,
        .value_type = VALUE_TYPE_INTEGER,
        .units = {"%"},
        .min = 0,
        .max = 100,
    },
    .attr_operationTime = {
        .name = "operationTime",
        .property = ATTR_SET_VALUE_MIN,
        .value_type = VALUE_TYPE_INTEGER,
        .min = 0,
    },
    .attr_machineState = {
        .name = "machineState",
        .property = NULL,
        .value_type = VALUE_TYPE_STRING,
        .values = {"ready", "running", "paused"},
    },
    .cmd_start = { .name = "start" }, // arguments: mode(string) time(integer) setpoint(integer) 
    .cmd_stop = { .name = "stop" },
    .cmd_setMachineState = { .name = "setMachineState" }, // arguments: state(string) 
};

#endif /* _IOT_CAPS_HERLPER_OVEN_OPERATING_STATE_ */
