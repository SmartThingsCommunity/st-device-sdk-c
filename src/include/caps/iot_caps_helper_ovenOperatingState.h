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

#ifndef _IOT_CAPS_HELPER_OVEN_OPERATING_STATE_
#define _IOT_CAPS_HELPER_OVEN_OPERATING_STATE_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_OVENOPERATINGSTATE_OVENJOBSTATE_VALUE_CLEANING,
    CAP_ENUM_OVENOPERATINGSTATE_OVENJOBSTATE_VALUE_COOKING,
    CAP_ENUM_OVENOPERATINGSTATE_OVENJOBSTATE_VALUE_COOLING,
    CAP_ENUM_OVENOPERATINGSTATE_OVENJOBSTATE_VALUE_DRAINING,
    CAP_ENUM_OVENOPERATINGSTATE_OVENJOBSTATE_VALUE_PREHEAT,
    CAP_ENUM_OVENOPERATINGSTATE_OVENJOBSTATE_VALUE_READY,
    CAP_ENUM_OVENOPERATINGSTATE_OVENJOBSTATE_VALUE_RINSING,
    CAP_ENUM_OVENOPERATINGSTATE_OVENJOBSTATE_VALUE_FINISHED,
    CAP_ENUM_OVENOPERATINGSTATE_OVENJOBSTATE_VALUE_SCHEDULEDSTART,
    CAP_ENUM_OVENOPERATINGSTATE_OVENJOBSTATE_VALUE_WARMING,
    CAP_ENUM_OVENOPERATINGSTATE_OVENJOBSTATE_VALUE_DEFROSTING,
    CAP_ENUM_OVENOPERATINGSTATE_OVENJOBSTATE_VALUE_SENSING,
    CAP_ENUM_OVENOPERATINGSTATE_OVENJOBSTATE_VALUE_SEARING,
    CAP_ENUM_OVENOPERATINGSTATE_OVENJOBSTATE_VALUE_FASTPREHEAT,
    CAP_ENUM_OVENOPERATINGSTATE_OVENJOBSTATE_VALUE_SCHEDULEDEND,
    CAP_ENUM_OVENOPERATINGSTATE_OVENJOBSTATE_VALUE_STONEHEATING,
    CAP_ENUM_OVENOPERATINGSTATE_OVENJOBSTATE_VALUE_TIMEHOLDPREHEAT,
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
        const unsigned char valueType;
        const char *values[CAP_ENUM_OVENOPERATINGSTATE_OVENJOBSTATE_VALUE_MAX];
        const char *value_cleaning;
        const char *value_cooking;
        const char *value_cooling;
        const char *value_draining;
        const char *value_preheat;
        const char *value_ready;
        const char *value_rinsing;
        const char *value_finished;
        const char *value_scheduledStart;
        const char *value_warming;
        const char *value_defrosting;
        const char *value_sensing;
        const char *value_searing;
        const char *value_fastPreheat;
        const char *value_scheduledEnd;
        const char *value_stoneHeating;
        const char *value_timeHoldPreheat;
    } attr_ovenJobState;
    const struct ovenOperatingState_attr_completionTime {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
    } attr_completionTime;
    const struct ovenOperatingState_attr_supportedMachineStates {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_OVENOPERATINGSTATE_SUPPORTEDMACHINESTATES_VALUE_MAX];
        const char *value_ready;
        const char *value_running;
        const char *value_paused;
    } attr_supportedMachineStates;
    const struct ovenOperatingState_attr_progress {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *units[CAP_ENUM_OVENOPERATINGSTATE_PROGRESS_UNIT_MAX];
        const char *unit_percent;
        const int min;
        const int max;
    } attr_progress;
    const struct ovenOperatingState_attr_operationTime {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const int min;
    } attr_operationTime;
    const struct ovenOperatingState_attr_machineState {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_OVENOPERATINGSTATE_MACHINESTATE_VALUE_MAX];
        const char *value_ready;
        const char *value_running;
        const char *value_paused;
    } attr_machineState;
    const struct ovenOperatingState_cmd_start { const char* name; } cmd_start;
    const struct ovenOperatingState_cmd_stop { const char* name; } cmd_stop;
    const struct ovenOperatingState_cmd_setMachineState { const char* name; } cmd_setMachineState;
} caps_helper_ovenOperatingState = {
    .id = "ovenOperatingState",
    .attr_ovenJobState = {
        .name = "ovenJobState",
        .property = 0,
        .valueType = VALUE_TYPE_STRING,
        .values = {"cleaning", "cooking", "cooling", "draining", "preheat", "ready", "rinsing", "finished", "scheduledStart", "warming", "defrosting", "sensing", "searing", "fastPreheat", "scheduledEnd", "stoneHeating", "timeHoldPreheat"},
        .value_cleaning = "cleaning",
        .value_cooking = "cooking",
        .value_cooling = "cooling",
        .value_draining = "draining",
        .value_preheat = "preheat",
        .value_ready = "ready",
        .value_rinsing = "rinsing",
        .value_finished = "finished",
        .value_scheduledStart = "scheduledStart",
        .value_warming = "warming",
        .value_defrosting = "defrosting",
        .value_sensing = "sensing",
        .value_searing = "searing",
        .value_fastPreheat = "fastPreheat",
        .value_scheduledEnd = "scheduledEnd",
        .value_stoneHeating = "stoneHeating",
        .value_timeHoldPreheat = "timeHoldPreheat",
    },
    .attr_completionTime = {
        .name = "completionTime",
        .property = ATTR_SET_VALUE_REQUIRED,
        .valueType = VALUE_TYPE_STRING,
    },
    .attr_supportedMachineStates = {
        .name = "supportedMachineStates",
        .property = ATTR_SET_VALUE_ARRAY,
        .valueType = VALUE_TYPE_STRING,
        .values = {"ready", "running", "paused"},
        .value_ready = "ready",
        .value_running = "running",
        .value_paused = "paused",
    },
    .attr_progress = {
        .name = "progress",
        .property = ATTR_SET_VALUE_MIN | ATTR_SET_VALUE_MAX | ATTR_SET_VALUE_REQUIRED,
        .valueType = VALUE_TYPE_INTEGER,
        .units = {"%"},
        .unit_percent = "%",
        .min = 0,
        .max = 100,
    },
    .attr_operationTime = {
        .name = "operationTime",
        .property = ATTR_SET_VALUE_MIN,
        .valueType = VALUE_TYPE_INTEGER,
        .min = 0,
    },
    .attr_machineState = {
        .name = "machineState",
        .property = 0,
        .valueType = VALUE_TYPE_STRING,
        .values = {"ready", "running", "paused"},
        .value_ready = "ready",
        .value_running = "running",
        .value_paused = "paused",
    },
    .cmd_start = { .name = "start" }, // arguments: mode(string) time(integer) setpoint(integer) 
    .cmd_stop = { .name = "stop" },
    .cmd_setMachineState = { .name = "setMachineState" }, // arguments: state(string) 
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_OVEN_OPERATING_STATE_ */
