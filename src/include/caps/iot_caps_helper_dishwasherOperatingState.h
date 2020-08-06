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
        const unsigned char valueType;
    } attr_completionTime;
    const struct dishwasherOperatingState_attr_supportedMachineStates {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_DISHWASHEROPERATINGSTATE_SUPPORTEDMACHINESTATES_VALUE_MAX];
        const char *value_pause;
        const char *value_run;
        const char *value_stop;
    } attr_supportedMachineStates;
    const struct dishwasherOperatingState_attr_machineState {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_DISHWASHEROPERATINGSTATE_MACHINESTATE_VALUE_MAX];
        const char *value_pause;
        const char *value_run;
        const char *value_stop;
    } attr_machineState;
    const struct dishwasherOperatingState_attr_dishwasherJobState {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_DISHWASHEROPERATINGSTATE_DISHWASHERJOBSTATE_VALUE_MAX];
        const char *value_airwash;
        const char *value_cooling;
        const char *value_drying;
        const char *value_finish;
        const char *value_preDrain;
        const char *value_prewash;
        const char *value_rinse;
        const char *value_spin;
        const char *value_unknown;
        const char *value_wash;
        const char *value_wrinklePrevent;
    } attr_dishwasherJobState;
    const struct dishwasherOperatingState_cmd_setMachineState { const char* name; } cmd_setMachineState;
} caps_helper_dishwasherOperatingState = {
    .id = "dishwasherOperatingState",
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
    .attr_dishwasherJobState = {
        .name = "dishwasherJobState",
        .property = ATTR_SET_VALUE_REQUIRED,
        .valueType = VALUE_TYPE_STRING,
        .values = {"airwash", "cooling", "drying", "finish", "preDrain", "prewash", "rinse", "spin", "unknown", "wash", "wrinklePrevent"},
        .value_airwash = "airwash",
        .value_cooling = "cooling",
        .value_drying = "drying",
        .value_finish = "finish",
        .value_preDrain = "preDrain",
        .value_prewash = "prewash",
        .value_rinse = "rinse",
        .value_spin = "spin",
        .value_unknown = "unknown",
        .value_wash = "wash",
        .value_wrinklePrevent = "wrinklePrevent",
    },
    .cmd_setMachineState = { .name = "setMachineState" }, // arguments: state(string) 
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_DISHWASHER_OPERATING_STATE_ */
