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

#ifndef _IOT_CAPS_HELPER_WASHER_OPERATING_STATE_
#define _IOT_CAPS_HELPER_WASHER_OPERATING_STATE_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CAP_ENUM_WASHEROPERATINGSTATE_SUPPORTEDMACHINESTATES_VALUE_MAX 3
enum {
    CAP_ENUM_WASHEROPERATINGSTATE_MACHINESTATE_VALUE_PAUSE,
    CAP_ENUM_WASHEROPERATINGSTATE_MACHINESTATE_VALUE_RUN,
    CAP_ENUM_WASHEROPERATINGSTATE_MACHINESTATE_VALUE_STOP,
    CAP_ENUM_WASHEROPERATINGSTATE_MACHINESTATE_VALUE_MAX
};

enum {
    CAP_ENUM_WASHEROPERATINGSTATE_WASHERJOBSTATE_VALUE_AIRWASH,
    CAP_ENUM_WASHEROPERATINGSTATE_WASHERJOBSTATE_VALUE_AIRINSE,
    CAP_ENUM_WASHEROPERATINGSTATE_WASHERJOBSTATE_VALUE_AISPIN,
    CAP_ENUM_WASHEROPERATINGSTATE_WASHERJOBSTATE_VALUE_AIWASH,
    CAP_ENUM_WASHEROPERATINGSTATE_WASHERJOBSTATE_VALUE_COOLING,
    CAP_ENUM_WASHEROPERATINGSTATE_WASHERJOBSTATE_VALUE_DELAYWASH,
    CAP_ENUM_WASHEROPERATINGSTATE_WASHERJOBSTATE_VALUE_DRYING,
    CAP_ENUM_WASHEROPERATINGSTATE_WASHERJOBSTATE_VALUE_FINISH,
    CAP_ENUM_WASHEROPERATINGSTATE_WASHERJOBSTATE_VALUE_NONE,
    CAP_ENUM_WASHEROPERATINGSTATE_WASHERJOBSTATE_VALUE_PREWASH,
    CAP_ENUM_WASHEROPERATINGSTATE_WASHERJOBSTATE_VALUE_RINSE,
    CAP_ENUM_WASHEROPERATINGSTATE_WASHERJOBSTATE_VALUE_SPIN,
    CAP_ENUM_WASHEROPERATINGSTATE_WASHERJOBSTATE_VALUE_WASH,
    CAP_ENUM_WASHEROPERATINGSTATE_WASHERJOBSTATE_VALUE_WEIGHTSENSING,
    CAP_ENUM_WASHEROPERATINGSTATE_WASHERJOBSTATE_VALUE_WRINKLEPREVENT,
    CAP_ENUM_WASHEROPERATINGSTATE_WASHERJOBSTATE_VALUE_FREEZEPROTECTION,
    CAP_ENUM_WASHEROPERATINGSTATE_WASHERJOBSTATE_VALUE_MAX
};

const static struct iot_caps_washerOperatingState {
    const char *id;
    const struct washerOperatingState_attr_completionTime {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
    } attr_completionTime;
    const struct washerOperatingState_attr_machineState {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_WASHEROPERATINGSTATE_MACHINESTATE_VALUE_MAX];
        const char *value_pause;
        const char *value_run;
        const char *value_stop;
    } attr_machineState;
    const struct washerOperatingState_attr_washerJobState {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_WASHEROPERATINGSTATE_WASHERJOBSTATE_VALUE_MAX];
        const char *value_airWash;
        const char *value_aIRinse;
        const char *value_aISpin;
        const char *value_aIWash;
        const char *value_cooling;
        const char *value_delayWash;
        const char *value_drying;
        const char *value_finish;
        const char *value_none;
        const char *value_preWash;
        const char *value_rinse;
        const char *value_spin;
        const char *value_wash;
        const char *value_weightSensing;
        const char *value_wrinklePrevent;
        const char *value_freezeProtection;
    } attr_washerJobState;
    const struct washerOperatingState_attr_supportedMachineStates {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_WASHEROPERATINGSTATE_SUPPORTEDMACHINESTATES_VALUE_MAX];
        const char *value_pause;
        const char *value_run;
        const char *value_stop;
    } attr_supportedMachineStates;
    const struct washerOperatingState_cmd_setMachineState {
        const char *name;
    } cmd_setMachineState;
} caps_helper_washerOperatingState = {
    .id = "washerOperatingState",
    .attr_completionTime =
        {
            .name = "completionTime",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
        },
    .attr_machineState =
        {
            .name = "machineState",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"pause", "run", "stop"},
            .value_pause = "pause",
            .value_run = "run",
            .value_stop = "stop",
        },
    .attr_washerJobState =
        {
            .name = "washerJobState",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"airWash", "aIRinse", "aISpin", "aIWash", "cooling", "delayWash", "drying", "finish", "none",
                       "preWash", "rinse", "spin", "wash", "weightSensing", "wrinklePrevent", "freezeProtection"},
            .value_airWash = "airWash",
            .value_aIRinse = "aIRinse",
            .value_aISpin = "aISpin",
            .value_aIWash = "aIWash",
            .value_cooling = "cooling",
            .value_delayWash = "delayWash",
            .value_drying = "drying",
            .value_finish = "finish",
            .value_none = "none",
            .value_preWash = "preWash",
            .value_rinse = "rinse",
            .value_spin = "spin",
            .value_wash = "wash",
            .value_weightSensing = "weightSensing",
            .value_wrinklePrevent = "wrinklePrevent",
            .value_freezeProtection = "freezeProtection",
        },
    .attr_supportedMachineStates =
        {
            .name = "supportedMachineStates",
            .property = ATTR_SET_VALUE_ARRAY,
            .valueType = VALUE_TYPE_STRING,
            .values = {"pause", "run", "stop"},
            .value_pause = "pause",
            .value_run = "run",
            .value_stop = "stop",
        },
    .cmd_setMachineState = {.name = "setMachineState"},  // arguments: state(string)
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_WASHER_OPERATING_STATE_ */
