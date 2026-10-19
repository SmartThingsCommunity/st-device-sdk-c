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

#ifndef _IOT_CAPS_HELPER_OPERATIONAL_STATE_
#define _IOT_CAPS_HELPER_OPERATIONAL_STATE_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_OPERATIONALSTATE_OPERATIONALSTATE_VALUE_RUNNING,
    CAP_ENUM_OPERATIONALSTATE_OPERATIONALSTATE_VALUE_STOPPED,
    CAP_ENUM_OPERATIONALSTATE_OPERATIONALSTATE_VALUE_PAUSED,
    CAP_ENUM_OPERATIONALSTATE_OPERATIONALSTATE_VALUE_UNABLETOSTARTORRESUME,
    CAP_ENUM_OPERATIONALSTATE_OPERATIONALSTATE_VALUE_UNABLETOCOMPLETEOPERATION,
    CAP_ENUM_OPERATIONALSTATE_OPERATIONALSTATE_VALUE_COMMANDINVALIDINCURRENTSTATE,
    CAP_ENUM_OPERATIONALSTATE_OPERATIONALSTATE_VALUE_STANDBY,
    CAP_ENUM_OPERATIONALSTATE_OPERATIONALSTATE_VALUE_MAX
};

enum {
    CAP_ENUM_OPERATIONALSTATE_SUPPORTEDOPERATIONALSTATES_VALUE_RUNNING,
    CAP_ENUM_OPERATIONALSTATE_SUPPORTEDOPERATIONALSTATES_VALUE_STOPPED,
    CAP_ENUM_OPERATIONALSTATE_SUPPORTEDOPERATIONALSTATES_VALUE_PAUSED,
    CAP_ENUM_OPERATIONALSTATE_SUPPORTEDOPERATIONALSTATES_VALUE_UNABLETOSTARTORRESUME,
    CAP_ENUM_OPERATIONALSTATE_SUPPORTEDOPERATIONALSTATES_VALUE_UNABLETOCOMPLETEOPERATION,
    CAP_ENUM_OPERATIONALSTATE_SUPPORTEDOPERATIONALSTATES_VALUE_COMMANDINVALIDINCURRENTSTATE,
    CAP_ENUM_OPERATIONALSTATE_SUPPORTEDOPERATIONALSTATES_VALUE_STANDBY,
    CAP_ENUM_OPERATIONALSTATE_SUPPORTEDOPERATIONALSTATES_VALUE_MAX
};

enum {
    CAP_ENUM_OPERATIONALSTATE_SUPPORTEDCOMMANDS_VALUE_START,
    CAP_ENUM_OPERATIONALSTATE_SUPPORTEDCOMMANDS_VALUE_STOP,
    CAP_ENUM_OPERATIONALSTATE_SUPPORTEDCOMMANDS_VALUE_RESUME,
    CAP_ENUM_OPERATIONALSTATE_SUPPORTEDCOMMANDS_VALUE_PAUSE,
    CAP_ENUM_OPERATIONALSTATE_SUPPORTEDCOMMANDS_VALUE_MAX
};

const static struct iot_caps_operationalState {
    const char *id;
    const struct operationalState_attr_operationalState {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_OPERATIONALSTATE_OPERATIONALSTATE_VALUE_MAX];
        const char *value_running;
        const char *value_stopped;
        const char *value_paused;
        const char *value_unableToStartOrResume;
        const char *value_unableToCompleteOperation;
        const char *value_commandInvalidInCurrentState;
        const char *value_standby;
    } attr_operationalState;
    const struct operationalState_attr_supportedOperationalStates {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_OPERATIONALSTATE_SUPPORTEDOPERATIONALSTATES_VALUE_MAX];
        const char *value_running;
        const char *value_stopped;
        const char *value_paused;
        const char *value_unableToStartOrResume;
        const char *value_unableToCompleteOperation;
        const char *value_commandInvalidInCurrentState;
        const char *value_standby;
    } attr_supportedOperationalStates;
    const struct operationalState_attr_supportedCommands {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_OPERATIONALSTATE_SUPPORTEDCOMMANDS_VALUE_MAX];
        const char *value_start;
        const char *value_stop;
        const char *value_resume;
        const char *value_pause;
    } attr_supportedCommands;
    const struct operationalState_cmd_start {
        const char *name;
    } cmd_start;
    const struct operationalState_cmd_stop {
        const char *name;
    } cmd_stop;
    const struct operationalState_cmd_pause {
        const char *name;
    } cmd_pause;
    const struct operationalState_cmd_resume {
        const char *name;
    } cmd_resume;
} caps_helper_operationalState = {
    .id = "operationalState",
    .attr_operationalState =
        {
            .name = "operationalState",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"running", "stopped", "paused", "unableToStartOrResume", "unableToCompleteOperation",
                       "commandInvalidInCurrentState", "standby"},
            .value_running = "running",
            .value_stopped = "stopped",
            .value_paused = "paused",
            .value_unableToStartOrResume = "unableToStartOrResume",
            .value_unableToCompleteOperation = "unableToCompleteOperation",
            .value_commandInvalidInCurrentState = "commandInvalidInCurrentState",
            .value_standby = "standby",
        },
    .attr_supportedOperationalStates =
        {
            .name = "supportedOperationalStates",
            .property = ATTR_SET_VALUE_ARRAY,
            .valueType = VALUE_TYPE_STRING,
            .values = {"running", "stopped", "paused", "unableToStartOrResume", "unableToCompleteOperation",
                       "commandInvalidInCurrentState", "standby"},
            .value_running = "running",
            .value_stopped = "stopped",
            .value_paused = "paused",
            .value_unableToStartOrResume = "unableToStartOrResume",
            .value_unableToCompleteOperation = "unableToCompleteOperation",
            .value_commandInvalidInCurrentState = "commandInvalidInCurrentState",
            .value_standby = "standby",
        },
    .attr_supportedCommands =
        {
            .name = "supportedCommands",
            .property = ATTR_SET_VALUE_ARRAY,
            .valueType = VALUE_TYPE_STRING,
            .values = {"start", "stop", "resume", "pause"},
            .value_start = "start",
            .value_stop = "stop",
            .value_resume = "resume",
            .value_pause = "pause",
        },
    .cmd_start = {.name = "start"},
    .cmd_stop = {.name = "stop"},
    .cmd_pause = {.name = "pause"},
    .cmd_resume = {.name = "resume"},
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_OPERATIONAL_STATE_ */
