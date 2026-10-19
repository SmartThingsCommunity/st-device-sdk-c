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

#ifndef _IOT_CAPS_HELPER_ROBOT_CLEANER_OPERATING_STATE_
#define _IOT_CAPS_HELPER_ROBOT_CLEANER_OPERATING_STATE_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_ROBOTCLEANEROPERATINGSTATE_OPERATINGSTATE_VALUE_STOPPED,
    CAP_ENUM_ROBOTCLEANEROPERATINGSTATE_OPERATINGSTATE_VALUE_RUNNING,
    CAP_ENUM_ROBOTCLEANEROPERATINGSTATE_OPERATINGSTATE_VALUE_PAUSED,
    CAP_ENUM_ROBOTCLEANEROPERATINGSTATE_OPERATINGSTATE_VALUE_SEEKINGCHARGER,
    CAP_ENUM_ROBOTCLEANEROPERATINGSTATE_OPERATINGSTATE_VALUE_CHARGING,
    CAP_ENUM_ROBOTCLEANEROPERATINGSTATE_OPERATINGSTATE_VALUE_DOCKED,
    CAP_ENUM_ROBOTCLEANEROPERATINGSTATE_OPERATINGSTATE_VALUE_UNABLETOSTARTORRESUME,
    CAP_ENUM_ROBOTCLEANEROPERATINGSTATE_OPERATINGSTATE_VALUE_UNABLETOCOMPLETEOPERATION,
    CAP_ENUM_ROBOTCLEANEROPERATINGSTATE_OPERATINGSTATE_VALUE_COMMANDINVALIDINSTATE,
    CAP_ENUM_ROBOTCLEANEROPERATINGSTATE_OPERATINGSTATE_VALUE_FAILEDTOFINDCHARGINGDOCK,
    CAP_ENUM_ROBOTCLEANEROPERATINGSTATE_OPERATINGSTATE_VALUE_STUCK,
    CAP_ENUM_ROBOTCLEANEROPERATINGSTATE_OPERATINGSTATE_VALUE_DUSTBINMISSING,
    CAP_ENUM_ROBOTCLEANEROPERATINGSTATE_OPERATINGSTATE_VALUE_DUSTBINFULL,
    CAP_ENUM_ROBOTCLEANEROPERATINGSTATE_OPERATINGSTATE_VALUE_WATERTANKEMPTY,
    CAP_ENUM_ROBOTCLEANEROPERATINGSTATE_OPERATINGSTATE_VALUE_WATERTANKMISSING,
    CAP_ENUM_ROBOTCLEANEROPERATINGSTATE_OPERATINGSTATE_VALUE_WATERTANKLIDOPEN,
    CAP_ENUM_ROBOTCLEANEROPERATINGSTATE_OPERATINGSTATE_VALUE_MOPCLEANINGPADMISSING,
    CAP_ENUM_ROBOTCLEANEROPERATINGSTATE_OPERATINGSTATE_VALUE_MAX
};

#define CAP_ENUM_ROBOTCLEANEROPERATINGSTATE_SUPPORTEDCOMMANDS_VALUE_MAX 3
#define CAP_ENUM_ROBOTCLEANEROPERATINGSTATE_SUPPORTEDOPERATINGSTATECOMMANDS_VALUE_MAX 3
const static struct iot_caps_robotCleanerOperatingState {
    const char *id;
    const struct robotCleanerOperatingState_attr_operatingState {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_ROBOTCLEANEROPERATINGSTATE_OPERATINGSTATE_VALUE_MAX];
        const char *value_stopped;
        const char *value_running;
        const char *value_paused;
        const char *value_seekingCharger;
        const char *value_charging;
        const char *value_docked;
        const char *value_unableToStartOrResume;
        const char *value_unableToCompleteOperation;
        const char *value_commandInvalidInState;
        const char *value_failedToFindChargingDock;
        const char *value_stuck;
        const char *value_dustBinMissing;
        const char *value_dustBinFull;
        const char *value_waterTankEmpty;
        const char *value_waterTankMissing;
        const char *value_waterTankLidOpen;
        const char *value_mopCleaningPadMissing;
    } attr_operatingState;
    const struct robotCleanerOperatingState_attr_supportedOperatingStates {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_ROBOTCLEANEROPERATINGSTATE_OPERATINGSTATE_VALUE_MAX];
        const char *value_stopped;
        const char *value_running;
        const char *value_paused;
        const char *value_seekingCharger;
        const char *value_charging;
        const char *value_docked;
        const char *value_unableToStartOrResume;
        const char *value_unableToCompleteOperation;
        const char *value_commandInvalidInState;
        const char *value_failedToFindChargingDock;
        const char *value_stuck;
        const char *value_dustBinMissing;
        const char *value_dustBinFull;
        const char *value_waterTankEmpty;
        const char *value_waterTankMissing;
        const char *value_waterTankLidOpen;
        const char *value_mopCleaningPadMissing;
    } attr_supportedOperatingStates;
    const struct robotCleanerOperatingState_attr_supportedCommands {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_ROBOTCLEANEROPERATINGSTATE_SUPPORTEDCOMMANDS_VALUE_MAX];
        const char *value_start;
        const char *value_pause;
        const char *value_goHome;
    } attr_supportedCommands;
    const struct robotCleanerOperatingState_attr_supportedOperatingStateCommands {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_ROBOTCLEANEROPERATINGSTATE_SUPPORTEDOPERATINGSTATECOMMANDS_VALUE_MAX];
        const char *value_start;
        const char *value_pause;
        const char *value_goHome;
    } attr_supportedOperatingStateCommands;
    const struct robotCleanerOperatingState_cmd_goHome {
        const char *name;
    } cmd_goHome;
    const struct robotCleanerOperatingState_cmd_start {
        const char *name;
    } cmd_start;
    const struct robotCleanerOperatingState_cmd_pause {
        const char *name;
    } cmd_pause;
} caps_helper_robotCleanerOperatingState = {
    .id = "robotCleanerOperatingState",
    .attr_operatingState =
        {
            .name = "operatingState",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"stopped", "running", "paused", "seekingCharger", "charging", "docked", "unableToStartOrResume",
                       "unableToCompleteOperation", "commandInvalidInState", "failedToFindChargingDock", "stuck",
                       "dustBinMissing", "dustBinFull", "waterTankEmpty", "waterTankMissing", "waterTankLidOpen",
                       "mopCleaningPadMissing"},
            .value_stopped = "stopped",
            .value_running = "running",
            .value_paused = "paused",
            .value_seekingCharger = "seekingCharger",
            .value_charging = "charging",
            .value_docked = "docked",
            .value_unableToStartOrResume = "unableToStartOrResume",
            .value_unableToCompleteOperation = "unableToCompleteOperation",
            .value_commandInvalidInState = "commandInvalidInState",
            .value_failedToFindChargingDock = "failedToFindChargingDock",
            .value_stuck = "stuck",
            .value_dustBinMissing = "dustBinMissing",
            .value_dustBinFull = "dustBinFull",
            .value_waterTankEmpty = "waterTankEmpty",
            .value_waterTankMissing = "waterTankMissing",
            .value_waterTankLidOpen = "waterTankLidOpen",
            .value_mopCleaningPadMissing = "mopCleaningPadMissing",
        },
    .attr_supportedOperatingStates =
        {
            .name = "supportedOperatingStates",
            .property = ATTR_SET_VALUE_REQUIRED | ATTR_SET_VALUE_ARRAY,
            .valueType = VALUE_TYPE_STRING,
            .values = {"stopped", "running", "paused", "seekingCharger", "charging", "docked", "unableToStartOrResume",
                       "unableToCompleteOperation", "commandInvalidInState", "failedToFindChargingDock", "stuck",
                       "dustBinMissing", "dustBinFull", "waterTankEmpty", "waterTankMissing", "waterTankLidOpen",
                       "mopCleaningPadMissing"},
            .value_stopped = "stopped",
            .value_running = "running",
            .value_paused = "paused",
            .value_seekingCharger = "seekingCharger",
            .value_charging = "charging",
            .value_docked = "docked",
            .value_unableToStartOrResume = "unableToStartOrResume",
            .value_unableToCompleteOperation = "unableToCompleteOperation",
            .value_commandInvalidInState = "commandInvalidInState",
            .value_failedToFindChargingDock = "failedToFindChargingDock",
            .value_stuck = "stuck",
            .value_dustBinMissing = "dustBinMissing",
            .value_dustBinFull = "dustBinFull",
            .value_waterTankEmpty = "waterTankEmpty",
            .value_waterTankMissing = "waterTankMissing",
            .value_waterTankLidOpen = "waterTankLidOpen",
            .value_mopCleaningPadMissing = "mopCleaningPadMissing",
        },
    .attr_supportedCommands =
        {
            .name = "supportedCommands",
            .property = ATTR_SET_VALUE_ARRAY,
            .valueType = VALUE_TYPE_STRING,
            .values = {"start", "pause", "goHome"},
            .value_start = "start",
            .value_pause = "pause",
            .value_goHome = "goHome",
        },
    .attr_supportedOperatingStateCommands =
        {
            .name = "supportedOperatingStateCommands",
            .property = ATTR_SET_VALUE_ARRAY,
            .valueType = VALUE_TYPE_STRING,
            .values = {"start", "pause", "goHome"},
            .value_start = "start",
            .value_pause = "pause",
            .value_goHome = "goHome",
        },
    .cmd_goHome = {.name = "goHome"},
    .cmd_start = {.name = "start"},
    .cmd_pause = {.name = "pause"},
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_ROBOT_CLEANER_OPERATING_STATE_ */
