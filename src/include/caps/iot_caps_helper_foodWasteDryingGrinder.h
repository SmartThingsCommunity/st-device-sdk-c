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

#ifndef _IOT_CAPS_HELPER_FOOD_WASTE_DRYING_GRINDER_
#define _IOT_CAPS_HELPER_FOOD_WASTE_DRYING_GRINDER_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_FOODWASTEDRYINGGRINDER_STATE_VALUE_WAITING,
    CAP_ENUM_FOODWASTEDRYINGGRINDER_STATE_VALUE_RUNNING,
    CAP_ENUM_FOODWASTEDRYINGGRINDER_STATE_VALUE_DRYING,
    CAP_ENUM_FOODWASTEDRYINGGRINDER_STATE_VALUE_GRINDING,
    CAP_ENUM_FOODWASTEDRYINGGRINDER_STATE_VALUE_COOLING,
    CAP_ENUM_FOODWASTEDRYINGGRINDER_STATE_VALUE_CLEANING,
    CAP_ENUM_FOODWASTEDRYINGGRINDER_STATE_VALUE_COMPLETED,
    CAP_ENUM_FOODWASTEDRYINGGRINDER_STATE_VALUE_ERROR,
    CAP_ENUM_FOODWASTEDRYINGGRINDER_STATE_VALUE_MAX
};

enum {
    CAP_ENUM_FOODWASTEDRYINGGRINDER_SUPPORTEDSTATES_VALUE_WAITING,
    CAP_ENUM_FOODWASTEDRYINGGRINDER_SUPPORTEDSTATES_VALUE_RUNNING,
    CAP_ENUM_FOODWASTEDRYINGGRINDER_SUPPORTEDSTATES_VALUE_DRYING,
    CAP_ENUM_FOODWASTEDRYINGGRINDER_SUPPORTEDSTATES_VALUE_GRINDING,
    CAP_ENUM_FOODWASTEDRYINGGRINDER_SUPPORTEDSTATES_VALUE_COOLING,
    CAP_ENUM_FOODWASTEDRYINGGRINDER_SUPPORTEDSTATES_VALUE_CLEANING,
    CAP_ENUM_FOODWASTEDRYINGGRINDER_SUPPORTEDSTATES_VALUE_COMPLETED,
    CAP_ENUM_FOODWASTEDRYINGGRINDER_SUPPORTEDSTATES_VALUE_ERROR,
    CAP_ENUM_FOODWASTEDRYINGGRINDER_SUPPORTEDSTATES_VALUE_MAX
};

enum {
    CAP_ENUM_FOODWASTEDRYINGGRINDER_MODE_VALUE_AUTO,
    CAP_ENUM_FOODWASTEDRYINGGRINDER_MODE_VALUE_STANDARD,
    CAP_ENUM_FOODWASTEDRYINGGRINDER_MODE_VALUE_POWER,
    CAP_ENUM_FOODWASTEDRYINGGRINDER_MODE_VALUE_ECO,
    CAP_ENUM_FOODWASTEDRYINGGRINDER_MODE_VALUE_STORAGE,
    CAP_ENUM_FOODWASTEDRYINGGRINDER_MODE_VALUE_CLEAN,
    CAP_ENUM_FOODWASTEDRYINGGRINDER_MODE_VALUE_MAX
};

enum {
    CAP_ENUM_FOODWASTEDRYINGGRINDER_SUPPORTEDMODES_VALUE_AUTO,
    CAP_ENUM_FOODWASTEDRYINGGRINDER_SUPPORTEDMODES_VALUE_STANDARD,
    CAP_ENUM_FOODWASTEDRYINGGRINDER_SUPPORTEDMODES_VALUE_POWER,
    CAP_ENUM_FOODWASTEDRYINGGRINDER_SUPPORTEDMODES_VALUE_ECO,
    CAP_ENUM_FOODWASTEDRYINGGRINDER_SUPPORTEDMODES_VALUE_STORAGE,
    CAP_ENUM_FOODWASTEDRYINGGRINDER_SUPPORTEDMODES_VALUE_CLEAN,
    CAP_ENUM_FOODWASTEDRYINGGRINDER_SUPPORTEDMODES_VALUE_MAX
};

enum {
    CAP_ENUM_FOODWASTEDRYINGGRINDER_EVENT_VALUE_ERROR,
    CAP_ENUM_FOODWASTEDRYINGGRINDER_EVENT_VALUE_OPERATIONCOMPLETE,
    CAP_ENUM_FOODWASTEDRYINGGRINDER_EVENT_VALUE_CLEANINGCOMPLETE,
    CAP_ENUM_FOODWASTEDRYINGGRINDER_EVENT_VALUE_MAX
};

enum {
    CAP_ENUM_FOODWASTEDRYINGGRINDER_SUPPORTEDEVENTS_VALUE_ERROR,
    CAP_ENUM_FOODWASTEDRYINGGRINDER_SUPPORTEDEVENTS_VALUE_OPERATIONCOMPLETE,
    CAP_ENUM_FOODWASTEDRYINGGRINDER_SUPPORTEDEVENTS_VALUE_CLEANINGCOMPLETE,
    CAP_ENUM_FOODWASTEDRYINGGRINDER_SUPPORTEDEVENTS_VALUE_MAX
};

const static struct iot_caps_foodWasteDryingGrinder {
    const char *id;
    const struct foodWasteDryingGrinder_attr_state {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_FOODWASTEDRYINGGRINDER_STATE_VALUE_MAX];
        const char *value_waiting;
        const char *value_running;
        const char *value_drying;
        const char *value_grinding;
        const char *value_cooling;
        const char *value_cleaning;
        const char *value_completed;
        const char *value_error;
    } attr_state;
    const struct foodWasteDryingGrinder_attr_supportedStates {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_FOODWASTEDRYINGGRINDER_SUPPORTEDSTATES_VALUE_MAX];
        const char *value_waiting;
        const char *value_running;
        const char *value_drying;
        const char *value_grinding;
        const char *value_cooling;
        const char *value_cleaning;
        const char *value_completed;
        const char *value_error;
    } attr_supportedStates;
    const struct foodWasteDryingGrinder_attr_mode {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_FOODWASTEDRYINGGRINDER_MODE_VALUE_MAX];
        const char *value_auto;
        const char *value_standard;
        const char *value_power;
        const char *value_eco;
        const char *value_storage;
        const char *value_clean;
    } attr_mode;
    const struct foodWasteDryingGrinder_attr_supportedModes {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_FOODWASTEDRYINGGRINDER_SUPPORTEDMODES_VALUE_MAX];
        const char *value_auto;
        const char *value_standard;
        const char *value_power;
        const char *value_eco;
        const char *value_storage;
        const char *value_clean;
    } attr_supportedModes;
    const struct foodWasteDryingGrinder_attr_event {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_FOODWASTEDRYINGGRINDER_EVENT_VALUE_MAX];
        const char *value_error;
        const char *value_operationComplete;
        const char *value_cleaningComplete;
    } attr_event;
    const struct foodWasteDryingGrinder_attr_supportedEvents {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_FOODWASTEDRYINGGRINDER_SUPPORTEDEVENTS_VALUE_MAX];
        const char *value_error;
        const char *value_operationComplete;
        const char *value_cleaningComplete;
    } attr_supportedEvents;
    const struct foodWasteDryingGrinder_cmd_start {
        const char *name;
    } cmd_start;
    const struct foodWasteDryingGrinder_cmd_stop {
        const char *name;
    } cmd_stop;
    const struct foodWasteDryingGrinder_cmd_setMode {
        const char *name;
    } cmd_setMode;
} caps_helper_foodWasteDryingGrinder = {
    .id = "foodWasteDryingGrinder",
    .attr_state =
        {
            .name = "state",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"waiting", "running", "drying", "grinding", "cooling", "cleaning", "completed", "error"},
            .value_waiting = "waiting",
            .value_running = "running",
            .value_drying = "drying",
            .value_grinding = "grinding",
            .value_cooling = "cooling",
            .value_cleaning = "cleaning",
            .value_completed = "completed",
            .value_error = "error",
        },
    .attr_supportedStates =
        {
            .name = "supportedStates",
            .property = ATTR_SET_VALUE_ARRAY | ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"waiting", "running", "drying", "grinding", "cooling", "cleaning", "completed", "error"},
            .value_waiting = "waiting",
            .value_running = "running",
            .value_drying = "drying",
            .value_grinding = "grinding",
            .value_cooling = "cooling",
            .value_cleaning = "cleaning",
            .value_completed = "completed",
            .value_error = "error",
        },
    .attr_mode =
        {
            .name = "mode",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"auto", "standard", "power", "eco", "storage", "clean"},
            .value_auto = "auto",
            .value_standard = "standard",
            .value_power = "power",
            .value_eco = "eco",
            .value_storage = "storage",
            .value_clean = "clean",
        },
    .attr_supportedModes =
        {
            .name = "supportedModes",
            .property = ATTR_SET_VALUE_ARRAY | ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"auto", "standard", "power", "eco", "storage", "clean"},
            .value_auto = "auto",
            .value_standard = "standard",
            .value_power = "power",
            .value_eco = "eco",
            .value_storage = "storage",
            .value_clean = "clean",
        },
    .attr_event =
        {
            .name = "event",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"error", "operationComplete", "cleaningComplete"},
            .value_error = "error",
            .value_operationComplete = "operationComplete",
            .value_cleaningComplete = "cleaningComplete",
        },
    .attr_supportedEvents =
        {
            .name = "supportedEvents",
            .property = ATTR_SET_VALUE_ARRAY | ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"error", "operationComplete", "cleaningComplete"},
            .value_error = "error",
            .value_operationComplete = "operationComplete",
            .value_cleaningComplete = "cleaningComplete",
        },
    .cmd_start = {.name = "start"},
    .cmd_stop = {.name = "stop"},
    .cmd_setMode = {.name = "setMode"},  // arguments: mode(string)
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_FOOD_WASTE_DRYING_GRINDER_ */
