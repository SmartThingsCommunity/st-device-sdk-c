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

#ifndef _IOT_CAPS_HELPER_ANTISNORINGPILLOW_
#define _IOT_CAPS_HELPER_ANTISNORINGPILLOW_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_ANTISNORINGPILLOW_STATE_VALUE_OFF,
    CAP_ENUM_ANTISNORINGPILLOW_STATE_VALUE_PREPARING,
    CAP_ENUM_ANTISNORINGPILLOW_STATE_VALUE_RUNNING,
    CAP_ENUM_ANTISNORINGPILLOW_STATE_VALUE_STOPPED,
    CAP_ENUM_ANTISNORINGPILLOW_STATE_VALUE_MAX,
};

const static struct iot_caps_antiSnoringPillow {
    const char *id;
    const struct antiSnoringPillow_attr_state {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_ANTISNORINGPILLOW_STATE_VALUE_MAX];
        const char *value_off;
        const char *value_preparing;
        const char *value_running;
        const char *value_stopped;
    } attr_state;
    const struct antiSnoringPillow_attr_snoringTime {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
    } attr_snoringTime;
    const struct antiSnoringPillow_attr_snoringTimeDelta {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
    } attr_snoringTimeDelta;
    const struct antiSnoringPillow_attr_supportSnoringTimeGraph {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
    } attr_supportSnoringTimeGraph;
    const struct antiSnoringPillow_attr_pillowOperationTime {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
    } attr_pillowOperationTime;
    const struct antiSnoringPillow_attr_pillowOperationTimeDelta {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
    } attr_pillowOperationTimeDelta;
    const struct antiSnoringPillow_attr_supportPillowOperationTimeGraph {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
    } attr_supportPillowOperationTimeGraph;
    const struct antiSnoringPillow_cmd_on { const char* name; } cmd_on;
    const struct antiSnoringPillow_cmd_off { const char* name; } cmd_off;
} caps_helper_antiSnoringPillow = {
    .id = "antiSnoringPillow",
    .attr_state = {
        .name = "state",
        .property = ATTR_SET_VALUE_REQUIRED,
        .valueType = VALUE_TYPE_STRING,
        .values = {"off", "preparing", "running", "stopped"},
        .value_off = "off",
        .value_preparing = "preparing",
        .value_running = "running",
        .value_stopped = "stopped",
    },
    .attr_snoringTime = {
        .name = "snoringTime",
        .property = ATTR_SET_VALUE_REQUIRED,
        .valueType = VALUE_TYPE_INTEGER,
    },
    .attr_snoringTimeDelta = {
        .name = "snoringTimeDelta",
        .property = ATTR_SET_VALUE_REQUIRED,
        .valueType = VALUE_TYPE_INTEGER,
    },
    .attr_supportSnoringTimeGraph = {
        .name = "supportSnoringTimeGraph",
        .property = ATTR_SET_VALUE_REQUIRED,
        .valueType = VALUE_TYPE_BOOLEAN,
    },
    .attr_pillowOperationTime = {
        .name = "pillowOperationTime",
        .property = ATTR_SET_VALUE_REQUIRED,
        .valueType = VALUE_TYPE_INTEGER,
    },
    .attr_pillowOperationTimeDelta = {
        .name = "pillowOperationTimeDelta",
        .property = ATTR_SET_VALUE_REQUIRED,
        .valueType = VALUE_TYPE_INTEGER,
    },
    .attr_supportPillowOperationTimeGraph = {
        .name = "supportPillowOperationTimeGraph",
        .property = ATTR_SET_VALUE_REQUIRED,
        .valueType = VALUE_TYPE_BOOLEAN,
    },
    .cmd_on = { .name = "on" },
    .cmd_off = { .name = "off" },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_SWITCH_ */
