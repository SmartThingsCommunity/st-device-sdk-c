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

#ifndef _IOT_CAPS_HELPER_TIMED_SESSION_
#define _IOT_CAPS_HELPER_TIMED_SESSION_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_TIMEDSESSION_SESSIONSTATUS_VALUE_CANCELED,
    CAP_ENUM_TIMEDSESSION_SESSIONSTATUS_VALUE_PAUSED,
    CAP_ENUM_TIMEDSESSION_SESSIONSTATUS_VALUE_RUNNING,
    CAP_ENUM_TIMEDSESSION_SESSIONSTATUS_VALUE_STOPPED,
    CAP_ENUM_TIMEDSESSION_SESSIONSTATUS_VALUE_MAX
};

const static struct iot_caps_timedSession {
    const char *id;
    const struct timedSession_attr_completionTime {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
    } attr_completionTime;
    const struct timedSession_attr_sessionStatus {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_TIMEDSESSION_SESSIONSTATUS_VALUE_MAX];
        const char *value_canceled;
        const char *value_paused;
        const char *value_running;
        const char *value_stopped;
    } attr_sessionStatus;
    const struct timedSession_cmd_cancel { const char* name; } cmd_cancel;
    const struct timedSession_cmd_start { const char* name; } cmd_start;
    const struct timedSession_cmd_setCompletionTime { const char* name; } cmd_setCompletionTime;
    const struct timedSession_cmd_pause { const char* name; } cmd_pause;
    const struct timedSession_cmd_stop { const char* name; } cmd_stop;
} caps_helper_timedSession = {
    .id = "timedSession",
    .attr_completionTime = {
        .name = "completionTime",
        .property = ATTR_SET_VALUE_REQUIRED,
        .valueType = VALUE_TYPE_STRING,
    },
    .attr_sessionStatus = {
        .name = "sessionStatus",
        .property = ATTR_SET_VALUE_REQUIRED,
        .valueType = VALUE_TYPE_STRING,
        .values = {"canceled", "paused", "running", "stopped"},
        .value_canceled = "canceled",
        .value_paused = "paused",
        .value_running = "running",
        .value_stopped = "stopped",
    },
    .cmd_cancel = { .name = "cancel" },
    .cmd_start = { .name = "start" },
    .cmd_setCompletionTime = { .name = "setCompletionTime" }, // arguments: completionTime(string) 
    .cmd_pause = { .name = "pause" },
    .cmd_stop = { .name = "stop" },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_TIMED_SESSION_ */
