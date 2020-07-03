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

#ifndef _IOT_CAPS_HELPER_WINDOW_SHADE_
#define _IOT_CAPS_HELPER_WINDOW_SHADE_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_WINDOWSHADE_WINDOWSHADE_VALUE_CLOSED,
    CAP_ENUM_WINDOWSHADE_WINDOWSHADE_VALUE_CLOSING,
    CAP_ENUM_WINDOWSHADE_WINDOWSHADE_VALUE_OPEN,
    CAP_ENUM_WINDOWSHADE_WINDOWSHADE_VALUE_OPENING,
    CAP_ENUM_WINDOWSHADE_WINDOWSHADE_VALUE_PARTIALLY_OPEN,
    CAP_ENUM_WINDOWSHADE_WINDOWSHADE_VALUE_UNKNOWN,
    CAP_ENUM_WINDOWSHADE_WINDOWSHADE_VALUE_MAX
};

#define CAP_ENUM_WINDOWSHADE_SUPPORTEDWINDOWSHADECOMMANDS_VALUE_MAX 3
const static struct iot_caps_windowShade {
    const char *id;
    const struct windowShade_attr_windowShade {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_WINDOWSHADE_WINDOWSHADE_VALUE_MAX];
        const char *value_closed;
        const char *value_closing;
        const char *value_open;
        const char *value_opening;
        const char *value_partially_open;
        const char *value_unknown;
    } attr_windowShade;
    const struct windowShade_attr_supportedWindowShadeCommands {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_WINDOWSHADE_SUPPORTEDWINDOWSHADECOMMANDS_VALUE_MAX];
        const char *value_open;
        const char *value_close;
        const char *value_pause;
    } attr_supportedWindowShadeCommands;
    const struct windowShade_cmd_close { const char* name; } cmd_close;
    const struct windowShade_cmd_pause { const char* name; } cmd_pause;
    const struct windowShade_cmd_open { const char* name; } cmd_open;
} caps_helper_windowShade = {
    .id = "windowShade",
    .attr_windowShade = {
        .name = "windowShade",
        .property = ATTR_SET_VALUE_REQUIRED,
        .valueType = VALUE_TYPE_STRING,
        .values = {"closed", "closing", "open", "opening", "partially open", "unknown"},
        .value_closed = "closed",
        .value_closing = "closing",
        .value_open = "open",
        .value_opening = "opening",
        .value_partially_open = "partially open",
        .value_unknown = "unknown",
    },
    .attr_supportedWindowShadeCommands = {
        .name = "supportedWindowShadeCommands",
        .property = ATTR_SET_VALUE_ARRAY,
        .valueType = VALUE_TYPE_STRING,
        .values = {"open", "close", "pause"},
        .value_open = "open",
        .value_close = "close",
        .value_pause = "pause",
    },
    .cmd_close = { .name = "close" },
    .cmd_pause = { .name = "pause" },
    .cmd_open = { .name = "open" },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_WINDOW_SHADE_ */
