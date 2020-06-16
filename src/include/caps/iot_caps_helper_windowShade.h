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
        const unsigned char value_type;
        const char *values[CAP_ENUM_WINDOWSHADE_WINDOWSHADE_VALUE_MAX];
    } attr_windowShade;
    const struct windowShade_attr_supportedWindowShadeCommands {
        const char *name;
        const unsigned char property;
        const unsigned char value_type;
        const char *values[CAP_ENUM_WINDOWSHADE_SUPPORTEDWINDOWSHADECOMMANDS_VALUE_MAX];
    } attr_supportedWindowShadeCommands;
    const struct windowShade_cmd_close { const char* name; } cmd_close;
    const struct windowShade_cmd_pause { const char* name; } cmd_pause;
    const struct windowShade_cmd_open { const char* name; } cmd_open;
} caps_helper_windowShade = {
    .id = "windowShade",
    .attr_windowShade = {
        .name = "windowShade",
        .property = ATTR_SET_VALUE_REQUIRED,
        .value_type = VALUE_TYPE_STRING,
        .values = {"closed", "closing", "open", "opening", "partially open", "unknown"},
    },
    .attr_supportedWindowShadeCommands = {
        .name = "supportedWindowShadeCommands",
        .property = ATTR_SET_VALUE_ARRAY,
        .value_type = VALUE_TYPE_STRING,
        .values = {"open", "close", "pause"},
    },
    .cmd_close = { .name = "close" },
    .cmd_pause = { .name = "pause" },
    .cmd_open = { .name = "open" },
};

#endif /* _IOT_CAPS_HERLPER_WINDOW_SHADE_ */
