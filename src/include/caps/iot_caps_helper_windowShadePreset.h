/* ***************************************************************************
 *
 * Copyright 2019-2026 Samsung Electronics All Rights Reserved.
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

#ifndef _IOT_CAPS_HELPER_WINDOW_SHADE_PRESET_
#define _IOT_CAPS_HELPER_WINDOW_SHADE_PRESET_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum { CAP_ENUM_WINDOWSHADEPRESET_POSITION_UNIT_PERCENT, CAP_ENUM_WINDOWSHADEPRESET_POSITION_UNIT_MAX };

enum {
    CAP_ENUM_WINDOWSHADEPRESET_SUPPORTEDCOMMANDS_VALUE_PRESETPOSITION,
    CAP_ENUM_WINDOWSHADEPRESET_SUPPORTEDCOMMANDS_VALUE_SETPRESETPOSITION,
    CAP_ENUM_WINDOWSHADEPRESET_SUPPORTEDCOMMANDS_VALUE_MAX
};

const static struct iot_caps_windowShadePreset {
    const char *id;
    const struct windowShadePreset_attr_supportedCommands {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_WINDOWSHADEPRESET_SUPPORTEDCOMMANDS_VALUE_MAX];
        const char *value_presetPosition;
        const char *value_setPresetPosition;
    } attr_supportedCommands;
    const struct windowShadePreset_attr_position {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *units[CAP_ENUM_WINDOWSHADEPRESET_POSITION_UNIT_MAX];
        const char *unit_percent;
        const int min;
        const int max;
    } attr_position;
    const struct windowShadePreset_cmd_setPresetPosition {
        const char *name;
    } cmd_setPresetPosition;
    const struct windowShadePreset_cmd_presetPosition {
        const char *name;
    } cmd_presetPosition;
} caps_helper_windowShadePreset = {
    .id = "windowShadePreset",
    .attr_supportedCommands =
        {
            .name = "supportedCommands",
            .property = ATTR_SET_VALUE_ARRAY,
            .valueType = VALUE_TYPE_STRING,
            .values = {"presetPosition", "setPresetPosition"},
            .value_presetPosition = "presetPosition",
            .value_setPresetPosition = "setPresetPosition",
        },
    .attr_position =
        {
            .name = "position",
            .property = ATTR_SET_VALUE_MIN | ATTR_SET_VALUE_MAX | ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_INTEGER,
            .units = {"%"},
            .unit_percent = "%",
            .min = 0,
            .max = 100,
        },
    .cmd_setPresetPosition = {.name = "setPresetPosition"},  // arguments: position(integer)
    .cmd_presetPosition = {.name = "presetPosition"},
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_WINDOW_SHADE_PRESET_ */
