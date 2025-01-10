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

#ifndef _IOT_CAPS_HELPER_AUDIO_MUTE_
#define _IOT_CAPS_HELPER_AUDIO_MUTE_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_AUDIOMUTE_MUTE_VALUE_MUTED,
    CAP_ENUM_AUDIOMUTE_MUTE_VALUE_UNMUTED,
    CAP_ENUM_AUDIOMUTE_MUTE_VALUE_MAX
};

const static struct iot_caps_audioMute {
    const char *id;
    const struct audioMute_attr_mute {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_AUDIOMUTE_MUTE_VALUE_MAX];
        const char *value_muted;
        const char *value_unmuted;
    } attr_mute;
    const struct audioMute_cmd_unmute { const char* name; } cmd_unmute;
    const struct audioMute_cmd_setMute { const char* name; } cmd_setMute;
    const struct audioMute_cmd_mute { const char* name; } cmd_mute;
} caps_helper_audioMute = {
    .id = "audioMute",
    .attr_mute = {
        .name = "mute",
        .property = ATTR_SET_VALUE_REQUIRED,
        .valueType = VALUE_TYPE_STRING,
        .values = {"muted", "unmuted"},
        .value_muted = "muted",
        .value_unmuted = "unmuted",
    },
    .cmd_unmute = { .name = "unmute" },
    .cmd_setMute = { .name = "setMute" }, // arguments: state(string) 
    .cmd_mute = { .name = "mute" },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_AUDIO_MUTE_ */
