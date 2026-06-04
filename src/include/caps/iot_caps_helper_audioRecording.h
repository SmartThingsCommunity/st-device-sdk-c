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

#ifndef _IOT_CAPS_HELPER_AUDIO_RECORDING_
#define _IOT_CAPS_HELPER_AUDIO_RECORDING_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_AUDIORECORDING_AUDIORECORDING_VALUE_ENABLED,
    CAP_ENUM_AUDIORECORDING_AUDIORECORDING_VALUE_DISABLED,
    CAP_ENUM_AUDIORECORDING_AUDIORECORDING_VALUE_MAX
};

const static struct iot_caps_audioRecording {
    const char *id;
    const struct audioRecording_attr_audioRecording {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_AUDIORECORDING_AUDIORECORDING_VALUE_MAX];
        const char *value_enabled;
        const char *value_disabled;
    } attr_audioRecording;
    const struct audioRecording_cmd_setAudioRecording {
        const char *name;
    } cmd_setAudioRecording;
} caps_helper_audioRecording = {
    .id = "audioRecording",
    .attr_audioRecording =
        {
            .name = "audioRecording",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"enabled", "disabled"},
            .value_enabled = "enabled",
            .value_disabled = "disabled",
        },
    .cmd_setAudioRecording = {.name = "setAudioRecording"},  // arguments: state(string)
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_AUDIO_RECORDING_ */
