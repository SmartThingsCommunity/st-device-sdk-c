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

#ifndef _IOT_CAPS_HELPER_MEDIA_TRACK_CONTROL_
#define _IOT_CAPS_HELPER_MEDIA_TRACK_CONTROL_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_MEDIATRACKCONTROL_SUPPORTEDTRACKCONTROLCOMMANDS_VALUE_PREVIOUSTRACK,
    CAP_ENUM_MEDIATRACKCONTROL_SUPPORTEDTRACKCONTROLCOMMANDS_VALUE_NEXTTRACK,
    CAP_ENUM_MEDIATRACKCONTROL_SUPPORTEDTRACKCONTROLCOMMANDS_VALUE_MAX
};

const static struct iot_caps_mediaTrackControl {
    const char *id;
    const struct mediaTrackControl_attr_supportedTrackControlCommands {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_MEDIATRACKCONTROL_SUPPORTEDTRACKCONTROLCOMMANDS_VALUE_MAX];
        const char *value_previousTrack;
        const char *value_nextTrack;
    } attr_supportedTrackControlCommands;
    const struct mediaTrackControl_cmd_previousTrack {
        const char *name;
    } cmd_previousTrack;
    const struct mediaTrackControl_cmd_nextTrack {
        const char *name;
    } cmd_nextTrack;
} caps_helper_mediaTrackControl = {
    .id = "mediaTrackControl",
    .attr_supportedTrackControlCommands =
        {
            .name = "supportedTrackControlCommands",
            .property = ATTR_SET_VALUE_ARRAY,
            .valueType = VALUE_TYPE_STRING,
            .values = {"previousTrack", "nextTrack"},
            .value_previousTrack = "previousTrack",
            .value_nextTrack = "nextTrack",
        },
    .cmd_previousTrack = {.name = "previousTrack"},
    .cmd_nextTrack = {.name = "nextTrack"},
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_MEDIA_TRACK_CONTROL_ */
