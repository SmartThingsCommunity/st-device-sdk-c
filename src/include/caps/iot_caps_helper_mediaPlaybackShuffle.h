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

#ifndef _IOT_CAPS_HELPER_MEDIA_PLAYBACK_SHUFFLE_
#define _IOT_CAPS_HELPER_MEDIA_PLAYBACK_SHUFFLE_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_MEDIAPLAYBACKSHUFFLE_PLAYBACKSHUFFLE_VALUE_DISABLED,
    CAP_ENUM_MEDIAPLAYBACKSHUFFLE_PLAYBACKSHUFFLE_VALUE_ENABLED,
    CAP_ENUM_MEDIAPLAYBACKSHUFFLE_PLAYBACKSHUFFLE_VALUE_MAX
};

const static struct iot_caps_mediaPlaybackShuffle {
    const char *id;
    const struct mediaPlaybackShuffle_attr_playbackShuffle {
        const char *name;
        const unsigned char property;
        const unsigned char value_type;
        const char *values[CAP_ENUM_MEDIAPLAYBACKSHUFFLE_PLAYBACKSHUFFLE_VALUE_MAX];
    } attr_playbackShuffle;
    const struct mediaPlaybackShuffle_cmd_setPlaybackShuffle { const char* name; } cmd_setPlaybackShuffle;
} caps_helper_mediaPlaybackShuffle = {
    .id = "mediaPlaybackShuffle",
    .attr_playbackShuffle = {
        .name = "playbackShuffle",
        .property = ATTR_SET_VALUE_REQUIRED,
        .value_type = VALUE_TYPE_STRING,
        .values = {"disabled", "enabled"},
    },
    .cmd_setPlaybackShuffle = { .name = "setPlaybackShuffle" }, // arguments: shuffle(string) 
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_MEDIA_PLAYBACK_SHUFFLE_ */
