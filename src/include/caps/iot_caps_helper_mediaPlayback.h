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

#ifndef _IOT_CAPS_HELPER_MEDIA_PLAYBACK_
#define _IOT_CAPS_HELPER_MEDIA_PLAYBACK_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CAP_ENUM_MEDIAPLAYBACK_SUPPORTEDPLAYBACKCOMMANDS_VALUE_MAX 5
enum {
    CAP_ENUM_MEDIAPLAYBACK_PLAYBACKSTATUS_VALUE_PAUSED,
    CAP_ENUM_MEDIAPLAYBACK_PLAYBACKSTATUS_VALUE_PLAYING,
    CAP_ENUM_MEDIAPLAYBACK_PLAYBACKSTATUS_VALUE_STOPPED,
    CAP_ENUM_MEDIAPLAYBACK_PLAYBACKSTATUS_VALUE_FAST_FORWARDING,
    CAP_ENUM_MEDIAPLAYBACK_PLAYBACKSTATUS_VALUE_REWINDING,
    CAP_ENUM_MEDIAPLAYBACK_PLAYBACKSTATUS_VALUE_MAX
};

const static struct iot_caps_mediaPlayback {
    const char *id;
    const struct mediaPlayback_attr_supportedPlaybackCommands {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_MEDIAPLAYBACK_SUPPORTEDPLAYBACKCOMMANDS_VALUE_MAX];
        const char *value_pause;
        const char *value_play;
        const char *value_stop;
        const char *value_fastForward;
        const char *value_rewind;
    } attr_supportedPlaybackCommands;
    const struct mediaPlayback_attr_playbackStatus {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_MEDIAPLAYBACK_PLAYBACKSTATUS_VALUE_MAX];
        const char *value_paused;
        const char *value_playing;
        const char *value_stopped;
        const char *value_fast_forwarding;
        const char *value_rewinding;
    } attr_playbackStatus;
    const struct mediaPlayback_cmd_setPlaybackStatus { const char* name; } cmd_setPlaybackStatus;
    const struct mediaPlayback_cmd_play { const char* name; } cmd_play;
    const struct mediaPlayback_cmd_pause { const char* name; } cmd_pause;
    const struct mediaPlayback_cmd_rewind { const char* name; } cmd_rewind;
    const struct mediaPlayback_cmd_fastForward { const char* name; } cmd_fastForward;
    const struct mediaPlayback_cmd_stop { const char* name; } cmd_stop;
} caps_helper_mediaPlayback = {
    .id = "mediaPlayback",
    .attr_supportedPlaybackCommands = {
        .name = "supportedPlaybackCommands",
        .property = ATTR_SET_VALUE_ARRAY,
        .valueType = VALUE_TYPE_STRING,
        .values = {"pause", "play", "stop", "fastForward", "rewind"},
        .value_pause = "pause",
        .value_play = "play",
        .value_stop = "stop",
        .value_fastForward = "fastForward",
        .value_rewind = "rewind",
    },
    .attr_playbackStatus = {
        .name = "playbackStatus",
        .property = 0,
        .valueType = VALUE_TYPE_STRING,
        .values = {"paused", "playing", "stopped", "fast forwarding", "rewinding"},
        .value_paused = "paused",
        .value_playing = "playing",
        .value_stopped = "stopped",
        .value_fast_forwarding = "fast forwarding",
        .value_rewinding = "rewinding",
    },
    .cmd_setPlaybackStatus = { .name = "setPlaybackStatus" }, // arguments: status(string) 
    .cmd_play = { .name = "play" },
    .cmd_pause = { .name = "pause" },
    .cmd_rewind = { .name = "rewind" },
    .cmd_fastForward = { .name = "fastForward" },
    .cmd_stop = { .name = "stop" },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_MEDIA_PLAYBACK_ */
