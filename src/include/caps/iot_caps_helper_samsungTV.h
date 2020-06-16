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

#ifndef _IOT_CAPS_HELPER_SAMSUNG_TV_
#define _IOT_CAPS_HELPER_SAMSUNG_TV_

#include "iot_caps_helper.h"

enum {
    CAP_ENUM_SAMSUNGTV_SWITCH_VALUE_ON,
    CAP_ENUM_SAMSUNGTV_SWITCH_VALUE_OFF,
    CAP_ENUM_SAMSUNGTV_SWITCH_VALUE_MAX
};

enum {
    CAP_ENUM_SAMSUNGTV_MUTE_VALUE_MUTED,
    CAP_ENUM_SAMSUNGTV_MUTE_VALUE_UNKNOWN,
    CAP_ENUM_SAMSUNGTV_MUTE_VALUE_UNMUTED,
    CAP_ENUM_SAMSUNGTV_MUTE_VALUE_MAX
};

enum {
    CAP_ENUM_SAMSUNGTV_PICTUREMODE_VALUE_DYNAMIC,
    CAP_ENUM_SAMSUNGTV_PICTUREMODE_VALUE_MOVIE,
    CAP_ENUM_SAMSUNGTV_PICTUREMODE_VALUE_STANDARD,
    CAP_ENUM_SAMSUNGTV_PICTUREMODE_VALUE_UNKNOWN,
    CAP_ENUM_SAMSUNGTV_PICTUREMODE_VALUE_MAX
};

enum {
    CAP_ENUM_SAMSUNGTV_SOUNDMODE_VALUE_CLEAR_VOICE,
    CAP_ENUM_SAMSUNGTV_SOUNDMODE_VALUE_MOVIE,
    CAP_ENUM_SAMSUNGTV_SOUNDMODE_VALUE_MUSIC,
    CAP_ENUM_SAMSUNGTV_SOUNDMODE_VALUE_STANDARD,
    CAP_ENUM_SAMSUNGTV_SOUNDMODE_VALUE_UNKNOWN,
    CAP_ENUM_SAMSUNGTV_SOUNDMODE_VALUE_MAX
};

const static struct iot_caps_samsungTV {
    const char *id;
    const struct samsungTV_attr_volume {
        const char *name;
        const unsigned char property;
        const unsigned char value_type;
        const int min;
    } attr_volume;
    const struct samsungTV_attr_messageButton {
        const char *name;
        const unsigned char property;
        const unsigned char value_type;
    } attr_messageButton;
    const struct samsungTV_attr_switch {
        const char *name;
        const unsigned char property;
        const unsigned char value_type;
        const char *values[CAP_ENUM_SAMSUNGTV_SWITCH_VALUE_MAX];
    } attr_switch;
    const struct samsungTV_attr_mute {
        const char *name;
        const unsigned char property;
        const unsigned char value_type;
        const char *values[CAP_ENUM_SAMSUNGTV_MUTE_VALUE_MAX];
    } attr_mute;
    const struct samsungTV_attr_pictureMode {
        const char *name;
        const unsigned char property;
        const unsigned char value_type;
        const char *values[CAP_ENUM_SAMSUNGTV_PICTUREMODE_VALUE_MAX];
    } attr_pictureMode;
    const struct samsungTV_attr_soundMode {
        const char *name;
        const unsigned char property;
        const unsigned char value_type;
        const char *values[CAP_ENUM_SAMSUNGTV_SOUNDMODE_VALUE_MAX];
    } attr_soundMode;
    const struct samsungTV_cmd_on { const char* name; } cmd_on;
    const struct samsungTV_cmd_off { const char* name; } cmd_off;
    const struct samsungTV_cmd_mute { const char* name; } cmd_mute;
    const struct samsungTV_cmd_unmute { const char* name; } cmd_unmute;
    const struct samsungTV_cmd_setPictureMode { const char* name; } cmd_setPictureMode;
    const struct samsungTV_cmd_setSoundMode { const char* name; } cmd_setSoundMode;
    const struct samsungTV_cmd_volumeDown { const char* name; } cmd_volumeDown;
    const struct samsungTV_cmd_showMessage { const char* name; } cmd_showMessage;
    const struct samsungTV_cmd_volumeUp { const char* name; } cmd_volumeUp;
    const struct samsungTV_cmd_setVolume { const char* name; } cmd_setVolume;
} caps_helper_samsungTV = {
    .id = "samsungTV",
    .attr_volume = {
        .name = "volume",
        .property = ATTR_SET_VALUE_MIN,
        .value_type = VALUE_TYPE_INTEGER,
        .min = 0,
    },
    .attr_messageButton = {
        .name = "messageButton",
        .property = NULL,
        .value_type = VALUE_TYPE_OBJECT,
    },
    .attr_switch = {
        .name = "switch",
        .property = NULL,
        .value_type = VALUE_TYPE_STRING,
        .values = {"on", "off"},
    },
    .attr_mute = {
        .name = "mute",
        .property = NULL,
        .value_type = VALUE_TYPE_STRING,
        .values = {"muted", "unknown", "unmuted"},
    },
    .attr_pictureMode = {
        .name = "pictureMode",
        .property = NULL,
        .value_type = VALUE_TYPE_STRING,
        .values = {"dynamic", "movie", "standard", "unknown"},
    },
    .attr_soundMode = {
        .name = "soundMode",
        .property = NULL,
        .value_type = VALUE_TYPE_STRING,
        .values = {"clear voice", "movie", "music", "standard", "unknown"},
    },
    .cmd_on = { .name = "on" },
    .cmd_off = { .name = "off" },
    .cmd_mute = { .name = "mute" },
    .cmd_unmute = { .name = "unmute" },
    .cmd_setPictureMode = { .name = "setPictureMode" }, // arguments: pictureMode(string) 
    .cmd_setSoundMode = { .name = "setSoundMode" }, // arguments: soundMode(string) 
    .cmd_volumeDown = { .name = "volumeDown" },
    .cmd_showMessage = { .name = "showMessage" }, // arguments: 1(string) 2(string) 3(string) 4(string) 
    .cmd_volumeUp = { .name = "volumeUp" },
    .cmd_setVolume = { .name = "setVolume" }, // arguments: volume(integer) 
};

#endif /* _IOT_CAPS_HERLPER_SAMSUNG_TV_ */
