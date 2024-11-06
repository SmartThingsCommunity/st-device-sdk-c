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

#ifndef _IOT_CAPS_HELPER_MEDIA_INPUT_SOURCE_
#define _IOT_CAPS_HELPER_MEDIA_INPUT_SOURCE_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_MEDIAINPUTSOURCE_INPUTSOURCE_VALUE_AM,
    CAP_ENUM_MEDIAINPUTSOURCE_INPUTSOURCE_VALUE_CD,
    CAP_ENUM_MEDIAINPUTSOURCE_INPUTSOURCE_VALUE_FM,
    CAP_ENUM_MEDIAINPUTSOURCE_INPUTSOURCE_VALUE_HDMI,
    CAP_ENUM_MEDIAINPUTSOURCE_INPUTSOURCE_VALUE_HDMI1,
    CAP_ENUM_MEDIAINPUTSOURCE_INPUTSOURCE_VALUE_HDMI2,
    CAP_ENUM_MEDIAINPUTSOURCE_INPUTSOURCE_VALUE_HDMI3,
    CAP_ENUM_MEDIAINPUTSOURCE_INPUTSOURCE_VALUE_HDMI4,
    CAP_ENUM_MEDIAINPUTSOURCE_INPUTSOURCE_VALUE_HDMI5,
    CAP_ENUM_MEDIAINPUTSOURCE_INPUTSOURCE_VALUE_HDMI6,
    CAP_ENUM_MEDIAINPUTSOURCE_INPUTSOURCE_VALUE_DIGITALTV,
    CAP_ENUM_MEDIAINPUTSOURCE_INPUTSOURCE_VALUE_USB,
    CAP_ENUM_MEDIAINPUTSOURCE_INPUTSOURCE_VALUE_YOUTUBE,
    CAP_ENUM_MEDIAINPUTSOURCE_INPUTSOURCE_VALUE_AUX,
    CAP_ENUM_MEDIAINPUTSOURCE_INPUTSOURCE_VALUE_BLUETOOTH,
    CAP_ENUM_MEDIAINPUTSOURCE_INPUTSOURCE_VALUE_DIGITAL,
    CAP_ENUM_MEDIAINPUTSOURCE_INPUTSOURCE_VALUE_MELON,
    CAP_ENUM_MEDIAINPUTSOURCE_INPUTSOURCE_VALUE_WIFI,
    CAP_ENUM_MEDIAINPUTSOURCE_INPUTSOURCE_VALUE_MAX
};

#define CAP_ENUM_MEDIAINPUTSOURCE_SUPPORTEDINPUTSOURCES_VALUE_MAX 18
const static struct iot_caps_mediaInputSource {
    const char *id;
    const struct mediaInputSource_attr_inputSource {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_MEDIAINPUTSOURCE_INPUTSOURCE_VALUE_MAX];
        const char *value_AM;
        const char *value_CD;
        const char *value_FM;
        const char *value_HDMI;
        const char *value_HDMI1;
        const char *value_HDMI2;
        const char *value_HDMI3;
        const char *value_HDMI4;
        const char *value_HDMI5;
        const char *value_HDMI6;
        const char *value_digitalTv;
        const char *value_USB;
        const char *value_YouTube;
        const char *value_aux;
        const char *value_bluetooth;
        const char *value_digital;
        const char *value_melon;
        const char *value_wifi;
    } attr_inputSource;
    const struct mediaInputSource_attr_supportedInputSources {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_MEDIAINPUTSOURCE_SUPPORTEDINPUTSOURCES_VALUE_MAX];
        const char *value_AM;
        const char *value_CD;
        const char *value_FM;
        const char *value_HDMI;
        const char *value_HDMI1;
        const char *value_HDMI2;
        const char *value_HDMI3;
        const char *value_HDMI4;
        const char *value_HDMI5;
        const char *value_HDMI6;
        const char *value_digitalTv;
        const char *value_USB;
        const char *value_YouTube;
        const char *value_aux;
        const char *value_bluetooth;
        const char *value_digital;
        const char *value_melon;
        const char *value_wifi;
    } attr_supportedInputSources;
    const struct mediaInputSource_cmd_setInputSource { const char* name; } cmd_setInputSource;
} caps_helper_mediaInputSource = {
    .id = "mediaInputSource",
    .attr_inputSource = {
        .name = "inputSource",
        .property = ATTR_SET_VALUE_REQUIRED,
        .valueType = VALUE_TYPE_STRING,
        .values = {"AM", "CD", "FM", "HDMI", "HDMI1", "HDMI2", "HDMI3", "HDMI4", "HDMI5", "HDMI6", "digitalTv", "USB", "YouTube", "aux", "bluetooth", "digital", "melon", "wifi"},
        .value_AM = "AM",
        .value_CD = "CD",
        .value_FM = "FM",
        .value_HDMI = "HDMI",
        .value_HDMI1 = "HDMI1",
        .value_HDMI2 = "HDMI2",
        .value_HDMI3 = "HDMI3",
        .value_HDMI4 = "HDMI4",
        .value_HDMI5 = "HDMI5",
        .value_HDMI6 = "HDMI6",
        .value_digitalTv = "digitalTv",
        .value_USB = "USB",
        .value_YouTube = "YouTube",
        .value_aux = "aux",
        .value_bluetooth = "bluetooth",
        .value_digital = "digital",
        .value_melon = "melon",
        .value_wifi = "wifi",
    },
    .attr_supportedInputSources = {
        .name = "supportedInputSources",
        .property = ATTR_SET_VALUE_REQUIRED | ATTR_SET_VALUE_ARRAY,
        .valueType = VALUE_TYPE_STRING,
        .values = {"AM", "CD", "FM", "HDMI", "HDMI1", "HDMI2", "HDMI3", "HDMI4", "HDMI5", "HDMI6", "digitalTv", "USB", "YouTube", "aux", "bluetooth", "digital", "melon", "wifi"},
        .value_AM = "AM",
        .value_CD = "CD",
        .value_FM = "FM",
        .value_HDMI = "HDMI",
        .value_HDMI1 = "HDMI1",
        .value_HDMI2 = "HDMI2",
        .value_HDMI3 = "HDMI3",
        .value_HDMI4 = "HDMI4",
        .value_HDMI5 = "HDMI5",
        .value_HDMI6 = "HDMI6",
        .value_digitalTv = "digitalTv",
        .value_USB = "USB",
        .value_YouTube = "YouTube",
        .value_aux = "aux",
        .value_bluetooth = "bluetooth",
        .value_digital = "digital",
        .value_melon = "melon",
        .value_wifi = "wifi",
    },
    .cmd_setInputSource = { .name = "setInputSource" }, // arguments: mode(string) 
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_MEDIA_INPUT_SOURCE_ */
