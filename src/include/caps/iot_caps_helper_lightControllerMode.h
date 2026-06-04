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

#ifndef _IOT_CAPS_HELPER_LIGHT_CONTROLLER_MODE_
#define _IOT_CAPS_HELPER_LIGHT_CONTROLLER_MODE_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_LIGHTCONTROLLERMODE_LIGHTCONTROLLERMODE_VALUE_RGBW,
    CAP_ENUM_LIGHTCONTROLLERMODE_LIGHTCONTROLLERMODE_VALUE_RGB,
    CAP_ENUM_LIGHTCONTROLLERMODE_LIGHTCONTROLLERMODE_VALUE_COLORTEMPERATURE,
    CAP_ENUM_LIGHTCONTROLLERMODE_LIGHTCONTROLLERMODE_VALUE_DIMMER,
    CAP_ENUM_LIGHTCONTROLLERMODE_LIGHTCONTROLLERMODE_VALUE_MAX
};

enum {
    CAP_ENUM_LIGHTCONTROLLERMODE_SUPPORTEDLIGHTCONTROLLERMODES_VALUE_RGBW,
    CAP_ENUM_LIGHTCONTROLLERMODE_SUPPORTEDLIGHTCONTROLLERMODES_VALUE_RGB,
    CAP_ENUM_LIGHTCONTROLLERMODE_SUPPORTEDLIGHTCONTROLLERMODES_VALUE_COLORTEMPERATURE,
    CAP_ENUM_LIGHTCONTROLLERMODE_SUPPORTEDLIGHTCONTROLLERMODES_VALUE_DIMMER,
    CAP_ENUM_LIGHTCONTROLLERMODE_SUPPORTEDLIGHTCONTROLLERMODES_VALUE_MAX
};

const static struct iot_caps_lightControllerMode {
    const char *id;
    const struct lightControllerMode_attr_lightControllerMode {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_LIGHTCONTROLLERMODE_LIGHTCONTROLLERMODE_VALUE_MAX];
        const char *value_rgbw;
        const char *value_rgb;
        const char *value_colorTemperature;
        const char *value_dimmer;
    } attr_lightControllerMode;
    const struct lightControllerMode_attr_supportedLightControllerModes {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_LIGHTCONTROLLERMODE_SUPPORTEDLIGHTCONTROLLERMODES_VALUE_MAX];
        const char *value_rgbw;
        const char *value_rgb;
        const char *value_colorTemperature;
        const char *value_dimmer;
    } attr_supportedLightControllerModes;
    const struct lightControllerMode_cmd_setLightControllerMode {
        const char *name;
    } cmd_setLightControllerMode;
} caps_helper_lightControllerMode = {
    .id = "lightControllerMode",
    .attr_lightControllerMode =
        {
            .name = "lightControllerMode",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"rgbw", "rgb", "colorTemperature", "dimmer"},
            .value_rgbw = "rgbw",
            .value_rgb = "rgb",
            .value_colorTemperature = "colorTemperature",
            .value_dimmer = "dimmer",
        },
    .attr_supportedLightControllerModes =
        {
            .name = "supportedLightControllerModes",
            .property = ATTR_SET_VALUE_ARRAY,
            .valueType = VALUE_TYPE_STRING,
            .values = {"rgbw", "rgb", "colorTemperature", "dimmer"},
            .value_rgbw = "rgbw",
            .value_rgb = "rgb",
            .value_colorTemperature = "colorTemperature",
            .value_dimmer = "dimmer",
        },
    .cmd_setLightControllerMode = {.name = "setLightControllerMode"},  // arguments: mode(string)
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_LIGHT_CONTROLLER_MODE_ */
