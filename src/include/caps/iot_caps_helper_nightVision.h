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

#ifndef _IOT_CAPS_HELPER_NIGHT_VISION_
#define _IOT_CAPS_HELPER_NIGHT_VISION_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_NIGHTVISION_NIGHTVISION_VALUE_ON,
    CAP_ENUM_NIGHTVISION_NIGHTVISION_VALUE_OFF,
    CAP_ENUM_NIGHTVISION_NIGHTVISION_VALUE_AUTO,
    CAP_ENUM_NIGHTVISION_NIGHTVISION_VALUE_MAX
};

enum {
    CAP_ENUM_NIGHTVISION_NIGHTVISIONMODE_VALUE_COLOR,
    CAP_ENUM_NIGHTVISION_NIGHTVISIONMODE_VALUE_BLACKANDWHITE,
    CAP_ENUM_NIGHTVISION_NIGHTVISIONMODE_VALUE_MAX
};

enum {
    CAP_ENUM_NIGHTVISION_ILLUMINATION_VALUE_ON,
    CAP_ENUM_NIGHTVISION_ILLUMINATION_VALUE_OFF,
    CAP_ENUM_NIGHTVISION_ILLUMINATION_VALUE_AUTO,
    CAP_ENUM_NIGHTVISION_ILLUMINATION_VALUE_MAX
};

enum {
    CAP_ENUM_NIGHTVISION_SUPPORTEDATTRIBUTES_VALUE_ILLUMINATION,
    CAP_ENUM_NIGHTVISION_SUPPORTEDATTRIBUTES_VALUE_NIGHTVISIONMODE,
    CAP_ENUM_NIGHTVISION_SUPPORTEDATTRIBUTES_VALUE_MAX
};

const static struct iot_caps_nightVision {
    const char *id;
    const struct nightVision_attr_nightVision {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_NIGHTVISION_NIGHTVISION_VALUE_MAX];
        const char *value_on;
        const char *value_off;
        const char *value_auto;
    } attr_nightVision;
    const struct nightVision_attr_nightVisionMode {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_NIGHTVISION_NIGHTVISIONMODE_VALUE_MAX];
        const char *value_Color;
        const char *value_BlackAndWhite;
    } attr_nightVisionMode;
    const struct nightVision_attr_illumination {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_NIGHTVISION_ILLUMINATION_VALUE_MAX];
        const char *value_on;
        const char *value_off;
        const char *value_auto;
    } attr_illumination;
    const struct nightVision_attr_supportedAttributes {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_NIGHTVISION_SUPPORTEDATTRIBUTES_VALUE_MAX];
        const char *value_illumination;
        const char *value_nightVisionMode;
    } attr_supportedAttributes;
    const struct nightVision_cmd_setNightVision {
        const char *name;
    } cmd_setNightVision;
    const struct nightVision_cmd_setNightVisionMode {
        const char *name;
    } cmd_setNightVisionMode;
    const struct nightVision_cmd_setIllumination {
        const char *name;
    } cmd_setIllumination;
} caps_helper_nightVision = {
    .id = "nightVision",
    .attr_nightVision =
        {
            .name = "nightVision",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"on", "off", "auto"},
            .value_on = "on",
            .value_off = "off",
            .value_auto = "auto",
        },
    .attr_nightVisionMode =
        {
            .name = "nightVisionMode",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"Color", "BlackAndWhite"},
            .value_Color = "Color",
            .value_BlackAndWhite = "BlackAndWhite",
        },
    .attr_illumination =
        {
            .name = "illumination",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"on", "off", "auto"},
            .value_on = "on",
            .value_off = "off",
            .value_auto = "auto",
        },
    .attr_supportedAttributes =
        {
            .name = "supportedAttributes",
            .property = ATTR_SET_VALUE_ARRAY | ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"illumination", "nightVisionMode"},
            .value_illumination = "illumination",
            .value_nightVisionMode = "nightVisionMode",
        },
    .cmd_setNightVision = {.name = "setNightVision"},          // arguments: mode(string)
    .cmd_setNightVisionMode = {.name = "setNightVisionMode"},  // arguments: mode(string)
    .cmd_setIllumination = {.name = "setIllumination"},        // arguments: mode(string)
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_NIGHT_VISION_ */
