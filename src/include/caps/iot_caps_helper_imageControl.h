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

#ifndef _IOT_CAPS_HELPER_IMAGE_CONTROL_
#define _IOT_CAPS_HELPER_IMAGE_CONTROL_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_IMAGECONTROL_IMAGEFLIPHORIZONTAL_VALUE_ENABLED,
    CAP_ENUM_IMAGECONTROL_IMAGEFLIPHORIZONTAL_VALUE_DISABLED,
    CAP_ENUM_IMAGECONTROL_IMAGEFLIPHORIZONTAL_VALUE_MAX
};

enum {
    CAP_ENUM_IMAGECONTROL_IMAGEFLIPVERTICAL_VALUE_ENABLED,
    CAP_ENUM_IMAGECONTROL_IMAGEFLIPVERTICAL_VALUE_DISABLED,
    CAP_ENUM_IMAGECONTROL_IMAGEFLIPVERTICAL_VALUE_MAX
};

enum { CAP_ENUM_IMAGECONTROL_IMAGEROTATION_UNIT_DEGREE, CAP_ENUM_IMAGECONTROL_IMAGEROTATION_UNIT_MAX };

enum {
    CAP_ENUM_IMAGECONTROL_SUPPORTEDATTRIBUTES_VALUE_IMAGEFLIPHORIZONTAL,
    CAP_ENUM_IMAGECONTROL_SUPPORTEDATTRIBUTES_VALUE_IMAGEFLIPVERTICAL,
    CAP_ENUM_IMAGECONTROL_SUPPORTEDATTRIBUTES_VALUE_IMAGEROTATION,
    CAP_ENUM_IMAGECONTROL_SUPPORTEDATTRIBUTES_VALUE_MAX
};

const static struct iot_caps_imageControl {
    const char *id;
    const struct imageControl_attr_imageFlipHorizontal {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_IMAGECONTROL_IMAGEFLIPHORIZONTAL_VALUE_MAX];
        const char *value_enabled;
        const char *value_disabled;
    } attr_imageFlipHorizontal;
    const struct imageControl_attr_imageFlipVertical {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_IMAGECONTROL_IMAGEFLIPVERTICAL_VALUE_MAX];
        const char *value_enabled;
        const char *value_disabled;
    } attr_imageFlipVertical;
    const struct imageControl_attr_imageRotation {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *units[CAP_ENUM_IMAGECONTROL_IMAGEROTATION_UNIT_MAX];
        const char *unit_degree;
        const int min;
        const int max;
    } attr_imageRotation;
    const struct imageControl_attr_supportedAttributes {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_IMAGECONTROL_SUPPORTEDATTRIBUTES_VALUE_MAX];
        const char *value_imageFlipHorizontal;
        const char *value_imageFlipVertical;
        const char *value_imageRotation;
    } attr_supportedAttributes;
    const struct imageControl_cmd_setImageFlipHorizontal {
        const char *name;
    } cmd_setImageFlipHorizontal;
    const struct imageControl_cmd_setImageFlipVertical {
        const char *name;
    } cmd_setImageFlipVertical;
    const struct imageControl_cmd_setImageRotation {
        const char *name;
    } cmd_setImageRotation;
} caps_helper_imageControl = {
    .id = "imageControl",
    .attr_imageFlipHorizontal =
        {
            .name = "imageFlipHorizontal",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"enabled", "disabled"},
            .value_enabled = "enabled",
            .value_disabled = "disabled",
        },
    .attr_imageFlipVertical =
        {
            .name = "imageFlipVertical",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"enabled", "disabled"},
            .value_enabled = "enabled",
            .value_disabled = "disabled",
        },
    .attr_imageRotation =
        {
            .name = "imageRotation",
            .property = ATTR_SET_VALUE_MIN | ATTR_SET_VALUE_MAX | ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_INTEGER,
            .units = {"°"},
            .unit_degree = "°",
            .min = 0,
            .max = 359,
        },
    .attr_supportedAttributes =
        {
            .name = "supportedAttributes",
            .property = ATTR_SET_VALUE_ARRAY | ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"imageFlipHorizontal", "imageFlipVertical", "imageRotation"},
            .value_imageFlipHorizontal = "imageFlipHorizontal",
            .value_imageFlipVertical = "imageFlipVertical",
            .value_imageRotation = "imageRotation",
        },
    .cmd_setImageFlipHorizontal = {.name = "setImageFlipHorizontal"},  // arguments: state(string)
    .cmd_setImageFlipVertical = {.name = "setImageFlipVertical"},      // arguments: state(string)
    .cmd_setImageRotation = {.name = "setImageRotation"},              // arguments: rotation(integer)
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_IMAGE_CONTROL_ */
