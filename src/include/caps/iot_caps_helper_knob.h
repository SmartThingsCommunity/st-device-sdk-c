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

#ifndef _IOT_CAPS_HELPER_KNOB_
#define _IOT_CAPS_HELPER_KNOB_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum { CAP_ENUM_KNOB_ROTATEAMOUNT_UNIT_PERCENT, CAP_ENUM_KNOB_ROTATEAMOUNT_UNIT_MAX };

enum { CAP_ENUM_KNOB_HELDROTATEAMOUNT_UNIT_PERCENT, CAP_ENUM_KNOB_HELDROTATEAMOUNT_UNIT_MAX };

enum {
    CAP_ENUM_KNOB_SUPPORTEDATTRIBUTES_VALUE_ROTATEAMOUNT,
    CAP_ENUM_KNOB_SUPPORTEDATTRIBUTES_VALUE_HELDROTATEAMOUNT,
    CAP_ENUM_KNOB_SUPPORTEDATTRIBUTES_VALUE_MAX
};

const static struct iot_caps_knob {
    const char *id;
    const struct knob_attr_rotateAmount {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *units[CAP_ENUM_KNOB_ROTATEAMOUNT_UNIT_MAX];
        const char *unit_percent;
        const int min;
        const int max;
    } attr_rotateAmount;
    const struct knob_attr_heldRotateAmount {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *units[CAP_ENUM_KNOB_HELDROTATEAMOUNT_UNIT_MAX];
        const char *unit_percent;
        const int min;
        const int max;
    } attr_heldRotateAmount;
    const struct knob_attr_supportedAttributes {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_KNOB_SUPPORTEDATTRIBUTES_VALUE_MAX];
        const char *value_rotateAmount;
        const char *value_heldRotateAmount;
    } attr_supportedAttributes;
} caps_helper_knob = {
    .id = "knob",
    .attr_rotateAmount =
        {
            .name = "rotateAmount",
            .property = ATTR_SET_VALUE_MIN | ATTR_SET_VALUE_MAX | ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_INTEGER,
            .units = {"%"},
            .unit_percent = "%",
            .min = -100,
            .max = 100,
        },
    .attr_heldRotateAmount =
        {
            .name = "heldRotateAmount",
            .property = ATTR_SET_VALUE_MIN | ATTR_SET_VALUE_MAX | ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_INTEGER,
            .units = {"%"},
            .unit_percent = "%",
            .min = -100,
            .max = 100,
        },
    .attr_supportedAttributes =
        {
            .name = "supportedAttributes",
            .property = ATTR_SET_VALUE_ARRAY,
            .valueType = VALUE_TYPE_STRING,
            .values = {"rotateAmount", "heldRotateAmount"},
            .value_rotateAmount = "rotateAmount",
            .value_heldRotateAmount = "heldRotateAmount",
        },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_KNOB_ */
