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

#ifndef _IOT_CAPS_HELPER_PEST_CONTROL_
#define _IOT_CAPS_HELPER_PEST_CONTROL_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_PESTCONTROL_PESTCONTROL_VALUE_IDLE,
    CAP_ENUM_PESTCONTROL_PESTCONTROL_VALUE_TRAPARMED,
    CAP_ENUM_PESTCONTROL_PESTCONTROL_VALUE_TRAPREARMREQUIRED,
    CAP_ENUM_PESTCONTROL_PESTCONTROL_VALUE_PESTDETECTED,
    CAP_ENUM_PESTCONTROL_PESTCONTROL_VALUE_PESTEXTERMINATED,
    CAP_ENUM_PESTCONTROL_PESTCONTROL_VALUE_MAX
};

const static struct iot_caps_pestControl {
    const char *id;
    const struct pestControl_attr_pestControl {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_PESTCONTROL_PESTCONTROL_VALUE_MAX];
        const char *value_idle;
        const char *value_trapArmed;
        const char *value_trapRearmRequired;
        const char *value_pestDetected;
        const char *value_pestExterminated;
    } attr_pestControl;
} caps_helper_pestControl = {
    .id = "pestControl",
    .attr_pestControl =
        {
            .name = "pestControl",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"idle", "trapArmed", "trapRearmRequired", "pestDetected", "pestExterminated"},
            .value_idle = "idle",
            .value_trapArmed = "trapArmed",
            .value_trapRearmRequired = "trapRearmRequired",
            .value_pestDetected = "pestDetected",
            .value_pestExterminated = "pestExterminated",
        },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_PEST_CONTROL_ */
