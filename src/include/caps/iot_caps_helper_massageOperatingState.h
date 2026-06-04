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

#ifndef _IOT_CAPS_HELPER_MASSAGE_OPERATING_STATE_
#define _IOT_CAPS_HELPER_MASSAGE_OPERATING_STATE_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_MASSAGEOPERATINGSTATE_MASSAGESTATE_VALUE_OFF,
    CAP_ENUM_MASSAGEOPERATINGSTATE_MASSAGESTATE_VALUE_ON,
    CAP_ENUM_MASSAGEOPERATINGSTATE_MASSAGESTATE_VALUE_MAX
};

const static struct iot_caps_massageOperatingState {
    const char *id;
    const struct massageOperatingState_attr_massageState {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_MASSAGEOPERATINGSTATE_MASSAGESTATE_VALUE_MAX];
        const char *value_off;
        const char *value_on;
    } attr_massageState;
} caps_helper_massageOperatingState = {
    .id = "massageOperatingState",
    .attr_massageState =
        {
            .name = "massageState",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"off", "on"},
            .value_off = "off",
            .value_on = "on",
        },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_MASSAGE_OPERATING_STATE_ */
