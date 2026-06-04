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

#ifndef _IOT_CAPS_HELPER_SWITCH_STATE_
#define _IOT_CAPS_HELPER_SWITCH_STATE_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_SWITCHSTATE_SWITCHSTATE_VALUE_ON,
    CAP_ENUM_SWITCHSTATE_SWITCHSTATE_VALUE_OFF,
    CAP_ENUM_SWITCHSTATE_SWITCHSTATE_VALUE_MAX
};

const static struct iot_caps_switchState {
    const char *id;
    const struct switchState_attr_switchState {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_SWITCHSTATE_SWITCHSTATE_VALUE_MAX];
        const char *value_on;
        const char *value_off;
    } attr_switchState;
} caps_helper_switchState = {
    .id = "switchState",
    .attr_switchState =
        {
            .name = "switchState",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"on", "off"},
            .value_on = "on",
            .value_off = "off",
        },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_SWITCH_STATE_ */
