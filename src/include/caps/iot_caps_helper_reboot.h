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

#ifndef _IOT_CAPS_HELPER_REBOOT_
#define _IOT_CAPS_HELPER_REBOOT_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_REBOOT_REBOOTSTATE_VALUE_INPROGRESS,
    CAP_ENUM_REBOOT_REBOOTSTATE_VALUE_IDLE,
    CAP_ENUM_REBOOT_REBOOTSTATE_VALUE_MAX
};

const static struct iot_caps_reboot {
    const char *id;
    const struct reboot_attr_rebootState {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_REBOOT_REBOOTSTATE_VALUE_MAX];
        const char *value_inProgress;
        const char *value_idle;
    } attr_rebootState;
    const struct reboot_cmd_reboot {
        const char *name;
    } cmd_reboot;
} caps_helper_reboot = {
    .id = "reboot",
    .attr_rebootState =
        {
            .name = "rebootState",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"inProgress", "idle"},
            .value_inProgress = "inProgress",
            .value_idle = "idle",
        },
    .cmd_reboot = {.name = "reboot"},
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_REBOOT_ */
