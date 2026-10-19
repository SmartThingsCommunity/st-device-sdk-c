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

#ifndef _IOT_CAPS_HELPER_DOOR_STATE_
#define _IOT_CAPS_HELPER_DOOR_STATE_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_DOORSTATE_DOORSTATE_VALUE_OPEN,
    CAP_ENUM_DOORSTATE_DOORSTATE_VALUE_CLOSED,
    CAP_ENUM_DOORSTATE_DOORSTATE_VALUE_JAMMED,
    CAP_ENUM_DOORSTATE_DOORSTATE_VALUE_FORCEDOPEN,
    CAP_ENUM_DOORSTATE_DOORSTATE_VALUE_UNSPECIFIEDERROR,
    CAP_ENUM_DOORSTATE_DOORSTATE_VALUE_AJAR,
    CAP_ENUM_DOORSTATE_DOORSTATE_VALUE_MAX
};

enum {
    CAP_ENUM_DOORSTATE_SUPPORTEDDOORSTATES_VALUE_OPEN,
    CAP_ENUM_DOORSTATE_SUPPORTEDDOORSTATES_VALUE_CLOSED,
    CAP_ENUM_DOORSTATE_SUPPORTEDDOORSTATES_VALUE_JAMMED,
    CAP_ENUM_DOORSTATE_SUPPORTEDDOORSTATES_VALUE_FORCEDOPEN,
    CAP_ENUM_DOORSTATE_SUPPORTEDDOORSTATES_VALUE_UNSPECIFIEDERROR,
    CAP_ENUM_DOORSTATE_SUPPORTEDDOORSTATES_VALUE_AJAR,
    CAP_ENUM_DOORSTATE_SUPPORTEDDOORSTATES_VALUE_MAX
};

const static struct iot_caps_doorState {
    const char *id;
    const struct doorState_attr_doorState {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_DOORSTATE_DOORSTATE_VALUE_MAX];
        const char *value_open;
        const char *value_closed;
        const char *value_jammed;
        const char *value_forcedOpen;
        const char *value_unspecifiedError;
        const char *value_ajar;
    } attr_doorState;
    const struct doorState_attr_supportedDoorStates {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_DOORSTATE_SUPPORTEDDOORSTATES_VALUE_MAX];
        const char *value_open;
        const char *value_closed;
        const char *value_jammed;
        const char *value_forcedOpen;
        const char *value_unspecifiedError;
        const char *value_ajar;
    } attr_supportedDoorStates;
} caps_helper_doorState = {
    .id = "doorState",
    .attr_doorState =
        {
            .name = "doorState",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"open", "closed", "jammed", "forcedOpen", "unspecifiedError", "ajar"},
            .value_open = "open",
            .value_closed = "closed",
            .value_jammed = "jammed",
            .value_forcedOpen = "forcedOpen",
            .value_unspecifiedError = "unspecifiedError",
            .value_ajar = "ajar",
        },
    .attr_supportedDoorStates =
        {
            .name = "supportedDoorStates",
            .property = ATTR_SET_VALUE_ARRAY | ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"open", "closed", "jammed", "forcedOpen", "unspecifiedError", "ajar"},
            .value_open = "open",
            .value_closed = "closed",
            .value_jammed = "jammed",
            .value_forcedOpen = "forcedOpen",
            .value_unspecifiedError = "unspecifiedError",
            .value_ajar = "ajar",
        },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_DOOR_STATE_ */
