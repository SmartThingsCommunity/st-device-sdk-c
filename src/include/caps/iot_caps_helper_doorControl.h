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

#ifndef _IOT_CAPS_HELPER_DOOR_CONTROL_
#define _IOT_CAPS_HELPER_DOOR_CONTROL_

#include "iot_caps_helper.h"

enum {
    CAP_ENUM_DOORCONTROL_DOOR_VALUE_CLOSED,
    CAP_ENUM_DOORCONTROL_DOOR_VALUE_CLOSING,
    CAP_ENUM_DOORCONTROL_DOOR_VALUE_OPEN,
    CAP_ENUM_DOORCONTROL_DOOR_VALUE_OPENING,
    CAP_ENUM_DOORCONTROL_DOOR_VALUE_UNKNOWN,
    CAP_ENUM_DOORCONTROL_DOOR_VALUE_MAX
};

const static struct iot_caps_doorControl {
    const char *id;
    const struct doorControl_attr_door {
        const char *name;
        const unsigned char property;
        const unsigned char value_type;
        const char *values[CAP_ENUM_DOORCONTROL_DOOR_VALUE_MAX];
    } attr_door;
    const struct doorControl_cmd_close { const char* name; } cmd_close;
    const struct doorControl_cmd_open { const char* name; } cmd_open;
} caps_helper_doorControl = {
    .id = "doorControl",
    .attr_door = {
        .name = "door",
        .property = ATTR_SET_VALUE_REQUIRED,
        .value_type = VALUE_TYPE_STRING,
        .values = {"closed", "closing", "open", "opening", "unknown"},
    },
    .cmd_close = { .name = "close" },
    .cmd_open = { .name = "open" },
};

#endif /* _IOT_CAPS_HERLPER_DOOR_CONTROL_ */
