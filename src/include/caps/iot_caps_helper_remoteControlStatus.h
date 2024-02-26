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

#ifndef _IOT_CAPS_HELPER_REMOTE_CONTROL_STATUS_
#define _IOT_CAPS_HELPER_REMOTE_CONTROL_STATUS_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_REMOTECONTROLSTATUS_REMOTECONTROLENABLED_VALUE_TRUE,
    CAP_ENUM_REMOTECONTROLSTATUS_REMOTECONTROLENABLED_VALUE_FALSE,
    CAP_ENUM_REMOTECONTROLSTATUS_REMOTECONTROLENABLED_VALUE_MAX,
};

const static struct iot_caps_remoteControlStatus {
    const char *id;
    const struct remoteControlStatus_attr_remoteControlEnabled {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_REMOTECONTROLSTATUS_REMOTECONTROLENABLED_VALUE_MAX];
        const char *value_true;
        const char *value_false;
    } attr_remoteControlEnabled;
} caps_helper_remoteControlStatus = {
    .id = "remoteControlStatus",
    .attr_remoteControlEnabled = {
        .name = "remoteControlEnabled",
        .property = ATTR_SET_VALUE_REQUIRED,
        .valueType = VALUE_TYPE_STRING,
        .values = {"true", "false"},
        .value_true = "true",
        .value_false = "false",
    },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HELPER_REMOTE_CONTROL_STATUS_ */
