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

#ifndef _IOT_CAPS_HELPER_BYPASSABLE_
#define _IOT_CAPS_HELPER_BYPASSABLE_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_BYPASSABLE_BYPASSSTATUS_VALUE_READY,
    CAP_ENUM_BYPASSABLE_BYPASSSTATUS_VALUE_NOTREADY,
    CAP_ENUM_BYPASSABLE_BYPASSSTATUS_VALUE_BYPASSED,
    CAP_ENUM_BYPASSABLE_BYPASSSTATUS_VALUE_MAX
};

const static struct iot_caps_bypassable {
    const char *id;
    const struct bypassable_attr_bypassStatus {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_BYPASSABLE_BYPASSSTATUS_VALUE_MAX];
        const char *value_ready;
        const char *value_notReady;
        const char *value_bypassed;
    } attr_bypassStatus;
} caps_helper_bypassable = {
    .id = "bypassable",
    .attr_bypassStatus =
        {
            .name = "bypassStatus",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"ready", "notReady", "bypassed"},
            .value_ready = "ready",
            .value_notReady = "notReady",
            .value_bypassed = "bypassed",
        },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_BYPASSABLE_ */
