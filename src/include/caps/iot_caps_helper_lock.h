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

#ifndef _IOT_CAPS_HELPER_LOCK_
#define _IOT_CAPS_HELPER_LOCK_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_LOCK_LOCK_VALUE_LOCKED,
    CAP_ENUM_LOCK_LOCK_VALUE_UNKNOWN,
    CAP_ENUM_LOCK_LOCK_VALUE_UNLOCKED,
    CAP_ENUM_LOCK_LOCK_VALUE_UNLOCKED_WITH_TIMEOUT,
    CAP_ENUM_LOCK_LOCK_VALUE_MAX
};

const static struct iot_caps_lock {
    const char *id;
    const struct lock_attr_lock {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_LOCK_LOCK_VALUE_MAX];
        const char *value_locked;
        const char *value_unknown;
        const char *value_unlocked;
        const char *value_unlocked_with_timeout;
    } attr_lock;
    const struct lock_cmd_lock { const char* name; } cmd_lock;
    const struct lock_cmd_unlock { const char* name; } cmd_unlock;
} caps_helper_lock = {
    .id = "lock",
    .attr_lock = {
        .name = "lock",
        .property = ATTR_SET_VALUE_REQUIRED,
        .valueType = VALUE_TYPE_STRING,
        .values = {"locked", "unknown", "unlocked", "unlocked with timeout"},
        .value_locked = "locked",
        .value_unknown = "unknown",
        .value_unlocked = "unlocked",
        .value_unlocked_with_timeout = "unlocked with timeout",
    },
    .cmd_lock = { .name = "lock" },
    .cmd_unlock = { .name = "unlock" },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_LOCK_ */
