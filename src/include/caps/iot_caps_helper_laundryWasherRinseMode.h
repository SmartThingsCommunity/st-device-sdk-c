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

#ifndef _IOT_CAPS_HELPER_LAUNDRY_WASHER_RINSE_MODE_
#define _IOT_CAPS_HELPER_LAUNDRY_WASHER_RINSE_MODE_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CAP_ENUM_LAUNDRYWASHERRINSEMODE_SUPPORTEDRINSEMODES_VALUE_MAX 4
enum {
    CAP_ENUM_LAUNDRYWASHERRINSEMODE_RINSEMODE_VALUE_NONE,
    CAP_ENUM_LAUNDRYWASHERRINSEMODE_RINSEMODE_VALUE_NORMAL,
    CAP_ENUM_LAUNDRYWASHERRINSEMODE_RINSEMODE_VALUE_EXTRA,
    CAP_ENUM_LAUNDRYWASHERRINSEMODE_RINSEMODE_VALUE_MAX,
    CAP_ENUM_LAUNDRYWASHERRINSEMODE_RINSEMODE_VALUE_COUNT
};

const static struct iot_caps_laundryWasherRinseMode {
    const char *id;
    const struct laundryWasherRinseMode_attr_rinseMode {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_LAUNDRYWASHERRINSEMODE_RINSEMODE_VALUE_COUNT];
        const char *value_none;
        const char *value_normal;
        const char *value_extra;
        const char *value_max;
    } attr_rinseMode;
    const struct laundryWasherRinseMode_attr_supportedRinseModes {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_LAUNDRYWASHERRINSEMODE_SUPPORTEDRINSEMODES_VALUE_MAX];
        const char *value_none;
        const char *value_normal;
        const char *value_extra;
        const char *value_max;
    } attr_supportedRinseModes;
    const struct laundryWasherRinseMode_cmd_setRinseMode {
        const char *name;
    } cmd_setRinseMode;
} caps_helper_laundryWasherRinseMode = {
    .id = "laundryWasherRinseMode",
    .attr_rinseMode =
        {
            .name = "rinseMode",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"none", "normal", "extra", "max"},
            .value_none = "none",
            .value_normal = "normal",
            .value_extra = "extra",
            .value_max = "max",
        },
    .attr_supportedRinseModes =
        {
            .name = "supportedRinseModes",
            .property = ATTR_SET_VALUE_REQUIRED | ATTR_SET_VALUE_ARRAY,
            .valueType = VALUE_TYPE_STRING,
            .values = {"none", "normal", "extra", "max"},
            .value_none = "none",
            .value_normal = "normal",
            .value_extra = "extra",
            .value_max = "max",
        },
    .cmd_setRinseMode = {.name = "setRinseMode"},  // arguments: rinseMode(string)
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_LAUNDRY_WASHER_RINSE_MODE_ */
