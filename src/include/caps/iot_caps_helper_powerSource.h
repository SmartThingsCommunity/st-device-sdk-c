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

#ifndef _IOT_CAPS_HELPER_POWER_SOURCE_
#define _IOT_CAPS_HELPER_POWER_SOURCE_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_POWERSOURCE_POWERSOURCE_VALUE_BATTERY,
    CAP_ENUM_POWERSOURCE_POWERSOURCE_VALUE_DC,
    CAP_ENUM_POWERSOURCE_POWERSOURCE_VALUE_MAINS,
    CAP_ENUM_POWERSOURCE_POWERSOURCE_VALUE_UNKNOWN,
    CAP_ENUM_POWERSOURCE_POWERSOURCE_VALUE_MAX
};

const static struct iot_caps_powerSource {
    const char *id;
    const struct powerSource_attr_powerSource {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_POWERSOURCE_POWERSOURCE_VALUE_MAX];
        const char *value_battery;
        const char *value_dc;
        const char *value_mains;
        const char *value_unknown;
    } attr_powerSource;
} caps_helper_powerSource = {
    .id = "powerSource",
    .attr_powerSource = {
        .name = "powerSource",
        .property = ATTR_SET_VALUE_REQUIRED,
        .valueType = VALUE_TYPE_STRING,
        .values = {"battery", "dc", "mains", "unknown"},
        .value_battery = "battery",
        .value_dc = "dc",
        .value_mains = "mains",
        .value_unknown = "unknown",
    },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_POWER_SOURCE_ */
