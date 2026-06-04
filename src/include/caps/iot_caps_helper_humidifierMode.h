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

#ifndef _IOT_CAPS_HELPER_HUMIDIFIER_MODE_
#define _IOT_CAPS_HELPER_HUMIDIFIER_MODE_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_HUMIDIFIERMODE_HUMIDIFIERMODE_VALUE_AUTO,
    CAP_ENUM_HUMIDIFIERMODE_HUMIDIFIERMODE_VALUE_LOW,
    CAP_ENUM_HUMIDIFIERMODE_HUMIDIFIERMODE_VALUE_MEDIUM,
    CAP_ENUM_HUMIDIFIERMODE_HUMIDIFIERMODE_VALUE_HIGH,
    CAP_ENUM_HUMIDIFIERMODE_HUMIDIFIERMODE_VALUE_MAX
};

const static struct iot_caps_humidifierMode {
    const char *id;
    const struct humidifierMode_attr_humidifierMode {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_HUMIDIFIERMODE_HUMIDIFIERMODE_VALUE_MAX];
        const char *value_auto;
        const char *value_low;
        const char *value_medium;
        const char *value_high;
    } attr_humidifierMode;
    const struct humidifierMode_cmd_setHumidifierMode {
        const char *name;
    } cmd_setHumidifierMode;
} caps_helper_humidifierMode = {
    .id = "humidifierMode",
    .attr_humidifierMode =
        {
            .name = "humidifierMode",
            .property = 0,
            .valueType = VALUE_TYPE_STRING,
            .values = {"auto", "low", "medium", "high"},
            .value_auto = "auto",
            .value_low = "low",
            .value_medium = "medium",
            .value_high = "high",
        },
    .cmd_setHumidifierMode = {.name = "setHumidifierMode"},  // arguments: humidifierMode(string)
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_HUMIDIFIER_MODE_ */
