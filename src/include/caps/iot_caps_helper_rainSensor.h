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

#ifndef _IOT_CAPS_HELPER_RAIN_SENSOR_
#define _IOT_CAPS_HELPER_RAIN_SENSOR_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_RAINSENSOR_RAIN_VALUE_UNDETECTED,
    CAP_ENUM_RAINSENSOR_RAIN_VALUE_DETECTED,
    CAP_ENUM_RAINSENSOR_RAIN_VALUE_MAX
};

const static struct iot_caps_rainSensor {
    const char *id;
    const struct rainSensor_attr_rain {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_RAINSENSOR_RAIN_VALUE_MAX];
        const char *value_undetected;
        const char *value_detected;
    } attr_rain;
} caps_helper_rainSensor = {
    .id = "rainSensor",
    .attr_rain =
        {
            .name = "rain",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"undetected", "detected"},
            .value_undetected = "undetected",
            .value_detected = "detected",
        },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_RAIN_SENSOR_ */
