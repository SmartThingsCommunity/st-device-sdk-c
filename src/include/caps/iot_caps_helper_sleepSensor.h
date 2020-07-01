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

#ifndef _IOT_CAPS_HELPER_SLEEP_SENSOR_
#define _IOT_CAPS_HELPER_SLEEP_SENSOR_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_SLEEPSENSOR_SLEEPING_VALUE_NOT_SLEEPING,
    CAP_ENUM_SLEEPSENSOR_SLEEPING_VALUE_SLEEPING,
    CAP_ENUM_SLEEPSENSOR_SLEEPING_VALUE_MAX
};

const static struct iot_caps_sleepSensor {
    const char *id;
    const struct sleepSensor_attr_sleeping {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_SLEEPSENSOR_SLEEPING_VALUE_MAX];
        const char *value_not_sleeping;
        const char *value_sleeping;
    } attr_sleeping;
} caps_helper_sleepSensor = {
    .id = "sleepSensor",
    .attr_sleeping = {
        .name = "sleeping",
        .property = ATTR_SET_VALUE_REQUIRED,
        .valueType = VALUE_TYPE_STRING,
        .values = {"not sleeping", "sleeping"},
        .value_not_sleeping = "not sleeping",
        .value_sleeping = "sleeping",
    },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_SLEEP_SENSOR_ */
