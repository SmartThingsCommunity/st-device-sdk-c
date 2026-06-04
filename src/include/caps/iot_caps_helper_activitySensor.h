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

#ifndef _IOT_CAPS_HELPER_ACTIVITY_SENSOR_
#define _IOT_CAPS_HELPER_ACTIVITY_SENSOR_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_ACTIVITYSENSOR_ACTIVITY_VALUE_NOACTIVITY,
    CAP_ENUM_ACTIVITYSENSOR_ACTIVITY_VALUE_FALLING,
    CAP_ENUM_ACTIVITYSENSOR_ACTIVITY_VALUE_LYING,
    CAP_ENUM_ACTIVITYSENSOR_ACTIVITY_VALUE_SITTING,
    CAP_ENUM_ACTIVITYSENSOR_ACTIVITY_VALUE_STANDING,
    CAP_ENUM_ACTIVITYSENSOR_ACTIVITY_VALUE_EATING,
    CAP_ENUM_ACTIVITYSENSOR_ACTIVITY_VALUE_MAX
};

const static struct iot_caps_activitySensor {
    const char *id;
    const struct activitySensor_attr_activity {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_ACTIVITYSENSOR_ACTIVITY_VALUE_MAX];
        const char *value_noActivity;
        const char *value_falling;
        const char *value_lying;
        const char *value_sitting;
        const char *value_standing;
        const char *value_eating;
    } attr_activity;
} caps_helper_activitySensor = {
    .id = "activitySensor",
    .attr_activity =
        {
            .name = "activity",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"noActivity", "falling", "lying", "sitting", "standing", "eating"},
            .value_noActivity = "noActivity",
            .value_falling = "falling",
            .value_lying = "lying",
            .value_sitting = "sitting",
            .value_standing = "standing",
            .value_eating = "eating",
        },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_ACTIVITY_SENSOR_ */
