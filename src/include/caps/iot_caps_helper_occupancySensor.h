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

#ifndef _IOT_CAPS_HELPER_OCCUPANCY_SENSOR_
#define _IOT_CAPS_HELPER_OCCUPANCY_SENSOR_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_OCCUPANCYSENSOR_OCCUPANCY_VALUE_OCCUPIED,
    CAP_ENUM_OCCUPANCYSENSOR_OCCUPANCY_VALUE_UNOCCUPIED,
    CAP_ENUM_OCCUPANCYSENSOR_OCCUPANCY_VALUE_MAX
};

const static struct iot_caps_occupancySensor {
    const char *id;
    const struct occupancySensor_attr_occupancy {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_OCCUPANCYSENSOR_OCCUPANCY_VALUE_MAX];
        const char *value_occupied;
        const char *value_unoccupied;
    } attr_occupancy;
} caps_helper_occupancySensor = {
    .id = "occupancySensor",
    .attr_occupancy =
        {
            .name = "occupancy",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"occupied", "unoccupied"},
            .value_occupied = "occupied",
            .value_unoccupied = "unoccupied",
        },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_OCCUPANCY_SENSOR_ */
