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

#ifndef _IOT_CAPS_HELPER_CARBON_DIOXIDE_MEASUREMENT_
#define _IOT_CAPS_HELPER_CARBON_DIOXIDE_MEASUREMENT_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_CARBONDIOXIDEMEASUREMENT_CARBONDIOXIDE_UNIT_PPM,
    CAP_ENUM_CARBONDIOXIDEMEASUREMENT_CARBONDIOXIDE_UNIT_MAX
};

const static struct iot_caps_carbonDioxideMeasurement {
    const char *id;
    const struct carbonDioxideMeasurement_attr_carbonDioxide {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *units[CAP_ENUM_CARBONDIOXIDEMEASUREMENT_CARBONDIOXIDE_UNIT_MAX];
        const char *unit_ppm;
        const int min;
        const int max;
    } attr_carbonDioxide;
} caps_helper_carbonDioxideMeasurement = {
    .id = "carbonDioxideMeasurement",
    .attr_carbonDioxide = {
        .name = "carbonDioxide",
        .property = ATTR_SET_VALUE_MIN | ATTR_SET_VALUE_MAX | ATTR_SET_VALUE_REQUIRED,
        .valueType = VALUE_TYPE_INTEGER,
        .units = {"ppm"},
        .unit_ppm = "ppm",
        .min = 0,
        .max = 1000000,
    },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_CARBON_DIOXIDE_MEASUREMENT_ */
