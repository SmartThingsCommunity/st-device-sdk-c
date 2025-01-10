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

#ifndef _IOT_CAPS_HELPER_EQUIVALENT_CARBON_DIOXIDE_MEASUREMENT_
#define _IOT_CAPS_HELPER_EQUIVALENT_CARBON_DIOXIDE_MEASUREMENT_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_EQUIVALENTCARBONDIOXIDEMEASUREMENT_EQUIVALENTCARBONDIOXIDEMEASUREMENT_UNIT_PPM,
    CAP_ENUM_EQUIVALENTCARBONDIOXIDEMEASUREMENT_EQUIVALENTCARBONDIOXIDEMEASUREMENT_UNIT_MAX
};

const static struct iot_caps_equivalentCarbonDioxideMeasurement {
    const char *id;
    const struct equivalentCarbonDioxideMeasurement_attr_equivalentCarbonDioxideMeasurement {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *units[CAP_ENUM_EQUIVALENTCARBONDIOXIDEMEASUREMENT_EQUIVALENTCARBONDIOXIDEMEASUREMENT_UNIT_MAX];
        const char *unit_ppm;
        const double min;
        const double max;
    } attr_equivalentCarbonDioxideMeasurement;
} caps_helper_equivalentCarbonDioxideMeasurement = {
    .id = "equivalentCarbonDioxideMeasurement",
    .attr_equivalentCarbonDioxideMeasurement = {
        .name = "equivalentCarbonDioxideMeasurement",
        .property = ATTR_SET_VALUE_MIN | ATTR_SET_VALUE_MAX | ATTR_SET_VALUE_REQUIRED,
        .valueType = VALUE_TYPE_NUMBER,
        .units = {"ppm"},
        .unit_ppm = "ppm",
        .min = 0,
        .max = 1000000,
    },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_EQUIVALENT_CARBON_DIOXIDE_MEASUREMENT_ */
