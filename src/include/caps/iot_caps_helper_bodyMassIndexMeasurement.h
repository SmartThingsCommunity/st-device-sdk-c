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

#ifndef _IOT_CAPS_HELPER_BODY_MASS_INDEX_MEASUREMENT_
#define _IOT_CAPS_HELPER_BODY_MASS_INDEX_MEASUREMENT_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_BODYMASSINDEXMEASUREMENT_BMIMEASUREMENT_UNIT_KG_PER_M2,
    CAP_ENUM_BODYMASSINDEXMEASUREMENT_BMIMEASUREMENT_UNIT_MAX
};

const static struct iot_caps_bodyMassIndexMeasurement {
    const char *id;
    const struct bodyMassIndexMeasurement_attr_bmiMeasurement {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *units[CAP_ENUM_BODYMASSINDEXMEASUREMENT_BMIMEASUREMENT_UNIT_MAX];
        const char *unit_kg_per_m2;
        const double min;
    } attr_bmiMeasurement;
} caps_helper_bodyMassIndexMeasurement = {
    .id = "bodyMassIndexMeasurement",
    .attr_bmiMeasurement = {
        .name = "bmiMeasurement",
        .property = ATTR_SET_VALUE_MIN | ATTR_SET_VALUE_REQUIRED,
        .valueType = VALUE_TYPE_NUMBER,
        .units = {"kg/m^2"},
        .unit_kg_per_m2 = "kg/m^2",
        .min = 0,
    },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_BODY_MASS_INDEX_MEASUREMENT_ */
