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

#ifndef _IOT_CAPS_HELPER_BODY_WEIGHT_MEASUREMENT_
#define _IOT_CAPS_HELPER_BODY_WEIGHT_MEASUREMENT_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_BODYWEIGHTMEASUREMENT_BODYWEIGHTMEASUREMENT_UNIT_KG,
    CAP_ENUM_BODYWEIGHTMEASUREMENT_BODYWEIGHTMEASUREMENT_UNIT_LBS,
    CAP_ENUM_BODYWEIGHTMEASUREMENT_BODYWEIGHTMEASUREMENT_UNIT_CATTY,
    CAP_ENUM_BODYWEIGHTMEASUREMENT_BODYWEIGHTMEASUREMENT_UNIT_MAX
};

const static struct iot_caps_bodyWeightMeasurement {
    const char *id;
    const struct bodyWeightMeasurement_attr_bodyWeightMeasurement {
        const char *name;
        const unsigned char property;
        const unsigned char value_type;
        const char *units[CAP_ENUM_BODYWEIGHTMEASUREMENT_BODYWEIGHTMEASUREMENT_UNIT_MAX];
        const double min;
    } attr_bodyWeightMeasurement;
} caps_helper_bodyWeightMeasurement = {
    .id = "bodyWeightMeasurement",
    .attr_bodyWeightMeasurement = {
        .name = "bodyWeightMeasurement",
        .property = ATTR_SET_VALUE_MIN | ATTR_SET_VALUE_REQUIRED | ATTR_SET_UNIT_REQUIRED,
        .value_type = VALUE_TYPE_NUMBER,
        .units = {"kg", "lbs", "斤"},
        .min = 0,
    },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_BODY_WEIGHT_MEASUREMENT_ */
