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

#ifndef _IOT_CAPS_HELPER_VEHICLE_RANGE_
#define _IOT_CAPS_HELPER_VEHICLE_RANGE_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_VEHICLERANGE_ESTIMATEDREMAININGRANGE_UNIT_MI,
    CAP_ENUM_VEHICLERANGE_ESTIMATEDREMAININGRANGE_UNIT_KM,
    CAP_ENUM_VEHICLERANGE_ESTIMATEDREMAININGRANGE_UNIT_M,
    CAP_ENUM_VEHICLERANGE_ESTIMATEDREMAININGRANGE_UNIT_MAX
};

const static struct iot_caps_vehicleRange {
    const char *id;
    const struct vehicleRange_attr_estimatedRemainingRange {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *units[CAP_ENUM_VEHICLERANGE_ESTIMATEDREMAININGRANGE_UNIT_MAX];
        const char *unit_mi;
        const char *unit_km;
        const char *unit_m;
        const double min;
    } attr_estimatedRemainingRange;
} caps_helper_vehicleRange = {
    .id = "vehicleRange",
    .attr_estimatedRemainingRange =
        {
            .name = "estimatedRemainingRange",
            .property = ATTR_SET_VALUE_MIN | ATTR_SET_VALUE_REQUIRED | ATTR_SET_UNIT_REQUIRED,
            .valueType = VALUE_TYPE_NUMBER,
            .units = {"mi", "km", "m"},
            .unit_mi = "mi",
            .unit_km = "km",
            .unit_m = "m",
            .min = 0,
        },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_VEHICLE_RANGE_ */
