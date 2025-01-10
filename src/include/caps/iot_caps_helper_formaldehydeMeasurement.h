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

#ifndef _IOT_CAPS_HELPER_FORMALDEHYDE_MEASUREMENT_
#define _IOT_CAPS_HELPER_FORMALDEHYDE_MEASUREMENT_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_FORMALDEHYDEMEASUREMENT_FORMALDEHYDELEVEL_UNIT_PPM,
    CAP_ENUM_FORMALDEHYDEMEASUREMENT_FORMALDEHYDELEVEL_UNIT_MG_PER_M3,
    CAP_ENUM_FORMALDEHYDEMEASUREMENT_FORMALDEHYDELEVEL_UNIT_MAX
};

const static struct iot_caps_formaldehydeMeasurement {
    const char *id;
    const struct formaldehydeMeasurement_attr_formaldehydeLevel {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *units[CAP_ENUM_FORMALDEHYDEMEASUREMENT_FORMALDEHYDELEVEL_UNIT_MAX];
        const char *unit_ppm;
        const char *unit_mg_per_m3;
        const double min;
        const double max;
    } attr_formaldehydeLevel;
} caps_helper_formaldehydeMeasurement = {
    .id = "formaldehydeMeasurement",
    .attr_formaldehydeLevel = {
        .name = "formaldehydeLevel",
        .property = ATTR_SET_VALUE_MIN | ATTR_SET_VALUE_MAX | ATTR_SET_VALUE_REQUIRED | ATTR_SET_UNIT_REQUIRED,
        .valueType = VALUE_TYPE_NUMBER,
        .units = {"ppm", "mg/m^3"},
        .unit_ppm = "ppm",
        .unit_mg_per_m3 = "mg/m^3",
        .min = 0,
        .max = 1000000,
    },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_FORMALDEHYDE_MEASUREMENT_ */
