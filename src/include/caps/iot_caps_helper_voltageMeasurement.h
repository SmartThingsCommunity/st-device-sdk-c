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

#ifndef _IOT_CAPS_HELPER_VOLTAGE_MEASUREMENT_
#define _IOT_CAPS_HELPER_VOLTAGE_MEASUREMENT_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_VOLTAGEMEASUREMENT_VOLTAGE_UNIT_V,
    CAP_ENUM_VOLTAGEMEASUREMENT_VOLTAGE_UNIT_MAX
};

const static struct iot_caps_voltageMeasurement {
    const char *id;
    const struct voltageMeasurement_attr_voltage {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *units[CAP_ENUM_VOLTAGEMEASUREMENT_VOLTAGE_UNIT_MAX];
        const char *unit_V;
        const double min;
    } attr_voltage;
} caps_helper_voltageMeasurement = {
    .id = "voltageMeasurement",
    .attr_voltage = {
        .name = "voltage",
        .property = ATTR_SET_VALUE_MIN | ATTR_SET_VALUE_REQUIRED,
        .valueType = VALUE_TYPE_NUMBER,
        .units = {"V"},
        .unit_V = "V",
        .min = 0,
    },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_VOLTAGE_MEASUREMENT_ */
