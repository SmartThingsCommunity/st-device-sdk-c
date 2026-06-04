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

#ifndef _IOT_CAPS_HELPER_WATER_PRESSURE_MEASUREMENT_
#define _IOT_CAPS_HELPER_WATER_PRESSURE_MEASUREMENT_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_WATERPRESSUREMEASUREMENT_PRESSURE_UNIT_PSI,
    CAP_ENUM_WATERPRESSUREMEASUREMENT_PRESSURE_UNIT_KPA,
    CAP_ENUM_WATERPRESSUREMEASUREMENT_PRESSURE_UNIT_BAR,
    CAP_ENUM_WATERPRESSUREMEASUREMENT_PRESSURE_UNIT_MAX
};

enum {
    CAP_ENUM_WATERPRESSUREMEASUREMENT_PRESSUREALARM_VALUE_NORMAL,
    CAP_ENUM_WATERPRESSUREMEASUREMENT_PRESSUREALARM_VALUE_LOW,
    CAP_ENUM_WATERPRESSUREMEASUREMENT_PRESSUREALARM_VALUE_HIGH,
    CAP_ENUM_WATERPRESSUREMEASUREMENT_PRESSUREALARM_VALUE_MAX
};

const static struct iot_caps_waterPressureMeasurement {
    const char *id;
    const struct waterPressureMeasurement_attr_pressure {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *units[CAP_ENUM_WATERPRESSUREMEASUREMENT_PRESSURE_UNIT_MAX];
        const char *unit_psi;
        const char *unit_kPa;
        const char *unit_bar;
        const double min;
    } attr_pressure;
    const struct waterPressureMeasurement_attr_pressureAlarm {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_WATERPRESSUREMEASUREMENT_PRESSUREALARM_VALUE_MAX];
        const char *value_normal;
        const char *value_low;
        const char *value_high;
    } attr_pressureAlarm;
} caps_helper_waterPressureMeasurement = {
    .id = "waterPressureMeasurement",
    .attr_pressure =
        {
            .name = "pressure",
            .property = ATTR_SET_VALUE_MIN | ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_NUMBER,
            .units = {"psi", "kPa", "bar"},
            .unit_psi = "psi",
            .unit_kPa = "kPa",
            .unit_bar = "bar",
            .min = 0,
        },
    .attr_pressureAlarm =
        {
            .name = "pressureAlarm",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"normal", "low", "high"},
            .value_normal = "normal",
            .value_low = "low",
            .value_high = "high",
        },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_WATER_PRESSURE_MEASUREMENT_ */
