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

#ifndef _IOT_CAPS_HELPER_ATMOSPHERIC_PRESSURE_MEASUREMENT_
#define _IOT_CAPS_HELPER_ATMOSPHERIC_PRESSURE_MEASUREMENT_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_ATMOSPHERICPRESSUREMEASUREMENT_ATMOSPHERICPRESSURE_UNIT_KPA,
    CAP_ENUM_ATMOSPHERICPRESSUREMEASUREMENT_ATMOSPHERICPRESSURE_UNIT_HPA,
    CAP_ENUM_ATMOSPHERICPRESSUREMEASUREMENT_ATMOSPHERICPRESSURE_UNIT_BAR,
    CAP_ENUM_ATMOSPHERICPRESSUREMEASUREMENT_ATMOSPHERICPRESSURE_UNIT_MBAR,
    CAP_ENUM_ATMOSPHERICPRESSUREMEASUREMENT_ATMOSPHERICPRESSURE_UNIT_MMHG,
    CAP_ENUM_ATMOSPHERICPRESSUREMEASUREMENT_ATMOSPHERICPRESSURE_UNIT_INHG,
    CAP_ENUM_ATMOSPHERICPRESSUREMEASUREMENT_ATMOSPHERICPRESSURE_UNIT_ATM,
    CAP_ENUM_ATMOSPHERICPRESSUREMEASUREMENT_ATMOSPHERICPRESSURE_UNIT_PSI,
    CAP_ENUM_ATMOSPHERICPRESSUREMEASUREMENT_ATMOSPHERICPRESSURE_UNIT_MAX
};

const static struct iot_caps_atmosphericPressureMeasurement {
    const char *id;
    const struct atmosphericPressureMeasurement_attr_atmosphericPressure {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *units[CAP_ENUM_ATMOSPHERICPRESSUREMEASUREMENT_ATMOSPHERICPRESSURE_UNIT_MAX];
        const char *unit_kPa;
        const char *unit_hPa;
        const char *unit_bar;
        const char *unit_mbar;
        const char *unit_mmHg;
        const char *unit_inHg;
        const char *unit_atm;
        const char *unit_psi;
        const double min;
    } attr_atmosphericPressure;
} caps_helper_atmosphericPressureMeasurement = {
    .id = "atmosphericPressureMeasurement",
    .attr_atmosphericPressure =
        {
            .name = "atmosphericPressure",
            .property = ATTR_SET_VALUE_MIN | ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_NUMBER,
            .units = {"kPa", "hPa", "bar", "mbar", "mmHg", "inHg", "atm", "psi"},
            .unit_kPa = "kPa",
            .unit_hPa = "hPa",
            .unit_bar = "bar",
            .unit_mbar = "mbar",
            .unit_mmHg = "mmHg",
            .unit_inHg = "inHg",
            .unit_atm = "atm",
            .unit_psi = "psi",
            .min = 0,
        },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_ATMOSPHERIC_PRESSURE_MEASUREMENT_ */
