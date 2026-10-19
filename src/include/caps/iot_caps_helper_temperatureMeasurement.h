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

#ifndef _IOT_CAPS_HELPER_TEMPERATURE_MEASUREMENT_
#define _IOT_CAPS_HELPER_TEMPERATURE_MEASUREMENT_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_TEMPERATUREMEASUREMENT_TEMPERATURE_UNIT_F,
    CAP_ENUM_TEMPERATUREMEASUREMENT_TEMPERATURE_UNIT_C,
    CAP_ENUM_TEMPERATUREMEASUREMENT_TEMPERATURE_UNIT_MAX
};

const static struct iot_caps_temperatureMeasurement {
    const char *id;
    const struct temperatureMeasurement_attr_temperatureRange {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *units[CAP_ENUM_TEMPERATUREMEASUREMENT_TEMPERATURE_UNIT_MAX];
        const char *unit_F;
        const char *unit_C;
        const struct temperatureRange_value_minimum {
            const char *name;
            const unsigned char property;
            const unsigned char valueType;
            const double min;
            const double max;
        } value_minimum;
        const struct temperatureRange_value_maximum {
            const char *name;
            const unsigned char property;
            const unsigned char valueType;
            const double min;
            const double max;
        } value_maximum;
        const struct temperatureRange_value_step {
            const char *name;
            const unsigned char property;
            const unsigned char valueType;
            const double min;
            const double max;
        } value_step;
    } attr_temperatureRange;
    const struct temperatureMeasurement_attr_temperature {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *units[CAP_ENUM_TEMPERATUREMEASUREMENT_TEMPERATURE_UNIT_MAX];
        const char *unit_F;
        const char *unit_C;
        const double min;
        const double max;
    } attr_temperature;
} caps_helper_temperatureMeasurement = {
    .id = "temperatureMeasurement",
    .attr_temperatureRange =
        {
            .name = "temperatureRange",
            .property = ATTR_SET_VALUE_REQUIRED | ATTR_SET_UNIT_REQUIRED,
            .valueType = VALUE_TYPE_OBJECT,
            .units = {"F", "C"},
            .unit_F = "F",
            .unit_C = "C",
            .value_minimum =
                {
                    .name = "minimum",
                    .property = ATTR_SET_VALUE_MIN | ATTR_SET_VALUE_MAX | ATTR_SET_VALUE_REQUIRED,
                    .valueType = VALUE_TYPE_NUMBER,
                    .min = -460,
                    .max = 10000,
                },
            .value_maximum =
                {
                    .name = "maximum",
                    .property = ATTR_SET_VALUE_MIN | ATTR_SET_VALUE_MAX | ATTR_SET_VALUE_REQUIRED,
                    .valueType = VALUE_TYPE_NUMBER,
                    .min = -460,
                    .max = 10000,
                },
            .value_step =
                {
                    .name = "step",
                    .property = ATTR_SET_VALUE_MIN | ATTR_SET_VALUE_MAX,
                    .valueType = VALUE_TYPE_NUMBER,
                    .min = -460,
                    .max = 10000,
                },
        },
    .attr_temperature =
        {
            .name = "temperature",
            .property = ATTR_SET_VALUE_MIN | ATTR_SET_VALUE_MAX | ATTR_SET_VALUE_REQUIRED | ATTR_SET_UNIT_REQUIRED,
            .valueType = VALUE_TYPE_NUMBER,
            .units = {"F", "C"},
            .unit_F = "F",
            .unit_C = "C",
            .min = -460,
            .max = 10000,
        },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_TEMPERATURE_MEASUREMENT_ */
