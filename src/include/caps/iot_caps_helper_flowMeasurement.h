/* ***************************************************************************
 *
 * Copyright 2019-2026 Samsung Electronics All Rights Reserved.
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

#ifndef _IOT_CAPS_HELPER_FLOW_MEASUREMENT_
#define _IOT_CAPS_HELPER_FLOW_MEASUREMENT_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum { CAP_ENUM_FLOWMEASUREMENT_FLOW_UNIT_M3_PER_H, CAP_ENUM_FLOWMEASUREMENT_FLOW_UNIT_MAX };

const static struct iot_caps_flowMeasurement {
    const char *id;
    const struct flowMeasurement_attr_flow {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *units[CAP_ENUM_FLOWMEASUREMENT_FLOW_UNIT_MAX];
        const char *unit_m3_per_h;
        const double min;
    } attr_flow;
    const struct flowMeasurement_attr_flowRange {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *units[CAP_ENUM_FLOWMEASUREMENT_FLOW_UNIT_MAX];
        const char *unit_m3_per_h;
        const struct flowMeasurement_flowRange_value_minimum {
            const char *name;
            const unsigned char property;
            const unsigned char valueType;
            const double min;
        } value_minimum;
        const struct flowMeasurement_flowRange_value_maximum {
            const char *name;
            const unsigned char property;
            const unsigned char valueType;
            const double min;
        } value_maximum;
    } attr_flowRange;
} caps_helper_flowMeasurement = {
    .id = "flowMeasurement",
    .attr_flow =
        {
            .name = "flow",
            .property = ATTR_SET_VALUE_MIN | ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_NUMBER,
            .units = {"m^3/h"},
            .unit_m3_per_h = "m^3/h",
            .min = 0,
        },
    .attr_flowRange =
        {
            .name = "flowRange",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_OBJECT,
            .units = {"m^3/h"},
            .unit_m3_per_h = "m^3/h",
            .value_minimum =
                {
                    .name = "minimum",
                    .property = ATTR_SET_VALUE_MIN | ATTR_SET_VALUE_REQUIRED,
                    .valueType = VALUE_TYPE_NUMBER,
                    .min = 0,
                },
            .value_maximum =
                {
                    .name = "maximum",
                    .property = ATTR_SET_VALUE_MIN | ATTR_SET_VALUE_REQUIRED,
                    .valueType = VALUE_TYPE_NUMBER,
                    .min = 0,
                },
        },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_FLOW_MEASUREMENT_ */
