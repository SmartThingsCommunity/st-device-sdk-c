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

#ifndef _IOT_CAPS_HELPER_RADON_MEASUREMENT_
#define _IOT_CAPS_HELPER_RADON_MEASUREMENT_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum { CAP_ENUM_RADONMEASUREMENT_RADONLEVEL_UNIT_PCI_PER_L, CAP_ENUM_RADONMEASUREMENT_RADONLEVEL_UNIT_MAX };

const static struct iot_caps_radonMeasurement {
    const char *id;
    const struct radonMeasurement_attr_radonLevel {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *units[CAP_ENUM_RADONMEASUREMENT_RADONLEVEL_UNIT_MAX];
        const char *unit_pCi_per_L;
    } attr_radonLevel;
} caps_helper_radonMeasurement = {
    .id = "radonMeasurement",
    .attr_radonLevel =
        {
            .name = "radonLevel",
            .property = ATTR_SET_VALUE_REQUIRED | ATTR_SET_UNIT_REQUIRED,
            .valueType = VALUE_TYPE_NUMBER,
            .units = {"pCi/L"},
            .unit_pCi_per_L = "pCi/L",
        },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_RADON_MEASUREMENT_ */
