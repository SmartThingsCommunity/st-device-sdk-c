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

#ifndef _IOT_CAPS_HELPER_THREE_AXIS_
#define _IOT_CAPS_HELPER_THREE_AXIS_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_THREEAXIS_THREEAXIS_UNIT_MG,
    CAP_ENUM_THREEAXIS_THREEAXIS_UNIT_MAX
};

const static struct iot_caps_threeAxis {
    const char *id;
    const struct threeAxis_attr_threeAxis {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *units[CAP_ENUM_THREEAXIS_THREEAXIS_UNIT_MAX];
        const char *unit_mG;
        const int min;
        const int max;
    } attr_threeAxis;
} caps_helper_threeAxis = {
    .id = "threeAxis",
    .attr_threeAxis = {
        .name = "threeAxis",
        .property = ATTR_SET_VALUE_MIN | ATTR_SET_VALUE_MAX | ATTR_SET_VALUE_REQUIRED | ATTR_SET_VALUE_ARRAY,
        .valueType = VALUE_TYPE_INTEGER,
        .units = {"mG"},
        .unit_mG = "mG",
        .min = -10000,
        .max = 10000,
    },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_THREE_AXIS_ */
