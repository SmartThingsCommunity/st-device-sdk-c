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

#ifndef _IOT_CAPS_HELPER_ULTRAVIOLET_INDEX_
#define _IOT_CAPS_HELPER_ULTRAVIOLET_INDEX_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

const static struct iot_caps_ultravioletIndex {
    const char *id;
    const struct ultravioletIndex_attr_ultravioletIndex {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const double min;
        const double max;
    } attr_ultravioletIndex;
} caps_helper_ultravioletIndex = {
    .id = "ultravioletIndex",
    .attr_ultravioletIndex = {
        .name = "ultravioletIndex",
        .property = ATTR_SET_VALUE_MIN | ATTR_SET_VALUE_MAX | ATTR_SET_VALUE_REQUIRED,
        .valueType = VALUE_TYPE_NUMBER,
        .min = 0,
        .max = 255,
    },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_ULTRAVIOLET_INDEX_ */
