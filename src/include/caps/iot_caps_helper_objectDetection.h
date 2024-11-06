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

#ifndef _IOT_CAPS_HELPER_OBJECT_DETECTION_
#define _IOT_CAPS_HELPER_OBJECT_DETECTION_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

const static struct iot_caps_objectDetection {
    const char *id;
    const struct objectDetection_attr_detected {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
    } attr_detected;
    const struct objectDetection_attr_supportedValues {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const unsigned int max_length;
    } attr_supportedValues;
} caps_helper_objectDetection = {
    .id = "objectDetection",
    .attr_detected = {
        .name = "detected",
        .property = ATTR_SET_VALUE_REQUIRED,
        .valueType = VALUE_TYPE_OBJECT,
    },
    .attr_supportedValues = {
        .name = "supportedValues",
        .property = ATTR_SET_MAX_LENGTH | ATTR_SET_VALUE_ARRAY,
        .valueType = VALUE_TYPE_STRING,
        .max_length = 255,
    },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_OBJECT_DETECTION_ */
