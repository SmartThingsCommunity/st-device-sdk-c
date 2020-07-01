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

#ifndef _IOT_CAPS_HELPER_CARBON_MONOXIDE_DETECTOR_
#define _IOT_CAPS_HELPER_CARBON_MONOXIDE_DETECTOR_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_CARBONMONOXIDEDETECTOR_CARBONMONOXIDE_VALUE_CLEAR,
    CAP_ENUM_CARBONMONOXIDEDETECTOR_CARBONMONOXIDE_VALUE_DETECTED,
    CAP_ENUM_CARBONMONOXIDEDETECTOR_CARBONMONOXIDE_VALUE_TESTED,
    CAP_ENUM_CARBONMONOXIDEDETECTOR_CARBONMONOXIDE_VALUE_MAX
};

const static struct iot_caps_carbonMonoxideDetector {
    const char *id;
    const struct carbonMonoxideDetector_attr_carbonMonoxide {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_CARBONMONOXIDEDETECTOR_CARBONMONOXIDE_VALUE_MAX];
        const char *value_clear;
        const char *value_detected;
        const char *value_tested;
    } attr_carbonMonoxide;
} caps_helper_carbonMonoxideDetector = {
    .id = "carbonMonoxideDetector",
    .attr_carbonMonoxide = {
        .name = "carbonMonoxide",
        .property = ATTR_SET_VALUE_REQUIRED,
        .valueType = VALUE_TYPE_STRING,
        .values = {"clear", "detected", "tested"},
        .value_clear = "clear",
        .value_detected = "detected",
        .value_tested = "tested",
    },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_CARBON_MONOXIDE_DETECTOR_ */
