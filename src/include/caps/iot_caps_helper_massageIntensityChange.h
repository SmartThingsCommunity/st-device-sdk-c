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

#ifndef _IOT_CAPS_HELPER_MASSAGE_INTENSITY_CHANGE_
#define _IOT_CAPS_HELPER_MASSAGE_INTENSITY_CHANGE_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_MASSAGEINTENSITYCHANGE_SUPPORTEDPOSITIONS_VALUE_HEAD,
    CAP_ENUM_MASSAGEINTENSITYCHANGE_SUPPORTEDPOSITIONS_VALUE_FOOT,
    CAP_ENUM_MASSAGEINTENSITYCHANGE_SUPPORTEDPOSITIONS_VALUE_WHOLE,
    CAP_ENUM_MASSAGEINTENSITYCHANGE_SUPPORTEDPOSITIONS_VALUE_MAX
};

const static struct iot_caps_massageIntensityChange {
    const char *id;
    const struct massageIntensityChange_attr_supportedPositions {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_MASSAGEINTENSITYCHANGE_SUPPORTEDPOSITIONS_VALUE_MAX];
        const char *value_head;
        const char *value_foot;
        const char *value_whole;
    } attr_supportedPositions;
    const struct massageIntensityChange_cmd_nextIntensity {
        const char *name;
    } cmd_nextIntensity;
} caps_helper_massageIntensityChange = {
    .id = "massageIntensityChange",
    .attr_supportedPositions =
        {
            .name = "supportedPositions",
            .property = ATTR_SET_VALUE_ARRAY,
            .valueType = VALUE_TYPE_STRING,
            .values = {"head", "foot", "whole"},
            .value_head = "head",
            .value_foot = "foot",
            .value_whole = "whole",
        },
    .cmd_nextIntensity = {.name = "nextIntensity"},  // arguments: position(string)
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_MASSAGE_INTENSITY_CHANGE_ */
