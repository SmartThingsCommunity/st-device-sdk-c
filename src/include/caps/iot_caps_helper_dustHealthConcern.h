/* ***************************************************************************
 *
 * Copyright 2019-2022 Samsung Electronics All Rights Reserved.
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

#ifndef _IOT_CAPS_HELPER_DUST_HEALTH_CONCERN_
#define _IOT_CAPS_HELPER_DUST_HEALTH_CONCERN_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_DUSTHEALTHCONCERN_DUSTHEALTHCONCERN_VALUE_GOOD,
    CAP_ENUM_DUSTHEALTHCONCERN_DUSTHEALTHCONCERN_VALUE_MODERATE,
    CAP_ENUM_DUSTHEALTHCONCERN_DUSTHEALTHCONCERN_VALUE_SLIGHTLYUNHEALTHY,
    CAP_ENUM_DUSTHEALTHCONCERN_DUSTHEALTHCONCERN_VALUE_UNHEALTHY,
    CAP_ENUM_DUSTHEALTHCONCERN_DUSTHEALTHCONCERN_VALUE_VERYUNHEALTHY,
    CAP_ENUM_DUSTHEALTHCONCERN_DUSTHEALTHCONCERN_VALUE_HAZARDOUS,
    CAP_ENUM_DUSTHEALTHCONCERN_DUSTHEALTHCONCERN_VALUE_MAX
};

const static struct iot_caps_dustHealthConcern {
    const char *id;
    const struct dustHealthConcern_attr_dustHealthConcern {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_DUSTHEALTHCONCERN_DUSTHEALTHCONCERN_VALUE_MAX];
        const char *value_good;
        const char *value_moderate;
        const char *value_slightlyUnhealthy;
        const char *value_unhealthy;
        const char *value_veryUnhealthy;
        const char *value_hazardous;
    } attr_dustHealthConcern;
} caps_helper_dustHealthConcern = {
    .id = "dustHealthConcern",
    .attr_dustHealthConcern = {
        .name = "dustHealthConcern",
        .property = ATTR_SET_VALUE_REQUIRED,
        .valueType = VALUE_TYPE_STRING,
        .values = {"good", "moderate", "slightlyUnhealthy", "unhealthy", "veryUnhealthy", "hazardous"},
        .value_good = "good",
        .value_moderate = "moderate",
        .value_slightlyUnhealthy = "slightlyUnhealthy",
        .value_unhealthy = "unhealthy",
        .value_veryUnhealthy = "veryUnhealthy",
        .value_hazardous = "hazardous",
    },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_DUST_HEALTH_CONCERN_ */
