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

#ifndef _IOT_CAPS_HELPER_TVOC_HEALTH_CONCERN_
#define _IOT_CAPS_HELPER_TVOC_HEALTH_CONCERN_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_TVOCHEALTHCONCERN_VALUE_GOOD,
    CAP_ENUM_TVOCHEALTHCONCERN_VALUE_MODERATE,
    CAP_ENUM_TVOCHEALTHCONCERN_VALUE_SLIGHTLY_UNHEALTHY,
    CAP_ENUM_TVOCHEALTHCONCERN_VALUE_UNHEALTHY,
    CAP_ENUM_TVOCHEALTHCONCERN_VALUE_VERY_UNHEALTHY,
    CAP_ENUM_TVOCHEALTHCONCERN_VALUE_HAZARDOUS,
	CAP_ENUM_TVOCHEALTHCONCERN_VALUE_MAX,
};

const static struct iot_caps_tvocHealthConcern {
    const char *id;
    const struct tvocHealthConcern_attr_tvocHealthConcern {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_TVOCHEALTHCONCERN_VALUE_MAX];
        const char *value_good;
        const char *value_moderate;
        const char *value_slightly_unhealthy;
        const char *value_unhealthy;
        const char *value_very_unhealthy;
        const char *value_hazardous;
    } attr_tvocHealthConcern;
} caps_helper_tvocHealthConcern = {
    .id = "tvocHealthConcern",
    .attr_tvocHealthConcern = {
        .name = "tvocHealthConcern",
        .property = ATTR_SET_VALUE_REQUIRED,
        .valueType = VALUE_TYPE_STRING,
        .values = {"good", "moderate", "slightlyUnhealthy", "unhealthy", "veryUnhealthy", "hazardous"},
        .value_good = "good",
        .value_moderate = "moderate",
        .value_slightly_unhealthy = "slightlyUnhealthy",
        .value_unhealthy = "unhealthy",
        .value_very_unhealthy = "veryUnhealthy",
        .value_hazardous = "hazardous",
    },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HELPER_TVOC_HEALTH_CONCERN_ */
