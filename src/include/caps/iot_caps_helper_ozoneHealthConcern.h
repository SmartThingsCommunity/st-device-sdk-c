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

#ifndef _IOT_CAPS_HELPER_OZONE_HEALTH_CONCERN_
#define _IOT_CAPS_HELPER_OZONE_HEALTH_CONCERN_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CAP_ENUM_OZONEHEALTHCONCERN_SUPPORTEDOZONEVALUES_VALUE_MAX 7
enum {
    CAP_ENUM_OZONEHEALTHCONCERN_OZONEHEALTHCONCERN_VALUE_UNKNOWN,
    CAP_ENUM_OZONEHEALTHCONCERN_OZONEHEALTHCONCERN_VALUE_GOOD,
    CAP_ENUM_OZONEHEALTHCONCERN_OZONEHEALTHCONCERN_VALUE_MODERATE,
    CAP_ENUM_OZONEHEALTHCONCERN_OZONEHEALTHCONCERN_VALUE_SLIGHTLYUNHEALTHY,
    CAP_ENUM_OZONEHEALTHCONCERN_OZONEHEALTHCONCERN_VALUE_UNHEALTHY,
    CAP_ENUM_OZONEHEALTHCONCERN_OZONEHEALTHCONCERN_VALUE_VERYUNHEALTHY,
    CAP_ENUM_OZONEHEALTHCONCERN_OZONEHEALTHCONCERN_VALUE_HAZARDOUS,
    CAP_ENUM_OZONEHEALTHCONCERN_OZONEHEALTHCONCERN_VALUE_MAX
};

const static struct iot_caps_ozoneHealthConcern {
    const char *id;
    const struct ozoneHealthConcern_attr_ozoneHealthConcern {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_OZONEHEALTHCONCERN_OZONEHEALTHCONCERN_VALUE_MAX];
        const char *value_unknown;
        const char *value_good;
        const char *value_moderate;
        const char *value_slightlyUnhealthy;
        const char *value_unhealthy;
        const char *value_veryUnhealthy;
        const char *value_hazardous;
    } attr_ozoneHealthConcern;
    const struct ozoneHealthConcern_attr_supportedOzoneValues {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_OZONEHEALTHCONCERN_SUPPORTEDOZONEVALUES_VALUE_MAX];
        const char *value_unknown;
        const char *value_good;
        const char *value_moderate;
        const char *value_slightlyUnhealthy;
        const char *value_unhealthy;
        const char *value_veryUnhealthy;
        const char *value_hazardous;
    } attr_supportedOzoneValues;
} caps_helper_ozoneHealthConcern = {
    .id = "ozoneHealthConcern",
    .attr_ozoneHealthConcern =
        {
            .name = "ozoneHealthConcern",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"unknown", "good", "moderate", "slightlyUnhealthy", "unhealthy", "veryUnhealthy", "hazardous"},
            .value_unknown = "unknown",
            .value_good = "good",
            .value_moderate = "moderate",
            .value_slightlyUnhealthy = "slightlyUnhealthy",
            .value_unhealthy = "unhealthy",
            .value_veryUnhealthy = "veryUnhealthy",
            .value_hazardous = "hazardous",
        },
    .attr_supportedOzoneValues =
        {
            .name = "supportedOzoneValues",
            .property = ATTR_SET_VALUE_ARRAY,
            .valueType = VALUE_TYPE_STRING,
            .values = {"unknown", "good", "moderate", "slightlyUnhealthy", "unhealthy", "veryUnhealthy", "hazardous"},
            .value_unknown = "unknown",
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

#endif /* _IOT_CAPS_HERLPER_OZONE_HEALTH_CONCERN_ */
