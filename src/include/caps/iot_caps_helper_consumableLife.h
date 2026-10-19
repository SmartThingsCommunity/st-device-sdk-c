/* ***************************************************************************
 *
 * Copyright 2026 Samsung Electronics All Rights Reserved.
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

#ifndef _IOT_CAPS_HELPER_CONSUMABLE_LIFE_
#define _IOT_CAPS_HELPER_CONSUMABLE_LIFE_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_CONSUMABLELIFE_TYPE_VALUE_DESICCANT,
    CAP_ENUM_CONSUMABLELIFE_TYPE_VALUE_DIFFUSER,
    CAP_ENUM_CONSUMABLELIFE_TYPE_VALUE_FILTER,
    CAP_ENUM_CONSUMABLELIFE_TYPE_VALUE_MAX
};

const static struct iot_caps_consumableLife {
    const char *id;
    const struct consumableLife_attr_startDate {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
    } attr_startDate;
    const struct consumableLife_attr_lifespan {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const int min;
    } attr_lifespan;
    const struct consumableLife_attr_type {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_CONSUMABLELIFE_TYPE_VALUE_MAX];
        const char *value_desiccant;
        const char *value_diffuser;
        const char *value_filter;
    } attr_type;
    const struct consumableLife_cmd_reset {
        const char *name;
    } cmd_reset;
} caps_helper_consumableLife = {
    .id = "consumableLife",
    .attr_startDate =
        {
            .name = "startDate",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
        },
    .attr_lifespan =
        {
            .name = "lifespan",
            .property = ATTR_SET_VALUE_MIN,
            .valueType = VALUE_TYPE_INTEGER,
            .min = 0,
        },
    .attr_type =
        {
            .name = "type",
            .property = 0,
            .valueType = VALUE_TYPE_STRING,
            .values = {"desiccant", "diffuser", "filter"},
            .value_desiccant = "desiccant",
            .value_diffuser = "diffuser",
            .value_filter = "filter",
        },
    .cmd_reset = {.name = "reset"},
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_CONSUMABLE_LIFE_ */
