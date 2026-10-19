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

#ifndef _IOT_CAPS_HELPER_FEEDER_PORTION_
#define _IOT_CAPS_HELPER_FEEDER_PORTION_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_FEEDERPORTION_FEEDPORTION_UNIT_G,
    CAP_ENUM_FEEDERPORTION_FEEDPORTION_UNIT_LBS,
    CAP_ENUM_FEEDERPORTION_FEEDPORTION_UNIT_OZ,
    CAP_ENUM_FEEDERPORTION_FEEDPORTION_UNIT_SERVINGS,
    CAP_ENUM_FEEDERPORTION_FEEDPORTION_UNIT_MAX
};

const static struct iot_caps_feederPortion {
    const char *id;
    const struct feederPortion_attr_feedPortion {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *units[CAP_ENUM_FEEDERPORTION_FEEDPORTION_UNIT_MAX];
        const char *unit_g;
        const char *unit_lbs;
        const char *unit_oz;
        const char *unit_servings;
        const double min;
        const double max;
    } attr_feedPortion;
    const struct feederPortion_cmd_setPortion {
        const char *name;
    } cmd_setPortion;
} caps_helper_feederPortion = {
    .id = "feederPortion",
    .attr_feedPortion =
        {
            .name = "feedPortion",
            .property = ATTR_SET_VALUE_MIN | ATTR_SET_VALUE_MAX | ATTR_SET_VALUE_REQUIRED | ATTR_SET_UNIT_REQUIRED,
            .valueType = VALUE_TYPE_NUMBER,
            .units = {"g", "lbs", "oz", "servings"},
            .unit_g = "g",
            .unit_lbs = "lbs",
            .unit_oz = "oz",
            .unit_servings = "servings",
            .min = 0,
            .max = 2000,
        },
    .cmd_setPortion = {.name = "setPortion"},  // arguments: portion(number) unit(string)
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_FEEDER_PORTION_ */
