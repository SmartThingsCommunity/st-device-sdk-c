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

#ifndef _IOT_CAPS_HELPER_DISHWASHER_MODE_
#define _IOT_CAPS_HELPER_DISHWASHER_MODE_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_DISHWASHERMODE_DISHWASHERMODE_VALUE_ECO,
    CAP_ENUM_DISHWASHERMODE_DISHWASHERMODE_VALUE_INTENSE,
    CAP_ENUM_DISHWASHERMODE_DISHWASHERMODE_VALUE_AUTO,
    CAP_ENUM_DISHWASHERMODE_DISHWASHERMODE_VALUE_QUICK,
    CAP_ENUM_DISHWASHERMODE_DISHWASHERMODE_VALUE_RINSE,
    CAP_ENUM_DISHWASHERMODE_DISHWASHERMODE_VALUE_DRY,
    CAP_ENUM_DISHWASHERMODE_DISHWASHERMODE_VALUE_SMART,
    CAP_ENUM_DISHWASHERMODE_DISHWASHERMODE_VALUE_DAILY,
    CAP_ENUM_DISHWASHERMODE_DISHWASHERMODE_VALUE_SUPERCLEAN,
    CAP_ENUM_DISHWASHERMODE_DISHWASHERMODE_VALUE_BRIGHTENING,
    CAP_ENUM_DISHWASHERMODE_DISHWASHERMODE_VALUE_PREWASH,
    CAP_ENUM_DISHWASHERMODE_DISHWASHERMODE_VALUE_MAX
};

enum {
    CAP_ENUM_DISHWASHERMODE_SUPPORTEDDISHWASHERMODES_VALUE_ECO,
    CAP_ENUM_DISHWASHERMODE_SUPPORTEDDISHWASHERMODES_VALUE_INTENSE,
    CAP_ENUM_DISHWASHERMODE_SUPPORTEDDISHWASHERMODES_VALUE_AUTO,
    CAP_ENUM_DISHWASHERMODE_SUPPORTEDDISHWASHERMODES_VALUE_QUICK,
    CAP_ENUM_DISHWASHERMODE_SUPPORTEDDISHWASHERMODES_VALUE_RINSE,
    CAP_ENUM_DISHWASHERMODE_SUPPORTEDDISHWASHERMODES_VALUE_DRY,
    CAP_ENUM_DISHWASHERMODE_SUPPORTEDDISHWASHERMODES_VALUE_SMART,
    CAP_ENUM_DISHWASHERMODE_SUPPORTEDDISHWASHERMODES_VALUE_DAILY,
    CAP_ENUM_DISHWASHERMODE_SUPPORTEDDISHWASHERMODES_VALUE_SUPERCLEAN,
    CAP_ENUM_DISHWASHERMODE_SUPPORTEDDISHWASHERMODES_VALUE_BRIGHTENING,
    CAP_ENUM_DISHWASHERMODE_SUPPORTEDDISHWASHERMODES_VALUE_PREWASH,
    CAP_ENUM_DISHWASHERMODE_SUPPORTEDDISHWASHERMODES_VALUE_MAX
};

const static struct iot_caps_dishwasherMode {
    const char *id;
    const struct dishwasherMode_attr_dishwasherMode {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_DISHWASHERMODE_DISHWASHERMODE_VALUE_MAX];
        const char *value_eco;
        const char *value_intense;
        const char *value_auto;
        const char *value_quick;
        const char *value_rinse;
        const char *value_dry;
        const char *value_smart;
        const char *value_daily;
        const char *value_superClean;
        const char *value_brightening;
        const char *value_prewash;
    } attr_dishwasherMode;
    const struct dishwasherMode_attr_supportedDishwasherModes {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_DISHWASHERMODE_SUPPORTEDDISHWASHERMODES_VALUE_MAX];
        const char *value_eco;
        const char *value_intense;
        const char *value_auto;
        const char *value_quick;
        const char *value_rinse;
        const char *value_dry;
        const char *value_smart;
        const char *value_daily;
        const char *value_superClean;
        const char *value_brightening;
        const char *value_prewash;
    } attr_supportedDishwasherModes;
    const struct dishwasherMode_cmd_setDishwasherMode {
        const char *name;
    } cmd_setDishwasherMode;
} caps_helper_dishwasherMode = {
    .id = "dishwasherMode",
    .attr_dishwasherMode =
        {
            .name = "dishwasherMode",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"eco", "intense", "auto", "quick", "rinse", "dry", "smart", "daily", "superClean", "brightening",
                       "prewash"},
            .value_eco = "eco",
            .value_intense = "intense",
            .value_auto = "auto",
            .value_quick = "quick",
            .value_rinse = "rinse",
            .value_dry = "dry",
            .value_smart = "smart",
            .value_daily = "daily",
            .value_superClean = "superClean",
            .value_brightening = "brightening",
            .value_prewash = "prewash",
        },
    .attr_supportedDishwasherModes =
        {
            .name = "supportedDishwasherModes",
            .property = ATTR_SET_VALUE_ARRAY,
            .valueType = VALUE_TYPE_STRING,
            .values = {"eco", "intense", "auto", "quick", "rinse", "dry", "smart", "daily", "superClean", "brightening",
                       "prewash"},
            .value_eco = "eco",
            .value_intense = "intense",
            .value_auto = "auto",
            .value_quick = "quick",
            .value_rinse = "rinse",
            .value_dry = "dry",
            .value_smart = "smart",
            .value_daily = "daily",
            .value_superClean = "superClean",
            .value_brightening = "brightening",
            .value_prewash = "prewash",
        },
    .cmd_setDishwasherMode = {.name = "setDishwasherMode"},  // arguments: mode(string)
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_DISHWASHER_MODE_ */
