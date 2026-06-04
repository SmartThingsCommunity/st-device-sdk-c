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

#ifndef _IOT_CAPS_HELPER_WATER_USAGE_METER_
#define _IOT_CAPS_HELPER_WATER_USAGE_METER_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_WATERUSAGEMETER_WATERUSAGEDAY_UNIT_GAL,
    CAP_ENUM_WATERUSAGEMETER_WATERUSAGEDAY_UNIT_L,
    CAP_ENUM_WATERUSAGEMETER_WATERUSAGEDAY_UNIT_MAX
};

enum {
    CAP_ENUM_WATERUSAGEMETER_WATERUSAGEMONTH_UNIT_GAL,
    CAP_ENUM_WATERUSAGEMETER_WATERUSAGEMONTH_UNIT_L,
    CAP_ENUM_WATERUSAGEMETER_WATERUSAGEMONTH_UNIT_MAX
};

const static struct iot_caps_waterUsageMeter {
    const char *id;
    const struct waterUsageMeter_attr_waterUsageDay {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *units[CAP_ENUM_WATERUSAGEMETER_WATERUSAGEDAY_UNIT_MAX];
        const char *unit_gal;
        const char *unit_L;
    } attr_waterUsageDay;
    const struct waterUsageMeter_attr_waterUsageMonth {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *units[CAP_ENUM_WATERUSAGEMETER_WATERUSAGEMONTH_UNIT_MAX];
        const char *unit_gal;
        const char *unit_L;
    } attr_waterUsageMonth;
} caps_helper_waterUsageMeter = {
    .id = "waterUsageMeter",
    .attr_waterUsageDay =
        {
            .name = "waterUsageDay",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_NUMBER,
            .units = {"gal", "L"},
            .unit_gal = "gal",
            .unit_L = "L",
        },
    .attr_waterUsageMonth =
        {
            .name = "waterUsageMonth",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_NUMBER,
            .units = {"gal", "L"},
            .unit_gal = "gal",
            .unit_L = "L",
        },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_WATER_USAGE_METER_ */
