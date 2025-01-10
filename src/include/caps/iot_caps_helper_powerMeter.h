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

#ifndef _IOT_CAPS_HELPER_POWER_METER_
#define _IOT_CAPS_HELPER_POWER_METER_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_POWERMETER_POWER_UNIT_W,
    CAP_ENUM_POWERMETER_POWER_UNIT_MAX
};

const static struct iot_caps_powerMeter {
    const char *id;
    const struct powerMeter_attr_power {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *units[CAP_ENUM_POWERMETER_POWER_UNIT_MAX];
        const char *unit_W;
        const double min;
    } attr_power;
} caps_helper_powerMeter = {
    .id = "powerMeter",
    .attr_power = {
        .name = "power",
        .property = ATTR_SET_VALUE_MIN | ATTR_SET_VALUE_REQUIRED,
        .valueType = VALUE_TYPE_NUMBER,
        .units = {"W"},
        .unit_W = "W",
        .min = 0,
    },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_POWER_METER_ */
