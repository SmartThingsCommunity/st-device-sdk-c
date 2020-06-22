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

#ifndef _IOT_CAPS_HELPER_ENERGY_METER_
#define _IOT_CAPS_HELPER_ENERGY_METER_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_ENERGYMETER_ENERGY_UNIT_WH,
    CAP_ENUM_ENERGYMETER_ENERGY_UNIT_KWH,
    CAP_ENUM_ENERGYMETER_ENERGY_UNIT_MWH,
    CAP_ENUM_ENERGYMETER_ENERGY_UNIT_MAX
};

const static struct iot_caps_energyMeter {
    const char *id;
    const struct energyMeter_attr_energy {
        const char *name;
        const unsigned char property;
        const unsigned char value_type;
        const char *units[CAP_ENUM_ENERGYMETER_ENERGY_UNIT_MAX];
        const double min;
    } attr_energy;
} caps_helper_energyMeter = {
    .id = "energyMeter",
    .attr_energy = {
        .name = "energy",
        .property = ATTR_SET_VALUE_MIN | ATTR_SET_VALUE_REQUIRED,
        .value_type = VALUE_TYPE_NUMBER,
        .units = {"Wh", "kWh", "mWh"},
        .min = 0,
    },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_ENERGY_METER_ */
