/* ***************************************************************************
 *
 * Copyright 2019-2021 Samsung Electronics All Rights Reserved.
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
    CAP_ENUM_ENERGYMETER_ENERGY_UNIT_KVAH,
    CAP_ENUM_ENERGYMETER_ENERGY_UNIT_MAX
};

const static struct iot_caps_energyMeter {
    const char *id;
    const struct energyMeter_attr_energy {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *units[CAP_ENUM_ENERGYMETER_ENERGY_UNIT_MAX];
        const char *unit_Wh;
        const char *unit_kWh;
        const char *unit_mWh;
        const char *unit_kVAh;
        const double min;
    } attr_energy;
    const struct energyMeter_cmd_resetEnergyMeter { const char* name; } cmd_resetEnergyMeter;
} caps_helper_energyMeter = {
    .id = "energyMeter",
    .attr_energy = {
        .name = "energy",
        .property = ATTR_SET_VALUE_MIN | ATTR_SET_VALUE_REQUIRED,
        .valueType = VALUE_TYPE_NUMBER,
        .units = {"Wh", "kWh", "mWh", "kVAh"},
        .unit_Wh = "Wh",
        .unit_kWh = "kWh",
        .unit_mWh = "mWh",
        .unit_kVAh = "kVAh",
        .min = 0,
    },
    .cmd_resetEnergyMeter = { .name = "resetEnergyMeter" },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_ENERGY_METER_ */
