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

#ifndef _IOT_CAPS_HELPER_THERMOSTAT_MODE_
#define _IOT_CAPS_HELPER_THERMOSTAT_MODE_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_ASLEEP,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_AUTO,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_AUTOWITHECO,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_AUTOWITHRESET,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_AUTOCHANGEOVER,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_AUTOCHANGEOVERACTIVE,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_AUTOCOOL,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_AUTOHEAT,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_AUXHEATONLY,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_AUXILIARYEMERGENCYHEAT,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_AWAY,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_COOL,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_CUSTOM,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_DAYOFF,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_DRYAIR,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_ECO,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_EMERGENCY_HEAT,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_EMERGENCYHEAT,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_EMERGENCYHEATACTIVE,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_ENERGYSAVECOOL,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_ENERGYSAVEHEAT,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_FANONLY,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_FROSTGUARD,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_FURNACE,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_HEAT,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_HEATINGOFF,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_HOME,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_IN,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_MANUAL,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_MOISTAIR,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_OFF,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_OUT,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_RESUME,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_RUSH_HOUR,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_RUSHHOUR,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_SCHEDULE,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_SOUTHERNAWAY,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_MAX
};

#define CAP_ENUM_THERMOSTATMODE_SUPPORTEDTHERMOSTATMODES_VALUE_MAX 37
const static struct iot_caps_thermostatMode {
    const char *id;
    const struct thermostatMode_attr_thermostatMode {
        const char *name;
        const unsigned char property;
        const unsigned char value_type;
        const char *values[CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_MAX];
    } attr_thermostatMode;
    const struct thermostatMode_attr_supportedThermostatModes {
        const char *name;
        const unsigned char property;
        const unsigned char value_type;
        const char *values[CAP_ENUM_THERMOSTATMODE_SUPPORTEDTHERMOSTATMODES_VALUE_MAX];
    } attr_supportedThermostatModes;
    const struct thermostatMode_cmd_heat { const char* name; } cmd_heat;
    const struct thermostatMode_cmd_emergencyHeat { const char* name; } cmd_emergencyHeat;
    const struct thermostatMode_cmd_auto { const char* name; } cmd_auto;
    const struct thermostatMode_cmd_cool { const char* name; } cmd_cool;
    const struct thermostatMode_cmd_off { const char* name; } cmd_off;
    const struct thermostatMode_cmd_setThermostatMode { const char* name; } cmd_setThermostatMode;
} caps_helper_thermostatMode = {
    .id = "thermostatMode",
    .attr_thermostatMode = {
        .name = "thermostatMode",
        .property = ATTR_SET_VALUE_REQUIRED,
        .value_type = VALUE_TYPE_STRING,
        .values = {"asleep", "auto", "autowitheco", "autowithreset", "autochangeover", "autochangeoveractive", "autocool", "autoheat", "auxheatonly", "auxiliaryemergencyheat", "away", "cool", "custom", "dayoff", "dryair", "eco", "emergency heat", "emergencyheat", "emergencyheatactive", "energysavecool", "energysaveheat", "fanonly", "frostguard", "furnace", "heat", "heatingoff", "home", "in", "manual", "moistair", "off", "out", "resume", "rush hour", "rushhour", "schedule", "southernaway"},
    },
    .attr_supportedThermostatModes = {
        .name = "supportedThermostatModes",
        .property = ATTR_SET_VALUE_ARRAY,
        .value_type = VALUE_TYPE_STRING,
        .values = {"asleep", "auto", "autowitheco", "autowithreset", "autochangeover", "autochangeoveractive", "autocool", "autoheat", "auxheatonly", "auxiliaryemergencyheat", "away", "cool", "custom", "dayoff", "dryair", "eco", "emergency heat", "emergencyheat", "emergencyheatactive", "energysavecool", "energysaveheat", "fanonly", "frostguard", "furnace", "heat", "heatingoff", "home", "in", "manual", "moistair", "off", "out", "resume", "rush hour", "rushhour", "schedule", "southernaway"},
    },
    .cmd_heat = { .name = "heat" },
    .cmd_emergencyHeat = { .name = "emergencyHeat" },
    .cmd_auto = { .name = "auto" },
    .cmd_cool = { .name = "cool" },
    .cmd_off = { .name = "off" },
    .cmd_setThermostatMode = { .name = "setThermostatMode" }, // arguments: mode(string) 
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_THERMOSTAT_MODE_ */
