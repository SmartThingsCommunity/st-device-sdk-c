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
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_ANTIFREEZING,
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
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_COOLINGFLOORANDCOLDAIR,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_COMFORT,
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
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_HOTWATERONLY,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_IN,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_MANUAL,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_MOISTAIR,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_OFF,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_ON,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_OUT,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_RADIATINGFLOOR,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_RADIATINGFLOORANDHOTAIR,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_RESUME,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_RUSH_HOUR,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_RUSHHOUR,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_SCHEDULE,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_SOUTHERNAWAY,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_PRECOOLING,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_LUKEWARM,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_WARM,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_HOT,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_VERYHOT,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_ONDOL,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_BATH,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_ITERATIVERESERVATION,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_24HOURRESERVATION,
    CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_MAX
};

#define CAP_ENUM_THERMOSTATMODE_SUPPORTEDTHERMOSTATMODES_VALUE_MAX 53
const static struct iot_caps_thermostatMode {
    const char *id;
    const struct thermostatMode_attr_thermostatMode {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_THERMOSTATMODE_THERMOSTATMODE_VALUE_MAX];
        const char *value_24hourReservation;
        const char *value_antifreezing;
        const char *value_asleep;
        const char *value_auto;
        const char *value_autowitheco;
        const char *value_autowithreset;
        const char *value_autochangeover;
        const char *value_autochangeoveractive;
        const char *value_autocool;
        const char *value_autoheat;
        const char *value_auxheatonly;
        const char *value_auxiliaryemergencyheat;
        const char *value_away;
        const char *value_bath;
        const char *value_cool;
        const char *value_coolingfloorandcoldair;
        const char *value_comfort;
        const char *value_custom;
        const char *value_dayoff;
        const char *value_dryair;
        const char *value_eco;
        const char *value_emergency_heat;
        const char *value_emergencyheat;
        const char *value_emergencyheatactive;
        const char *value_energysavecool;
        const char *value_energysaveheat;
        const char *value_fanonly;
        const char *value_frostguard;
        const char *value_furnace;
        const char *value_heat;
        const char *value_heatingoff;
        const char *value_home;
        const char *value_hot;
        const char *value_hotwateronly;
        const char *value_in;
        const char *value_iterativeReservation;
        const char *value_lukewarm;
        const char *value_manual;
        const char *value_moistair;
        const char *value_off;
        const char *value_on;
        const char *value_ondol;
        const char *value_out;
        const char *value_precooling;
        const char *value_radiatingfloor;
        const char *value_radiatingfloorandhotair;
        const char *value_resume;
        const char *value_rush_hour;
        const char *value_rushhour;
        const char *value_schedule;
        const char *value_southernaway;
        const char *value_veryhot;
        const char *value_warm;
    } attr_thermostatMode;
    const struct thermostatMode_attr_supportedThermostatModes {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_THERMOSTATMODE_SUPPORTEDTHERMOSTATMODES_VALUE_MAX];
        const char *value_24hourReservation;
        const char *value_antifreezing;
        const char *value_asleep;
        const char *value_auto;
        const char *value_autowitheco;
        const char *value_autowithreset;
        const char *value_autochangeover;
        const char *value_autochangeoveractive;
        const char *value_autocool;
        const char *value_autoheat;
        const char *value_auxheatonly;
        const char *value_auxiliaryemergencyheat;
        const char *value_away;
        const char *value_bath;
        const char *value_cool;
        const char *value_coolingfloorandcoldair;
        const char *value_comfort;
        const char *value_custom;
        const char *value_dayoff;
        const char *value_dryair;
        const char *value_eco;
        const char *value_emergency_heat;
        const char *value_emergencyheat;
        const char *value_emergencyheatactive;
        const char *value_energysavecool;
        const char *value_energysaveheat;
        const char *value_fanonly;
        const char *value_frostguard;
        const char *value_furnace;
        const char *value_heat;
        const char *value_heatingoff;
        const char *value_home;
        const char *value_hot;
        const char *value_hotwateronly;
        const char *value_in;
        const char *value_iterativeReservation;
        const char *value_lukewarm;
        const char *value_manual;
        const char *value_moistair;
        const char *value_off;
        const char *value_on;
        const char *value_ondol;
        const char *value_out;
        const char *value_precooling;
        const char *value_radiatingfloor;
        const char *value_radiatingfloorandhotair;
        const char *value_resume;
        const char *value_rush_hour;
        const char *value_rushhour;
        const char *value_schedule;
        const char *value_southernaway;
        const char *value_veryhot;
        const char *value_warm;
    } attr_supportedThermostatModes;
    const struct thermostatMode_cmd_heat {
        const char *name;
    } cmd_heat;
    const struct thermostatMode_cmd_emergencyHeat {
        const char *name;
    } cmd_emergencyHeat;
    const struct thermostatMode_cmd_auto {
        const char *name;
    } cmd_auto;
    const struct thermostatMode_cmd_cool {
        const char *name;
    } cmd_cool;
    const struct thermostatMode_cmd_off {
        const char *name;
    } cmd_off;
    const struct thermostatMode_cmd_setThermostatMode {
        const char *name;
    } cmd_setThermostatMode;
} caps_helper_thermostatMode = {
    .id = "thermostatMode",
    .attr_thermostatMode =
        {
            .name = "thermostatMode",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"antifreezing",
                       "asleep",
                       "auto",
                       "autowitheco",
                       "autowithreset",
                       "autochangeover",
                       "autochangeoveractive",
                       "autocool",
                       "autoheat",
                       "auxheatonly",
                       "auxiliaryemergencyheat",
                       "away",
                       "cool",
                       "coolingfloorandcoldair",
                       "comfort",
                       "custom",
                       "dayoff",
                       "dryair",
                       "eco",
                       "emergency heat",
                       "emergencyheat",
                       "emergencyheatactive",
                       "energysavecool",
                       "energysaveheat",
                       "fanonly",
                       "frostguard",
                       "furnace",
                       "heat",
                       "heatingoff",
                       "home",
                       "hotwateronly",
                       "in",
                       "manual",
                       "moistair",
                       "off",
                       "on",
                       "out",
                       "radiatingfloor",
                       "radiatingfloorandhotair",
                       "resume",
                       "rush hour",
                       "rushhour",
                       "schedule",
                       "southernaway",
                       "precooling",
                       "lukewarm",
                       "warm",
                       "hot",
                       "veryhot",
                       "ondol",
                       "bath",
                       "iterativeReservation",
                       "24hourReservation"},
            .value_antifreezing = "antifreezing",
            .value_24hourReservation = "24hourReservation",
            .value_asleep = "asleep",
            .value_auto = "auto",
            .value_autowitheco = "autowitheco",
            .value_autowithreset = "autowithreset",
            .value_autochangeover = "autochangeover",
            .value_autochangeoveractive = "autochangeoveractive",
            .value_autocool = "autocool",
            .value_autoheat = "autoheat",
            .value_auxheatonly = "auxheatonly",
            .value_auxiliaryemergencyheat = "auxiliaryemergencyheat",
            .value_away = "away",
            .value_bath = "bath",
            .value_cool = "cool",
            .value_coolingfloorandcoldair = "coolingfloorandcoldair",
            .value_comfort = "comfort",
            .value_custom = "custom",
            .value_dayoff = "dayoff",
            .value_dryair = "dryair",
            .value_eco = "eco",
            .value_emergency_heat = "emergency heat",
            .value_emergencyheat = "emergencyheat",
            .value_emergencyheatactive = "emergencyheatactive",
            .value_energysavecool = "energysavecool",
            .value_energysaveheat = "energysaveheat",
            .value_fanonly = "fanonly",
            .value_frostguard = "frostguard",
            .value_furnace = "furnace",
            .value_heat = "heat",
            .value_heatingoff = "heatingoff",
            .value_home = "home",
            .value_hot = "hot",
            .value_hotwateronly = "hotwateronly",
            .value_in = "in",
            .value_iterativeReservation = "iterativeReservation",
            .value_lukewarm = "lukewarm",
            .value_manual = "manual",
            .value_moistair = "moistair",
            .value_off = "off",
            .value_on = "on",
            .value_ondol = "ondol",
            .value_out = "out",
            .value_precooling = "precooling",
            .value_radiatingfloor = "radiatingfloor",
            .value_radiatingfloorandhotair = "radiatingfloorandhotair",
            .value_resume = "resume",
            .value_rush_hour = "rush hour",
            .value_rushhour = "rushhour",
            .value_schedule = "schedule",
            .value_southernaway = "southernaway",
            .value_veryhot = "veryhot",
            .value_warm = "warm",
        },
    .attr_supportedThermostatModes =
        {
            .name = "supportedThermostatModes",
            .property = ATTR_SET_VALUE_ARRAY,
            .valueType = VALUE_TYPE_STRING,
            .values = {"antifreezing",
                       "asleep",
                       "auto",
                       "autowitheco",
                       "autowithreset",
                       "autochangeover",
                       "autochangeoveractive",
                       "autocool",
                       "autoheat",
                       "auxheatonly",
                       "auxiliaryemergencyheat",
                       "away",
                       "cool",
                       "coolingfloorandcoldair",
                       "comfort",
                       "custom",
                       "dayoff",
                       "dryair",
                       "eco",
                       "emergency heat",
                       "emergencyheat",
                       "emergencyheatactive",
                       "energysavecool",
                       "energysaveheat",
                       "fanonly",
                       "frostguard",
                       "furnace",
                       "heat",
                       "heatingoff",
                       "home",
                       "hotwateronly",
                       "in",
                       "manual",
                       "moistair",
                       "off",
                       "on",
                       "out",
                       "radiatingfloor",
                       "radiatingfloorandhotair",
                       "resume",
                       "rush hour",
                       "rushhour",
                       "schedule",
                       "southernaway",
                       "precooling",
                       "lukewarm",
                       "warm",
                       "hot",
                       "veryhot",
                       "ondol",
                       "bath",
                       "iterativeReservation",
                       "24hourReservation"},
            .value_antifreezing = "antifreezing",
            .value_24hourReservation = "24hourReservation",
            .value_asleep = "asleep",
            .value_auto = "auto",
            .value_autowitheco = "autowitheco",
            .value_autowithreset = "autowithreset",
            .value_autochangeover = "autochangeover",
            .value_autochangeoveractive = "autochangeoveractive",
            .value_autocool = "autocool",
            .value_autoheat = "autoheat",
            .value_auxheatonly = "auxheatonly",
            .value_auxiliaryemergencyheat = "auxiliaryemergencyheat",
            .value_away = "away",
            .value_bath = "bath",
            .value_cool = "cool",
            .value_coolingfloorandcoldair = "coolingfloorandcoldair",
            .value_comfort = "comfort",
            .value_custom = "custom",
            .value_dayoff = "dayoff",
            .value_dryair = "dryair",
            .value_eco = "eco",
            .value_emergency_heat = "emergency heat",
            .value_emergencyheat = "emergencyheat",
            .value_emergencyheatactive = "emergencyheatactive",
            .value_energysavecool = "energysavecool",
            .value_energysaveheat = "energysaveheat",
            .value_fanonly = "fanonly",
            .value_frostguard = "frostguard",
            .value_furnace = "furnace",
            .value_heat = "heat",
            .value_heatingoff = "heatingoff",
            .value_home = "home",
            .value_hot = "hot",
            .value_hotwateronly = "hotwateronly",
            .value_in = "in",
            .value_iterativeReservation = "iterativeReservation",
            .value_lukewarm = "lukewarm",
            .value_manual = "manual",
            .value_moistair = "moistair",
            .value_off = "off",
            .value_on = "on",
            .value_ondol = "ondol",
            .value_out = "out",
            .value_precooling = "precooling",
            .value_radiatingfloor = "radiatingfloor",
            .value_radiatingfloorandhotair = "radiatingfloorandhotair",
            .value_resume = "resume",
            .value_rush_hour = "rush hour",
            .value_rushhour = "rushhour",
            .value_schedule = "schedule",
            .value_southernaway = "southernaway",
            .value_veryhot = "veryhot",
            .value_warm = "warm",
        },
    .cmd_heat = {.name = "heat"},
    .cmd_emergencyHeat = {.name = "emergencyHeat"},
    .cmd_auto = {.name = "auto"},
    .cmd_cool = {.name = "cool"},
    .cmd_off = {.name = "off"},
    .cmd_setThermostatMode = {.name = "setThermostatMode"},  // arguments: mode(string)
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_THERMOSTAT_MODE_ */
