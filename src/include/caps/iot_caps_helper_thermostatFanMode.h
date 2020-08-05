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

#ifndef _IOT_CAPS_HELPER_THERMOSTAT_FAN_MODE_
#define _IOT_CAPS_HELPER_THERMOSTAT_FAN_MODE_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_THERMOSTATFANMODE_THERMOSTATFANMODE_VALUE_AUTO,
    CAP_ENUM_THERMOSTATFANMODE_THERMOSTATFANMODE_VALUE_CIRCULATE,
    CAP_ENUM_THERMOSTATFANMODE_THERMOSTATFANMODE_VALUE_FOLLOWSCHEDULE,
    CAP_ENUM_THERMOSTATFANMODE_THERMOSTATFANMODE_VALUE_ON,
    CAP_ENUM_THERMOSTATFANMODE_THERMOSTATFANMODE_VALUE_MAX
};

#define CAP_ENUM_THERMOSTATFANMODE_SUPPORTEDTHERMOSTATFANMODES_VALUE_MAX 4
const static struct iot_caps_thermostatFanMode {
    const char *id;
    const struct thermostatFanMode_attr_thermostatFanMode {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_THERMOSTATFANMODE_THERMOSTATFANMODE_VALUE_MAX];
        const char *value_auto;
        const char *value_circulate;
        const char *value_followschedule;
        const char *value_on;
    } attr_thermostatFanMode;
    const struct thermostatFanMode_attr_supportedThermostatFanModes {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_THERMOSTATFANMODE_SUPPORTEDTHERMOSTATFANMODES_VALUE_MAX];
        const char *value_auto;
        const char *value_circulate;
        const char *value_followschedule;
        const char *value_on;
    } attr_supportedThermostatFanModes;
    const struct thermostatFanMode_cmd_fanOn { const char* name; } cmd_fanOn;
    const struct thermostatFanMode_cmd_fanCirculate { const char* name; } cmd_fanCirculate;
    const struct thermostatFanMode_cmd_fanAuto { const char* name; } cmd_fanAuto;
    const struct thermostatFanMode_cmd_setThermostatFanMode { const char* name; } cmd_setThermostatFanMode;
} caps_helper_thermostatFanMode = {
    .id = "thermostatFanMode",
    .attr_thermostatFanMode = {
        .name = "thermostatFanMode",
        .property = ATTR_SET_VALUE_REQUIRED,
        .valueType = VALUE_TYPE_STRING,
        .values = {"auto", "circulate", "followschedule", "on"},
        .value_auto = "auto",
        .value_circulate = "circulate",
        .value_followschedule = "followschedule",
        .value_on = "on",
    },
    .attr_supportedThermostatFanModes = {
        .name = "supportedThermostatFanModes",
        .property = ATTR_SET_VALUE_ARRAY,
        .valueType = VALUE_TYPE_STRING,
        .values = {"auto", "circulate", "followschedule", "on"},
        .value_auto = "auto",
        .value_circulate = "circulate",
        .value_followschedule = "followschedule",
        .value_on = "on",
    },
    .cmd_fanOn = { .name = "fanOn" },
    .cmd_fanCirculate = { .name = "fanCirculate" },
    .cmd_fanAuto = { .name = "fanAuto" },
    .cmd_setThermostatFanMode = { .name = "setThermostatFanMode" }, // arguments: mode(string) 
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_THERMOSTAT_FAN_MODE_ */
