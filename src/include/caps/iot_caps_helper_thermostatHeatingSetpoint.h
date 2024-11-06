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

#ifndef _IOT_CAPS_HELPER_THERMOSTAT_HEATING_SETPOINT_
#define _IOT_CAPS_HELPER_THERMOSTAT_HEATING_SETPOINT_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_THERMOSTATHEATINGSETPOINT_HEATINGSETPOINT_UNIT_F,
    CAP_ENUM_THERMOSTATHEATINGSETPOINT_HEATINGSETPOINT_UNIT_C,
    CAP_ENUM_THERMOSTATHEATINGSETPOINT_HEATINGSETPOINT_UNIT_MAX
};

const static struct iot_caps_thermostatHeatingSetpoint {
    const char *id;
    const struct thermostatHeatingSetpoint_attr_heatingSetpoint {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *units[CAP_ENUM_THERMOSTATHEATINGSETPOINT_HEATINGSETPOINT_UNIT_MAX];
        const char *unit_F;
        const char *unit_C;
        const double min;
        const double max;
    } attr_heatingSetpoint;
    const struct thermostatHeatingSetpoint_cmd_setHeatingSetpoint { const char* name; } cmd_setHeatingSetpoint;
} caps_helper_thermostatHeatingSetpoint = {
    .id = "thermostatHeatingSetpoint",
    .attr_heatingSetpoint = {
        .name = "heatingSetpoint",
        .property = ATTR_SET_VALUE_MIN | ATTR_SET_VALUE_MAX | ATTR_SET_VALUE_REQUIRED | ATTR_SET_UNIT_REQUIRED,
        .valueType = VALUE_TYPE_NUMBER,
        .units = {"F", "C"},
        .unit_F = "F",
        .unit_C = "C",
        .min = -460,
        .max = 10000,
    },
    .cmd_setHeatingSetpoint = { .name = "setHeatingSetpoint" }, // arguments: setpoint(number) 
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_THERMOSTAT_HEATING_SETPOINT_ */
