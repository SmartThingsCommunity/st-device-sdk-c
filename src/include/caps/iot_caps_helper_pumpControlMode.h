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

#ifndef _IOT_CAPS_HELPER_PUMP_CONTROL_MODE_
#define _IOT_CAPS_HELPER_PUMP_CONTROL_MODE_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_PUMPCONTROLMODE_CONTROLMODE_VALUE_CONSTANTSPEED,
    CAP_ENUM_PUMPCONTROLMODE_CONTROLMODE_VALUE_CONSTANTPRESSURE,
    CAP_ENUM_PUMPCONTROLMODE_CONTROLMODE_VALUE_PROPORTIONALPRESSURE,
    CAP_ENUM_PUMPCONTROLMODE_CONTROLMODE_VALUE_CONSTANTFLOW,
    CAP_ENUM_PUMPCONTROLMODE_CONTROLMODE_VALUE_CONSTANTTEMPERATURE,
    CAP_ENUM_PUMPCONTROLMODE_CONTROLMODE_VALUE_AUTOMATIC,
    CAP_ENUM_PUMPCONTROLMODE_CONTROLMODE_VALUE_MAX
};

enum {
    CAP_ENUM_PUMPCONTROLMODE_CURRENTCONTROLMODE_VALUE_CONSTANTSPEED,
    CAP_ENUM_PUMPCONTROLMODE_CURRENTCONTROLMODE_VALUE_CONSTANTPRESSURE,
    CAP_ENUM_PUMPCONTROLMODE_CURRENTCONTROLMODE_VALUE_PROPORTIONALPRESSURE,
    CAP_ENUM_PUMPCONTROLMODE_CURRENTCONTROLMODE_VALUE_CONSTANTFLOW,
    CAP_ENUM_PUMPCONTROLMODE_CURRENTCONTROLMODE_VALUE_CONSTANTTEMPERATURE,
    CAP_ENUM_PUMPCONTROLMODE_CURRENTCONTROLMODE_VALUE_AUTOMATIC,
    CAP_ENUM_PUMPCONTROLMODE_CURRENTCONTROLMODE_VALUE_MAX
};

enum {
    CAP_ENUM_PUMPCONTROLMODE_SUPPORTEDCONTROLMODES_VALUE_CONSTANTSPEED,
    CAP_ENUM_PUMPCONTROLMODE_SUPPORTEDCONTROLMODES_VALUE_CONSTANTPRESSURE,
    CAP_ENUM_PUMPCONTROLMODE_SUPPORTEDCONTROLMODES_VALUE_PROPORTIONALPRESSURE,
    CAP_ENUM_PUMPCONTROLMODE_SUPPORTEDCONTROLMODES_VALUE_CONSTANTFLOW,
    CAP_ENUM_PUMPCONTROLMODE_SUPPORTEDCONTROLMODES_VALUE_CONSTANTTEMPERATURE,
    CAP_ENUM_PUMPCONTROLMODE_SUPPORTEDCONTROLMODES_VALUE_AUTOMATIC,
    CAP_ENUM_PUMPCONTROLMODE_SUPPORTEDCONTROLMODES_VALUE_MAX
};

const static struct iot_caps_pumpControlMode {
    const char *id;
    const struct pumpControlMode_attr_controlMode {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_PUMPCONTROLMODE_CONTROLMODE_VALUE_MAX];
        const char *value_constantSpeed;
        const char *value_constantPressure;
        const char *value_proportionalPressure;
        const char *value_constantFlow;
        const char *value_constantTemperature;
        const char *value_automatic;
    } attr_controlMode;
    const struct pumpControlMode_attr_currentControlMode {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_PUMPCONTROLMODE_CURRENTCONTROLMODE_VALUE_MAX];
        const char *value_constantSpeed;
        const char *value_constantPressure;
        const char *value_proportionalPressure;
        const char *value_constantFlow;
        const char *value_constantTemperature;
        const char *value_automatic;
    } attr_currentControlMode;
    const struct pumpControlMode_attr_supportedControlModes {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_PUMPCONTROLMODE_SUPPORTEDCONTROLMODES_VALUE_MAX];
        const char *value_constantSpeed;
        const char *value_constantPressure;
        const char *value_proportionalPressure;
        const char *value_constantFlow;
        const char *value_constantTemperature;
        const char *value_automatic;
    } attr_supportedControlModes;
    const struct pumpControlMode_cmd_setControlMode {
        const char *name;
    } cmd_setControlMode;
} caps_helper_pumpControlMode = {
    .id = "pumpControlMode",
    .attr_controlMode =
        {
            .name = "controlMode",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"constantSpeed", "constantPressure", "proportionalPressure", "constantFlow",
                       "constantTemperature", "automatic"},
            .value_constantSpeed = "constantSpeed",
            .value_constantPressure = "constantPressure",
            .value_proportionalPressure = "proportionalPressure",
            .value_constantFlow = "constantFlow",
            .value_constantTemperature = "constantTemperature",
            .value_automatic = "automatic",
        },
    .attr_currentControlMode =
        {
            .name = "currentControlMode",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"constantSpeed", "constantPressure", "proportionalPressure", "constantFlow",
                       "constantTemperature", "automatic"},
            .value_constantSpeed = "constantSpeed",
            .value_constantPressure = "constantPressure",
            .value_proportionalPressure = "proportionalPressure",
            .value_constantFlow = "constantFlow",
            .value_constantTemperature = "constantTemperature",
            .value_automatic = "automatic",
        },
    .attr_supportedControlModes =
        {
            .name = "supportedControlModes",
            .property = ATTR_SET_VALUE_ARRAY,
            .valueType = VALUE_TYPE_STRING,
            .values = {"constantSpeed", "constantPressure", "proportionalPressure", "constantFlow",
                       "constantTemperature", "automatic"},
            .value_constantSpeed = "constantSpeed",
            .value_constantPressure = "constantPressure",
            .value_proportionalPressure = "proportionalPressure",
            .value_constantFlow = "constantFlow",
            .value_constantTemperature = "constantTemperature",
            .value_automatic = "automatic",
        },
    .cmd_setControlMode = {.name = "setControlMode"},  // arguments: controlMode(string)
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_PUMP_CONTROL_MODE_ */
