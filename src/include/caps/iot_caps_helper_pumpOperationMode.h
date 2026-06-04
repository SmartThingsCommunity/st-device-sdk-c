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

#ifndef _IOT_CAPS_HELPER_PUMP_OPERATION_MODE_
#define _IOT_CAPS_HELPER_PUMP_OPERATION_MODE_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_PUMPOPERATIONMODE_OPERATIONMODE_VALUE_NORMAL,
    CAP_ENUM_PUMPOPERATIONMODE_OPERATIONMODE_VALUE_MINIMUM,
    CAP_ENUM_PUMPOPERATIONMODE_OPERATIONMODE_VALUE_MAXIMUM,
    CAP_ENUM_PUMPOPERATIONMODE_OPERATIONMODE_VALUE_LOCALSETTING,
    CAP_ENUM_PUMPOPERATIONMODE_OPERATIONMODE_VALUE_MAX
};

enum {
    CAP_ENUM_PUMPOPERATIONMODE_CURRENTOPERATIONMODE_VALUE_NORMAL,
    CAP_ENUM_PUMPOPERATIONMODE_CURRENTOPERATIONMODE_VALUE_MINIMUM,
    CAP_ENUM_PUMPOPERATIONMODE_CURRENTOPERATIONMODE_VALUE_MAXIMUM,
    CAP_ENUM_PUMPOPERATIONMODE_CURRENTOPERATIONMODE_VALUE_LOCALSETTING,
    CAP_ENUM_PUMPOPERATIONMODE_CURRENTOPERATIONMODE_VALUE_MAX
};

enum {
    CAP_ENUM_PUMPOPERATIONMODE_SUPPORTEDOPERATIONMODES_VALUE_NORMAL,
    CAP_ENUM_PUMPOPERATIONMODE_SUPPORTEDOPERATIONMODES_VALUE_MINIMUM,
    CAP_ENUM_PUMPOPERATIONMODE_SUPPORTEDOPERATIONMODES_VALUE_MAXIMUM,
    CAP_ENUM_PUMPOPERATIONMODE_SUPPORTEDOPERATIONMODES_VALUE_LOCALSETTING,
    CAP_ENUM_PUMPOPERATIONMODE_SUPPORTEDOPERATIONMODES_VALUE_MAX
};

const static struct iot_caps_pumpOperationMode {
    const char *id;
    const struct pumpOperationMode_attr_operationMode {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_PUMPOPERATIONMODE_OPERATIONMODE_VALUE_MAX];
        const char *value_normal;
        const char *value_minimum;
        const char *value_maximum;
        const char *value_localSetting;
    } attr_operationMode;
    const struct pumpOperationMode_attr_currentOperationMode {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_PUMPOPERATIONMODE_CURRENTOPERATIONMODE_VALUE_MAX];
        const char *value_normal;
        const char *value_minimum;
        const char *value_maximum;
        const char *value_localSetting;
    } attr_currentOperationMode;
    const struct pumpOperationMode_attr_supportedOperationModes {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_PUMPOPERATIONMODE_SUPPORTEDOPERATIONMODES_VALUE_MAX];
        const char *value_normal;
        const char *value_minimum;
        const char *value_maximum;
        const char *value_localSetting;
    } attr_supportedOperationModes;
    const struct pumpOperationMode_cmd_setOperationMode {
        const char *name;
    } cmd_setOperationMode;
} caps_helper_pumpOperationMode = {
    .id = "pumpOperationMode",
    .attr_operationMode =
        {
            .name = "operationMode",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"normal", "minimum", "maximum", "localSetting"},
            .value_normal = "normal",
            .value_minimum = "minimum",
            .value_maximum = "maximum",
            .value_localSetting = "localSetting",
        },
    .attr_currentOperationMode =
        {
            .name = "currentOperationMode",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"normal", "minimum", "maximum", "localSetting"},
            .value_normal = "normal",
            .value_minimum = "minimum",
            .value_maximum = "maximum",
            .value_localSetting = "localSetting",
        },
    .attr_supportedOperationModes =
        {
            .name = "supportedOperationModes",
            .property = ATTR_SET_VALUE_ARRAY,
            .valueType = VALUE_TYPE_STRING,
            .values = {"normal", "minimum", "maximum", "localSetting"},
            .value_normal = "normal",
            .value_minimum = "minimum",
            .value_maximum = "maximum",
            .value_localSetting = "localSetting",
        },
    .cmd_setOperationMode = {.name = "setOperationMode"},  // arguments: operationMode(string)
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_PUMP_OPERATION_MODE_ */
