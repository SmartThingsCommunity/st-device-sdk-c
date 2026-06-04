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

#ifndef _IOT_CAPS_HELPER_TEMPERATURE_LEVEL_
#define _IOT_CAPS_HELPER_TEMPERATURE_LEVEL_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

const static struct iot_caps_temperatureLevel {
    const char *id;
    const struct temperatureLevel_attr_supportedTemperatureLevels {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
    } attr_supportedTemperatureLevels;
    const struct temperatureLevel_attr_temperatureLevel {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
    } attr_temperatureLevel;
    const struct temperatureLevel_cmd_setTemperatureLevel {
        const char *name;
    } cmd_setTemperatureLevel;
} caps_helper_temperatureLevel = {
    .id = "temperatureLevel",
    .attr_supportedTemperatureLevels =
        {
            .name = "supportedTemperatureLevels",
            .property = ATTR_SET_VALUE_ARRAY,
            .valueType = VALUE_TYPE_STRING,
        },
    .attr_temperatureLevel =
        {
            .name = "temperatureLevel",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
        },
    .cmd_setTemperatureLevel = {.name = "setTemperatureLevel"},  // arguments: temperatureLevel(string)
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_TEMPERATURE_LEVEL_ */
