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

#ifndef _IOT_CAPS_HELPER_AIR_CONDITIONER_FAN_MODE_
#define _IOT_CAPS_HELPER_AIR_CONDITIONER_FAN_MODE_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

const static struct iot_caps_airConditionerFanMode {
    const char *id;
    const struct airConditionerFanMode_attr_supportedAcFanModes {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
    } attr_supportedAcFanModes;
    const struct airConditionerFanMode_attr_availableAcFanModes {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
    } attr_availableAcFanModes;
    const struct airConditionerFanMode_attr_fanMode {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const unsigned int max_length;
    } attr_fanMode;
    const struct airConditionerFanMode_cmd_setFanMode {
        const char *name;
    } cmd_setFanMode;
} caps_helper_airConditionerFanMode = {
    .id = "airConditionerFanMode",
    .attr_supportedAcFanModes =
        {
            .name = "supportedAcFanModes",
            .property = ATTR_SET_VALUE_ARRAY,
            .valueType = VALUE_TYPE_STRING,
        },
    .attr_availableAcFanModes =
        {
            .name = "availableAcFanModes",
            .property = ATTR_SET_VALUE_ARRAY,
            .valueType = VALUE_TYPE_STRING,
        },
    .attr_fanMode =
        {
            .name = "fanMode",
            .property = ATTR_SET_MAX_LENGTH,
            .valueType = VALUE_TYPE_STRING,
            .max_length = 255,
        },
    .cmd_setFanMode = {.name = "setFanMode"},  // arguments: fanMode(string)
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_AIR_CONDITIONER_FAN_MODE_ */
