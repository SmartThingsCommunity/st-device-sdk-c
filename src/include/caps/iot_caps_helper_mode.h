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

#ifndef _IOT_CAPS_HELPER_MODE_
#define _IOT_CAPS_HELPER_MODE_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

const static struct iot_caps_mode {
    const char *id;
    const struct mode_attr_supportedModes {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
    } attr_supportedModes;
    const struct mode_attr_mode {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
    } attr_mode;
    const struct mode_cmd_setMode { const char* name; } cmd_setMode;
} caps_helper_mode = {
    .id = "mode",
    .attr_supportedModes = {
        .name = "supportedModes",
        .property = ATTR_SET_VALUE_ARRAY,
        .valueType = VALUE_TYPE_STRING,
    },
    .attr_mode = {
        .name = "mode",
        .property = ATTR_SET_VALUE_REQUIRED,
        .valueType = VALUE_TYPE_STRING,
    },
    .cmd_setMode = { .name = "setMode" }, // arguments: mode(string) 
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_MODE_ */
