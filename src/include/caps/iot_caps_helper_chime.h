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

#ifndef _IOT_CAPS_HELPER_CHIME_
#define _IOT_CAPS_HELPER_CHIME_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum { CAP_ENUM_CHIME_CHIME_VALUE_CHIME, CAP_ENUM_CHIME_CHIME_VALUE_OFF, CAP_ENUM_CHIME_CHIME_VALUE_MAX };

const static struct iot_caps_chime {
    const char *id;
    const struct chime_attr_chime {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_CHIME_CHIME_VALUE_MAX];
        const char *value_chime;
        const char *value_off;
    } attr_chime;
    const struct chime_cmd_chime {
        const char *name;
    } cmd_chime;
    const struct chime_cmd_off {
        const char *name;
    } cmd_off;
} caps_helper_chime = {
    .id = "chime",
    .attr_chime =
        {
            .name = "chime",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"chime", "off"},
            .value_chime = "chime",
            .value_off = "off",
        },
    .cmd_chime = {.name = "chime"},
    .cmd_off = {.name = "off"},
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_CHIME_ */
