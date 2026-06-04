/* ***************************************************************************
 *
 * Copyright 2019-2026 Samsung Electronics All Rights Reserved.
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

#ifndef _IOT_CAPS_HELPER_FAN_DIRECTION_
#define _IOT_CAPS_HELPER_FAN_DIRECTION_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_FANDIRECTION_FANDIRECTION_VALUE_SUMMERMODE,
    CAP_ENUM_FANDIRECTION_FANDIRECTION_VALUE_WINTERMODE,
    CAP_ENUM_FANDIRECTION_FANDIRECTION_VALUE_MAX
};

const static struct iot_caps_fanDirection {
    const char *id;
    const struct fanDirection_attr_fanDirection {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_FANDIRECTION_FANDIRECTION_VALUE_MAX];
        const char *value_summerMode;
        const char *value_winterMode;
    } attr_fanDirection;
    const struct fanDirection_cmd_summerMode {
        const char *name;
    } cmd_summerMode;
    const struct fanDirection_cmd_winterMode {
        const char *name;
    } cmd_winterMode;
} caps_helper_fanDirection = {
    .id = "fanDirection",
    .attr_fanDirection =
        {
            .name = "fanDirection",
            .property = 0,
            .valueType = VALUE_TYPE_STRING,
            .values = {"summerMode", "winterMode"},
            .value_summerMode = "summerMode",
            .value_winterMode = "winterMode",
        },
    .cmd_summerMode = {.name = "summerMode"},
    .cmd_winterMode = {.name = "winterMode"},
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_FAN_DIRECTION_ */
