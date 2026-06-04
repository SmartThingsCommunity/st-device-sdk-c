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

#ifndef _IOT_CAPS_HELPER_CLIP_DURATION_
#define _IOT_CAPS_HELPER_CLIP_DURATION_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

const static struct iot_caps_clipDuration {
    const char *id;
    const struct clipDuration_attr_clipDuration {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const int min;
    } attr_clipDuration;
    const struct clipDuration_attr_supportedMaxDuration {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const int min;
    } attr_supportedMaxDuration;
    const struct clipDuration_cmd_setClipDuration {
        const char *name;
    } cmd_setClipDuration;
} caps_helper_clipDuration = {
    .id = "clipDuration",
    .attr_clipDuration =
        {
            .name = "clipDuration",
            .property = ATTR_SET_VALUE_MIN | ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_INTEGER,
            .min = 0,
        },
    .attr_supportedMaxDuration =
        {
            .name = "supportedMaxDuration",
            .property = ATTR_SET_VALUE_MIN | ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_INTEGER,
            .min = 0,
        },
    .cmd_setClipDuration = {.name = "setClipDuration"},  // arguments: duration(integer)
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_CLIP_DURATION_ */
