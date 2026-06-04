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

#ifndef _IOT_CAPS_HELPER_THREAD_NETWORK_
#define _IOT_CAPS_HELPER_THREAD_NETWORK_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

const static struct iot_caps_threadNetwork {
    const char *id;
    const struct threadNetwork_attr_networkName {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const unsigned int max_length;
    } attr_networkName;
    const struct threadNetwork_attr_networkKey {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
    } attr_networkKey;
    const struct threadNetwork_attr_channel {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const int min;
        const int max;
    } attr_channel;
    const struct threadNetwork_attr_panId {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const int min;
        const int max;
    } attr_panId;
    const struct threadNetwork_attr_extendedPanId {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
    } attr_extendedPanId;
} caps_helper_threadNetwork = {
    .id = "threadNetwork",
    .attr_networkName =
        {
            .name = "networkName",
            .property = ATTR_SET_VALUE_REQUIRED | ATTR_SET_MAX_LENGTH,
            .valueType = VALUE_TYPE_STRING,
            .max_length = 255,
        },
    .attr_networkKey =
        {
            .name = "networkKey",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
        },
    .attr_channel =
        {
            .name = "channel",
            .property = ATTR_SET_VALUE_MIN | ATTR_SET_VALUE_MAX | ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_INTEGER,
            .min = 11,
            .max = 26,
        },
    .attr_panId =
        {
            .name = "panId",
            .property = ATTR_SET_VALUE_MIN | ATTR_SET_VALUE_MAX | ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_INTEGER,
            .min = 0,
            .max = 65535,
        },
    .attr_extendedPanId =
        {
            .name = "extendedPanId",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
        },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_THREAD_NETWORK_ */
