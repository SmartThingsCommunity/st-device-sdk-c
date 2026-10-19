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

#ifndef _IOT_CAPS_HELPER_THREAD_BORDER_ROUTER_
#define _IOT_CAPS_HELPER_THREAD_BORDER_ROUTER_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_THREADBORDERROUTER_THREADINTERFACESTATE_VALUE_DISABLED,
    CAP_ENUM_THREADBORDERROUTER_THREADINTERFACESTATE_VALUE_ENABLED,
    CAP_ENUM_THREADBORDERROUTER_THREADINTERFACESTATE_VALUE_MAX
};

const static struct iot_caps_threadBorderRouter {
    const char *id;
    const struct threadBorderRouter_attr_borderRouterName {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
    } attr_borderRouterName;
    const struct threadBorderRouter_attr_threadInterfaceState {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_THREADBORDERROUTER_THREADINTERFACESTATE_VALUE_MAX];
        const char *value_disabled;
        const char *value_enabled;
    } attr_threadInterfaceState;
    const struct threadBorderRouter_attr_threadVersion {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
    } attr_threadVersion;
} caps_helper_threadBorderRouter = {
    .id = "threadBorderRouter",
    .attr_borderRouterName =
        {
            .name = "borderRouterName",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
        },
    .attr_threadInterfaceState =
        {
            .name = "threadInterfaceState",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"disabled", "enabled"},
            .value_disabled = "disabled",
            .value_enabled = "enabled",
        },
    .attr_threadVersion =
        {
            .name = "threadVersion",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
        },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_THREAD_BORDER_ROUTER_ */
