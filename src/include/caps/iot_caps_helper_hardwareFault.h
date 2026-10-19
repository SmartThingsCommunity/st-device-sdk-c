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

#ifndef _IOT_CAPS_HELPER_HARDWARE_FAULT_
#define _IOT_CAPS_HELPER_HARDWARE_FAULT_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_HARDWAREFAULT_HARDWAREFAULT_VALUE_CLEAR,
    CAP_ENUM_HARDWAREFAULT_HARDWAREFAULT_VALUE_DETECTED,
    CAP_ENUM_HARDWAREFAULT_HARDWAREFAULT_VALUE_MAX
};

const static struct iot_caps_hardwareFault {
    const char *id;
    const struct hardwareFault_attr_hardwareFault {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_HARDWAREFAULT_HARDWAREFAULT_VALUE_MAX];
        const char *value_clear;
        const char *value_detected;
    } attr_hardwareFault;
} caps_helper_hardwareFault = {
    .id = "hardwareFault",
    .attr_hardwareFault =
        {
            .name = "hardwareFault",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"clear", "detected"},
            .value_clear = "clear",
            .value_detected = "detected",
        },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_HARDWARE_FAULT_ */
