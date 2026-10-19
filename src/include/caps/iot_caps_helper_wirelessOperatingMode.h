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

#ifndef _IOT_CAPS_HELPER_WIRELESS_OPERATING_MODE_
#define _IOT_CAPS_HELPER_WIRELESS_OPERATING_MODE_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_WIRELESSOPERATINGMODE_WIRELESSOPERATINGMODE_VALUE_WHENNEEDED,
    CAP_ENUM_WIRELESSOPERATINGMODE_WIRELESSOPERATINGMODE_VALUE_ALWAYSON,
    CAP_ENUM_WIRELESSOPERATINGMODE_WIRELESSOPERATINGMODE_VALUE_MAX
};

const static struct iot_caps_wirelessOperatingMode {
    const char *id;
    const struct wirelessOperatingMode_attr_wirelessOperatingMode {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_WIRELESSOPERATINGMODE_WIRELESSOPERATINGMODE_VALUE_MAX];
        const char *value_whenNeeded;
        const char *value_alwaysOn;
    } attr_wirelessOperatingMode;
    const struct wirelessOperatingMode_cmd_setWirelessOperatingMode {
        const char *name;
    } cmd_setWirelessOperatingMode;
} caps_helper_wirelessOperatingMode = {
    .id = "wirelessOperatingMode",
    .attr_wirelessOperatingMode =
        {
            .name = "wirelessOperatingMode",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"whenNeeded", "alwaysOn"},
            .value_whenNeeded = "whenNeeded",
            .value_alwaysOn = "alwaysOn",
        },
    .cmd_setWirelessOperatingMode = {.name = "setWirelessOperatingMode"},  // arguments: wirelessOperatingMode(string)
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_WIRELESS_OPERATING_MODE_ */
