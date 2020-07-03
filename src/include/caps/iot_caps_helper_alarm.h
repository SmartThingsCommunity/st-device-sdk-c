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

#ifndef _IOT_CAPS_HELPER_ALARM_
#define _IOT_CAPS_HELPER_ALARM_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_ALARM_ALARM_VALUE_BOTH,
    CAP_ENUM_ALARM_ALARM_VALUE_OFF,
    CAP_ENUM_ALARM_ALARM_VALUE_SIREN,
    CAP_ENUM_ALARM_ALARM_VALUE_STROBE,
    CAP_ENUM_ALARM_ALARM_VALUE_MAX
};

const static struct iot_caps_alarm {
    const char *id;
    const struct alarm_attr_alarm {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_ALARM_ALARM_VALUE_MAX];
        const char *value_both;
        const char *value_off;
        const char *value_siren;
        const char *value_strobe;
    } attr_alarm;
    const struct alarm_cmd_both { const char* name; } cmd_both;
    const struct alarm_cmd_siren { const char* name; } cmd_siren;
    const struct alarm_cmd_off { const char* name; } cmd_off;
    const struct alarm_cmd_strobe { const char* name; } cmd_strobe;
} caps_helper_alarm = {
    .id = "alarm",
    .attr_alarm = {
        .name = "alarm",
        .property = ATTR_SET_VALUE_REQUIRED,
        .valueType = VALUE_TYPE_STRING,
        .values = {"both", "off", "siren", "strobe"},
        .value_both = "both",
        .value_off = "off",
        .value_siren = "siren",
        .value_strobe = "strobe",
    },
    .cmd_both = { .name = "both" },
    .cmd_siren = { .name = "siren" },
    .cmd_off = { .name = "off" },
    .cmd_strobe = { .name = "strobe" },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_ALARM_ */
