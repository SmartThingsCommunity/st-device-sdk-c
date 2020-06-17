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

#ifndef _IOT_CAPS_HELPER_TEMPERATURE_ALARM_
#define _IOT_CAPS_HELPER_TEMPERATURE_ALARM_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_TEMPERATUREALARM_TEMPERATUREALARM_VALUE_CLEARED,
    CAP_ENUM_TEMPERATUREALARM_TEMPERATUREALARM_VALUE_FREEZE,
    CAP_ENUM_TEMPERATUREALARM_TEMPERATUREALARM_VALUE_HEAT,
    CAP_ENUM_TEMPERATUREALARM_TEMPERATUREALARM_VALUE_RATEOFRISE,
    CAP_ENUM_TEMPERATUREALARM_TEMPERATUREALARM_VALUE_MAX
};

const static struct iot_caps_temperatureAlarm {
    const char *id;
    const struct temperatureAlarm_attr_temperatureAlarm {
        const char *name;
        const unsigned char property;
        const unsigned char value_type;
        const char *values[CAP_ENUM_TEMPERATUREALARM_TEMPERATUREALARM_VALUE_MAX];
    } attr_temperatureAlarm;
} caps_helper_temperatureAlarm = {
    .id = "temperatureAlarm",
    .attr_temperatureAlarm = {
        .name = "temperatureAlarm",
        .property = ATTR_SET_VALUE_REQUIRED,
        .value_type = VALUE_TYPE_STRING,
        .values = {"cleared", "freeze", "heat", "rateOfRise"},
    },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_TEMPERATURE_ALARM_ */
