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

#ifndef _IOT_CAPS_HELPER_ALARM_SENSOR_
#define _IOT_CAPS_HELPER_ALARM_SENSOR_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_ALARMSENSOR_ALARMSENSORSTATE_VALUE_OFF,
    CAP_ENUM_ALARMSENSOR_ALARMSENSORSTATE_VALUE_ENABLED,
    CAP_ENUM_ALARMSENSOR_ALARMSENSORSTATE_VALUE_SUPPRESSED,
    CAP_ENUM_ALARMSENSOR_ALARMSENSORSTATE_VALUE_MAX
};

enum {
    CAP_ENUM_ALARMSENSOR_SUPPORTEDALARMSENSORSTATES_VALUE_OFF,
    CAP_ENUM_ALARMSENSOR_SUPPORTEDALARMSENSORSTATES_VALUE_ENABLED,
    CAP_ENUM_ALARMSENSOR_SUPPORTEDALARMSENSORSTATES_VALUE_SUPPRESSED,
    CAP_ENUM_ALARMSENSOR_SUPPORTEDALARMSENSORSTATES_VALUE_MAX
};

const static struct iot_caps_alarmSensor {
    const char *id;
    const struct alarmSensor_attr_alarmSensorState {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_ALARMSENSOR_ALARMSENSORSTATE_VALUE_MAX];
        const char *value_off;
        const char *value_enabled;
        const char *value_suppressed;
    } attr_alarmSensorState;
    const struct alarmSensor_attr_supportedAlarmSensorStates {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_ALARMSENSOR_SUPPORTEDALARMSENSORSTATES_VALUE_MAX];
        const char *value_off;
        const char *value_enabled;
        const char *value_suppressed;
    } attr_supportedAlarmSensorStates;
    const struct alarmSensor_cmd_setAlarmSensorState {
        const char *name;
    } cmd_setAlarmSensorState;
} caps_helper_alarmSensor = {
    .id = "alarmSensor",
    .attr_alarmSensorState =
        {
            .name = "alarmSensorState",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"off", "enabled", "suppressed"},
            .value_off = "off",
            .value_enabled = "enabled",
            .value_suppressed = "suppressed",
        },
    .attr_supportedAlarmSensorStates =
        {
            .name = "supportedAlarmSensorStates",
            .property = ATTR_SET_VALUE_ARRAY,
            .valueType = VALUE_TYPE_STRING,
            .values = {"off", "enabled", "suppressed"},
            .value_off = "off",
            .value_enabled = "enabled",
            .value_suppressed = "suppressed",
        },
    .cmd_setAlarmSensorState = {.name = "setAlarmSensorState"},  // arguments: alarmSensorState(string)
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_ALARM_SENSOR_ */
