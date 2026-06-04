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

#ifndef _IOT_CAPS_HELPER_WATER_FLOW_ALARM_
#define _IOT_CAPS_HELPER_WATER_FLOW_ALARM_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_WATERFLOWALARM_VOLUMEALARM_VALUE_NORMAL,
    CAP_ENUM_WATERFLOWALARM_VOLUMEALARM_VALUE_WARNING,
    CAP_ENUM_WATERFLOWALARM_VOLUMEALARM_VALUE_ALARM,
    CAP_ENUM_WATERFLOWALARM_VOLUMEALARM_VALUE_MAX
};

enum {
    CAP_ENUM_WATERFLOWALARM_DURATIONALARM_VALUE_NORMAL,
    CAP_ENUM_WATERFLOWALARM_DURATIONALARM_VALUE_WARNING,
    CAP_ENUM_WATERFLOWALARM_DURATIONALARM_VALUE_ALARM,
    CAP_ENUM_WATERFLOWALARM_DURATIONALARM_VALUE_MAX
};

enum {
    CAP_ENUM_WATERFLOWALARM_RATEALARM_VALUE_NORMAL,
    CAP_ENUM_WATERFLOWALARM_RATEALARM_VALUE_WARNING,
    CAP_ENUM_WATERFLOWALARM_RATEALARM_VALUE_ALARM,
    CAP_ENUM_WATERFLOWALARM_RATEALARM_VALUE_MAX
};

enum {
    CAP_ENUM_WATERFLOWALARM_SUPPORTEDALARMSTATUSES_VALUE_NORMAL,
    CAP_ENUM_WATERFLOWALARM_SUPPORTEDALARMSTATUSES_VALUE_WARNING,
    CAP_ENUM_WATERFLOWALARM_SUPPORTEDALARMSTATUSES_VALUE_ALARM,
    CAP_ENUM_WATERFLOWALARM_SUPPORTEDALARMSTATUSES_VALUE_MAX
};

const static struct iot_caps_waterFlowAlarm {
    const char *id;
    const struct waterFlowAlarm_attr_volumeAlarm {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_WATERFLOWALARM_VOLUMEALARM_VALUE_MAX];
        const char *value_normal;
        const char *value_warning;
        const char *value_alarm;
    } attr_volumeAlarm;
    const struct waterFlowAlarm_attr_durationAlarm {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_WATERFLOWALARM_DURATIONALARM_VALUE_MAX];
        const char *value_normal;
        const char *value_warning;
        const char *value_alarm;
    } attr_durationAlarm;
    const struct waterFlowAlarm_attr_rateAlarm {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_WATERFLOWALARM_RATEALARM_VALUE_MAX];
        const char *value_normal;
        const char *value_warning;
        const char *value_alarm;
    } attr_rateAlarm;
    const struct waterFlowAlarm_attr_supportedAlarmStatuses {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_WATERFLOWALARM_SUPPORTEDALARMSTATUSES_VALUE_MAX];
        const char *value_normal;
        const char *value_warning;
        const char *value_alarm;
    } attr_supportedAlarmStatuses;
} caps_helper_waterFlowAlarm = {
    .id = "waterFlowAlarm",
    .attr_volumeAlarm =
        {
            .name = "volumeAlarm",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"normal", "warning", "alarm"},
            .value_normal = "normal",
            .value_warning = "warning",
            .value_alarm = "alarm",
        },
    .attr_durationAlarm =
        {
            .name = "durationAlarm",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"normal", "warning", "alarm"},
            .value_normal = "normal",
            .value_warning = "warning",
            .value_alarm = "alarm",
        },
    .attr_rateAlarm =
        {
            .name = "rateAlarm",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"normal", "warning", "alarm"},
            .value_normal = "normal",
            .value_warning = "warning",
            .value_alarm = "alarm",
        },
    .attr_supportedAlarmStatuses =
        {
            .name = "supportedAlarmStatuses",
            .property = ATTR_SET_VALUE_ARRAY | ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"normal", "warning", "alarm"},
            .value_normal = "normal",
            .value_warning = "warning",
            .value_alarm = "alarm",
        },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_WATER_FLOW_ALARM_ */
