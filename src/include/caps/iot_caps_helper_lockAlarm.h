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

#ifndef _IOT_CAPS_HELPER_LOCK_ALARM_
#define _IOT_CAPS_HELPER_LOCK_ALARM_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_LOCKALARM_ALARM_VALUE_CLEAR,
    CAP_ENUM_LOCKALARM_ALARM_VALUE_LOCKFACTORYRESET,
    CAP_ENUM_LOCKALARM_ALARM_VALUE_DAMAGED,
    CAP_ENUM_LOCKALARM_ALARM_VALUE_FORCEDOPENINGATTEMPT,
    CAP_ENUM_LOCKALARM_ALARM_VALUE_UNABLETOLOCKTHEDOOR,
    CAP_ENUM_LOCKALARM_ALARM_VALUE_NOTCLOSEDFORALONGTIME,
    CAP_ENUM_LOCKALARM_ALARM_VALUE_HIGHTEMPERATURE,
    CAP_ENUM_LOCKALARM_ALARM_VALUE_ATTEMPTSEXCEEDED,
    CAP_ENUM_LOCKALARM_ALARM_VALUE_PHYSICALIMPACT,
    CAP_ENUM_LOCKALARM_ALARM_VALUE_FAILEDOPENINGATTEMPT,
    CAP_ENUM_LOCKALARM_ALARM_VALUE_MAX
};

enum {
    CAP_ENUM_LOCKALARM_SUPPORTEDALARMVALUES_VALUE_CLEAR,
    CAP_ENUM_LOCKALARM_SUPPORTEDALARMVALUES_VALUE_LOCKFACTORYRESET,
    CAP_ENUM_LOCKALARM_SUPPORTEDALARMVALUES_VALUE_DAMAGED,
    CAP_ENUM_LOCKALARM_SUPPORTEDALARMVALUES_VALUE_FORCEDOPENINGATTEMPT,
    CAP_ENUM_LOCKALARM_SUPPORTEDALARMVALUES_VALUE_UNABLETOLOCKTHEDOOR,
    CAP_ENUM_LOCKALARM_SUPPORTEDALARMVALUES_VALUE_NOTCLOSEDFORALONGTIME,
    CAP_ENUM_LOCKALARM_SUPPORTEDALARMVALUES_VALUE_HIGHTEMPERATURE,
    CAP_ENUM_LOCKALARM_SUPPORTEDALARMVALUES_VALUE_ATTEMPTSEXCEEDED,
    CAP_ENUM_LOCKALARM_SUPPORTEDALARMVALUES_VALUE_PHYSICALIMPACT,
    CAP_ENUM_LOCKALARM_SUPPORTEDALARMVALUES_VALUE_FAILEDOPENINGATTEMPT,
    CAP_ENUM_LOCKALARM_SUPPORTEDALARMVALUES_VALUE_MAX
};

const static struct iot_caps_lockAlarm {
    const char *id;
    const struct lockAlarm_attr_alarm {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_LOCKALARM_ALARM_VALUE_MAX];
        const char *value_clear;
        const char *value_lockFactoryReset;
        const char *value_damaged;
        const char *value_forcedOpeningAttempt;
        const char *value_unableToLockTheDoor;
        const char *value_notClosedForALongTime;
        const char *value_highTemperature;
        const char *value_attemptsExceeded;
        const char *value_physicalImpact;
        const char *value_failedOpeningAttempt;
    } attr_alarm;
    const struct lockAlarm_attr_supportedAlarmValues {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_LOCKALARM_SUPPORTEDALARMVALUES_VALUE_MAX];
        const char *value_clear;
        const char *value_lockFactoryReset;
        const char *value_damaged;
        const char *value_forcedOpeningAttempt;
        const char *value_unableToLockTheDoor;
        const char *value_notClosedForALongTime;
        const char *value_highTemperature;
        const char *value_attemptsExceeded;
        const char *value_physicalImpact;
        const char *value_failedOpeningAttempt;
    } attr_supportedAlarmValues;
} caps_helper_lockAlarm = {
    .id = "lockAlarm",
    .attr_alarm =
        {
            .name = "alarm",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"clear", "lockFactoryReset", "damaged", "forcedOpeningAttempt", "unableToLockTheDoor",
                       "notClosedForALongTime", "highTemperature", "attemptsExceeded", "physicalImpact",
                       "failedOpeningAttempt"},
            .value_clear = "clear",
            .value_lockFactoryReset = "lockFactoryReset",
            .value_damaged = "damaged",
            .value_forcedOpeningAttempt = "forcedOpeningAttempt",
            .value_unableToLockTheDoor = "unableToLockTheDoor",
            .value_notClosedForALongTime = "notClosedForALongTime",
            .value_highTemperature = "highTemperature",
            .value_attemptsExceeded = "attemptsExceeded",
            .value_physicalImpact = "physicalImpact",
            .value_failedOpeningAttempt = "failedOpeningAttempt",
        },
    .attr_supportedAlarmValues =
        {
            .name = "supportedAlarmValues",
            .property = ATTR_SET_VALUE_ARRAY,
            .valueType = VALUE_TYPE_STRING,
            .values = {"clear", "lockFactoryReset", "damaged", "forcedOpeningAttempt", "unableToLockTheDoor",
                       "notClosedForALongTime", "highTemperature", "attemptsExceeded", "physicalImpact",
                       "failedOpeningAttempt"},
            .value_clear = "clear",
            .value_lockFactoryReset = "lockFactoryReset",
            .value_damaged = "damaged",
            .value_forcedOpeningAttempt = "forcedOpeningAttempt",
            .value_unableToLockTheDoor = "unableToLockTheDoor",
            .value_notClosedForALongTime = "notClosedForALongTime",
            .value_highTemperature = "highTemperature",
            .value_attemptsExceeded = "attemptsExceeded",
            .value_physicalImpact = "physicalImpact",
            .value_failedOpeningAttempt = "failedOpeningAttempt",
        },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_LOCK_ALARM_ */
