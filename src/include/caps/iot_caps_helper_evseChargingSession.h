/* ***************************************************************************
 *
 * Copyright 2019-2026 Samsung Electronics All Rights Reserved.
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

#ifndef _IOT_CAPS_HELPER_EVSE_CHARGING_SESSION_
#define _IOT_CAPS_HELPER_EVSE_CHARGING_SESSION_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_EVSECHARGINGSESSION_CHARGINGSTATE_VALUE_CHARGING,
    CAP_ENUM_EVSECHARGINGSESSION_CHARGINGSTATE_VALUE_STOPPED,
    CAP_ENUM_EVSECHARGINGSESSION_CHARGINGSTATE_VALUE_DISABLED,
    CAP_ENUM_EVSECHARGINGSESSION_CHARGINGSTATE_VALUE_MAX
};

enum { CAP_ENUM_EVSECHARGINGSESSION_MINCURRENT_UNIT_MA, CAP_ENUM_EVSECHARGINGSESSION_MINCURRENT_UNIT_MAX };

enum { CAP_ENUM_EVSECHARGINGSESSION_MAXCURRENT_UNIT_MA, CAP_ENUM_EVSECHARGINGSESSION_MAXCURRENT_UNIT_MAX };

enum { CAP_ENUM_EVSECHARGINGSESSION_SESSIONTIME_UNIT_S, CAP_ENUM_EVSECHARGINGSESSION_SESSIONTIME_UNIT_MAX };

enum { CAP_ENUM_EVSECHARGINGSESSION_ENERGYDELIVERED_UNIT_MWH, CAP_ENUM_EVSECHARGINGSESSION_ENERGYDELIVERED_UNIT_MAX };

enum {
    CAP_ENUM_EVSECHARGINGSESSION_SUPPORTEDCHARGINGCOMMANDS_VALUE_ENABLECHARGING,
    CAP_ENUM_EVSECHARGINGSESSION_SUPPORTEDCHARGINGCOMMANDS_VALUE_DISABLECHARGING,
    CAP_ENUM_EVSECHARGINGSESSION_SUPPORTEDCHARGINGCOMMANDS_VALUE_MAX
};

const static struct iot_caps_evseChargingSession {
    const char *id;
    const struct evseChargingSession_attr_chargingState {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_EVSECHARGINGSESSION_CHARGINGSTATE_VALUE_MAX];
        const char *value_charging;
        const char *value_stopped;
        const char *value_disabled;
    } attr_chargingState;
    const struct evseChargingSession_attr_targetEndTime {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
    } attr_targetEndTime;
    const struct evseChargingSession_attr_minCurrent {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *units[CAP_ENUM_EVSECHARGINGSESSION_MINCURRENT_UNIT_MAX];
        const char *unit_mA;
        const int min;
    } attr_minCurrent;
    const struct evseChargingSession_attr_maxCurrent {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *units[CAP_ENUM_EVSECHARGINGSESSION_MAXCURRENT_UNIT_MAX];
        const char *unit_mA;
        const int min;
    } attr_maxCurrent;
    const struct evseChargingSession_attr_sessionTime {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *units[CAP_ENUM_EVSECHARGINGSESSION_SESSIONTIME_UNIT_MAX];
        const char *unit_s;
        const int min;
    } attr_sessionTime;
    const struct evseChargingSession_attr_energyDelivered {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *units[CAP_ENUM_EVSECHARGINGSESSION_ENERGYDELIVERED_UNIT_MAX];
        const char *unit_mWh;
        const int min;
    } attr_energyDelivered;
    const struct evseChargingSession_attr_supportedChargingCommands {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_EVSECHARGINGSESSION_SUPPORTEDCHARGINGCOMMANDS_VALUE_MAX];
        const char *value_enableCharging;
        const char *value_disableCharging;
    } attr_supportedChargingCommands;
    const struct evseChargingSession_cmd_setTargetEndTime {
        const char *name;
    } cmd_setTargetEndTime;
    const struct evseChargingSession_cmd_setMinCurrent {
        const char *name;
    } cmd_setMinCurrent;
    const struct evseChargingSession_cmd_setMaxCurrent {
        const char *name;
    } cmd_setMaxCurrent;
    const struct evseChargingSession_cmd_enableCharging {
        const char *name;
    } cmd_enableCharging;
    const struct evseChargingSession_cmd_disableCharging {
        const char *name;
    } cmd_disableCharging;
} caps_helper_evseChargingSession = {
    .id = "evseChargingSession",
    .attr_chargingState =
        {
            .name = "chargingState",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"charging", "stopped", "disabled"},
            .value_charging = "charging",
            .value_stopped = "stopped",
            .value_disabled = "disabled",
        },
    .attr_targetEndTime =
        {
            .name = "targetEndTime",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
        },
    .attr_minCurrent =
        {
            .name = "minCurrent",
            .property = ATTR_SET_VALUE_MIN | ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_INTEGER,
            .units = {"mA"},
            .unit_mA = "mA",
            .min = 0,
        },
    .attr_maxCurrent =
        {
            .name = "maxCurrent",
            .property = ATTR_SET_VALUE_MIN | ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_INTEGER,
            .units = {"mA"},
            .unit_mA = "mA",
            .min = 0,
        },
    .attr_sessionTime =
        {
            .name = "sessionTime",
            .property = ATTR_SET_VALUE_MIN | ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_INTEGER,
            .units = {"s"},
            .unit_s = "s",
            .min = 0,
        },
    .attr_energyDelivered =
        {
            .name = "energyDelivered",
            .property = ATTR_SET_VALUE_MIN | ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_INTEGER,
            .units = {"mWh"},
            .unit_mWh = "mWh",
            .min = 0,
        },
    .attr_supportedChargingCommands =
        {
            .name = "supportedChargingCommands",
            .property = ATTR_SET_VALUE_ARRAY,
            .valueType = VALUE_TYPE_STRING,
            .values = {"enableCharging", "disableCharging"},
            .value_enableCharging = "enableCharging",
            .value_disableCharging = "disableCharging",
        },
    .cmd_setTargetEndTime = {.name = "setTargetEndTime"},  // arguments: time(string)
    .cmd_setMinCurrent = {.name = "setMinCurrent"},        // arguments: minCurrent(integer)
    .cmd_setMaxCurrent = {.name = "setMaxCurrent"},        // arguments: maxCurrent(integer)
    .cmd_enableCharging = {.name =
                               "enableCharging"},  // arguments: time(string) minCurrent(integer) maxCurrent(integer)
    .cmd_disableCharging = {.name = "disableCharging"},
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_EVSE_CHARGING_SESSION_ */
