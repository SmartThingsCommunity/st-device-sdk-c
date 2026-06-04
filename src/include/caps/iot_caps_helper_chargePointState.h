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

#ifndef _IOT_CAPS_HELPER_CHARGE_POINT_STATE_
#define _IOT_CAPS_HELPER_CHARGE_POINT_STATE_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_CHARGEPOINTSTATE_CHARGEPOINTSTATE_VALUE_AVAILABLE,
    CAP_ENUM_CHARGEPOINTSTATE_CHARGEPOINTSTATE_VALUE_PREPARING,
    CAP_ENUM_CHARGEPOINTSTATE_CHARGEPOINTSTATE_VALUE_CHARGING,
    CAP_ENUM_CHARGEPOINTSTATE_CHARGEPOINTSTATE_VALUE_DISCHARGING,
    CAP_ENUM_CHARGEPOINTSTATE_CHARGEPOINTSTATE_VALUE_SUSPENDEDEVSE,
    CAP_ENUM_CHARGEPOINTSTATE_CHARGEPOINTSTATE_VALUE_SUSPENDEDEV,
    CAP_ENUM_CHARGEPOINTSTATE_CHARGEPOINTSTATE_VALUE_FINISHING,
    CAP_ENUM_CHARGEPOINTSTATE_CHARGEPOINTSTATE_VALUE_RESERVED,
    CAP_ENUM_CHARGEPOINTSTATE_CHARGEPOINTSTATE_VALUE_UNAVAILABLE,
    CAP_ENUM_CHARGEPOINTSTATE_CHARGEPOINTSTATE_VALUE_FAULTED,
    CAP_ENUM_CHARGEPOINTSTATE_CHARGEPOINTSTATE_VALUE_MAX
};

enum {
    CAP_ENUM_CHARGEPOINTSTATE_SUPPORTEDCHARGEPOINTSTATES_VALUE_AVAILABLE,
    CAP_ENUM_CHARGEPOINTSTATE_SUPPORTEDCHARGEPOINTSTATES_VALUE_PREPARING,
    CAP_ENUM_CHARGEPOINTSTATE_SUPPORTEDCHARGEPOINTSTATES_VALUE_CHARGING,
    CAP_ENUM_CHARGEPOINTSTATE_SUPPORTEDCHARGEPOINTSTATES_VALUE_DISCHARGING,
    CAP_ENUM_CHARGEPOINTSTATE_SUPPORTEDCHARGEPOINTSTATES_VALUE_SUSPENDEDEVSE,
    CAP_ENUM_CHARGEPOINTSTATE_SUPPORTEDCHARGEPOINTSTATES_VALUE_SUSPENDEDEV,
    CAP_ENUM_CHARGEPOINTSTATE_SUPPORTEDCHARGEPOINTSTATES_VALUE_FINISHING,
    CAP_ENUM_CHARGEPOINTSTATE_SUPPORTEDCHARGEPOINTSTATES_VALUE_RESERVED,
    CAP_ENUM_CHARGEPOINTSTATE_SUPPORTEDCHARGEPOINTSTATES_VALUE_UNAVAILABLE,
    CAP_ENUM_CHARGEPOINTSTATE_SUPPORTEDCHARGEPOINTSTATES_VALUE_FAULTED,
    CAP_ENUM_CHARGEPOINTSTATE_SUPPORTEDCHARGEPOINTSTATES_VALUE_MAX
};

const static struct iot_caps_chargePointState {
    const char *id;
    const struct chargePointState_attr_chargePointState {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_CHARGEPOINTSTATE_CHARGEPOINTSTATE_VALUE_MAX];
        const char *value_available;
        const char *value_preparing;
        const char *value_charging;
        const char *value_discharging;
        const char *value_suspendedEVSE;
        const char *value_suspendedEV;
        const char *value_finishing;
        const char *value_reserved;
        const char *value_unavailable;
        const char *value_faulted;
    } attr_chargePointState;
    const struct chargePointState_attr_supportedChargePointStates {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_CHARGEPOINTSTATE_SUPPORTEDCHARGEPOINTSTATES_VALUE_MAX];
        const char *value_available;
        const char *value_preparing;
        const char *value_charging;
        const char *value_discharging;
        const char *value_suspendedEVSE;
        const char *value_suspendedEV;
        const char *value_finishing;
        const char *value_reserved;
        const char *value_unavailable;
        const char *value_faulted;
    } attr_supportedChargePointStates;
} caps_helper_chargePointState = {
    .id = "chargePointState",
    .attr_chargePointState =
        {
            .name = "chargePointState",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"available", "preparing", "charging", "discharging", "suspendedEVSE", "suspendedEV", "finishing",
                       "reserved", "unavailable", "faulted"},
            .value_available = "available",
            .value_preparing = "preparing",
            .value_charging = "charging",
            .value_discharging = "discharging",
            .value_suspendedEVSE = "suspendedEVSE",
            .value_suspendedEV = "suspendedEV",
            .value_finishing = "finishing",
            .value_reserved = "reserved",
            .value_unavailable = "unavailable",
            .value_faulted = "faulted",
        },
    .attr_supportedChargePointStates =
        {
            .name = "supportedChargePointStates",
            .property = ATTR_SET_VALUE_ARRAY,
            .valueType = VALUE_TYPE_STRING,
            .values = {"available", "preparing", "charging", "discharging", "suspendedEVSE", "suspendedEV", "finishing",
                       "reserved", "unavailable", "faulted"},
            .value_available = "available",
            .value_preparing = "preparing",
            .value_charging = "charging",
            .value_discharging = "discharging",
            .value_suspendedEVSE = "suspendedEVSE",
            .value_suspendedEV = "suspendedEV",
            .value_finishing = "finishing",
            .value_reserved = "reserved",
            .value_unavailable = "unavailable",
            .value_faulted = "faulted",
        },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_CHARGE_POINT_STATE_ */
