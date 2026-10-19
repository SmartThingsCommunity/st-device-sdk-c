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

#ifndef _IOT_CAPS_HELPER_CHARGING_STATE_
#define _IOT_CAPS_HELPER_CHARGING_STATE_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_CHARGINGSTATE_CHARGINGSTATE_VALUE_CHARGING,
    CAP_ENUM_CHARGINGSTATE_CHARGINGSTATE_VALUE_DISCHARGING,
    CAP_ENUM_CHARGINGSTATE_CHARGINGSTATE_VALUE_STOPPED,
    CAP_ENUM_CHARGINGSTATE_CHARGINGSTATE_VALUE_FULLYCHARGED,
    CAP_ENUM_CHARGINGSTATE_CHARGINGSTATE_VALUE_ERROR,
    CAP_ENUM_CHARGINGSTATE_CHARGINGSTATE_VALUE_OTHER,
    CAP_ENUM_CHARGINGSTATE_CHARGINGSTATE_VALUE_MAX
};

enum {
    CAP_ENUM_CHARGINGSTATE_SUPPORTEDCHARGINGSTATES_VALUE_CHARGING,
    CAP_ENUM_CHARGINGSTATE_SUPPORTEDCHARGINGSTATES_VALUE_DISCHARGING,
    CAP_ENUM_CHARGINGSTATE_SUPPORTEDCHARGINGSTATES_VALUE_STOPPED,
    CAP_ENUM_CHARGINGSTATE_SUPPORTEDCHARGINGSTATES_VALUE_FULLYCHARGED,
    CAP_ENUM_CHARGINGSTATE_SUPPORTEDCHARGINGSTATES_VALUE_ERROR,
    CAP_ENUM_CHARGINGSTATE_SUPPORTEDCHARGINGSTATES_VALUE_OTHER,
    CAP_ENUM_CHARGINGSTATE_SUPPORTEDCHARGINGSTATES_VALUE_MAX
};

const static struct iot_caps_chargingState {
    const char *id;
    const struct chargingState_attr_chargingState {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_CHARGINGSTATE_CHARGINGSTATE_VALUE_MAX];
        const char *value_charging;
        const char *value_discharging;
        const char *value_stopped;
        const char *value_fullyCharged;
        const char *value_error;
        const char *value_other;
    } attr_chargingState;
    const struct chargingState_attr_supportedChargingStates {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_CHARGINGSTATE_SUPPORTEDCHARGINGSTATES_VALUE_MAX];
        const char *value_charging;
        const char *value_discharging;
        const char *value_stopped;
        const char *value_fullyCharged;
        const char *value_error;
        const char *value_other;
    } attr_supportedChargingStates;
} caps_helper_chargingState = {
    .id = "chargingState",
    .attr_chargingState =
        {
            .name = "chargingState",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"charging", "discharging", "stopped", "fullyCharged", "error", "other"},
            .value_charging = "charging",
            .value_discharging = "discharging",
            .value_stopped = "stopped",
            .value_fullyCharged = "fullyCharged",
            .value_error = "error",
            .value_other = "other",
        },
    .attr_supportedChargingStates =
        {
            .name = "supportedChargingStates",
            .property = ATTR_SET_VALUE_ARRAY,
            .valueType = VALUE_TYPE_STRING,
            .values = {"charging", "discharging", "stopped", "fullyCharged", "error", "other"},
            .value_charging = "charging",
            .value_discharging = "discharging",
            .value_stopped = "stopped",
            .value_fullyCharged = "fullyCharged",
            .value_error = "error",
            .value_other = "other",
        },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_CHARGING_STATE_ */
