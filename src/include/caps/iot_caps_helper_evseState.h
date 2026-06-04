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

#ifndef _IOT_CAPS_HELPER_EVSE_STATE_
#define _IOT_CAPS_HELPER_EVSE_STATE_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_EVSESTATE_STATE_VALUE_NOTPLUGGEDIN,
    CAP_ENUM_EVSESTATE_STATE_VALUE_PLUGGEDINNODEMAND,
    CAP_ENUM_EVSESTATE_STATE_VALUE_PLUGGEDINDEMAND,
    CAP_ENUM_EVSESTATE_STATE_VALUE_PLUGGEDINCHARGING,
    CAP_ENUM_EVSESTATE_STATE_VALUE_PLUGGEDINDISCHARGING,
    CAP_ENUM_EVSESTATE_STATE_VALUE_SESSIONENDING,
    CAP_ENUM_EVSESTATE_STATE_VALUE_FAULT,
    CAP_ENUM_EVSESTATE_STATE_VALUE_MAX
};

enum {
    CAP_ENUM_EVSESTATE_SUPPLYSTATE_VALUE_DISABLED,
    CAP_ENUM_EVSESTATE_SUPPLYSTATE_VALUE_CHARGINGENABLED,
    CAP_ENUM_EVSESTATE_SUPPLYSTATE_VALUE_DISCHARGINGENABLED,
    CAP_ENUM_EVSESTATE_SUPPLYSTATE_VALUE_DISABLEDERROR,
    CAP_ENUM_EVSESTATE_SUPPLYSTATE_VALUE_DISABLEDDIAGNOSTICS,
    CAP_ENUM_EVSESTATE_SUPPLYSTATE_VALUE_MAX
};

enum {
    CAP_ENUM_EVSESTATE_FAULTSTATE_VALUE_NOERROR,
    CAP_ENUM_EVSESTATE_FAULTSTATE_VALUE_METERFAILURE,
    CAP_ENUM_EVSESTATE_FAULTSTATE_VALUE_OVERVOLTAGE,
    CAP_ENUM_EVSESTATE_FAULTSTATE_VALUE_UNDERVOLTAGE,
    CAP_ENUM_EVSESTATE_FAULTSTATE_VALUE_OVERCURRENT,
    CAP_ENUM_EVSESTATE_FAULTSTATE_VALUE_CONTACTWETFAILURE,
    CAP_ENUM_EVSESTATE_FAULTSTATE_VALUE_CONTACTDRYFAILURE,
    CAP_ENUM_EVSESTATE_FAULTSTATE_VALUE_GROUNDFAULT,
    CAP_ENUM_EVSESTATE_FAULTSTATE_VALUE_POWERLOSS,
    CAP_ENUM_EVSESTATE_FAULTSTATE_VALUE_POWERQUALITY,
    CAP_ENUM_EVSESTATE_FAULTSTATE_VALUE_PILOTSHORTCIRCUIT,
    CAP_ENUM_EVSESTATE_FAULTSTATE_VALUE_EMERGENCYSTOP,
    CAP_ENUM_EVSESTATE_FAULTSTATE_VALUE_EVDISCONNECTED,
    CAP_ENUM_EVSESTATE_FAULTSTATE_VALUE_WRONGPOWERSUPPLY,
    CAP_ENUM_EVSESTATE_FAULTSTATE_VALUE_LIVENEUTRALSWAP,
    CAP_ENUM_EVSESTATE_FAULTSTATE_VALUE_OVERTEMPERATURE,
    CAP_ENUM_EVSESTATE_FAULTSTATE_VALUE_OTHER,
    CAP_ENUM_EVSESTATE_FAULTSTATE_VALUE_MAX
};

const static struct iot_caps_evseState {
    const char *id;
    const struct evseState_attr_state {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_EVSESTATE_STATE_VALUE_MAX];
        const char *value_notPluggedIn;
        const char *value_pluggedInNoDemand;
        const char *value_pluggedInDemand;
        const char *value_pluggedInCharging;
        const char *value_pluggedInDischarging;
        const char *value_sessionEnding;
        const char *value_fault;
    } attr_state;
    const struct evseState_attr_supplyState {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_EVSESTATE_SUPPLYSTATE_VALUE_MAX];
        const char *value_disabled;
        const char *value_chargingEnabled;
        const char *value_dischargingEnabled;
        const char *value_disabledError;
        const char *value_disabledDiagnostics;
    } attr_supplyState;
    const struct evseState_attr_faultState {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_EVSESTATE_FAULTSTATE_VALUE_MAX];
        const char *value_noError;
        const char *value_meterFailure;
        const char *value_overVoltage;
        const char *value_underVoltage;
        const char *value_overCurrent;
        const char *value_contactWetFailure;
        const char *value_contactDryFailure;
        const char *value_groundFault;
        const char *value_powerLoss;
        const char *value_powerQuality;
        const char *value_pilotShortCircuit;
        const char *value_emergencyStop;
        const char *value_eVDisconnected;
        const char *value_wrongPowerSupply;
        const char *value_liveNeutralSwap;
        const char *value_overTemperature;
        const char *value_other;
    } attr_faultState;
} caps_helper_evseState = {
    .id = "evseState",
    .attr_state =
        {
            .name = "state",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"notPluggedIn", "pluggedInNoDemand", "pluggedInDemand", "pluggedInCharging",
                       "pluggedInDischarging", "sessionEnding", "fault"},
            .value_notPluggedIn = "notPluggedIn",
            .value_pluggedInNoDemand = "pluggedInNoDemand",
            .value_pluggedInDemand = "pluggedInDemand",
            .value_pluggedInCharging = "pluggedInCharging",
            .value_pluggedInDischarging = "pluggedInDischarging",
            .value_sessionEnding = "sessionEnding",
            .value_fault = "fault",
        },
    .attr_supplyState =
        {
            .name = "supplyState",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"disabled", "chargingEnabled", "dischargingEnabled", "disabledError", "disabledDiagnostics"},
            .value_disabled = "disabled",
            .value_chargingEnabled = "chargingEnabled",
            .value_dischargingEnabled = "dischargingEnabled",
            .value_disabledError = "disabledError",
            .value_disabledDiagnostics = "disabledDiagnostics",
        },
    .attr_faultState =
        {
            .name = "faultState",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"noError", "meterFailure", "overVoltage", "underVoltage", "overCurrent", "contactWetFailure",
                       "contactDryFailure", "groundFault", "powerLoss", "powerQuality", "pilotShortCircuit",
                       "emergencyStop", "eVDisconnected", "wrongPowerSupply", "liveNeutralSwap", "overTemperature",
                       "other"},
            .value_noError = "noError",
            .value_meterFailure = "meterFailure",
            .value_overVoltage = "overVoltage",
            .value_underVoltage = "underVoltage",
            .value_overCurrent = "overCurrent",
            .value_contactWetFailure = "contactWetFailure",
            .value_contactDryFailure = "contactDryFailure",
            .value_groundFault = "groundFault",
            .value_powerLoss = "powerLoss",
            .value_powerQuality = "powerQuality",
            .value_pilotShortCircuit = "pilotShortCircuit",
            .value_emergencyStop = "emergencyStop",
            .value_eVDisconnected = "eVDisconnected",
            .value_wrongPowerSupply = "wrongPowerSupply",
            .value_liveNeutralSwap = "liveNeutralSwap",
            .value_overTemperature = "overTemperature",
            .value_other = "other",
        },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_EVSE_STATE_ */
