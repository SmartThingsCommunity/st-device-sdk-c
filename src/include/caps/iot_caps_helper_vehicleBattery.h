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

#ifndef _IOT_CAPS_HELPER_VEHICLE_BATTERY_
#define _IOT_CAPS_HELPER_VEHICLE_BATTERY_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum { CAP_ENUM_VEHICLEBATTERY_BATTERYLEVEL_UNIT_PERCENT, CAP_ENUM_VEHICLEBATTERY_BATTERYLEVEL_UNIT_MAX };

enum {
    CAP_ENUM_VEHICLEBATTERY_CHARGINGSTATE_VALUE_CHARGING,
    CAP_ENUM_VEHICLEBATTERY_CHARGINGSTATE_VALUE_STOPPED,
    CAP_ENUM_VEHICLEBATTERY_CHARGINGSTATE_VALUE_MAX
};

enum { CAP_ENUM_VEHICLEBATTERY_CHARGINGREMAINTIME_UNIT_MINS, CAP_ENUM_VEHICLEBATTERY_CHARGINGREMAINTIME_UNIT_MAX };

enum {
    CAP_ENUM_VEHICLEBATTERY_CHARGINGDETAIL_VALUE_NOCHARGING,
    CAP_ENUM_VEHICLEBATTERY_CHARGINGDETAIL_VALUE_CHARGING,
    CAP_ENUM_VEHICLEBATTERY_CHARGINGDETAIL_VALUE_VERYFASTCHARGING,
    CAP_ENUM_VEHICLEBATTERY_CHARGINGDETAIL_VALUE_FASTCHARGING,
    CAP_ENUM_VEHICLEBATTERY_CHARGINGDETAIL_VALUE_V2LDISCHARGE,
    CAP_ENUM_VEHICLEBATTERY_CHARGINGDETAIL_VALUE_V2LCHARGING,
    CAP_ENUM_VEHICLEBATTERY_CHARGINGDETAIL_VALUE_V2LSTOP,
    CAP_ENUM_VEHICLEBATTERY_CHARGINGDETAIL_VALUE_V2XDISCHARGE,
    CAP_ENUM_VEHICLEBATTERY_CHARGINGDETAIL_VALUE_V2XCHARGING,
    CAP_ENUM_VEHICLEBATTERY_CHARGINGDETAIL_VALUE_RESEVEREDCHARGING,
    CAP_ENUM_VEHICLEBATTERY_CHARGINGDETAIL_VALUE_MAX
};

enum {
    CAP_ENUM_VEHICLEBATTERY_CHARGINGPLUG_VALUE_CONNECTED,
    CAP_ENUM_VEHICLEBATTERY_CHARGINGPLUG_VALUE_DISCONNECTED,
    CAP_ENUM_VEHICLEBATTERY_CHARGINGPLUG_VALUE_MAX
};

const static struct iot_caps_vehicleBattery {
    const char *id;
    const struct vehicleBattery_attr_batteryLevel {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *units[CAP_ENUM_VEHICLEBATTERY_BATTERYLEVEL_UNIT_MAX];
        const char *unit_percent;
        const int min;
        const int max;
    } attr_batteryLevel;
    const struct vehicleBattery_attr_chargingState {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_VEHICLEBATTERY_CHARGINGSTATE_VALUE_MAX];
        const char *value_charging;
        const char *value_stopped;
    } attr_chargingState;
    const struct vehicleBattery_attr_chargingRemainTime {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *units[CAP_ENUM_VEHICLEBATTERY_CHARGINGREMAINTIME_UNIT_MAX];
        const char *unit_mins;
        const int min;
    } attr_chargingRemainTime;
    const struct vehicleBattery_attr_chargingDetail {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_VEHICLEBATTERY_CHARGINGDETAIL_VALUE_MAX];
        const char *value_noCharging;
        const char *value_charging;
        const char *value_veryFastCharging;
        const char *value_fastCharging;
        const char *value_v2lDischarge;
        const char *value_v2lCharging;
        const char *value_v2lStop;
        const char *value_v2xDischarge;
        const char *value_v2xCharging;
        const char *value_reseveredCharging;
    } attr_chargingDetail;
    const struct vehicleBattery_attr_chargingPlug {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_VEHICLEBATTERY_CHARGINGPLUG_VALUE_MAX];
        const char *value_connected;
        const char *value_disconnected;
    } attr_chargingPlug;
    const struct vehicleBattery_cmd_charge {
        const char *name;
    } cmd_charge;
    const struct vehicleBattery_cmd_stop {
        const char *name;
    } cmd_stop;
} caps_helper_vehicleBattery = {
    .id = "vehicleBattery",
    .attr_batteryLevel =
        {
            .name = "batteryLevel",
            .property = ATTR_SET_VALUE_MIN | ATTR_SET_VALUE_MAX | ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_INTEGER,
            .units = {"%"},
            .unit_percent = "%",
            .min = 0,
            .max = 100,
        },
    .attr_chargingState =
        {
            .name = "chargingState",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"charging", "stopped"},
            .value_charging = "charging",
            .value_stopped = "stopped",
        },
    .attr_chargingRemainTime =
        {
            .name = "chargingRemainTime",
            .property = ATTR_SET_VALUE_MIN | ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_INTEGER,
            .units = {"mins"},
            .unit_mins = "mins",
            .min = 0,
        },
    .attr_chargingDetail =
        {
            .name = "chargingDetail",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"noCharging", "charging", "veryFastCharging", "fastCharging", "v2lDischarge", "v2lCharging",
                       "v2lStop", "v2xDischarge", "v2xCharging", "reseveredCharging"},
            .value_noCharging = "noCharging",
            .value_charging = "charging",
            .value_veryFastCharging = "veryFastCharging",
            .value_fastCharging = "fastCharging",
            .value_v2lDischarge = "v2lDischarge",
            .value_v2lCharging = "v2lCharging",
            .value_v2lStop = "v2lStop",
            .value_v2xDischarge = "v2xDischarge",
            .value_v2xCharging = "v2xCharging",
            .value_reseveredCharging = "reseveredCharging",
        },
    .attr_chargingPlug =
        {
            .name = "chargingPlug",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"connected", "disconnected"},
            .value_connected = "connected",
            .value_disconnected = "disconnected",
        },
    .cmd_charge = {.name = "charge"},
    .cmd_stop = {.name = "stop"},
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_VEHICLE_BATTERY_ */
