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

#ifndef _IOT_CAPS_HELPER_VEHICLE_TIRE_PRESSURE_MONITOR_
#define _IOT_CAPS_HELPER_VEHICLE_TIRE_PRESSURE_MONITOR_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_VEHICLETIREPRESSUREMONITOR_TIREPRESSURESTATE_VALUE_NORMAL,
    CAP_ENUM_VEHICLETIREPRESSUREMONITOR_TIREPRESSURESTATE_VALUE_WARN,
    CAP_ENUM_VEHICLETIREPRESSUREMONITOR_TIREPRESSURESTATE_VALUE_MAX
};

const static struct iot_caps_vehicleTirePressureMonitor {
    const char *id;
    const struct vehicleTirePressureMonitor_attr_tirePressureState {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_VEHICLETIREPRESSUREMONITOR_TIREPRESSURESTATE_VALUE_MAX];
        const char *value_normal;
        const char *value_warn;
    } attr_tirePressureState;
} caps_helper_vehicleTirePressureMonitor = {
    .id = "vehicleTirePressureMonitor",
    .attr_tirePressureState =
        {
            .name = "tirePressureState",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"normal", "warn"},
            .value_normal = "normal",
            .value_warn = "warn",
        },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_VEHICLE_TIRE_PRESSURE_MONITOR_ */
