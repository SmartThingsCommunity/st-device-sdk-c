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

#ifndef _IOT_CAPS_HELPER_VEHICLE_ENGINE_
#define _IOT_CAPS_HELPER_VEHICLE_ENGINE_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_VEHICLEENGINE_ENGINESTATE_VALUE_STARTING,
    CAP_ENUM_VEHICLEENGINE_ENGINESTATE_VALUE_RUNNING,
    CAP_ENUM_VEHICLEENGINE_ENGINESTATE_VALUE_UNKNOWN,
    CAP_ENUM_VEHICLEENGINE_ENGINESTATE_VALUE_OFF,
    CAP_ENUM_VEHICLEENGINE_ENGINESTATE_VALUE_MAX
};

const static struct iot_caps_vehicleEngine {
    const char *id;
    const struct vehicleEngine_attr_engineState {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_VEHICLEENGINE_ENGINESTATE_VALUE_MAX];
        const char *value_starting;
        const char *value_running;
        const char *value_unknown;
        const char *value_off;
    } attr_engineState;
    const struct vehicleEngine_cmd_startEngine {
        const char *name;
    } cmd_startEngine;
    const struct vehicleEngine_cmd_stopEngine {
        const char *name;
    } cmd_stopEngine;
} caps_helper_vehicleEngine = {
    .id = "vehicleEngine",
    .attr_engineState =
        {
            .name = "engineState",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"starting", "running", "unknown", "off"},
            .value_starting = "starting",
            .value_running = "running",
            .value_unknown = "unknown",
            .value_off = "off",
        },
    .cmd_startEngine = {.name = "startEngine"},
    .cmd_stopEngine = {.name = "stopEngine"},
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_VEHICLE_ENGINE_ */
