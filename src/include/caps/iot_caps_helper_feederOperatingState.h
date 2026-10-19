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

#ifndef _IOT_CAPS_HELPER_FEEDER_OPERATING_STATE_
#define _IOT_CAPS_HELPER_FEEDER_OPERATING_STATE_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_FEEDEROPERATINGSTATE_FEEDEROPERATINGSTATE_VALUE_IDLE,
    CAP_ENUM_FEEDEROPERATINGSTATE_FEEDEROPERATINGSTATE_VALUE_FEEDING,
    CAP_ENUM_FEEDEROPERATINGSTATE_FEEDEROPERATINGSTATE_VALUE_ERROR,
    CAP_ENUM_FEEDEROPERATINGSTATE_FEEDEROPERATINGSTATE_VALUE_MAX
};

const static struct iot_caps_feederOperatingState {
    const char *id;
    const struct feederOperatingState_attr_feederOperatingState {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_FEEDEROPERATINGSTATE_FEEDEROPERATINGSTATE_VALUE_MAX];
        const char *value_idle;
        const char *value_feeding;
        const char *value_error;
    } attr_feederOperatingState;
    const struct feederOperatingState_cmd_startFeeding {
        const char *name;
    } cmd_startFeeding;
} caps_helper_feederOperatingState = {
    .id = "feederOperatingState",
    .attr_feederOperatingState =
        {
            .name = "feederOperatingState",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"idle", "feeding", "error"},
            .value_idle = "idle",
            .value_feeding = "feeding",
            .value_error = "error",
        },
    .cmd_startFeeding = {.name = "startFeeding"},
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_FEEDER_OPERATING_STATE_ */
