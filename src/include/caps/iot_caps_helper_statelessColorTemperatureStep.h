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

#ifndef _IOT_CAPS_HELPER_STATELESS_COLOR_TEMPERATURE_STEP_
#define _IOT_CAPS_HELPER_STATELESS_COLOR_TEMPERATURE_STEP_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

const static struct iot_caps_statelessColorTemperatureStep {
    const char *id;
    const struct statelessColorTemperatureStep_cmd_stepColorTemperatureByPercent {
        const char *name;
        const int min;
        const int max;
    } cmd_stepColorTemperatureByPercent;
} caps_helper_statelessColorTemperatureStep = {
    .id = "statelessColorTemperatureStep",
    .cmd_stepColorTemperatureByPercent =
        {
            .name = "stepColorTemperatureByPercent",
            .min = -100,
            .max = 100,
        },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_STATELESS_COLOR_TEMPERATURE_STEP_ */
