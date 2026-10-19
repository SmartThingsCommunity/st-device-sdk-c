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

#ifndef _IOT_CAPS_HELPER_STATELESS_SWITCH_LEVEL_STEP_
#define _IOT_CAPS_HELPER_STATELESS_SWITCH_LEVEL_STEP_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

const static struct iot_caps_statelessSwitchLevelStep {
    const char *id;
    const struct statelessSwitchLevelStep_cmd_stepLevel {
        const char *name;
        const int min;
        const int max;
    } cmd_stepLevel;
} caps_helper_statelessSwitchLevelStep = {
    .id = "statelessSwitchLevelStep",
    .cmd_stepLevel =
        {
            .name = "stepLevel",
            .min = -100,
            .max = 100,
        },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_STATELESS_SWITCH_LEVEL_STEP_ */
