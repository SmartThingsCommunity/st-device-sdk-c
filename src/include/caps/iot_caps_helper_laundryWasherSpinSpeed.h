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

#ifndef _IOT_CAPS_HELPER_LAUNDRY_WASHER_SPIN_SPEED_
#define _IOT_CAPS_HELPER_LAUNDRY_WASHER_SPIN_SPEED_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

const static struct iot_caps_laundryWasherSpinSpeed {
    const char *id;
    const struct laundryWasherSpinSpeed_attr_supportedSpinSpeeds {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
    } attr_supportedSpinSpeeds;
    const struct laundryWasherSpinSpeed_attr_spinSpeed {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
    } attr_spinSpeed;
    const struct laundryWasherSpinSpeed_cmd_setSpinSpeed {
        const char *name;
    } cmd_setSpinSpeed;
} caps_helper_laundryWasherSpinSpeed = {
    .id = "laundryWasherSpinSpeed",
    .attr_supportedSpinSpeeds =
        {
            .name = "supportedSpinSpeeds",
            .property = ATTR_SET_VALUE_ARRAY,
            .valueType = VALUE_TYPE_STRING,
        },
    .attr_spinSpeed =
        {
            .name = "spinSpeed",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
        },
    .cmd_setSpinSpeed = {.name = "setSpinSpeed"},  // arguments: spinSpeed(string)
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_LAUNDRY_WASHER_SPIN_SPEED_ */
