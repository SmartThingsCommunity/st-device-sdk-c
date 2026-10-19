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

#ifndef _IOT_CAPS_HELPER_REFRIGERATION_SETPOINT_
#define _IOT_CAPS_HELPER_REFRIGERATION_SETPOINT_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_REFRIGERATIONSETPOINT_REFRIGERATIONSETPOINT_UNIT_F,
    CAP_ENUM_REFRIGERATIONSETPOINT_REFRIGERATIONSETPOINT_UNIT_C,
    CAP_ENUM_REFRIGERATIONSETPOINT_REFRIGERATIONSETPOINT_UNIT_MAX
};

const static struct iot_caps_refrigerationSetpoint {
    const char *id;
    const struct refrigerationSetpoint_attr_refrigerationSetpoint {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *units[CAP_ENUM_REFRIGERATIONSETPOINT_REFRIGERATIONSETPOINT_UNIT_MAX];
        const char *unit_F;
        const char *unit_C;
        const double min;
        const double max;
    } attr_refrigerationSetpoint;
    const struct refrigerationSetpoint_cmd_setRefrigerationSetpoint {
        const char *name;
    } cmd_setRefrigerationSetpoint;
} caps_helper_refrigerationSetpoint = {
    .id = "refrigerationSetpoint",
    .attr_refrigerationSetpoint =
        {
            .name = "refrigerationSetpoint",
            .property = ATTR_SET_VALUE_MIN | ATTR_SET_VALUE_MAX | ATTR_SET_VALUE_REQUIRED | ATTR_SET_UNIT_REQUIRED,
            .valueType = VALUE_TYPE_NUMBER,
            .units = {"F", "C"},
            .unit_F = "F",
            .unit_C = "C",
            .min = -460,
            .max = 10000,
        },
    .cmd_setRefrigerationSetpoint = {.name = "setRefrigerationSetpoint"},  // arguments: setpoint(number)
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_REFRIGERATION_SETPOINT_ */
