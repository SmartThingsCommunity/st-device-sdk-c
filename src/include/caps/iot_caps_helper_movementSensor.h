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

#ifndef _IOT_CAPS_HELPER_MOVEMENT_SENSOR_
#define _IOT_CAPS_HELPER_MOVEMENT_SENSOR_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_MOVEMENTSENSOR_MOVEMENT_VALUE_INACTIVE,
    CAP_ENUM_MOVEMENTSENSOR_MOVEMENT_VALUE_APPROACHING,
    CAP_ENUM_MOVEMENTSENSOR_MOVEMENT_VALUE_MOVINGAWAY,
    CAP_ENUM_MOVEMENTSENSOR_MOVEMENT_VALUE_ENTERING,
    CAP_ENUM_MOVEMENTSENSOR_MOVEMENT_VALUE_LEAVING,
    CAP_ENUM_MOVEMENTSENSOR_MOVEMENT_VALUE_ENTERINGLEFT,
    CAP_ENUM_MOVEMENTSENSOR_MOVEMENT_VALUE_ENTERINGRIGHT,
    CAP_ENUM_MOVEMENTSENSOR_MOVEMENT_VALUE_LEAVINGLEFT,
    CAP_ENUM_MOVEMENTSENSOR_MOVEMENT_VALUE_LEAVINGRIGHT,
    CAP_ENUM_MOVEMENTSENSOR_MOVEMENT_VALUE_MAX
};

enum {
    CAP_ENUM_MOVEMENTSENSOR_SUPPORTEDMOVEMENTS_VALUE_INACTIVE,
    CAP_ENUM_MOVEMENTSENSOR_SUPPORTEDMOVEMENTS_VALUE_APPROACHING,
    CAP_ENUM_MOVEMENTSENSOR_SUPPORTEDMOVEMENTS_VALUE_MOVINGAWAY,
    CAP_ENUM_MOVEMENTSENSOR_SUPPORTEDMOVEMENTS_VALUE_ENTERING,
    CAP_ENUM_MOVEMENTSENSOR_SUPPORTEDMOVEMENTS_VALUE_LEAVING,
    CAP_ENUM_MOVEMENTSENSOR_SUPPORTEDMOVEMENTS_VALUE_ENTERINGLEFT,
    CAP_ENUM_MOVEMENTSENSOR_SUPPORTEDMOVEMENTS_VALUE_ENTERINGRIGHT,
    CAP_ENUM_MOVEMENTSENSOR_SUPPORTEDMOVEMENTS_VALUE_LEAVINGLEFT,
    CAP_ENUM_MOVEMENTSENSOR_SUPPORTEDMOVEMENTS_VALUE_LEAVINGRIGHT,
    CAP_ENUM_MOVEMENTSENSOR_SUPPORTEDMOVEMENTS_VALUE_MAX
};

const static struct iot_caps_movementSensor {
    const char *id;
    const struct movementSensor_attr_movement {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_MOVEMENTSENSOR_MOVEMENT_VALUE_MAX];
        const char *value_inactive;
        const char *value_approaching;
        const char *value_movingAway;
        const char *value_entering;
        const char *value_leaving;
        const char *value_enteringLeft;
        const char *value_enteringRight;
        const char *value_leavingLeft;
        const char *value_leavingRight;
    } attr_movement;
    const struct movementSensor_attr_supportedMovements {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_MOVEMENTSENSOR_SUPPORTEDMOVEMENTS_VALUE_MAX];
        const char *value_inactive;
        const char *value_approaching;
        const char *value_movingAway;
        const char *value_entering;
        const char *value_leaving;
        const char *value_enteringLeft;
        const char *value_enteringRight;
        const char *value_leavingLeft;
        const char *value_leavingRight;
    } attr_supportedMovements;
} caps_helper_movementSensor = {
    .id = "movementSensor",
    .attr_movement =
        {
            .name = "movement",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"inactive", "approaching", "movingAway", "entering", "leaving", "enteringLeft", "enteringRight",
                       "leavingLeft", "leavingRight"},
            .value_inactive = "inactive",
            .value_approaching = "approaching",
            .value_movingAway = "movingAway",
            .value_entering = "entering",
            .value_leaving = "leaving",
            .value_enteringLeft = "enteringLeft",
            .value_enteringRight = "enteringRight",
            .value_leavingLeft = "leavingLeft",
            .value_leavingRight = "leavingRight",
        },
    .attr_supportedMovements =
        {
            .name = "supportedMovements",
            .property = ATTR_SET_VALUE_ARRAY,
            .valueType = VALUE_TYPE_STRING,
            .values = {"inactive", "approaching", "movingAway", "entering", "leaving", "enteringLeft", "enteringRight",
                       "leavingLeft", "leavingRight"},
            .value_inactive = "inactive",
            .value_approaching = "approaching",
            .value_movingAway = "movingAway",
            .value_entering = "entering",
            .value_leaving = "leaving",
            .value_enteringLeft = "enteringLeft",
            .value_enteringRight = "enteringRight",
            .value_leavingLeft = "leavingLeft",
            .value_leavingRight = "leavingRight",
        },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_MOVEMENT_SENSOR_ */
