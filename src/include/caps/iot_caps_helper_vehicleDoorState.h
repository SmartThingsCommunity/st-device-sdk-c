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

#ifndef _IOT_CAPS_HELPER_VEHICLE_DOOR_STATE_
#define _IOT_CAPS_HELPER_VEHICLE_DOOR_STATE_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_VEHICLEDOORSTATE_LOCKSTATE_VALUE_LOCKED,
    CAP_ENUM_VEHICLEDOORSTATE_LOCKSTATE_VALUE_UNKNOWN,
    CAP_ENUM_VEHICLEDOORSTATE_LOCKSTATE_VALUE_UNLOCKED,
    CAP_ENUM_VEHICLEDOORSTATE_LOCKSTATE_VALUE_MAX
};

enum {
    CAP_ENUM_VEHICLEDOORSTATE_FRONTLEFTDOOR_VALUE_OPEN,
    CAP_ENUM_VEHICLEDOORSTATE_FRONTLEFTDOOR_VALUE_CLOSED,
    CAP_ENUM_VEHICLEDOORSTATE_FRONTLEFTDOOR_VALUE_LOCKED,
    CAP_ENUM_VEHICLEDOORSTATE_FRONTLEFTDOOR_VALUE_MAX
};

enum {
    CAP_ENUM_VEHICLEDOORSTATE_FRONTRIGHTDOOR_VALUE_OPEN,
    CAP_ENUM_VEHICLEDOORSTATE_FRONTRIGHTDOOR_VALUE_CLOSED,
    CAP_ENUM_VEHICLEDOORSTATE_FRONTRIGHTDOOR_VALUE_LOCKED,
    CAP_ENUM_VEHICLEDOORSTATE_FRONTRIGHTDOOR_VALUE_MAX
};

enum {
    CAP_ENUM_VEHICLEDOORSTATE_REARLEFTDOOR_VALUE_OPEN,
    CAP_ENUM_VEHICLEDOORSTATE_REARLEFTDOOR_VALUE_CLOSED,
    CAP_ENUM_VEHICLEDOORSTATE_REARLEFTDOOR_VALUE_LOCKED,
    CAP_ENUM_VEHICLEDOORSTATE_REARLEFTDOOR_VALUE_MAX
};

enum {
    CAP_ENUM_VEHICLEDOORSTATE_REARRIGHTDOOR_VALUE_OPEN,
    CAP_ENUM_VEHICLEDOORSTATE_REARRIGHTDOOR_VALUE_CLOSED,
    CAP_ENUM_VEHICLEDOORSTATE_REARRIGHTDOOR_VALUE_LOCKED,
    CAP_ENUM_VEHICLEDOORSTATE_REARRIGHTDOOR_VALUE_MAX
};

enum {
    CAP_ENUM_VEHICLEDOORSTATE_SUPPORTEDATTRIBUTES_VALUE_FRONTLEFTDOOR,
    CAP_ENUM_VEHICLEDOORSTATE_SUPPORTEDATTRIBUTES_VALUE_FRONTRIGHTDOOR,
    CAP_ENUM_VEHICLEDOORSTATE_SUPPORTEDATTRIBUTES_VALUE_REARLEFTDOOR,
    CAP_ENUM_VEHICLEDOORSTATE_SUPPORTEDATTRIBUTES_VALUE_REARRIGHTDOOR,
    CAP_ENUM_VEHICLEDOORSTATE_SUPPORTEDATTRIBUTES_VALUE_MAX
};

const static struct iot_caps_vehicleDoorState {
    const char *id;
    const struct vehicleDoorState_attr_lockState {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_VEHICLEDOORSTATE_LOCKSTATE_VALUE_MAX];
        const char *value_locked;
        const char *value_unknown;
        const char *value_unlocked;
    } attr_lockState;
    const struct vehicleDoorState_attr_frontLeftDoor {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_VEHICLEDOORSTATE_FRONTLEFTDOOR_VALUE_MAX];
        const char *value_open;
        const char *value_closed;
        const char *value_locked;
    } attr_frontLeftDoor;
    const struct vehicleDoorState_attr_frontRightDoor {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_VEHICLEDOORSTATE_FRONTRIGHTDOOR_VALUE_MAX];
        const char *value_open;
        const char *value_closed;
        const char *value_locked;
    } attr_frontRightDoor;
    const struct vehicleDoorState_attr_rearLeftDoor {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_VEHICLEDOORSTATE_REARLEFTDOOR_VALUE_MAX];
        const char *value_open;
        const char *value_closed;
        const char *value_locked;
    } attr_rearLeftDoor;
    const struct vehicleDoorState_attr_rearRightDoor {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_VEHICLEDOORSTATE_REARRIGHTDOOR_VALUE_MAX];
        const char *value_open;
        const char *value_closed;
        const char *value_locked;
    } attr_rearRightDoor;
    const struct vehicleDoorState_attr_supportedAttributes {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_VEHICLEDOORSTATE_SUPPORTEDATTRIBUTES_VALUE_MAX];
        const char *value_frontLeftDoor;
        const char *value_frontRightDoor;
        const char *value_rearLeftDoor;
        const char *value_rearRightDoor;
    } attr_supportedAttributes;
    const struct vehicleDoorState_cmd_lock {
        const char *name;
    } cmd_lock;
    const struct vehicleDoorState_cmd_unlock {
        const char *name;
    } cmd_unlock;
} caps_helper_vehicleDoorState = {
    .id = "vehicleDoorState",
    .attr_lockState =
        {
            .name = "lockState",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"locked", "unknown", "unlocked"},
            .value_locked = "locked",
            .value_unknown = "unknown",
            .value_unlocked = "unlocked",
        },
    .attr_frontLeftDoor =
        {
            .name = "frontLeftDoor",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"open", "closed", "locked"},
            .value_open = "open",
            .value_closed = "closed",
            .value_locked = "locked",
        },
    .attr_frontRightDoor =
        {
            .name = "frontRightDoor",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"open", "closed", "locked"},
            .value_open = "open",
            .value_closed = "closed",
            .value_locked = "locked",
        },
    .attr_rearLeftDoor =
        {
            .name = "rearLeftDoor",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"open", "closed", "locked"},
            .value_open = "open",
            .value_closed = "closed",
            .value_locked = "locked",
        },
    .attr_rearRightDoor =
        {
            .name = "rearRightDoor",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"open", "closed", "locked"},
            .value_open = "open",
            .value_closed = "closed",
            .value_locked = "locked",
        },
    .attr_supportedAttributes =
        {
            .name = "supportedAttributes",
            .property = ATTR_SET_VALUE_ARRAY | ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"frontLeftDoor", "frontRightDoor", "rearLeftDoor", "rearRightDoor"},
            .value_frontLeftDoor = "frontLeftDoor",
            .value_frontRightDoor = "frontRightDoor",
            .value_rearLeftDoor = "rearLeftDoor",
            .value_rearRightDoor = "rearRightDoor",
        },
    .cmd_lock = {.name = "lock"},
    .cmd_unlock = {.name = "unlock"},
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_VEHICLE_DOOR_STATE_ */
