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

#ifndef _IOT_CAPS_HELPER_VEHICLE_WINDOW_STATE_
#define _IOT_CAPS_HELPER_VEHICLE_WINDOW_STATE_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_VEHICLEWINDOWSTATE_FRONTLEFTWINDOW_VALUE_OPEN,
    CAP_ENUM_VEHICLEWINDOWSTATE_FRONTLEFTWINDOW_VALUE_CLOSED,
    CAP_ENUM_VEHICLEWINDOWSTATE_FRONTLEFTWINDOW_VALUE_MAX
};

enum {
    CAP_ENUM_VEHICLEWINDOWSTATE_FRONTRIGHTWINDOW_VALUE_OPEN,
    CAP_ENUM_VEHICLEWINDOWSTATE_FRONTRIGHTWINDOW_VALUE_CLOSED,
    CAP_ENUM_VEHICLEWINDOWSTATE_FRONTRIGHTWINDOW_VALUE_MAX
};

enum {
    CAP_ENUM_VEHICLEWINDOWSTATE_REARLEFTWINDOW_VALUE_OPEN,
    CAP_ENUM_VEHICLEWINDOWSTATE_REARLEFTWINDOW_VALUE_CLOSED,
    CAP_ENUM_VEHICLEWINDOWSTATE_REARLEFTWINDOW_VALUE_MAX
};

enum {
    CAP_ENUM_VEHICLEWINDOWSTATE_REARRIGHTWINDOW_VALUE_OPEN,
    CAP_ENUM_VEHICLEWINDOWSTATE_REARRIGHTWINDOW_VALUE_CLOSED,
    CAP_ENUM_VEHICLEWINDOWSTATE_REARRIGHTWINDOW_VALUE_MAX
};

enum {
    CAP_ENUM_VEHICLEWINDOWSTATE_SUPPORTEDATTRIBUTES_VALUE_FRONTLEFTWINDOW,
    CAP_ENUM_VEHICLEWINDOWSTATE_SUPPORTEDATTRIBUTES_VALUE_FRONTRIGHTWINDOW,
    CAP_ENUM_VEHICLEWINDOWSTATE_SUPPORTEDATTRIBUTES_VALUE_REARLEFTWINDOW,
    CAP_ENUM_VEHICLEWINDOWSTATE_SUPPORTEDATTRIBUTES_VALUE_REARRIGHTWINDOW,
    CAP_ENUM_VEHICLEWINDOWSTATE_SUPPORTEDATTRIBUTES_VALUE_MAX
};

const static struct iot_caps_vehicleWindowState {
    const char *id;
    const struct vehicleWindowState_attr_frontLeftWindow {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_VEHICLEWINDOWSTATE_FRONTLEFTWINDOW_VALUE_MAX];
        const char *value_open;
        const char *value_closed;
    } attr_frontLeftWindow;
    const struct vehicleWindowState_attr_frontRightWindow {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_VEHICLEWINDOWSTATE_FRONTRIGHTWINDOW_VALUE_MAX];
        const char *value_open;
        const char *value_closed;
    } attr_frontRightWindow;
    const struct vehicleWindowState_attr_rearLeftWindow {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_VEHICLEWINDOWSTATE_REARLEFTWINDOW_VALUE_MAX];
        const char *value_open;
        const char *value_closed;
    } attr_rearLeftWindow;
    const struct vehicleWindowState_attr_rearRightWindow {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_VEHICLEWINDOWSTATE_REARRIGHTWINDOW_VALUE_MAX];
        const char *value_open;
        const char *value_closed;
    } attr_rearRightWindow;
    const struct vehicleWindowState_attr_supportedAttributes {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_VEHICLEWINDOWSTATE_SUPPORTEDATTRIBUTES_VALUE_MAX];
        const char *value_frontLeftWindow;
        const char *value_frontRightWindow;
        const char *value_rearLeftWindow;
        const char *value_rearRightWindow;
    } attr_supportedAttributes;
} caps_helper_vehicleWindowState = {
    .id = "vehicleWindowState",
    .attr_frontLeftWindow =
        {
            .name = "frontLeftWindow",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"open", "closed"},
            .value_open = "open",
            .value_closed = "closed",
        },
    .attr_frontRightWindow =
        {
            .name = "frontRightWindow",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"open", "closed"},
            .value_open = "open",
            .value_closed = "closed",
        },
    .attr_rearLeftWindow =
        {
            .name = "rearLeftWindow",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"open", "closed"},
            .value_open = "open",
            .value_closed = "closed",
        },
    .attr_rearRightWindow =
        {
            .name = "rearRightWindow",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"open", "closed"},
            .value_open = "open",
            .value_closed = "closed",
        },
    .attr_supportedAttributes =
        {
            .name = "supportedAttributes",
            .property = ATTR_SET_VALUE_ARRAY | ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"frontLeftWindow", "frontRightWindow", "rearLeftWindow", "rearRightWindow"},
            .value_frontLeftWindow = "frontLeftWindow",
            .value_frontRightWindow = "frontRightWindow",
            .value_rearLeftWindow = "rearLeftWindow",
            .value_rearRightWindow = "rearRightWindow",
        },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_VEHICLE_WINDOW_STATE_ */
