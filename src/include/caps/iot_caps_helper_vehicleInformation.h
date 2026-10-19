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

#ifndef _IOT_CAPS_HELPER_VEHICLE_INFORMATION_
#define _IOT_CAPS_HELPER_VEHICLE_INFORMATION_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

const static struct iot_caps_vehicleInformation {
    const char *id;
    const struct vehicleInformation_attr_vehicleColor {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const unsigned int max_length;
    } attr_vehicleColor;
    const struct vehicleInformation_attr_vehicleMake {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const unsigned int max_length;
    } attr_vehicleMake;
    const struct vehicleInformation_attr_vehicleModel {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const unsigned int max_length;
    } attr_vehicleModel;
    const struct vehicleInformation_attr_vehicleTrim {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const unsigned int max_length;
    } attr_vehicleTrim;
    const struct vehicleInformation_attr_vehicleYear {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const int min;
        const int max;
    } attr_vehicleYear;
    const struct vehicleInformation_attr_vehicleId {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const unsigned int max_length;
    } attr_vehicleId;
    const struct vehicleInformation_attr_vehiclePlate {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const unsigned int max_length;
    } attr_vehiclePlate;
    const struct vehicleInformation_attr_vehicleImage {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
    } attr_vehicleImage;
} caps_helper_vehicleInformation = {
    .id = "vehicleInformation",
    .attr_vehicleColor =
        {
            .name = "vehicleColor",
            .property = ATTR_SET_MAX_LENGTH,
            .valueType = VALUE_TYPE_STRING,
            .max_length = 255,
        },
    .attr_vehicleMake =
        {
            .name = "vehicleMake",
            .property = ATTR_SET_MAX_LENGTH,
            .valueType = VALUE_TYPE_STRING,
            .max_length = 255,
        },
    .attr_vehicleModel =
        {
            .name = "vehicleModel",
            .property = ATTR_SET_MAX_LENGTH,
            .valueType = VALUE_TYPE_STRING,
            .max_length = 255,
        },
    .attr_vehicleTrim =
        {
            .name = "vehicleTrim",
            .property = ATTR_SET_MAX_LENGTH,
            .valueType = VALUE_TYPE_STRING,
            .max_length = 255,
        },
    .attr_vehicleYear =
        {
            .name = "vehicleYear",
            .property = ATTR_SET_VALUE_MIN | ATTR_SET_VALUE_MAX,
            .valueType = VALUE_TYPE_INTEGER,
            .min = 0,
            .max = 9999,
        },
    .attr_vehicleId =
        {
            .name = "vehicleId",
            .property = ATTR_SET_MAX_LENGTH,
            .valueType = VALUE_TYPE_STRING,
            .max_length = 255,
        },
    .attr_vehiclePlate =
        {
            .name = "vehiclePlate",
            .property = ATTR_SET_MAX_LENGTH,
            .valueType = VALUE_TYPE_STRING,
            .max_length = 255,
        },
    .attr_vehicleImage =
        {
            .name = "vehicleImage",
            .property = 0,
            .valueType = VALUE_TYPE_STRING,
        },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_VEHICLE_INFORMATION_ */
