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

#ifndef _IOT_CAPS_HELPER_CONTAINER_STATE_
#define _IOT_CAPS_HELPER_CONTAINER_STATE_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_CONTAINERSTATE_CONTAINERSTATE_VALUE_EMPTY,
    CAP_ENUM_CONTAINERSTATE_CONTAINERSTATE_VALUE_NORMAL,
    CAP_ENUM_CONTAINERSTATE_CONTAINERSTATE_VALUE_FULL,
    CAP_ENUM_CONTAINERSTATE_CONTAINERSTATE_VALUE_MAX
};

enum {
    CAP_ENUM_CONTAINERSTATE_SUPPORTEDCONTAINERSTATES_VALUE_EMPTY,
    CAP_ENUM_CONTAINERSTATE_SUPPORTEDCONTAINERSTATES_VALUE_NORMAL,
    CAP_ENUM_CONTAINERSTATE_SUPPORTEDCONTAINERSTATES_VALUE_FULL,
    CAP_ENUM_CONTAINERSTATE_SUPPORTEDCONTAINERSTATES_VALUE_MAX
};

enum {
    CAP_ENUM_CONTAINERSTATE_CONTENT_VALUE_FOOD,
    CAP_ENUM_CONTAINERSTATE_CONTENT_VALUE_WATER,
    CAP_ENUM_CONTAINERSTATE_CONTENT_VALUE_LIQUID,
    CAP_ENUM_CONTAINERSTATE_CONTENT_VALUE_CONSUMABLE,
    CAP_ENUM_CONTAINERSTATE_CONTENT_VALUE_EXCRETIONS,
    CAP_ENUM_CONTAINERSTATE_CONTENT_VALUE_MAX
};

const static struct iot_caps_containerState {
    const char *id;
    const struct containerState_attr_containerState {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_CONTAINERSTATE_CONTAINERSTATE_VALUE_MAX];
        const char *value_empty;
        const char *value_normal;
        const char *value_full;
    } attr_containerState;
    const struct containerState_attr_supportedContainerStates {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_CONTAINERSTATE_SUPPORTEDCONTAINERSTATES_VALUE_MAX];
        const char *value_empty;
        const char *value_normal;
        const char *value_full;
    } attr_supportedContainerStates;
    const struct containerState_attr_content {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_CONTAINERSTATE_CONTENT_VALUE_MAX];
        const char *value_food;
        const char *value_water;
        const char *value_liquid;
        const char *value_consumable;
        const char *value_excretions;
    } attr_content;
} caps_helper_containerState = {
    .id = "containerState",
    .attr_containerState =
        {
            .name = "containerState",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"empty", "normal", "full"},
            .value_empty = "empty",
            .value_normal = "normal",
            .value_full = "full",
        },
    .attr_supportedContainerStates =
        {
            .name = "supportedContainerStates",
            .property = ATTR_SET_VALUE_ARRAY,
            .valueType = VALUE_TYPE_STRING,
            .values = {"empty", "normal", "full"},
            .value_empty = "empty",
            .value_normal = "normal",
            .value_full = "full",
        },
    .attr_content =
        {
            .name = "content",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"food", "water", "liquid", "consumable", "excretions"},
            .value_food = "food",
            .value_water = "water",
            .value_liquid = "liquid",
            .value_consumable = "consumable",
            .value_excretions = "excretions",
        },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_CONTAINER_STATE_ */
