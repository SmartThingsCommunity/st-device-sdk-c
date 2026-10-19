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

#ifndef _IOT_CAPS_HELPER_CONSUMABLE_
#define _IOT_CAPS_HELPER_CONSUMABLE_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_CONSUMABLE_CONSUMABLESTATUS_VALUE_GOOD,
    CAP_ENUM_CONSUMABLE_CONSUMABLESTATUS_VALUE_MAINTENANCE_REQUIRED,
    CAP_ENUM_CONSUMABLE_CONSUMABLESTATUS_VALUE_MISSING,
    CAP_ENUM_CONSUMABLE_CONSUMABLESTATUS_VALUE_ORDER,
    CAP_ENUM_CONSUMABLE_CONSUMABLESTATUS_VALUE_REPLACE,
    CAP_ENUM_CONSUMABLE_CONSUMABLESTATUS_VALUE_MAX
};

const static struct iot_caps_consumable {
    const char *id;
    const struct consumable_attr_consumableStatus {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_CONSUMABLE_CONSUMABLESTATUS_VALUE_MAX];
        const char *value_good;
        const char *value_maintenance_required;
        const char *value_missing;
        const char *value_order;
        const char *value_replace;
    } attr_consumableStatus;
} caps_helper_consumable = {
    .id = "consumable",
    .attr_consumableStatus =
        {
            .name = "consumableStatus",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"good", "maintenance_required", "missing", "order", "replace"},
            .value_good = "good",
            .value_maintenance_required = "maintenance_required",
            .value_missing = "missing",
            .value_order = "order",
            .value_replace = "replace",
        },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_CONSUMABLE_ */
