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

#ifndef _IOT_CAPS_HELPER_APPLIANCE_UTILIZATION_
#define _IOT_CAPS_HELPER_APPLIANCE_UTILIZATION_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_APPLIANCEUTILIZATION_STATUS_VALUE_INUSE,
    CAP_ENUM_APPLIANCEUTILIZATION_STATUS_VALUE_NOTINUSE,
    CAP_ENUM_APPLIANCEUTILIZATION_STATUS_VALUE_MAX
};

const static struct iot_caps_applianceUtilization {
    const char *id;
    const struct applianceUtilization_attr_status {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_APPLIANCEUTILIZATION_STATUS_VALUE_MAX];
        const char *value_inUse;
        const char *value_notInUse;
    } attr_status;
} caps_helper_applianceUtilization = {
    .id = "applianceUtilization",
    .attr_status =
        {
            .name = "status",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"inUse", "notInUse"},
            .value_inUse = "inUse",
            .value_notInUse = "notInUse",
        },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_APPLIANCE_UTILIZATION_ */
