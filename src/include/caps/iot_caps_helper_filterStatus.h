/* ***************************************************************************
 *
 * Copyright 2019-2020 Samsung Electronics All Rights Reserved.
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

#ifndef _IOT_CAPS_HELPER_FILTER_STATUS_
#define _IOT_CAPS_HELPER_FILTER_STATUS_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_FILTERSTATUS_FILTERSTATUS_VALUE_NORMAL,
    CAP_ENUM_FILTERSTATUS_FILTERSTATUS_VALUE_REPLACE,
    CAP_ENUM_FILTERSTATUS_FILTERSTATUS_VALUE_MAX
};

const static struct iot_caps_filterStatus {
    const char *id;
    const struct filterStatus_attr_filterStatus {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_FILTERSTATUS_FILTERSTATUS_VALUE_MAX];
        const char *value_normal;
        const char *value_replace;
    } attr_filterStatus;
} caps_helper_filterStatus = {
    .id = "filterStatus",
    .attr_filterStatus = {
        .name = "filterStatus",
        .property = ATTR_SET_VALUE_REQUIRED,
        .valueType = VALUE_TYPE_STRING,
        .values = {"normal", "replace"},
        .value_normal = "normal",
        .value_replace = "replace",
    },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_FILTER_STATUS_ */
