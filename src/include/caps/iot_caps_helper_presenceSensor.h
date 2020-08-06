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

#ifndef _IOT_CAPS_HELPER_PRESENCE_SENSOR_
#define _IOT_CAPS_HELPER_PRESENCE_SENSOR_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_PRESENCESENSOR_PRESENCE_VALUE_PRESENT,
    CAP_ENUM_PRESENCESENSOR_PRESENCE_VALUE_NOT_PRESENT,
    CAP_ENUM_PRESENCESENSOR_PRESENCE_VALUE_MAX
};

const static struct iot_caps_presenceSensor {
    const char *id;
    const struct presenceSensor_attr_presence {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_PRESENCESENSOR_PRESENCE_VALUE_MAX];
        const char *value_present;
        const char *value_not_present;
    } attr_presence;
} caps_helper_presenceSensor = {
    .id = "presenceSensor",
    .attr_presence = {
        .name = "presence",
        .property = ATTR_SET_VALUE_REQUIRED,
        .valueType = VALUE_TYPE_STRING,
        .values = {"present", "not present"},
        .value_present = "present",
        .value_not_present = "not present",
    },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_PRESENCE_SENSOR_ */
