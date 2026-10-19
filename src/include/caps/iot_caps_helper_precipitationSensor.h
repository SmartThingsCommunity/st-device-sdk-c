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

#ifndef _IOT_CAPS_HELPER_PRECIPITATION_SENSOR_
#define _IOT_CAPS_HELPER_PRECIPITATION_SENSOR_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_PRECIPITATIONSENSOR_PRECIPITATIONINTENSITY_VALUE_NONE,
    CAP_ENUM_PRECIPITATIONSENSOR_PRECIPITATIONINTENSITY_VALUE_POSSIBLEPRECIPITATION,
    CAP_ENUM_PRECIPITATIONSENSOR_PRECIPITATIONINTENSITY_VALUE_LIGHT,
    CAP_ENUM_PRECIPITATIONSENSOR_PRECIPITATIONINTENSITY_VALUE_MODERATE,
    CAP_ENUM_PRECIPITATIONSENSOR_PRECIPITATIONINTENSITY_VALUE_HEAVY,
    CAP_ENUM_PRECIPITATIONSENSOR_PRECIPITATIONINTENSITY_VALUE_VIOLENT,
    CAP_ENUM_PRECIPITATIONSENSOR_PRECIPITATIONINTENSITY_VALUE_MAX
};

const static struct iot_caps_precipitationSensor {
    const char *id;
    const struct precipitationSensor_attr_precipitationIntensity {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_PRECIPITATIONSENSOR_PRECIPITATIONINTENSITY_VALUE_MAX];
        const char *value_none;
        const char *value_possiblePrecipitation;
        const char *value_light;
        const char *value_moderate;
        const char *value_heavy;
        const char *value_violent;
    } attr_precipitationIntensity;
} caps_helper_precipitationSensor = {
    .id = "precipitationSensor",
    .attr_precipitationIntensity =
        {
            .name = "precipitationIntensity",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"none", "possiblePrecipitation", "light", "moderate", "heavy", "violent"},
            .value_none = "none",
            .value_possiblePrecipitation = "possiblePrecipitation",
            .value_light = "light",
            .value_moderate = "moderate",
            .value_heavy = "heavy",
            .value_violent = "violent",
        },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_PRECIPITATION_SENSOR_ */
