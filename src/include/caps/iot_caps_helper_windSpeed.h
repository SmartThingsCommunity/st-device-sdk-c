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

#ifndef _IOT_CAPS_HELPER_WIND_SPEED_
#define _IOT_CAPS_HELPER_WIND_SPEED_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_WINDSPEED_WINDSPEED_UNIT_M_PER_S,
    CAP_ENUM_WINDSPEED_WINDSPEED_UNIT_KM_PER_H,
    CAP_ENUM_WINDSPEED_WINDSPEED_UNIT_MPH,
    CAP_ENUM_WINDSPEED_WINDSPEED_UNIT_KNOTS,
    CAP_ENUM_WINDSPEED_WINDSPEED_UNIT_MAX
};

const static struct iot_caps_windSpeed {
    const char *id;
    const struct windSpeed_attr_windspeed {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *units[CAP_ENUM_WINDSPEED_WINDSPEED_UNIT_MAX];
        const char *unit_m_per_s;
        const char *unit_km_per_h;
        const char *unit_mph;
        const char *unit_knots;
        const double min;
    } attr_windspeed;
} caps_helper_windSpeed = {
    .id = "windSpeed",
    .attr_windspeed =
        {
            .name = "windspeed",
            .property = ATTR_SET_VALUE_MIN | ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_NUMBER,
            .units = {"m/s", "km/h", "mph", "knots"},
            .unit_m_per_s = "m/s",
            .unit_km_per_h = "km/h",
            .unit_mph = "mph",
            .unit_knots = "knots",
            .min = 0,
        },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_WIND_SPEED_ */
