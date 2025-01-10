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

#ifndef _IOT_CAPS_HELPER_SOUND_SENSOR_
#define _IOT_CAPS_HELPER_SOUND_SENSOR_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_SOUNDSENSOR_SOUND_VALUE_DETECTED,
    CAP_ENUM_SOUNDSENSOR_SOUND_VALUE_NOT_DETECTED,
    CAP_ENUM_SOUNDSENSOR_SOUND_VALUE_MAX
};

const static struct iot_caps_soundSensor {
    const char *id;
    const struct soundSensor_attr_sound {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_SOUNDSENSOR_SOUND_VALUE_MAX];
        const char *value_detected;
        const char *value_not_detected;
    } attr_sound;
} caps_helper_soundSensor = {
    .id = "soundSensor",
    .attr_sound = {
        .name = "sound",
        .property = ATTR_SET_VALUE_REQUIRED,
        .valueType = VALUE_TYPE_STRING,
        .values = {"detected", "not detected"},
        .value_detected = "detected",
        .value_not_detected = "not detected",
    },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_SOUND_SENSOR_ */
