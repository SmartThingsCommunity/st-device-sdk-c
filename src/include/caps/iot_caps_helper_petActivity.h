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

#ifndef _IOT_CAPS_HELPER_PET_ACTIVITY_
#define _IOT_CAPS_HELPER_PET_ACTIVITY_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_PETACTIVITY_PETACTIVITY_VALUE_IDLE,
    CAP_ENUM_PETACTIVITY_PETACTIVITY_VALUE_EATING,
    CAP_ENUM_PETACTIVITY_PETACTIVITY_VALUE_POOPING,
    CAP_ENUM_PETACTIVITY_PETACTIVITY_VALUE_SLEEPING,
    CAP_ENUM_PETACTIVITY_PETACTIVITY_VALUE_DRINKINGWATER,
    CAP_ENUM_PETACTIVITY_PETACTIVITY_VALUE_PEEING,
    CAP_ENUM_PETACTIVITY_PETACTIVITY_VALUE_PLAYING,
    CAP_ENUM_PETACTIVITY_PETACTIVITY_VALUE_RESTING,
    CAP_ENUM_PETACTIVITY_PETACTIVITY_VALUE_WALKING,
    CAP_ENUM_PETACTIVITY_PETACTIVITY_VALUE_RUNNING,
    CAP_ENUM_PETACTIVITY_PETACTIVITY_VALUE_BARKING,
    CAP_ENUM_PETACTIVITY_PETACTIVITY_VALUE_MEOWING,
    CAP_ENUM_PETACTIVITY_PETACTIVITY_VALUE_TOILETING,
    CAP_ENUM_PETACTIVITY_PETACTIVITY_VALUE_MAX
};

enum {
    CAP_ENUM_PETACTIVITY_SUPPORTEDPETACTIVITIES_VALUE_IDLE,
    CAP_ENUM_PETACTIVITY_SUPPORTEDPETACTIVITIES_VALUE_EATING,
    CAP_ENUM_PETACTIVITY_SUPPORTEDPETACTIVITIES_VALUE_POOPING,
    CAP_ENUM_PETACTIVITY_SUPPORTEDPETACTIVITIES_VALUE_SLEEPING,
    CAP_ENUM_PETACTIVITY_SUPPORTEDPETACTIVITIES_VALUE_DRINKINGWATER,
    CAP_ENUM_PETACTIVITY_SUPPORTEDPETACTIVITIES_VALUE_PEEING,
    CAP_ENUM_PETACTIVITY_SUPPORTEDPETACTIVITIES_VALUE_PLAYING,
    CAP_ENUM_PETACTIVITY_SUPPORTEDPETACTIVITIES_VALUE_RESTING,
    CAP_ENUM_PETACTIVITY_SUPPORTEDPETACTIVITIES_VALUE_WALKING,
    CAP_ENUM_PETACTIVITY_SUPPORTEDPETACTIVITIES_VALUE_RUNNING,
    CAP_ENUM_PETACTIVITY_SUPPORTEDPETACTIVITIES_VALUE_BARKING,
    CAP_ENUM_PETACTIVITY_SUPPORTEDPETACTIVITIES_VALUE_MEOWING,
    CAP_ENUM_PETACTIVITY_SUPPORTEDPETACTIVITIES_VALUE_TOILETING,
    CAP_ENUM_PETACTIVITY_SUPPORTEDPETACTIVITIES_VALUE_MAX
};

const static struct iot_caps_petActivity {
    const char *id;
    const struct petActivity_attr_petActivity {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_PETACTIVITY_PETACTIVITY_VALUE_MAX];
        const char *value_idle;
        const char *value_eating;
        const char *value_pooping;
        const char *value_sleeping;
        const char *value_drinkingWater;
        const char *value_peeing;
        const char *value_playing;
        const char *value_resting;
        const char *value_walking;
        const char *value_running;
        const char *value_barking;
        const char *value_meowing;
        const char *value_toileting;
    } attr_petActivity;
    const struct petActivity_attr_supportedPetActivities {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_PETACTIVITY_SUPPORTEDPETACTIVITIES_VALUE_MAX];
        const char *value_idle;
        const char *value_eating;
        const char *value_pooping;
        const char *value_sleeping;
        const char *value_drinkingWater;
        const char *value_peeing;
        const char *value_playing;
        const char *value_resting;
        const char *value_walking;
        const char *value_running;
        const char *value_barking;
        const char *value_meowing;
        const char *value_toileting;
    } attr_supportedPetActivities;
} caps_helper_petActivity = {
    .id = "petActivity",
    .attr_petActivity =
        {
            .name = "petActivity",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"idle", "eating", "pooping", "sleeping", "drinkingWater", "peeing", "playing", "resting",
                       "walking", "running", "barking", "meowing", "toileting"},
            .value_idle = "idle",
            .value_eating = "eating",
            .value_pooping = "pooping",
            .value_sleeping = "sleeping",
            .value_drinkingWater = "drinkingWater",
            .value_peeing = "peeing",
            .value_playing = "playing",
            .value_resting = "resting",
            .value_walking = "walking",
            .value_running = "running",
            .value_barking = "barking",
            .value_meowing = "meowing",
            .value_toileting = "toileting",
        },
    .attr_supportedPetActivities =
        {
            .name = "supportedPetActivities",
            .property = ATTR_SET_VALUE_ARRAY,
            .valueType = VALUE_TYPE_STRING,
            .values = {"idle", "eating", "pooping", "sleeping", "drinkingWater", "peeing", "playing", "resting",
                       "walking", "running", "barking", "meowing", "toileting"},
            .value_idle = "idle",
            .value_eating = "eating",
            .value_pooping = "pooping",
            .value_sleeping = "sleeping",
            .value_drinkingWater = "drinkingWater",
            .value_peeing = "peeing",
            .value_playing = "playing",
            .value_resting = "resting",
            .value_walking = "walking",
            .value_running = "running",
            .value_barking = "barking",
            .value_meowing = "meowing",
            .value_toileting = "toileting",
        },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_PET_ACTIVITY_ */
