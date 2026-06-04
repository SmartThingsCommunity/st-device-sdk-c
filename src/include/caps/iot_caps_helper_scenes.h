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

#ifndef _IOT_CAPS_HELPER_SCENES_
#define _IOT_CAPS_HELPER_SCENES_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

const static struct iot_caps_scenes {
    const char *id;
    const struct scenes_attr_scene {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
    } attr_scene;
    const struct scenes_attr_supportedScenes {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
    } attr_supportedScenes;
    const struct scenes_cmd_setScene {
        const char *name;
    } cmd_setScene;
} caps_helper_scenes = {
    .id = "scenes",
    .attr_scene =
        {
            .name = "scene",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
        },
    .attr_supportedScenes =
        {
            .name = "supportedScenes",
            .property = ATTR_SET_VALUE_ARRAY | ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
        },
    .cmd_setScene = {.name = "setScene"},  // arguments: scene(string)
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_SCENES_ */
