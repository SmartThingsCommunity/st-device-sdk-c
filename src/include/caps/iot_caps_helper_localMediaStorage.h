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

#ifndef _IOT_CAPS_HELPER_LOCAL_MEDIA_STORAGE_
#define _IOT_CAPS_HELPER_LOCAL_MEDIA_STORAGE_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_LOCALMEDIASTORAGE_LOCALVIDEORECORDING_VALUE_ENABLED,
    CAP_ENUM_LOCALMEDIASTORAGE_LOCALVIDEORECORDING_VALUE_DISABLED,
    CAP_ENUM_LOCALMEDIASTORAGE_LOCALVIDEORECORDING_VALUE_MAX
};

enum {
    CAP_ENUM_LOCALMEDIASTORAGE_LOCALSNAPSHOTRECORDING_VALUE_ENABLED,
    CAP_ENUM_LOCALMEDIASTORAGE_LOCALSNAPSHOTRECORDING_VALUE_DISABLED,
    CAP_ENUM_LOCALMEDIASTORAGE_LOCALSNAPSHOTRECORDING_VALUE_MAX
};

enum {
    CAP_ENUM_LOCALMEDIASTORAGE_SUPPORTEDATTRIBUTES_VALUE_LOCALVIDEORECORDING,
    CAP_ENUM_LOCALMEDIASTORAGE_SUPPORTEDATTRIBUTES_VALUE_LOCALSNAPSHOTRECORDING,
    CAP_ENUM_LOCALMEDIASTORAGE_SUPPORTEDATTRIBUTES_VALUE_MAX
};

const static struct iot_caps_localMediaStorage {
    const char *id;
    const struct localMediaStorage_attr_localVideoRecording {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_LOCALMEDIASTORAGE_LOCALVIDEORECORDING_VALUE_MAX];
        const char *value_enabled;
        const char *value_disabled;
    } attr_localVideoRecording;
    const struct localMediaStorage_attr_localSnapshotRecording {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_LOCALMEDIASTORAGE_LOCALSNAPSHOTRECORDING_VALUE_MAX];
        const char *value_enabled;
        const char *value_disabled;
    } attr_localSnapshotRecording;
    const struct localMediaStorage_attr_supportedAttributes {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_LOCALMEDIASTORAGE_SUPPORTEDATTRIBUTES_VALUE_MAX];
        const char *value_localVideoRecording;
        const char *value_localSnapshotRecording;
    } attr_supportedAttributes;
    const struct localMediaStorage_cmd_setLocalVideoRecording {
        const char *name;
    } cmd_setLocalVideoRecording;
    const struct localMediaStorage_cmd_setLocalSnapshotRecording {
        const char *name;
    } cmd_setLocalSnapshotRecording;
} caps_helper_localMediaStorage = {
    .id = "localMediaStorage",
    .attr_localVideoRecording =
        {
            .name = "localVideoRecording",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"enabled", "disabled"},
            .value_enabled = "enabled",
            .value_disabled = "disabled",
        },
    .attr_localSnapshotRecording =
        {
            .name = "localSnapshotRecording",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"enabled", "disabled"},
            .value_enabled = "enabled",
            .value_disabled = "disabled",
        },
    .attr_supportedAttributes =
        {
            .name = "supportedAttributes",
            .property = ATTR_SET_VALUE_ARRAY | ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"localVideoRecording", "localSnapshotRecording"},
            .value_localVideoRecording = "localVideoRecording",
            .value_localSnapshotRecording = "localSnapshotRecording",
        },
    .cmd_setLocalVideoRecording = {.name = "setLocalVideoRecording"},        // arguments: state(string)
    .cmd_setLocalSnapshotRecording = {.name = "setLocalSnapshotRecording"},  // arguments: state(string)
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_LOCAL_MEDIA_STORAGE_ */
