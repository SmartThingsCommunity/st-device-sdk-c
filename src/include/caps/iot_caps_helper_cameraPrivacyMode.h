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

#ifndef _IOT_CAPS_HELPER_CAMERA_PRIVACY_MODE_
#define _IOT_CAPS_HELPER_CAMERA_PRIVACY_MODE_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_CAMERAPRIVACYMODE_SOFTRECORDINGPRIVACYMODE_VALUE_ENABLED,
    CAP_ENUM_CAMERAPRIVACYMODE_SOFTRECORDINGPRIVACYMODE_VALUE_DISABLED,
    CAP_ENUM_CAMERAPRIVACYMODE_SOFTRECORDINGPRIVACYMODE_VALUE_MAX
};

enum {
    CAP_ENUM_CAMERAPRIVACYMODE_SOFTLIVESTREAMPRIVACYMODE_VALUE_ENABLED,
    CAP_ENUM_CAMERAPRIVACYMODE_SOFTLIVESTREAMPRIVACYMODE_VALUE_DISABLED,
    CAP_ENUM_CAMERAPRIVACYMODE_SOFTLIVESTREAMPRIVACYMODE_VALUE_MAX
};

enum {
    CAP_ENUM_CAMERAPRIVACYMODE_HARDPRIVACYMODE_VALUE_ENABLED,
    CAP_ENUM_CAMERAPRIVACYMODE_HARDPRIVACYMODE_VALUE_DISABLED,
    CAP_ENUM_CAMERAPRIVACYMODE_HARDPRIVACYMODE_VALUE_MAX
};

enum {
    CAP_ENUM_CAMERAPRIVACYMODE_SUPPORTEDATTRIBUTES_VALUE_SOFTRECORDINGPRIVACYMODE,
    CAP_ENUM_CAMERAPRIVACYMODE_SUPPORTEDATTRIBUTES_VALUE_SOFTLIVESTREAMPRIVACYMODE,
    CAP_ENUM_CAMERAPRIVACYMODE_SUPPORTEDATTRIBUTES_VALUE_HARDPRIVACYMODE,
    CAP_ENUM_CAMERAPRIVACYMODE_SUPPORTEDATTRIBUTES_VALUE_MAX
};

enum {
    CAP_ENUM_CAMERAPRIVACYMODE_SUPPORTEDCOMMANDS_VALUE_SETSOFTRECORDINGPRIVACYMODE,
    CAP_ENUM_CAMERAPRIVACYMODE_SUPPORTEDCOMMANDS_VALUE_SETSOFTLIVESTREAMPRIVACYMODE,
    CAP_ENUM_CAMERAPRIVACYMODE_SUPPORTEDCOMMANDS_VALUE_MAX
};

const static struct iot_caps_cameraPrivacyMode {
    const char *id;
    const struct cameraPrivacyMode_attr_softRecordingPrivacyMode {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_CAMERAPRIVACYMODE_SOFTRECORDINGPRIVACYMODE_VALUE_MAX];
        const char *value_enabled;
        const char *value_disabled;
    } attr_softRecordingPrivacyMode;
    const struct cameraPrivacyMode_attr_softLivestreamPrivacyMode {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_CAMERAPRIVACYMODE_SOFTLIVESTREAMPRIVACYMODE_VALUE_MAX];
        const char *value_enabled;
        const char *value_disabled;
    } attr_softLivestreamPrivacyMode;
    const struct cameraPrivacyMode_attr_hardPrivacyMode {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_CAMERAPRIVACYMODE_HARDPRIVACYMODE_VALUE_MAX];
        const char *value_enabled;
        const char *value_disabled;
    } attr_hardPrivacyMode;
    const struct cameraPrivacyMode_attr_supportedAttributes {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_CAMERAPRIVACYMODE_SUPPORTEDATTRIBUTES_VALUE_MAX];
        const char *value_softRecordingPrivacyMode;
        const char *value_softLivestreamPrivacyMode;
        const char *value_hardPrivacyMode;
    } attr_supportedAttributes;
    const struct cameraPrivacyMode_attr_supportedCommands {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_CAMERAPRIVACYMODE_SUPPORTEDCOMMANDS_VALUE_MAX];
        const char *value_setSoftRecordingPrivacyMode;
        const char *value_setSoftLivestreamPrivacyMode;
    } attr_supportedCommands;
    const struct cameraPrivacyMode_cmd_setSoftRecordingPrivacyMode {
        const char *name;
    } cmd_setSoftRecordingPrivacyMode;
    const struct cameraPrivacyMode_cmd_setSoftLivestreamPrivacyMode {
        const char *name;
    } cmd_setSoftLivestreamPrivacyMode;
} caps_helper_cameraPrivacyMode = {
    .id = "cameraPrivacyMode",
    .attr_softRecordingPrivacyMode =
        {
            .name = "softRecordingPrivacyMode",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"enabled", "disabled"},
            .value_enabled = "enabled",
            .value_disabled = "disabled",
        },
    .attr_softLivestreamPrivacyMode =
        {
            .name = "softLivestreamPrivacyMode",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"enabled", "disabled"},
            .value_enabled = "enabled",
            .value_disabled = "disabled",
        },
    .attr_hardPrivacyMode =
        {
            .name = "hardPrivacyMode",
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
            .values = {"softRecordingPrivacyMode", "softLivestreamPrivacyMode", "hardPrivacyMode"},
            .value_softRecordingPrivacyMode = "softRecordingPrivacyMode",
            .value_softLivestreamPrivacyMode = "softLivestreamPrivacyMode",
            .value_hardPrivacyMode = "hardPrivacyMode",
        },
    .attr_supportedCommands =
        {
            .name = "supportedCommands",
            .property = ATTR_SET_VALUE_ARRAY | ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"setSoftRecordingPrivacyMode", "setSoftLivestreamPrivacyMode"},
            .value_setSoftRecordingPrivacyMode = "setSoftRecordingPrivacyMode",
            .value_setSoftLivestreamPrivacyMode = "setSoftLivestreamPrivacyMode",
        },
    .cmd_setSoftRecordingPrivacyMode = {.name = "setSoftRecordingPrivacyMode"},    // arguments: state(string)
    .cmd_setSoftLivestreamPrivacyMode = {.name = "setSoftLivestreamPrivacyMode"},  // arguments: state(string)
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_CAMERA_PRIVACY_MODE_ */
