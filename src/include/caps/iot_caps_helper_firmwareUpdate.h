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

#ifndef _IOT_CAPS_HELPER_FIRMWARE_UPDATE_
#define _IOT_CAPS_HELPER_FIRMWARE_UPDATE_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_FIRMWAREUPDATE_LASTUPDATESTATUS_VALUE_UPDATESUCCEEDED,
    CAP_ENUM_FIRMWAREUPDATE_LASTUPDATESTATUS_VALUE_UPDATEFAILED,
    CAP_ENUM_FIRMWAREUPDATE_LASTUPDATESTATUS_VALUE_MAX
};

enum {
    CAP_ENUM_FIRMWAREUPDATE_STATE_VALUE_NORMALOPERATION,
    CAP_ENUM_FIRMWAREUPDATE_STATE_VALUE_UPDATEINPROGRESS,
    CAP_ENUM_FIRMWAREUPDATE_STATE_VALUE_INSUFFICIENTSTORAGE,
    CAP_ENUM_FIRMWAREUPDATE_STATE_VALUE_UPDATEREQUESTED,
    CAP_ENUM_FIRMWAREUPDATE_STATE_VALUE_MAX
};

enum {
    CAP_ENUM_FIRMWAREUPDATE_IMAGETRANSFERPROGRESS_UNIT_PERCENT,
    CAP_ENUM_FIRMWAREUPDATE_IMAGETRANSFERPROGRESS_UNIT_MAX
};

enum {
    CAP_ENUM_FIRMWAREUPDATE_SUPPORTEDCOMMANDS_VALUE_CHECKFORFIRMWAREUPDATE,
    CAP_ENUM_FIRMWAREUPDATE_SUPPORTEDCOMMANDS_VALUE_UPDATEFIRMWARE,
    CAP_ENUM_FIRMWAREUPDATE_SUPPORTEDCOMMANDS_VALUE_MAX
};

const static struct iot_caps_firmwareUpdate {
    const char *id;
    const struct firmwareUpdate_attr_lastUpdateStatus {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_FIRMWAREUPDATE_LASTUPDATESTATUS_VALUE_MAX];
        const char *value_updateSucceeded;
        const char *value_updateFailed;
    } attr_lastUpdateStatus;
    const struct firmwareUpdate_attr_state {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_FIRMWAREUPDATE_STATE_VALUE_MAX];
        const char *value_normalOperation;
        const char *value_updateInProgress;
        const char *value_insufficientStorage;
        const char *value_updateRequested;
    } attr_state;
    const struct firmwareUpdate_attr_estimatedTimeRemaining {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const int min;
    } attr_estimatedTimeRemaining;
    const struct firmwareUpdate_attr_imageTransferProgress {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *units[CAP_ENUM_FIRMWAREUPDATE_IMAGETRANSFERPROGRESS_UNIT_MAX];
        const char *unit_percent;
        const int min;
        const int max;
    } attr_imageTransferProgress;
    const struct firmwareUpdate_attr_currentVersion {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
    } attr_currentVersion;
    const struct firmwareUpdate_attr_lastUpdateTime {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
    } attr_lastUpdateTime;
    const struct firmwareUpdate_attr_availableVersion {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
    } attr_availableVersion;
    const struct firmwareUpdate_attr_lastUpdateStatusReason {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
    } attr_lastUpdateStatusReason;

    const struct firmwareUpdate_attr_updateAvailable {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
    } attr_updateAvailable;
    const struct firmwareUpdate_attr_supportedCommands {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_FIRMWAREUPDATE_SUPPORTEDCOMMANDS_VALUE_MAX];
        const char *value_checkForFirmwareUpdate;
        const char *value_updateFirmware;
    } attr_supportedCommands;
    const struct firmwareUpdate_attr_supportsProgressReports {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
    } attr_supportsProgressReports;

    const struct firmwareUpdate_cmd_checkForFirmwareUpdate {
        const char *name;
    } cmd_checkForFirmwareUpdate;
    const struct firmwareUpdate_cmd_updateFirmware {
        const char *name;
    } cmd_updateFirmware;
} caps_helper_firmwareUpdate = {
    .id = "firmwareUpdate",
    .attr_lastUpdateStatus =
        {
            .name = "lastUpdateStatus",
            .property = 0,
            .valueType = VALUE_TYPE_STRING,
            .values = {"updateSucceeded", "updateFailed"},
            .value_updateSucceeded = "updateSucceeded",
            .value_updateFailed = "updateFailed",
        },
    .attr_state =
        {
            .name = "state",
            .property = 0,
            .valueType = VALUE_TYPE_STRING,
            .values = {"normalOperation", "updateInProgress", "insufficientStorage", "updateRequested"},
            .value_normalOperation = "normalOperation",
            .value_updateInProgress = "updateInProgress",
            .value_insufficientStorage = "insufficientStorage",
            .value_updateRequested = "updateRequested",
        },
    .attr_estimatedTimeRemaining =
        {
            .name = "estimatedTimeRemaining",
            .property = ATTR_SET_VALUE_MIN,
            .valueType = VALUE_TYPE_INTEGER,
            .min = 0,
        },
    .attr_imageTransferProgress =
        {
            .name = "imageTransferProgress",
            .property = ATTR_SET_VALUE_MIN | ATTR_SET_VALUE_MAX | ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_INTEGER,
            .units = {"%"},
            .unit_percent = "%",
            .min = 0,
            .max = 100,
        },
    .attr_currentVersion =
        {
            .name = "currentVersion",
            .property = 0,
            .valueType = VALUE_TYPE_STRING,
        },
    .attr_lastUpdateTime =
        {
            .name = "lastUpdateTime",
            .property = 0,
            .valueType = VALUE_TYPE_STRING,
        },
    .attr_availableVersion =
        {
            .name = "availableVersion",
            .property = 0,
            .valueType = VALUE_TYPE_STRING,
        },
    .attr_lastUpdateStatusReason =
        {
            .name = "lastUpdateStatusReason",
            .property = 0,
            .valueType = VALUE_TYPE_STRING,
        },

    .attr_updateAvailable =
        {
            .name = "updateAvailable",
            .property = 0,
            .valueType = VALUE_TYPE_BOOLEAN,
        },
    .attr_supportedCommands =
        {
            .name = "supportedCommands",
            .property = ATTR_SET_VALUE_ARRAY,
            .valueType = VALUE_TYPE_STRING,
            .values = {"checkForFirmwareUpdate", "updateFirmware"},
            .value_checkForFirmwareUpdate = "checkForFirmwareUpdate",
            .value_updateFirmware = "updateFirmware",
        },
    .attr_supportsProgressReports =
        {
            .name = "supportsProgressReports",
            .property = 0,
            .valueType = VALUE_TYPE_BOOLEAN,
        },

    .cmd_checkForFirmwareUpdate = {.name = "checkForFirmwareUpdate"},
    .cmd_updateFirmware = {.name = "updateFirmware"},
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_FIRMWARE_UPDATE_ */
