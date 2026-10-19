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

#ifndef _IOT_CAPS_HELPER_LOCK_
#define _IOT_CAPS_HELPER_LOCK_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_LOCK_LOCK_VALUE_LOCKED,
    CAP_ENUM_LOCK_LOCK_VALUE_UNKNOWN,
    CAP_ENUM_LOCK_LOCK_VALUE_UNLOCKED,
    CAP_ENUM_LOCK_LOCK_VALUE_UNLOCKED_WITH_TIMEOUT,
    CAP_ENUM_LOCK_LOCK_VALUE_NOT_FULLY_LOCKED,
    CAP_ENUM_LOCK_LOCK_VALUE_UNLATCHED,
    CAP_ENUM_LOCK_LOCK_VALUE_MAX
};

#define CAP_ENUM_LOCK_SUPPORTEDLOCKVALUES_VALUE_MAX CAP_ENUM_LOCK_LOCK_VALUE_MAX
enum {
    CAP_ENUM_LOCK_SUPPORTEDLOCKCOMMANDS_VALUE_LOCK,
    CAP_ENUM_LOCK_SUPPORTEDLOCKCOMMANDS_VALUE_UNLOCK,
    CAP_ENUM_LOCK_SUPPORTEDLOCKCOMMANDS_VALUE_UNLATCH,
    CAP_ENUM_LOCK_SUPPORTEDLOCKCOMMANDS_VALUE_MAX
};

enum {
    CAP_ENUM_LOCK_SUPPORTEDUNLOCKDIRECTIONS_VALUE_FROMINSIDE,
    CAP_ENUM_LOCK_SUPPORTEDUNLOCKDIRECTIONS_VALUE_FROMOUTSIDE,
    CAP_ENUM_LOCK_SUPPORTEDUNLOCKDIRECTIONS_VALUE_MAX
};

enum {
    CAP_ENUM_LOCK_LOCK_DATA_METHOD_VALUE_MANUAL,
    CAP_ENUM_LOCK_LOCK_DATA_METHOD_VALUE_KEYPAD,
    CAP_ENUM_LOCK_LOCK_DATA_METHOD_VALUE_AUTO,
    CAP_ENUM_LOCK_LOCK_DATA_METHOD_VALUE_COMMAND,
    CAP_ENUM_LOCK_LOCK_DATA_METHOD_VALUE_RFID,
    CAP_ENUM_LOCK_LOCK_DATA_METHOD_VALUE_FINGERPRINT,
    CAP_ENUM_LOCK_LOCK_DATA_METHOD_VALUE_BLUETOOTH,
    CAP_ENUM_LOCK_LOCK_DATA_METHOD_VALUE_PROPRIETARYREMOTE,
    CAP_ENUM_LOCK_LOCK_DATA_METHOD_VALUE_BUTTON,
    CAP_ENUM_LOCK_LOCK_DATA_METHOD_VALUE_DIGITALKEY,
    CAP_ENUM_LOCK_LOCK_DATA_METHOD_VALUE_FACE,
    CAP_ENUM_LOCK_LOCK_DATA_METHOD_VALUE_VEIN,
    CAP_ENUM_LOCK_LOCK_DATA_METHOD_VALUE_OTP,
    CAP_ENUM_LOCK_LOCK_DATA_METHOD_VALUE_MAX
};

enum {
    CAP_ENUM_LOCK_LOCK_DATA_USERTYPE_VALUE_ADMINMEMBER,
    CAP_ENUM_LOCK_LOCK_DATA_USERTYPE_VALUE_CONTROLONLYMEMBER,
    CAP_ENUM_LOCK_LOCK_DATA_USERTYPE_VALUE_GUEST,
    CAP_ENUM_LOCK_LOCK_DATA_USERTYPE_VALUE_MAX
};

#define CAP_ENUM_LOCK_LOCK_DATA_UNLOCKDIRECTION_VALUE_MAX CAP_ENUM_LOCK_SUPPORTEDUNLOCKDIRECTIONS_VALUE_MAX
const static struct iot_caps_lock {
    const char *id;
    const struct lock_attr_supportedLockCommands {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_LOCK_SUPPORTEDLOCKCOMMANDS_VALUE_MAX];
        const char *value_lock;
        const char *value_unlock;
        const char *value_unlatch;
    } attr_supportedLockCommands;
    const struct lock_attr_supportedLockValues {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_LOCK_SUPPORTEDLOCKVALUES_VALUE_MAX];
        const char *value_locked;
        const char *value_unknown;
        const char *value_unlocked;
        const char *value_unlocked_with_timeout;
        const char *value_not_fully_locked;
        const char *value_unlatched;
    } attr_supportedLockValues;
    const struct lock_attr_supportedUnlockDirections {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_LOCK_SUPPORTEDUNLOCKDIRECTIONS_VALUE_MAX];
        const char *value_fromInside;
        const char *value_fromOutside;
    } attr_supportedUnlockDirections;
    const struct lock_attr_lock {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_LOCK_LOCK_VALUE_MAX];
        const char *value_locked;
        const char *value_unknown;
        const char *value_unlocked;
        const char *value_unlocked_with_timeout;
        const char *value_not_fully_locked;
        const char *value_unlatched;
        const struct lock_attr_lock_data {
            const char *name;
            const unsigned char property;
            const unsigned char valueType;
            const struct lock_attr_lock_data_method {
                const char *name;
                const unsigned char property;
                const unsigned char valueType;
                const char *values[CAP_ENUM_LOCK_LOCK_DATA_METHOD_VALUE_MAX];
                const char *value_manual;
                const char *value_keypad;
                const char *value_auto;
                const char *value_command;
                const char *value_rfid;
                const char *value_fingerprint;
                const char *value_bluetooth;
                const char *value_proprietaryRemote;
                const char *value_button;
                const char *value_digitalKey;
                const char *value_face;
                const char *value_vein;
                const char *value_otp;
            } method;
            const struct lock_attr_lock_data_codeId {
                const char *name;
                const unsigned char property;
                const unsigned char valueType;
            } codeId;
            const struct lock_attr_lock_data_codeName {
                const char *name;
                const unsigned char property;
                const unsigned char valueType;
            } codeName;
            const struct lock_attr_lock_data_userIndex {
                const char *name;
                const unsigned char property;
                const unsigned char valueType;
            } userIndex;
            const struct lock_attr_lock_data_userName {
                const char *name;
                const unsigned char property;
                const unsigned char valueType;
            } userName;
            const struct lock_attr_lock_data_userType {
                const char *name;
                const unsigned char property;
                const unsigned char valueType;
                const char *values[CAP_ENUM_LOCK_LOCK_DATA_USERTYPE_VALUE_MAX];
                const char *value_adminMember;
                const char *value_controlOnlyMember;
                const char *value_guest;
            } userType;
            const struct lock_attr_lock_data_timeout {
                const char *name;
                const unsigned char property;
                const unsigned char valueType;
            } timeout;
            const struct lock_attr_lock_data_unlockDirection {
                const char *name;
                const unsigned char property;
                const unsigned char valueType;
                const char *values[CAP_ENUM_LOCK_LOCK_DATA_UNLOCKDIRECTION_VALUE_MAX];
                const char *value_fromInside;
                const char *value_fromOutside;
            } unlockDirection;
        } data;
    } attr_lock;
    const struct lock_cmd_lock {
        const char *name;
    } cmd_lock;
    const struct lock_cmd_unlock {
        const char *name;
    } cmd_unlock;
    const struct lock_cmd_unlatch {
        const char *name;
    } cmd_unlatch;
} caps_helper_lock = {
    .id = "lock",
    .attr_supportedLockCommands =
        {
            .name = "supportedLockCommands",
            .property = ATTR_SET_VALUE_ARRAY,
            .valueType = VALUE_TYPE_STRING,
            .values = {"lock", "unlock", "unlatch"},
            .value_lock = "lock",
            .value_unlock = "unlock",
            .value_unlatch = "unlatch",
        },
    .attr_supportedLockValues =
        {
            .name = "supportedLockValues",
            .property = ATTR_SET_VALUE_ARRAY,
            .valueType = VALUE_TYPE_STRING,
            .values = {"locked", "unknown", "unlocked", "unlocked with timeout", "not fully locked", "unlatched"},
            .value_locked = "locked",
            .value_unknown = "unknown",
            .value_unlocked = "unlocked",
            .value_unlocked_with_timeout = "unlocked with timeout",
            .value_not_fully_locked = "not fully locked",
            .value_unlatched = "unlatched",
        },
    .attr_supportedUnlockDirections =
        {
            .name = "supportedUnlockDirections",
            .property = ATTR_SET_VALUE_ARRAY,
            .valueType = VALUE_TYPE_STRING,
            .values = {"fromInside", "fromOutside"},
            .value_fromInside = "fromInside",
            .value_fromOutside = "fromOutside",
        },
    .attr_lock =
        {
            .name = "lock",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"locked", "unknown", "unlocked", "unlocked with timeout", "not fully locked", "unlatched"},
            .value_locked = "locked",
            .value_unknown = "unknown",
            .value_unlocked = "unlocked",
            .value_unlocked_with_timeout = "unlocked with timeout",
            .value_not_fully_locked = "not fully locked",
            .value_unlatched = "unlatched",
            .data =
                {
                    .name = "data",
                    .property = 0,
                    .valueType = VALUE_TYPE_OBJECT,
                    .method =
                        {
                            .name = "method",
                            .property = 0,
                            .valueType = VALUE_TYPE_STRING,
                            .values = {"manual", "keypad", "auto", "command", "rfid", "fingerprint", "bluetooth",
                                       "proprietaryRemote", "button", "digitalKey", "face", "vein", "otp"},
                            .value_manual = "manual",
                            .value_keypad = "keypad",
                            .value_auto = "auto",
                            .value_command = "command",
                            .value_rfid = "rfid",
                            .value_fingerprint = "fingerprint",
                            .value_bluetooth = "bluetooth",
                            .value_proprietaryRemote = "proprietaryRemote",
                            .value_button = "button",
                            .value_digitalKey = "digitalKey",
                            .value_face = "face",
                            .value_vein = "vein",
                            .value_otp = "otp",
                        },
                    .codeId =
                        {
                            .name = "codeId",
                            .property = 0,
                            .valueType = VALUE_TYPE_STRING,
                        },
                    .codeName =
                        {
                            .name = "codeName",
                            .property = 0,
                            .valueType = VALUE_TYPE_STRING,
                        },
                    .userIndex =
                        {
                            .name = "userIndex",
                            .property = 0,
                            .valueType = VALUE_TYPE_INTEGER,
                        },
                    .userName =
                        {
                            .name = "userName",
                            .property = 0,
                            .valueType = VALUE_TYPE_STRING,
                        },
                    .userType =
                        {
                            .name = "userType",
                            .property = 0,
                            .valueType = VALUE_TYPE_STRING,
                            .values = {"adminMember", "controlOnlyMember", "guest"},
                            .value_adminMember = "adminMember",
                            .value_controlOnlyMember = "controlOnlyMember",
                            .value_guest = "guest",
                        },
                    .timeout =
                        {
                            .name = "timeout",
                            .property = 0,
                            .valueType = VALUE_TYPE_STRING,
                        },
                    .unlockDirection =
                        {
                            .name = "unlockDirection",
                            .property = 0,
                            .valueType = VALUE_TYPE_STRING,
                            .values = {"fromInside", "fromOutside"},
                            .value_fromInside = "fromInside",
                            .value_fromOutside = "fromOutside",
                        },
                },
        },
    .cmd_lock = {.name = "lock"},
    .cmd_unlock = {.name = "unlock"},
    .cmd_unlatch = {.name = "unlatch"},
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_LOCK_ */
