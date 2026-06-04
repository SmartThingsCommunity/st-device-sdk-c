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

#ifndef _IOT_CAPS_HELPER_LOCK_CREDENTIALS_
#define _IOT_CAPS_HELPER_LOCK_CREDENTIALS_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_LOCKCREDENTIALS_CREDENTIALS_VALUE_CREDENTIALTYPE_VALUE_PIN,
    CAP_ENUM_LOCKCREDENTIALS_CREDENTIALS_VALUE_CREDENTIALTYPE_VALUE_RFID,
    CAP_ENUM_LOCKCREDENTIALS_CREDENTIALS_VALUE_CREDENTIALTYPE_VALUE_FINGERPRINT,
    CAP_ENUM_LOCKCREDENTIALS_CREDENTIALS_VALUE_CREDENTIALTYPE_VALUE_FINGERVEIN,
    CAP_ENUM_LOCKCREDENTIALS_CREDENTIALS_VALUE_CREDENTIALTYPE_VALUE_FACE,
    CAP_ENUM_LOCKCREDENTIALS_CREDENTIALS_VALUE_CREDENTIALTYPE_VALUE_MAX
};

#define CAP_ENUM_LOCKCREDENTIALS_SUPPORTEDCREDENTIALS_VALUE_MAX \
    CAP_ENUM_LOCKCREDENTIALS_CREDENTIALS_VALUE_CREDENTIALTYPE_VALUE_MAX
enum {
    CAP_ENUM_LOCKCREDENTIALS_COMMANDRESULT_VALUE_COMMANDNAME_VALUE_ADDCREDENTIAL,
    CAP_ENUM_LOCKCREDENTIALS_COMMANDRESULT_VALUE_COMMANDNAME_VALUE_UPDATECREDENTIAL,
    CAP_ENUM_LOCKCREDENTIALS_COMMANDRESULT_VALUE_COMMANDNAME_VALUE_DELETECREDENTIAL,
    CAP_ENUM_LOCKCREDENTIALS_COMMANDRESULT_VALUE_COMMANDNAME_VALUE_DELETEALLCREDENTIALS,
    CAP_ENUM_LOCKCREDENTIALS_COMMANDRESULT_VALUE_COMMANDNAME_VALUE_MAX
};

enum {
    CAP_ENUM_LOCKCREDENTIALS_COMMANDRESULT_VALUE_STATUSCODE_VALUE_SUCCESS,
    CAP_ENUM_LOCKCREDENTIALS_COMMANDRESULT_VALUE_STATUSCODE_VALUE_FAILURE,
    CAP_ENUM_LOCKCREDENTIALS_COMMANDRESULT_VALUE_STATUSCODE_VALUE_OCCUPIED,
    CAP_ENUM_LOCKCREDENTIALS_COMMANDRESULT_VALUE_STATUSCODE_VALUE_DUPLICATE,
    CAP_ENUM_LOCKCREDENTIALS_COMMANDRESULT_VALUE_STATUSCODE_VALUE_RESOURCEEXHAUSTED,
    CAP_ENUM_LOCKCREDENTIALS_COMMANDRESULT_VALUE_STATUSCODE_VALUE_INVALIDCOMMAND,
    CAP_ENUM_LOCKCREDENTIALS_COMMANDRESULT_VALUE_STATUSCODE_VALUE_BUSY,
    CAP_ENUM_LOCKCREDENTIALS_COMMANDRESULT_VALUE_STATUSCODE_VALUE_MAX
};

const static struct iot_caps_lockCredentials {
    const char *id;
    const struct lockCredentials_attr_credentials {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const struct lockCredentials_credentials_value_userIndex {
            const char *name;
            const unsigned char property;
            const unsigned char valueType;
            const int min;
        } value_userIndex;
        const struct lockCredentials_credentials_value_credentialIndex {
            const char *name;
            const unsigned char property;
            const unsigned char valueType;
            const int min;
        } value_credentialIndex;
        const struct lockCredentials_credentials_value_credentialType {
            const char *name;
            const unsigned char property;
            const unsigned char valueType;
            const char *values[CAP_ENUM_LOCKCREDENTIALS_CREDENTIALS_VALUE_CREDENTIALTYPE_VALUE_MAX];
            const char *value_pin;
            const char *value_rfid;
            const char *value_fingerprint;
            const char *value_fingervein;
            const char *value_face;
        } value_credentialType;
        const struct lockCredentials_credentials_value_credentialName {
            const char *name;
            const unsigned char property;
            const unsigned char valueType;
        } value_credentialName;
    } attr_credentials;
    const struct lockCredentials_attr_commandResult {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const struct lockCredentials_commandResult_value_commandName {
            const char *name;
            const unsigned char property;
            const unsigned char valueType;
            const char *values[CAP_ENUM_LOCKCREDENTIALS_COMMANDRESULT_VALUE_COMMANDNAME_VALUE_MAX];
            const char *value_addCredential;
            const char *value_updateCredential;
            const char *value_deleteCredential;
            const char *value_deleteAllCredentials;
        } value_commandName;
        const struct lockCredentials_commandResult_value_userIndex {
            const char *name;
            const unsigned char property;
            const unsigned char valueType;
            const int min;
        } value_userIndex;
        const struct lockCredentials_commandResult_value_credentialIndex {
            const char *name;
            const unsigned char property;
            const unsigned char valueType;
            const int min;
        } value_credentialIndex;
        const struct lockCredentials_commandResult_value_statusCode {
            const char *name;
            const unsigned char property;
            const unsigned char valueType;
            const char *values[CAP_ENUM_LOCKCREDENTIALS_COMMANDRESULT_VALUE_STATUSCODE_VALUE_MAX];
            const char *value_success;
            const char *value_failure;
            const char *value_occupied;
            const char *value_duplicate;
            const char *value_resourceExhausted;
            const char *value_invalidCommand;
            const char *value_busy;
        } value_statusCode;
    } attr_commandResult;
    const struct lockCredentials_attr_supportedCredentials {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_LOCKCREDENTIALS_SUPPORTEDCREDENTIALS_VALUE_MAX];
        const char *value_pin;
        const char *value_rfid;
        const char *value_fingerprint;
        const char *value_fingervein;
        const char *value_face;
    } attr_supportedCredentials;
    const struct lockCredentials_attr_pinUsersSupported {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const int min;
    } attr_pinUsersSupported;
    const struct lockCredentials_attr_minPinCodeLen {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const int min;
    } attr_minPinCodeLen;
    const struct lockCredentials_attr_maxPinCodeLen {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const int min;
    } attr_maxPinCodeLen;
    const struct lockCredentials_cmd_addCredential {
        const char *name;
    } cmd_addCredential;
    const struct lockCredentials_cmd_updateCredential {
        const char *name;
    } cmd_updateCredential;
    const struct lockCredentials_cmd_deleteCredential {
        const char *name;
    } cmd_deleteCredential;
    const struct lockCredentials_cmd_deleteAllCredentials {
        const char *name;
    } cmd_deleteAllCredentials;
} caps_helper_lockCredentials = {
    .id = "lockCredentials",
    .attr_credentials =
        {
            .name = "credentials",
            .property = ATTR_SET_VALUE_ARRAY,
            .valueType = VALUE_TYPE_OBJECT,
            .value_userIndex =
                {
                    .name = "userIndex",
                    .property = ATTR_SET_VALUE_MIN | ATTR_SET_VALUE_REQUIRED,
                    .valueType = VALUE_TYPE_INTEGER,
                    .min = 1,
                },
            .value_credentialIndex =
                {
                    .name = "credentialIndex",
                    .property = ATTR_SET_VALUE_MIN | ATTR_SET_VALUE_REQUIRED,
                    .valueType = VALUE_TYPE_INTEGER,
                    .min = 0,
                },
            .value_credentialType =
                {
                    .name = "credentialType",
                    .property = ATTR_SET_VALUE_REQUIRED,
                    .valueType = VALUE_TYPE_STRING,
                    .values = {"pin", "rfid", "fingerprint", "fingervein", "face"},
                    .value_pin = "pin",
                    .value_rfid = "rfid",
                    .value_fingerprint = "fingerprint",
                    .value_fingervein = "fingervein",
                    .value_face = "face",
                },
            .value_credentialName =
                {
                    .name = "credentialName",
                    .property = 0,
                    .valueType = VALUE_TYPE_STRING,
                },
        },
    .attr_commandResult =
        {
            .name = "commandResult",
            .property = 0,
            .valueType = VALUE_TYPE_OBJECT,
            .value_commandName =
                {
                    .name = "commandName",
                    .property = ATTR_SET_VALUE_REQUIRED,
                    .valueType = VALUE_TYPE_STRING,
                    .values = {"addCredential", "updateCredential", "deleteCredential", "deleteAllCredentials"},
                    .value_addCredential = "addCredential",
                    .value_updateCredential = "updateCredential",
                    .value_deleteCredential = "deleteCredential",
                    .value_deleteAllCredentials = "deleteAllCredentials",
                },
            .value_userIndex =
                {
                    .name = "userIndex",
                    .property = ATTR_SET_VALUE_MIN,
                    .valueType = VALUE_TYPE_INTEGER,
                    .min = 1,
                },
            .value_credentialIndex =
                {
                    .name = "credentialIndex",
                    .property = ATTR_SET_VALUE_MIN,
                    .valueType = VALUE_TYPE_INTEGER,
                    .min = 0,
                },
            .value_statusCode =
                {
                    .name = "statusCode",
                    .property = ATTR_SET_VALUE_REQUIRED,
                    .valueType = VALUE_TYPE_STRING,
                    .values = {"success", "failure", "occupied", "duplicate", "resourceExhausted", "invalidCommand",
                               "busy"},
                    .value_success = "success",
                    .value_failure = "failure",
                    .value_occupied = "occupied",
                    .value_duplicate = "duplicate",
                    .value_resourceExhausted = "resourceExhausted",
                    .value_invalidCommand = "invalidCommand",
                    .value_busy = "busy",
                },
        },
    .attr_supportedCredentials =
        {
            .name = "supportedCredentials",
            .property = ATTR_SET_VALUE_ARRAY | ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"pin", "rfid", "fingerprint", "fingervein", "face"},
            .value_pin = "pin",
            .value_rfid = "rfid",
            .value_fingerprint = "fingerprint",
            .value_fingervein = "fingervein",
            .value_face = "face",
        },
    .attr_pinUsersSupported =
        {
            .name = "pinUsersSupported",
            .property = ATTR_SET_VALUE_MIN | ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_INTEGER,
            .min = 0,
        },
    .attr_minPinCodeLen =
        {
            .name = "minPinCodeLen",
            .property = ATTR_SET_VALUE_MIN | ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_INTEGER,
            .min = 0,
        },
    .attr_maxPinCodeLen =
        {
            .name = "maxPinCodeLen",
            .property = ATTR_SET_VALUE_MIN | ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_INTEGER,
            .min = 0,
        },
    .cmd_addCredential = {.name = "addCredential"},        // arguments: userIndex(integer) userType(string)
    .cmd_updateCredential = {.name = "updateCredential"},  // arguments: userIndex(integer) credentialIndex(integer)
    .cmd_deleteCredential = {.name = "deleteCredential"},  // arguments: credentialIndex(integer) credentialType(string)
    .cmd_deleteAllCredentials = {.name = "deleteAllCredentials"},  // arguments: credentialType(string)
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_LOCK_CREDENTIALS_ */
