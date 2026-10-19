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

#ifndef _IOT_CAPS_HELPER_LOCK_USERS_
#define _IOT_CAPS_HELPER_LOCK_USERS_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_LOCKUSERS_USERS_VALUE_USERTYPE_VALUE_ADMINMEMBER,
    CAP_ENUM_LOCKUSERS_USERS_VALUE_USERTYPE_VALUE_CONTROLONLYMEMBER,
    CAP_ENUM_LOCKUSERS_USERS_VALUE_USERTYPE_VALUE_GUEST,
    CAP_ENUM_LOCKUSERS_USERS_VALUE_USERTYPE_VALUE_MAX
};

enum {
    CAP_ENUM_LOCKUSERS_COMMANDRESULT_VALUE_COMMANDNAME_VALUE_ADDUSER,
    CAP_ENUM_LOCKUSERS_COMMANDRESULT_VALUE_COMMANDNAME_VALUE_UPDATEUSER,
    CAP_ENUM_LOCKUSERS_COMMANDRESULT_VALUE_COMMANDNAME_VALUE_DELETEUSER,
    CAP_ENUM_LOCKUSERS_COMMANDRESULT_VALUE_COMMANDNAME_VALUE_DELETEALLUSERS,
    CAP_ENUM_LOCKUSERS_COMMANDRESULT_VALUE_COMMANDNAME_VALUE_MAX
};

enum {
    CAP_ENUM_LOCKUSERS_COMMANDRESULT_VALUE_STATUSCODE_VALUE_SUCCESS,
    CAP_ENUM_LOCKUSERS_COMMANDRESULT_VALUE_STATUSCODE_VALUE_FAILURE,
    CAP_ENUM_LOCKUSERS_COMMANDRESULT_VALUE_STATUSCODE_VALUE_OCCUPIED,
    CAP_ENUM_LOCKUSERS_COMMANDRESULT_VALUE_STATUSCODE_VALUE_INVALIDCOMMAND,
    CAP_ENUM_LOCKUSERS_COMMANDRESULT_VALUE_STATUSCODE_VALUE_RESOURCEEXHAUSTED,
    CAP_ENUM_LOCKUSERS_COMMANDRESULT_VALUE_STATUSCODE_VALUE_BUSY,
    CAP_ENUM_LOCKUSERS_COMMANDRESULT_VALUE_STATUSCODE_VALUE_MAX
};

const static struct iot_caps_lockUsers {
    const char *id;
    const struct lockUsers_attr_users {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const struct lockUsers_users_value_userIndex {
            const char *name;
            const unsigned char property;
            const unsigned char valueType;
            const int min;
        } value_userIndex;
        const struct lockUsers_users_value_userType {
            const char *name;
            const unsigned char property;
            const unsigned char valueType;
            const char *values[CAP_ENUM_LOCKUSERS_USERS_VALUE_USERTYPE_VALUE_MAX];
            const char *value_adminMember;
            const char *value_controlOnlyMember;
            const char *value_guest;
        } value_userType;
        const struct lockUsers_users_value_userName {
            const char *name;
            const unsigned char property;
            const unsigned char valueType;
        } value_userName;
    } attr_users;
    const struct lockUsers_attr_commandResult {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const struct lockUsers_commandResult_value_commandName {
            const char *name;
            const unsigned char property;
            const unsigned char valueType;
            const char *values[CAP_ENUM_LOCKUSERS_COMMANDRESULT_VALUE_COMMANDNAME_VALUE_MAX];
            const char *value_addUser;
            const char *value_updateUser;
            const char *value_deleteUser;
            const char *value_deleteAllUsers;
        } value_commandName;
        const struct lockUsers_commandResult_value_userIndex {
            const char *name;
            const unsigned char property;
            const unsigned char valueType;
        } value_userIndex;
        const struct lockUsers_commandResult_value_statusCode {
            const char *name;
            const unsigned char property;
            const unsigned char valueType;
            const char *values[CAP_ENUM_LOCKUSERS_COMMANDRESULT_VALUE_STATUSCODE_VALUE_MAX];
            const char *value_success;
            const char *value_failure;
            const char *value_occupied;
            const char *value_invalidCommand;
            const char *value_resourceExhausted;
            const char *value_busy;
        } value_statusCode;
    } attr_commandResult;
    const struct lockUsers_attr_totalUsersSupported {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const int min;
    } attr_totalUsersSupported;
    const struct lockUsers_cmd_addUser {
        const char *name;
    } cmd_addUser;
    const struct lockUsers_cmd_updateUser {
        const char *name;
    } cmd_updateUser;
    const struct lockUsers_cmd_deleteUser {
        const char *name;
    } cmd_deleteUser;
    const struct lockUsers_cmd_deleteAllUsers {
        const char *name;
    } cmd_deleteAllUsers;
} caps_helper_lockUsers = {
    .id = "lockUsers",
    .attr_users =
        {
            .name = "users",
            .property = ATTR_SET_VALUE_ARRAY,
            .valueType = VALUE_TYPE_OBJECT,
            .value_userIndex =
                {
                    .name = "userIndex",
                    .property = ATTR_SET_VALUE_MIN | ATTR_SET_VALUE_REQUIRED,
                    .valueType = VALUE_TYPE_INTEGER,
                    .min = 1,
                },
            .value_userType =
                {
                    .name = "userType",
                    .property = ATTR_SET_VALUE_REQUIRED,
                    .valueType = VALUE_TYPE_STRING,
                    .values = {"adminMember", "controlOnlyMember", "guest"},
                    .value_adminMember = "adminMember",
                    .value_controlOnlyMember = "controlOnlyMember",
                    .value_guest = "guest",
                },
            .value_userName =
                {
                    .name = "userName",
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
                    .values = {"addUser", "updateUser", "deleteUser", "deleteAllUsers"},
                    .value_addUser = "addUser",
                    .value_updateUser = "updateUser",
                    .value_deleteUser = "deleteUser",
                    .value_deleteAllUsers = "deleteAllUsers",
                },
            .value_userIndex =
                {
                    .name = "userIndex",
                    .property = 0,
                    .valueType = VALUE_TYPE_INTEGER,
                },
            .value_statusCode =
                {
                    .name = "statusCode",
                    .property = ATTR_SET_VALUE_REQUIRED,
                    .valueType = VALUE_TYPE_STRING,
                    .values = {"success", "failure", "occupied", "invalidCommand", "resourceExhausted", "busy"},
                    .value_success = "success",
                    .value_failure = "failure",
                    .value_occupied = "occupied",
                    .value_invalidCommand = "invalidCommand",
                    .value_resourceExhausted = "resourceExhausted",
                    .value_busy = "busy",
                },
        },
    .attr_totalUsersSupported =
        {
            .name = "totalUsersSupported",
            .property = ATTR_SET_VALUE_MIN | ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_INTEGER,
            .min = 0,
        },
    .cmd_addUser = {.name = "addUser"},        // arguments: userName(string) userType(string)
    .cmd_updateUser = {.name = "updateUser"},  // arguments: userIndex(integer) userName(string) userType(string)
    .cmd_deleteUser = {.name = "deleteUser"},  // arguments: userIndex(integer)
    .cmd_deleteAllUsers = {.name = "deleteAllUsers"},
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_LOCK_USERS_ */
