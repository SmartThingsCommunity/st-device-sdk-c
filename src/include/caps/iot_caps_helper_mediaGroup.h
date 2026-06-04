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

#ifndef _IOT_CAPS_HELPER_MEDIA_GROUP_
#define _IOT_CAPS_HELPER_MEDIA_GROUP_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_MEDIAGROUP_GROUPROLE_VALUE_PRIMARY,
    CAP_ENUM_MEDIAGROUP_GROUPROLE_VALUE_AUXILARY,
    CAP_ENUM_MEDIAGROUP_GROUPROLE_VALUE_UNGROUPED,
    CAP_ENUM_MEDIAGROUP_GROUPROLE_VALUE_MAX
};

enum {
    CAP_ENUM_MEDIAGROUP_GROUPVOLUME_UNIT_PERCENT,
    CAP_ENUM_MEDIAGROUP_GROUPVOLUME_UNIT_MAX
};

enum {
    CAP_ENUM_MEDIAGROUP_GROUPMUTE_VALUE_MUTED,
    CAP_ENUM_MEDIAGROUP_GROUPMUTE_VALUE_UNMUTED,
    CAP_ENUM_MEDIAGROUP_GROUPMUTE_VALUE_MAX
};

const static struct iot_caps_mediaGroup {
    const char *id;
    const struct mediaGroup_attr_groupRole {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_MEDIAGROUP_GROUPROLE_VALUE_MAX];
        const char *value_primary;
        const char *value_auxilary;
        const char *value_ungrouped;
    } attr_groupRole;
    const struct mediaGroup_attr_groupPrimaryDeviceId {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const unsigned int max_length;
    } attr_groupPrimaryDeviceId;
    const struct mediaGroup_attr_groupId {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const unsigned int max_length;
    } attr_groupId;
    const struct mediaGroup_attr_groupVolume {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *units[CAP_ENUM_MEDIAGROUP_GROUPVOLUME_UNIT_MAX];
        const char *unit_percent;
        const int min;
        const int max;
    } attr_groupVolume;
    const struct mediaGroup_attr_groupMute {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_MEDIAGROUP_GROUPMUTE_VALUE_MAX];
        const char *value_muted;
        const char *value_unmuted;
    } attr_groupMute;
    const struct mediaGroup_cmd_setGroupVolume {
        const char *name;
    } cmd_setGroupVolume;
    const struct mediaGroup_cmd_groupVolumeUp {
        const char *name;
    } cmd_groupVolumeUp;
    const struct mediaGroup_cmd_groupVolumeDown {
        const char *name;
    } cmd_groupVolumeDown;
    const struct mediaGroup_cmd_setGroupMute {
        const char *name;
    } cmd_setGroupMute;
    const struct mediaGroup_cmd_muteGroup {
        const char *name;
    } cmd_muteGroup;
    const struct mediaGroup_cmd_unmuteGroup {
        const char *name;
    } cmd_unmuteGroup;
} caps_helper_mediaGroup = {
    .id = "mediaGroup",
    .attr_groupRole =
        {
            .name = "groupRole",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"primary", "auxilary", "ungrouped"},
            .value_primary = "primary",
            .value_auxilary = "auxilary",
            .value_ungrouped = "ungrouped",
        },
    .attr_groupPrimaryDeviceId =
        {
            .name = "groupPrimaryDeviceId",
            .property = ATTR_SET_VALUE_REQUIRED | ATTR_SET_MAX_LENGTH,
            .valueType = VALUE_TYPE_STRING,
            .max_length = 255,
        },
    .attr_groupId =
        {
            .name = "groupId",
            .property = ATTR_SET_VALUE_REQUIRED | ATTR_SET_MAX_LENGTH,
            .valueType = VALUE_TYPE_STRING,
            .max_length = 255,
        },
    .attr_groupVolume =
        {
            .name = "groupVolume",
            .property = ATTR_SET_VALUE_MIN | ATTR_SET_VALUE_MAX | ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_INTEGER,
            .units = {"%"},
            .unit_percent = "%",
            .min = 0,
            .max = 100,
        },
    .attr_groupMute =
        {
            .name = "groupMute",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"muted", "unmuted"},
            .value_muted = "muted",
            .value_unmuted = "unmuted",
        },
    .cmd_setGroupVolume = {.name = "setGroupVolume"},  // arguments: groupVolume(integer)
    .cmd_groupVolumeUp = {.name = "groupVolumeUp"},
    .cmd_groupVolumeDown = {.name = "groupVolumeDown"},
    .cmd_setGroupMute = {.name = "setGroupMute"},  // arguments: state(string)
    .cmd_muteGroup = {.name = "muteGroup"},
    .cmd_unmuteGroup = {.name = "unmuteGroup"},
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_MEDIA_GROUP_ */
