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

#ifndef _IOT_CAPS_HELPER_TV_CHANNEL_
#define _IOT_CAPS_HELPER_TV_CHANNEL_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

const static struct iot_caps_tvChannel {
    const char *id;
    const struct tvChannel_attr_tvChannel {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const unsigned int max_length;
    } attr_tvChannel;
    const struct tvChannel_attr_tvChannelName {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const unsigned int max_length;
    } attr_tvChannelName;
    const struct tvChannel_cmd_channelDown {
        const char *name;
    } cmd_channelDown;
    const struct tvChannel_cmd_channelUp {
        const char *name;
    } cmd_channelUp;
    const struct tvChannel_cmd_setTvChannel {
        const char *name;
    } cmd_setTvChannel;
    const struct tvChannel_cmd_setTvChannelName {
        const char *name;
    } cmd_setTvChannelName;
} caps_helper_tvChannel = {
    .id = "tvChannel",
    .attr_tvChannel =
        {
            .name = "tvChannel",
            .property = ATTR_SET_MAX_LENGTH,
            .valueType = VALUE_TYPE_STRING,
            .max_length = 255,
        },
    .attr_tvChannelName =
        {
            .name = "tvChannelName",
            .property = ATTR_SET_MAX_LENGTH,
            .valueType = VALUE_TYPE_STRING,
            .max_length = 255,
        },
    .cmd_channelDown = {.name = "channelDown"},
    .cmd_channelUp = {.name = "channelUp"},
    .cmd_setTvChannel = {.name = "setTvChannel"},          // arguments: tvChannel(string)
    .cmd_setTvChannelName = {.name = "setTvChannelName"},  // arguments: tvChannelName(string, optional)
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_TV_CHANNEL_ */
