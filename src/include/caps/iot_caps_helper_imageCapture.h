/* ***************************************************************************
 *
 * Copyright 2019-2021 Samsung Electronics All Rights Reserved.
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

#ifndef _IOT_CAPS_HELPER_IMAGE_CAPTURE_
#define _IOT_CAPS_HELPER_IMAGE_CAPTURE_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

const static struct iot_caps_imageCapture {
    const char *id;
    const struct imageCapture_attr_encrypted {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
    } attr_encrypted;
    const struct imageCapture_attr_image {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
    } attr_image;
    const struct imageCapture_attr_captureTime {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
    } attr_captureTime;
    const struct imageCapture_cmd_take {
        const char *name;
    } cmd_take;
    const struct imageCapture_cmd_uploadComplete {
        const char *name;
    } cmd_uploadComplete;
    const struct imageCapture_cmd_uploadFailed {
        const char *name;
    } cmd_uploadFailed;
} caps_helper_imageCapture = {
    .id = "imageCapture",
    .attr_encrypted =
        {
            .name = "encrypted",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_BOOLEAN,
        },
    .attr_image =
        {
            .name = "image",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
        },
    .attr_captureTime =
        {
            .name = "captureTime",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
        },
    .cmd_take = {.name = "take"},  // arguments: correlationId(string) reason(string)
    .cmd_uploadComplete =
        {.name =
             "uploadComplete"},  // arguments: imageId(string) mediaUrl(string) expirationTime(string) clipId(string)
    .cmd_uploadFailed = {.name = "uploadFailed"},  // arguments: imageId(string) error(object)
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_IMAGE_CAPTURE_ */
