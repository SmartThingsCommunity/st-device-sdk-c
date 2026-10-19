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

#ifndef _IOT_CAPS_HELPER_END_TO_END_ENCRYPTION_STATE_
#define _IOT_CAPS_HELPER_END_TO_END_ENCRYPTION_STATE_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_ENDTOENDENCRYPTIONSTATE_ENABLED_VALUE_ENABLED,
    CAP_ENUM_ENDTOENDENCRYPTIONSTATE_ENABLED_VALUE_DISABLED,
    CAP_ENUM_ENDTOENDENCRYPTIONSTATE_ENABLED_VALUE_MAX
};

const static struct iot_caps_endToEndEncryptionState {
    const char *id;
    const struct endToEndEncryptionState_attr_enabled {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_ENDTOENDENCRYPTIONSTATE_ENABLED_VALUE_MAX];
        const char *value_enabled;
        const char *value_disabled;
    } attr_enabled;
    const struct endToEndEncryptionState_cmd_setEnabled {
        const char *name;
    } cmd_setEnabled;
} caps_helper_endToEndEncryptionState = {
    .id = "endToEndEncryptionState",
    .attr_enabled =
        {
            .name = "enabled",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"enabled", "disabled"},
            .value_enabled = "enabled",
            .value_disabled = "disabled",
        },
    .cmd_setEnabled = {.name = "setEnabled"},  // arguments: state(string) clientId(string)
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_END_TO_END_ENCRYPTION_STATE_ */
