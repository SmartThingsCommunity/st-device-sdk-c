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

#ifndef _IOT_CAPS_HELPER_STATELESS_POWER_TOGGLE_BUTTON_
#define _IOT_CAPS_HELPER_STATELESS_POWER_TOGGLE_BUTTON_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_STATELESSPOWERTOGGLEBUTTON_AVAILABLEPOWERTOGGLEBUTTONS_VALUE_POWERTOGGLE,
    CAP_ENUM_STATELESSPOWERTOGGLEBUTTON_AVAILABLEPOWERTOGGLEBUTTONS_VALUE_MAX
};

const static struct iot_caps_statelessPowerToggleButton {
    const char *id;
    const struct statelessPowerToggleButton_attr_availablePowerToggleButtons {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_STATELESSPOWERTOGGLEBUTTON_AVAILABLEPOWERTOGGLEBUTTONS_VALUE_MAX];
        const char *value_powerToggle;
    } attr_availablePowerToggleButtons;
    const struct statelessPowerToggleButton_cmd_setButton {
        const char *name;
    } cmd_setButton;
} caps_helper_statelessPowerToggleButton = {
    .id = "statelessPowerToggleButton",
    .attr_availablePowerToggleButtons =
        {
            .name = "availablePowerToggleButtons",
            .property = ATTR_SET_VALUE_ARRAY,
            .valueType = VALUE_TYPE_STRING,
            .values = {"powerToggle"},
            .value_powerToggle = "powerToggle",
        },
    .cmd_setButton = {.name = "setButton"},  // arguments: button(string)
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_STATELESS_POWER_TOGGLE_BUTTON_ */
