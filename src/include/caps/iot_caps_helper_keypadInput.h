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

#ifndef _IOT_CAPS_HELPER_KEYPAD_INPUT_
#define _IOT_CAPS_HELPER_KEYPAD_INPUT_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_KEYPADINPUT_SUPPORTEDKEYCODES_VALUE_UP,
    CAP_ENUM_KEYPADINPUT_SUPPORTEDKEYCODES_VALUE_DOWN,
    CAP_ENUM_KEYPADINPUT_SUPPORTEDKEYCODES_VALUE_LEFT,
    CAP_ENUM_KEYPADINPUT_SUPPORTEDKEYCODES_VALUE_RIGHT,
    CAP_ENUM_KEYPADINPUT_SUPPORTEDKEYCODES_VALUE_SELECT,
    CAP_ENUM_KEYPADINPUT_SUPPORTEDKEYCODES_VALUE_BACK,
    CAP_ENUM_KEYPADINPUT_SUPPORTEDKEYCODES_VALUE_EXIT,
    CAP_ENUM_KEYPADINPUT_SUPPORTEDKEYCODES_VALUE_MENU,
    CAP_ENUM_KEYPADINPUT_SUPPORTEDKEYCODES_VALUE_SETTINGS,
    CAP_ENUM_KEYPADINPUT_SUPPORTEDKEYCODES_VALUE_HOME,
    CAP_ENUM_KEYPADINPUT_SUPPORTEDKEYCODES_VALUE_NUMBER0,
    CAP_ENUM_KEYPADINPUT_SUPPORTEDKEYCODES_VALUE_NUMBER1,
    CAP_ENUM_KEYPADINPUT_SUPPORTEDKEYCODES_VALUE_NUMBER2,
    CAP_ENUM_KEYPADINPUT_SUPPORTEDKEYCODES_VALUE_NUMBER3,
    CAP_ENUM_KEYPADINPUT_SUPPORTEDKEYCODES_VALUE_NUMBER4,
    CAP_ENUM_KEYPADINPUT_SUPPORTEDKEYCODES_VALUE_NUMBER5,
    CAP_ENUM_KEYPADINPUT_SUPPORTEDKEYCODES_VALUE_NUMBER6,
    CAP_ENUM_KEYPADINPUT_SUPPORTEDKEYCODES_VALUE_NUMBER7,
    CAP_ENUM_KEYPADINPUT_SUPPORTEDKEYCODES_VALUE_NUMBER8,
    CAP_ENUM_KEYPADINPUT_SUPPORTEDKEYCODES_VALUE_NUMBER9,
    CAP_ENUM_KEYPADINPUT_SUPPORTEDKEYCODES_VALUE_MAX
};

const static struct iot_caps_keypadInput {
    const char *id;
    const struct keypadInput_attr_supportedKeyCodes {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_KEYPADINPUT_SUPPORTEDKEYCODES_VALUE_MAX];
        const char *value_UP;
        const char *value_DOWN;
        const char *value_LEFT;
        const char *value_RIGHT;
        const char *value_SELECT;
        const char *value_BACK;
        const char *value_EXIT;
        const char *value_MENU;
        const char *value_SETTINGS;
        const char *value_HOME;
        const char *value_NUMBER0;
        const char *value_NUMBER1;
        const char *value_NUMBER2;
        const char *value_NUMBER3;
        const char *value_NUMBER4;
        const char *value_NUMBER5;
        const char *value_NUMBER6;
        const char *value_NUMBER7;
        const char *value_NUMBER8;
        const char *value_NUMBER9;
    } attr_supportedKeyCodes;
    const struct keypadInput_cmd_sendKey {
        const char *name;
    } cmd_sendKey;
} caps_helper_keypadInput = {
    .id = "keypadInput",
    .attr_supportedKeyCodes =
        {
            .name = "supportedKeyCodes",
            .property = ATTR_SET_VALUE_ARRAY,
            .valueType = VALUE_TYPE_STRING,
            .values = {"UP",      "DOWN",     "LEFT",    "RIGHT",   "SELECT",  "BACK",    "EXIT",
                       "MENU",    "SETTINGS", "HOME",    "NUMBER0", "NUMBER1", "NUMBER2", "NUMBER3",
                       "NUMBER4", "NUMBER5",  "NUMBER6", "NUMBER7", "NUMBER8", "NUMBER9"},
            .value_UP = "UP",
            .value_DOWN = "DOWN",
            .value_LEFT = "LEFT",
            .value_RIGHT = "RIGHT",
            .value_SELECT = "SELECT",
            .value_BACK = "BACK",
            .value_EXIT = "EXIT",
            .value_MENU = "MENU",
            .value_SETTINGS = "SETTINGS",
            .value_HOME = "HOME",
            .value_NUMBER0 = "NUMBER0",
            .value_NUMBER1 = "NUMBER1",
            .value_NUMBER2 = "NUMBER2",
            .value_NUMBER3 = "NUMBER3",
            .value_NUMBER4 = "NUMBER4",
            .value_NUMBER5 = "NUMBER5",
            .value_NUMBER6 = "NUMBER6",
            .value_NUMBER7 = "NUMBER7",
            .value_NUMBER8 = "NUMBER8",
            .value_NUMBER9 = "NUMBER9",
        },
    .cmd_sendKey = {.name = "sendKey"},  // arguments: keyCode(string)
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_KEYPAD_INPUT_ */
