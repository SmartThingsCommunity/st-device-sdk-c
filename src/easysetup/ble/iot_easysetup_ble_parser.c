/* ***************************************************************************
 *
 * Copyright (c) 2021 Samsung Electronics All Rights Reserved.
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

#include <string.h>
#include <ctype.h>
#include "easysetup_ble.h"
#include "iot_debug.h"
#include "iot_easysetup.h"

enum iot_easysetup_ble_cmd {
        IOT_EASYSETUP_BLE_CMD_DEVICEINFO = 1,   // TBD with initial value
        IOT_EASYSETUP_BLE_CMD_KEYINFO,
        IOT_EASYSETUP_BLE_CMD_CONFIRMINFO,
        IOT_EASYSETUP_BLE_CMD_CONFIRM,
        IOT_EASYSETUP_BLE_CMD_WIFISCANINFO,
        IOT_EASYSETUP_BLE_CMD_WIFIPROVIONINGINFO,
        IOT_EASYSETUP_BLE_CMD_TNC_AGREEMENTS,
        IOT_EASYSETUP_BLE_CMD_SETUPCOMPLETE,
        IOT_EASYSETUP_BLE_CMD_LOG_SYSTEMINFO,
        IOT_EASYSETUP_BLE_CMD_LOG_CREATE_DUMP,
        IOT_EASYSETUP_BLE_CMD_LOG_GET_DUMP,
        IOT_EASYSETUP_BLE_CMD_INVALID,
};

iot_error_t es_msg_parser(char *rx_buffer, size_t rx_buffer_len, uint8_t cmd_num, char **payload, int *cmd, int *type, size_t *content_len)
{
    if ((rx_buffer == NULL) || (cmd == NULL) || (type == NULL)) {
        IOT_ERROR("invalid data format!!");
        return IOT_ERROR_INVALID_ARGS;
    }

    if (cmd_num == IOT_EASYSETUP_BLE_CMD_DEVICEINFO) {
        *cmd  = IOT_EASYSETUP_STEP_DEVICEINFO;
        *type = D2D_GET;
    } else if (cmd_num == IOT_EASYSETUP_BLE_CMD_KEYINFO) {
        *cmd  = IOT_EASYSETUP_STEP_KEYINFO;
        *type = D2D_POST;
    } else if (cmd_num == IOT_EASYSETUP_BLE_CMD_CONFIRMINFO) {
        *cmd  = IOT_EASYSETUP_STEP_CONFIRMINFO;
        *type = D2D_POST;
    } else if (cmd_num == IOT_EASYSETUP_BLE_CMD_CONFIRM) {
        *cmd  = IOT_EASYSETUP_STEP_CONFIRM;
        *type = D2D_POST;
    } else if (cmd_num == IOT_EASYSETUP_BLE_CMD_WIFISCANINFO) {
        *cmd  = IOT_EASYSETUP_STEP_WIFISCANINFO;
        *type = D2D_GET;
    } else if (cmd_num == IOT_EASYSETUP_BLE_CMD_WIFIPROVIONINGINFO) {
        *cmd  = IOT_EASYSETUP_STEP_WIFIPROVIONINGINFO;
        *type = D2D_POST;
    } else if (cmd_num == IOT_EASYSETUP_BLE_CMD_TNC_AGREEMENTS) {
		/* TODO : Need to change BLE STEP */
        //*cmd  = IOT_EASYSETUP_STEP_TNC_AGREEMENTS;
        //*type = D2D_GET;
    } else if (cmd_num == IOT_EASYSETUP_BLE_CMD_SETUPCOMPLETE) {
        *cmd  = IOT_EASYSETUP_STEP_SETUPCOMPLETE;
        *type = D2D_POST;
    } else if (cmd_num == IOT_EASYSETUP_BLE_CMD_LOG_SYSTEMINFO) {
        *cmd  = IOT_EASYSETUP_STEP_LOG_SYSTEMINFO;
        *type = D2D_GET;
    } else if (cmd_num == IOT_EASYSETUP_BLE_CMD_LOG_CREATE_DUMP) {
        *cmd  = IOT_EASYSETUP_STEP_LOG_CREATE_DUMP;
        *type = D2D_POST;
    } else if (cmd_num == IOT_EASYSETUP_BLE_CMD_LOG_GET_DUMP) {
        *cmd  = IOT_EASYSETUP_STEP_LOG_GET_DUMP;
        *type = D2D_GET;
    } else {
        IOT_ERROR("Invalid step");
        *cmd  = IOT_EASYSETUP_INVALID_STEP;
        *type = D2D_ERROR;
    }

    *content_len = rx_buffer_len;
    *payload = rx_buffer;

    return IOT_ERROR_NONE;
}

