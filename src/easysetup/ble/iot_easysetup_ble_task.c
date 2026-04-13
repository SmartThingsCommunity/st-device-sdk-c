/* ***************************************************************************
 *
 * Copyright 2020-2021 Samsung Electronics All Rights Reserved.
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

#include "easysetup_ble.h"
#include "iot_bsp_ble.h"
#include "iot_debug.h"
#include "iot_easysetup.h"
#include "iot_os_util.h"

#define RX_BUFFER_MAX 512

static char rx_buffer[RX_BUFFER_MAX];
static uint32_t g_write_callback_len = 0;
static uint8_t g_write_cmd_num = 0;
static void _es_ble_msg_handler(struct iot_context *ctx, device_work_param param);

extern struct iot_context *context;

void es_msg_dispatch(iot_security_buffer_t *buf, uint8_t buf_count, uint8_t cmd_num)
{
    g_write_cmd_num = cmd_num;
    g_write_callback_len = buf[0].len;
    memcpy(rx_buffer, buf[0].p, buf[0].len);
    if (buf_count > 1) {
        // Not actually used
        // If there is a use case, need to be changed rx_buffer
        // to iot_security_buffer array data structure
        IOT_ERROR("Received data is too large.");
    }
    iot_put_device_work(context, _es_ble_msg_handler, NULL);
}

static void _es_ble_msg_handler(struct iot_context *ctx, device_work_param param)
{
    size_t len = g_write_callback_len;
    int cmd = g_write_cmd_num - 1;
    rx_buffer[len] = 0;
    iot_easysetup_ble_msg_handler(cmd, rx_buffer, g_write_callback_len);
}

void es_ble_init()
{
    iot_error_t iot_err = IOT_ERROR_NONE;
    IOT_INFO("ble init!!");

    iot_err = iot_easysetup_start_ble_advertisement(context);
    if (iot_err != IOT_ERROR_NONE) {
        IOT_ERROR("Can't create ble advertise packet for easysetup.(%d)", iot_err);
    }
}

void es_ble_deinit(void)
{
    IOT_ES_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_EASYSETUP_TCP_DEINIT, 0);
    iot_bsp_ble_deinit();
    IOT_INFO("ble deinit complete!");
    IOT_ES_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_EASYSETUP_TCP_DEINIT, 1);
}
