/* ***************************************************************************
 *
 * Copyright 2021 Samsung Electronics All Rights Reserved.
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

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "esp_system.h"
#include "esp_log.h"
#include "iot_debug.h"
#include "iot_bsp_ble.h"

#define HEADER_LEN_IN_MTU          (12)
#define MAX_MTU                   (183)

typedef bool (*CharWriteCallback)(uint8_t *buf, uint32_t len);

void msg_dispatch(uint8_t *buf, uint32_t len, uint8_t cmd_num);
uint32_t iot_bsp_ble_get_mtu(void);

static void msg_state_reset(void);

enum msg_state_e{
    MSG_STATE_IDLE = 0,
    MSG_STATE_ASSEMBLE,
    MSG_STATE_DISASSEMBLE,
};

struct msg_state_t{
    enum msg_state_e state;
    bool            msg_is_completed;
    uint32_t        mtu;
    uint8_t         op_code;
    uint8_t         cmd_num;
    uint8_t         transaction_id;
    uint32_t        total_size;
    uint8_t         *data;
};

#pragma pack(1)
struct transfor_data{
    uint8_t op_code;
    uint8_t cmd_num;
    uint8_t transaction_id;
    union {
        uint32_t total_size;
        uint32_t offset;
    };
    uint16_t segment_len;
    uint8_t  segment_data[0];
};
#pragma pack()

static struct msg_state_t msg_state = {
    .state = MSG_STATE_IDLE,
    .msg_is_completed = false,
    .mtu = 0,
    .op_code = 0,
    .cmd_num = 0,
    .transaction_id = 0,
    .total_size = 0,
    .data = NULL,
};

static void msg_state_reset(void)
{
    msg_state.state = MSG_STATE_IDLE;
    msg_state.msg_is_completed = false;
    msg_state.mtu = 0;
    msg_state.op_code = 0;
    msg_state.cmd_num = 0;
    msg_state.total_size = 0;
    if (msg_state.data != NULL) {
        free(msg_state.data);
        msg_state.data = NULL;
    }
}

int recv_size = 0;

bool msg_assemble(uint8_t *buf, uint32_t len)
{
    if (NULL == buf || 0 == len) {
        return false;
    }

    struct transfor_data *data = (struct transfor_data *)buf;

    switch (msg_state.state) {
        case MSG_STATE_ASSEMBLE:
            if ((data->op_code == msg_state.op_code + 1) && (data->cmd_num == msg_state.cmd_num)
                 && (data->transaction_id == msg_state.transaction_id))
            {
                msg_state.op_code = data->op_code;
                memcpy(msg_state.data + data->offset, data->segment_data, data->segment_len);
                if (data->offset + data->segment_len >= msg_state.total_size) {
                    msg_state.msg_is_completed = true;
                }
                break;
            }
            IOT_ERROR("Not available data is transfered");
            msg_state_reset();
            break;
        case MSG_STATE_DISASSEMBLE:
            msg_state_reset();
            break;
        case MSG_STATE_IDLE:
            if ((data->op_code != 0) || ((data->transaction_id <= msg_state.transaction_id)
                    && (msg_state.transaction_id != 0)))
            {
                msg_state_reset();
                return false;
            }

            msg_state.cmd_num = data->cmd_num;
            msg_state.transaction_id = data->transaction_id;
            msg_state.mtu = iot_bsp_ble_get_mtu() - HEADER_LEN_IN_MTU;
            msg_state.total_size = data->total_size;
            msg_state.data = (uint8_t *)malloc(data->total_size);

            memcpy(msg_state.data, data->segment_data, data->segment_len);
            recv_size = data->total_size;

            if ((data->total_size <= msg_state.mtu)
             && (data->total_size == data->segment_len)) {
                msg_state.msg_is_completed = true;
            } else {
                msg_state.state = MSG_STATE_ASSEMBLE;
            }
            break;

        default:
            break;
    }

    if(msg_state.msg_is_completed == true) {
        msg_state.state = MSG_STATE_IDLE;

        msg_dispatch(msg_state.data, msg_state.total_size, msg_state.cmd_num);

        msg_state.msg_is_completed = false;
        msg_state.mtu = 0;
        msg_state.op_code = 0;
        msg_state.total_size = 0;
        if (msg_state.data != NULL) {
            free(msg_state.data);
            msg_state.data = NULL;
        }
    }

    return true;
}
int g_flg = 0;
bool msg_disassemble(uint8_t *buf, uint32_t len)
{
    uint32_t sent_len = 0;
    struct transfor_data *ind;
   
    if (NULL == buf || 0 == len) {
        return false;
    }

    if (msg_state.state != MSG_STATE_IDLE) {
        return false;
    }
    msg_state.mtu = iot_bsp_ble_get_mtu() - HEADER_LEN_IN_MTU;

    ind = (struct transfor_data *)malloc(sizeof(struct transfor_data) - 0 + msg_state.mtu);
    if(NULL == ind) {
        return false;
    }

    msg_state.state = MSG_STATE_DISASSEMBLE;

    ind->op_code        = 0;
    ind->cmd_num        = msg_state.cmd_num;
    ind->transaction_id = msg_state.transaction_id;

    while(sent_len < len) {
        if(MSG_STATE_DISASSEMBLE != msg_state.state) {
            free(ind);
            return false;
        }
        if (ind->op_code == 0) {
            ind->total_size = len;
        } else {
            ind->offset = sent_len;
        }
        ind->segment_len = (sent_len + msg_state.mtu <= len) ? msg_state.mtu : (len - sent_len);
        memcpy(ind->segment_data, buf + sent_len, ind->segment_len);

        g_flg = 0;
        iot_send_indication((uint8_t*)ind,sizeof(struct transfor_data) - 0 + ind->segment_len);
        while(g_flg == 0);
        sent_len += ind->segment_len;
        ind->op_code += 1;
    }

    msg_state.state = MSG_STATE_IDLE;
    free(ind);
    return true;
}
