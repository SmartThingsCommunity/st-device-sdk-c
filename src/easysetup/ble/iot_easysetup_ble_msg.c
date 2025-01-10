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
#include "easysetup_ble.h"
#include "iot_debug.h"
#include "iot_bsp_ble.h"

#define HEADER_LEN_IN_MTU          (12)
#define MAX_MTU                   (183)

enum msg_state_e{
    MSG_STATE_IDLE = 0,
    MSG_STATE_ASSEMBLE,
    MSG_STATE_DISASSEMBLE,
};

struct msg_state_t{
    enum msg_state_e state;
    bool                    msg_is_completed;
    uint32_t                mtu;
    uint8_t                 op_code;
    uint8_t                 cmd_num;
    uint8_t                 transaction_id;
    uint32_t                total_size;
    uint8_t                 data_continued;
    uint8_t                 data_count;
    iot_security_buffer_t   *data;
    uint8_t                 data_idx;
};

#pragma pack(1)
struct transfor_data{
    uint8_t op_code;
    uint8_t cmd_num;
    uint8_t transaction_id;
    union {
        uint8_t total_size[3];
        uint8_t offset[3];
    };
    union {
        uint8_t chunk_data_continued;
        uint8_t segmented_data_continued;
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
    .data_continued = 0,
    .data_count = 0,
    .total_size = 0,
    .data = NULL,
    .data_idx = 0,
};

static void _es_msg_state_reset(void)
{
    int idx;

    msg_state.state = MSG_STATE_IDLE;
    msg_state.msg_is_completed = false;
    msg_state.mtu = 0;
    msg_state.op_code = 0;
    msg_state.total_size = 0;
    msg_state.data_continued = 0;
    if (msg_state.data != NULL) {
        for (idx = 0; idx<msg_state.data_count; idx++) {
            if (msg_state.data[idx].p != NULL)
                iot_os_free(msg_state.data[idx].p);
        }
        iot_os_free(msg_state.data);
        msg_state.data = NULL;
    }
    msg_state.data_count = 0;
    msg_state.data_idx = 0;
}

void es_reset_transferdata(void) {
    msg_state.transaction_id = 0;
    _es_msg_state_reset();
}

bool es_msg_assemble(uint8_t *buf, uint32_t len)
{
    if (NULL == buf || 0 == len) {
        return false;
    }

    struct transfor_data *data = (struct transfor_data *)buf;
    uint32_t total_size, offset;
    bool duplicated_cmd = false;

    total_size  = data->total_size[0];
    total_size += data->total_size[1] << 8;
    total_size += data->total_size[2] << 16;
    offset = total_size;

    IOT_INFO("op_code : %d, cmd_num : %d, transaction_id : %d, chunk_data_continued : %d, total_size : %d",
        data->op_code, data->cmd_num, data->transaction_id, data->chunk_data_continued, total_size);

    switch (msg_state.state) {
        case MSG_STATE_ASSEMBLE:
            if ((data->op_code == msg_state.op_code + 1) && (data->cmd_num == msg_state.cmd_num)
                 && (data->transaction_id == msg_state.transaction_id))
            {
                msg_state.op_code = data->op_code;
                memcpy(msg_state.data[msg_state.data_idx].p + offset, data->segment_data, data->segment_len);
                if (offset + data->segment_len >= msg_state.data[msg_state.data_idx].len) {
                    msg_state.msg_is_completed = true;
                }
                break;
            }
            IOT_ERROR("Not available data is transfered");
            _es_msg_state_reset();
            break;
        case MSG_STATE_DISASSEMBLE:
            IOT_INFO("MSG_STATE_DISASSEMBLE");
            _es_msg_state_reset();
            break;
        case MSG_STATE_IDLE:
            if ((data->op_code != 0) || ((data->transaction_id <= msg_state.transaction_id)
                    && (msg_state.transaction_id != 0)))
            {
                IOT_ERROR("op_code : %d, transaction_id : %d, msg_state.transaction_id : %d",
                    data->op_code, data->transaction_id, msg_state.transaction_id);
                _es_msg_state_reset();
                return false;
            }

            if (msg_state.data == NULL) {
                msg_state.mtu = iot_bsp_ble_get_mtu() - HEADER_LEN_IN_MTU;
                msg_state.data_count = data->chunk_data_continued + 1;
                msg_state.data = (iot_security_buffer_t *)iot_os_malloc(sizeof(iot_security_buffer_t) * msg_state.data_count);
                if(msg_state.data == NULL) {
                    IOT_ERROR("memory alloc fail for msg_state data array");
                    _es_msg_state_reset();
                    return false;
                }
                memset(msg_state.data, 0, sizeof(iot_security_buffer_t) * msg_state.data_count);
            }

            duplicated_cmd = (msg_state.cmd_num != 0 && msg_state.cmd_num == data->cmd_num) ? true : false;

            msg_state.op_code = data->op_code;
            msg_state.cmd_num = data->cmd_num;
            msg_state.transaction_id = data->transaction_id;
            msg_state.data_continued = data->chunk_data_continued;
            msg_state.data_idx = msg_state.data_count - msg_state.data_continued - 1;
            msg_state.data[msg_state.data_idx].p = (uint8_t *)iot_os_malloc(total_size);
            if(total_size != 0 && msg_state.data[msg_state.data_idx].p == NULL) {
                IOT_ERROR("memory alloc fail for msg_state data buffer");
                _es_msg_state_reset();
                return false;
            }
            msg_state.data[msg_state.data_idx].len = total_size;
            msg_state.total_size += total_size;

            IOT_INFO("msg command num[%d]", data->cmd_num);

			if (msg_state.data[msg_state.data_idx].p)
	            memcpy(msg_state.data[msg_state.data_idx].p, data->segment_data, data->segment_len);

            if ((total_size <= msg_state.mtu)
             && (total_size == data->segment_len)) {
                IOT_INFO("msg transfer is completed");
                msg_state.msg_is_completed = true;
            } else {
                msg_state.state = MSG_STATE_ASSEMBLE;
            }
            break;

        default:
            break;
    }

    if(msg_state.msg_is_completed == true) {
        if (msg_state.data_continued) {
            msg_state.state = MSG_STATE_IDLE;
            msg_state.msg_is_completed = false;
        } else {
            if (!duplicated_cmd) {
                IOT_INFO("es_msg_dispatch is called");
                es_msg_dispatch(msg_state.data, msg_state.data_count, msg_state.cmd_num);
            } else {
                IOT_INFO("skip msg_dispatch - duplicated cmd[%d]", msg_state.cmd_num);
            }
            _es_msg_state_reset();
        }
    }

    return true;
}

iot_error_t es_msg_disassemble(uint8_t *buf, uint32_t len, uint8_t data_continued, int cmd)
{
    uint32_t sent_len = 0;
    struct transfor_data *ind;
    int ind_ret = 0;

    if (NULL == buf || 0 == len) {
        IOT_ERROR("transferred request data is NULL");
        return IOT_ERROR_BAD_REQ;
    }

    if (cmd - 1 != IOT_EASYSETUP_BLE_STEP_SETUPCOMPLETE_RESPONSE && cmd != msg_state.cmd_num) {
        IOT_INFO("cmd[%d] was deprecated. (%d)", cmd, msg_state.cmd_num);
        return IOT_ERROR_NONE;
    }

    if (msg_state.state != MSG_STATE_IDLE) {
        IOT_ERROR("state isn't available to send the message[%d]", msg_state.state);
        return IOT_ERROR_BAD_REQ;
    }
    msg_state.mtu = iot_bsp_ble_get_mtu() - HEADER_LEN_IN_MTU;

    ind = (struct transfor_data *)malloc(sizeof(struct transfor_data) - 0 + msg_state.mtu);
    if(NULL == ind) {
        IOT_ERROR("memory alloc fail for indication");
        return IOT_ERROR_MEM_ALLOC;
    }

    msg_state.state = MSG_STATE_DISASSEMBLE;

    ind->op_code        = 0;
    ind->cmd_num        = msg_state.cmd_num;
    ind->transaction_id = msg_state.transaction_id;

    while(sent_len < len) {
        if (ind->op_code == 0) {
            ind->total_size[0] = (uint8_t)(len & 0x000000ff);
            ind->total_size[1] = (uint8_t)((len & 0x0000ff00) >> 8);
            ind->total_size[2] = (uint8_t)((len & 0x00ff0000) >> 16);
            ind->chunk_data_continued = data_continued;
        } else {
            ind->offset[0] = (uint8_t)(sent_len & 0x000000ff);
            ind->offset[1] = (uint8_t)((sent_len & 0x0000ff00) >> 8);
            ind->offset[2] = (uint8_t)((sent_len & 0x00ff0000) >> 16);
            ind->segmented_data_continued = (int)(len/msg_state.mtu) - ind->op_code;
        }
        ind->segment_len = (sent_len + msg_state.mtu <= len) ? msg_state.mtu : (len - sent_len);
        memcpy(ind->segment_data, buf + sent_len, ind->segment_len);

        IOT_INFO("Send [%d] [%d] / [%d]", data_continued, sent_len, len);
        ind_ret = iot_send_indication((uint8_t*)ind,sizeof(struct transfor_data) - 0 + ind->segment_len);
        if (ind_ret)
            break;
        sent_len += ind->segment_len;
        ind->op_code += 1;
    }

    msg_state.state = MSG_STATE_IDLE;
    msg_state.cmd_num = 0;
    free(ind);
    if (ind_ret)
        return IOT_ERROR_CONN_BLE_INDICATION_FAIL;
    IOT_INFO("send complete");
    return IOT_ERROR_NONE;
}
