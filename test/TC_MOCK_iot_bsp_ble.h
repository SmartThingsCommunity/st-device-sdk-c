/* ***************************************************************************
 *
 * Copyright (c) 2026 Samsung Electronics All Rights Reserved.
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
#ifndef ST_DEVICE_SDK_C_TC_MOCK_IOT_BSP_BLE_H
#define ST_DEVICE_SDK_C_TC_MOCK_IOT_BSP_BLE_H

#include <stdint.h>

struct iot_context;
struct iot_easysetup_payload;

void tc_mock_ble_reset(void);
void tc_mock_ble_set_mtu(uint32_t mtu);
void tc_mock_ble_set_send_indication_rc(int rc);
int tc_mock_ble_get_send_indication_call_count(void);
uint32_t tc_mock_ble_get_send_indication_last_len(void);
int tc_mock_ble_get_es_msg_dispatch_call_count(void);
uint8_t tc_mock_ble_get_es_msg_dispatch_last_cmd_num(void);
uint8_t tc_mock_ble_get_es_msg_dispatch_last_buf_count(void);
void tc_mock_ble_set_es_msg_dispatch_use_wrap(int use);
void tc_mock_ble_set_get_certificate_rc(int rc);
void tc_mock_ble_set_get_certificate_use_wrap(int use);
void tc_mock_ble_set_get_response_step(int step);
void tc_mock_ble_set_get_response_use_wrap(int use);
void tc_mock_ble_set_get_response_err(int err);
void tc_mock_ble_set_get_response_return_null(int null);
int tc_mock_ble_get_get_response_call_count(void);
int tc_mock_ble_get_get_response_last_step(void);
void tc_mock_ble_set_start_adv_rc(int rc);
int tc_mock_ble_get_start_adv_call_count(void);
int tc_mock_ble_get_bsp_ble_deinit_call_count(void);

#endif  // ST_DEVICE_SDK_C_TC_MOCK_IOT_BSP_BLE_H
