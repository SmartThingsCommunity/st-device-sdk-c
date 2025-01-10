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

#ifndef _EASYSETUP_BLE_H_
#define _EASYSETUP_BLE_H_

#ifdef __cplusplus
extern "C" {
#endif
#include "iot_main.h"
#include "iot_error.h"

enum cgi_type {
	D2D_GET= 0,
	D2D_POST,
	D2D_ERROR,
};

void es_ble_init(void);

void es_ble_deinit(void);

void es_ble_deinit_processing_set(bool flag);

bool es_msg_assemble(uint8_t *buf, uint32_t len);
iot_error_t es_msg_disassemble(uint8_t *buf, uint32_t len, uint8_t data_continued, int cmd);
void es_msg_dispatch(iot_security_buffer_t *buf, uint8_t buf_count, uint8_t cmd_num);
void es_reset_transferdata(void);
iot_error_t iot_easysetup_ble_ecdh_compute_shared_signature(iot_security_context_t **state,
                                    unsigned char *sec_random, unsigned char **dev_cert, unsigned char **sub_cert,
                                    unsigned char **spub_key, size_t *spub_key_len, unsigned char **signature, size_t *signature_len);
iot_error_t iot_easysetup_ble_ecdh_init(iot_security_context_t **state);
iot_error_t iot_easysetup_ble_ecdh_teardown(void **state);

/**
 * @brief            ble message handler
 * @details          This function manages onboarding message
 * @param[in]        cmd			request cmd
 * @param[in]        data_buf		transferred data from the mobile
 * @param[out]       data_buf_len   the length of transferred data
 */
void iot_easysetup_ble_msg_handler(int cmd, char* data_buf, size_t data_buf_len);

#ifdef __cplusplus
}
#endif

#endif /* _EASYSETUP_BLE_H_ */
