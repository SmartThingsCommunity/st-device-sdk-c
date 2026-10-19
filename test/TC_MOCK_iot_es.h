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

#ifndef ST_DEVICE_SDK_C_TC_MOCK_IOT_ES_H
#define ST_DEVICE_SDK_C_TC_MOCK_IOT_ES_H

#include "iot_error.h"

/* use_wrap = 0 (default) delegates to __real_iot_es_connect so the existing
 * iot_easysetup_st_mqtt tests keep exercising the real implementation. */
void tc_mock_es_set_connect_use_wrap(int use_wrap);
void tc_mock_es_set_connect_result(iot_error_t err);
int tc_mock_es_get_connect_call_count(void);
void tc_mock_es_reset_connect(void);

void tc_mock_es_set_disconnect_use_wrap(int use_wrap);
void tc_mock_es_set_disconnect_result(iot_error_t err);
int tc_mock_es_get_disconnect_call_count(void);
void tc_mock_es_reset_disconnect(void);

#endif  // ST_DEVICE_SDK_C_TC_MOCK_IOT_ES_H
