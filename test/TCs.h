/* ***************************************************************************
 *
 * Copyright 2020 Samsung Electronics All Rights Reserved.
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
#ifndef ST_DEVICE_SDK_C_TCS_H
#define ST_DEVICE_SDK_C_TCS_H

// TCs for iot_util.c
void TC_iot_util_get_random_uuid(void **state);
void TC_iot_util_convert_str_mac(void **state);

// TCs for iot_api.c
void TC_iot_api_device_info_load(void **state);
void TC_iot_api_onboarding_config_load(void **state);

// TCs for iot_uuid.c
void TC_iot_uuid_from_mac(void **state);

#endif //ST_DEVICE_SDK_C_TCS_H
