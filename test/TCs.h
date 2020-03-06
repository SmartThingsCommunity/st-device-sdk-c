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
void TC_iot_api_device_info_load_null_parameters(void **state);
void TC_iot_api_device_info_load_success(void **state);
void TC_iot_api_device_info_load_without_firmware_version(void **state);
void TC_iot_api_onboarding_config_load_null_parameters(void **state);
void TC_iot_api_onboarding_config_load_template_parameters(void **state);
void TC_iot_api_onboarding_config_load_success(void **state);
void TC_iot_api_onboarding_config_without_mnid(void **state);
void TC_iot_get_time_in_sec_null_parameters(void **state);
void TC_iot_get_time_in_sec_success(void **state);
void TC_iot_get_time_in_ms_null_parmaeters(void **state);
void TC_iot_get_time_in_ms_success(void **state);
void TC_iot_get_time_in_sec_by_long_null_parameters(void **state);
void TC_iot_get_time_in_sec_by_long_success(void **state);

// TCs for iot_uuid.c
void TC_iot_uuid_from_mac(void **state);
void TC_iot_uuid_from_mac_internal_failure(void **state);
void TC_iot_random_uuid_from_mac(void **state);
void TC_iot_ramdom_uuid_from_mac_internal_failure(void **state);

// TCs for iot_capability.c
int TC_iot_capability_teardown(void **state);
void TC_st_cap_attr_create_int_null_attribute(void **state);
void TC_st_cap_attr_create_int_null_unit(void **state);
void TC_st_cap_attr_create_int_with_unit(void **state);
void TC_st_cap_attr_create_int_internal_failure(void **state);
void TC_st_cap_attr_create_number_null_attribute(void **state);
void TC_st_cap_attr_create_number_null_unit(void **state);
void TC_st_cap_attr_create_number_with_unit(void **state);
void TC_st_cap_attr_create_number_internal_failure(void **state);

// TCs for iot_crypto.c
void TC_iot_crypto_pk_init_null_parameter(void **state);
void TC_iot_crypto_pk_init_ed25519(void **state);

// TCs for iot_nv_data.c
int TC_iot_nv_data_setup(void **state);
int TC_iot_nv_data_teardown(void **state);
void TC_iot_nv_get_root_certificate_success(void **state);
void TC_iot_nv_get_root_certificate_null_parameters(void **state);
void TC_iot_nv_get_root_certificate_internal_failure(void **state);
void TC_iot_nv_get_public_key_success(void **state);
void TC_iot_nv_get_public_key_null_parameters(void **state);
void TC_iot_nv_get_serial_number_success(void **state);
void TC_iot_nv_get_serial_number_null_parameters(void **state);

// TCs for iot_easysetup_d2d.c
int TC_iot_easysetup_create_ssid_setup(void **state);
int TC_iot_easysetup_create_ssid_teardown(void **state);
void TC_iot_easysetup_create_ssid_null_parameters(void **state);
void TC_iot_easysetup_create_ssid_success(void **state);
void TC_iot_easysetup_request_handler_null_parameters(void **state);

// TCs for easysetup d2d
int TC_easysetup_d2d_setup(void **state);
int TC_easysetup_d2d_teardown(void **state);
void TC_easysetup_d2d_get_deviceinfo_success(void **state);

#endif //ST_DEVICE_SDK_C_TCS_H