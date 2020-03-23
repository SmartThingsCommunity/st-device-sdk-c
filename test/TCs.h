/* ***************************************************************************
 *
 * Copyright (c) 2020 Samsung Electronics All Rights Reserved.
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
void TC_iot_util_get_random_uuid_success(void **state);
void TC_iot_util_get_random_uuid_null_parameter(void **state);
void TC_iot_util_convert_str_mac_success(void **state);
void TC_iot_util_convert_str_mac_invalid_parameters(void **state);
void TC_iot_util_convert_str_uuid_success(void **state);
void TC_iot_util_convert_str_uuid_null_parameters(void **state);

// TCs for iot_api.c
int TC_iot_api_memleak_detect_setup(void **state);
int TC_iot_api_memleak_detect_teardown(void **state);
void TC_iot_api_device_info_load_null_parameters(void **state);
void TC_iot_api_device_info_load_success(void **state);
void TC_iot_api_device_info_load_internal_failure(void **state);
void TC_iot_api_device_info_load_without_firmware_version(void **state);
void TC_iot_api_onboarding_config_load_null_parameters(void **state);
void TC_iot_api_onboarding_config_load_template_parameters(void **state);
void TC_iot_api_onboarding_config_load_success(void **state);
void TC_iot_api_onboarding_config_load_internal_failure(void **state);
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
void TC_iot_random_uuid_from_mac_internal_failure(void **state);

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
void TC_st_cap_attr_create_string_null_unit(void **state);
void TC_st_cap_attr_create_string_with_unit(void **state);
void TC_st_cap_attr_create_string_internal_failure(void **state);
void TC_st_cap_attr_create_string_null_parameters(void **state);
void TC_st_cap_handle_init_invalid_argument(void **state);
void TC_st_cap_handle_init_internal_failure(void **state);
void TC_st_cap_handle_init_success(void **state);

// TCs for iot_crypto.c
int TC_iot_crypto_pk_setup(void **state);
int TC_iot_crypto_pk_teardown(void **state);
void TC_iot_crypto_pk_init_null_parameter(void **state);
void TC_iot_crypto_pk_init_ed25519(void **state);
void TC_iot_crypto_pk_init_invalid_type(void **state);
void TC_iot_crypto_pk_free(void **state);
void TC_iot_crypto_pk_ed25519_success(void **state);
int TC_iot_crypto_cipher_aes_setup(void **state);
int TC_iot_crypto_cipher_aes_teardown(void **state);
void TC_iot_crypto_cipher_aes_null_parameter(void **state);
void TC_iot_crypto_cipher_aes_invalid_parameter(void **state);
void TC_iot_crypto_cipher_aes_success(void **state);
void TC_iot_crypto_cipher_get_align_size(void **state);
int TC_iot_crypto_ecdh_setup(void **state);
int TC_iot_crypto_ecdh_teardown(void **state);
void TC_iot_crypto_ecdh_invalid_parameter(void **state);
void TC_iot_crypto_ecdh_success(void **state);
int TC_iot_crypto_ed25519_keypair_setup(void **state);
int TC_iot_crypto_ed25519_keypair_teardown(void **state);
void TC_iot_crypto_ed25519_keypair_invalid_parameter(void **state);
void TC_iot_crypto_ed25519_keypair_success(void **state);
void TC_iot_crypto_ed25519_convert_invalid_parameter(void **state);
void TC_iot_crypto_ed25519_convert_success(void **state);
void TC_iot_crypto_base64_invalid_parameter(void **state);
void TC_iot_crypto_base64_failure(void **state);
void TC_iot_crypto_base64_encode_success(void **state);
void TC_iot_crypto_base64_decode_success(void **state);
void TC_iot_crypto_base64_urlsafe_encode_success(void **state);
void TC_iot_crypto_base64_urlsafe_decode_success(void **state);
void TC_iot_crypto_base64_buffer_size(void **state);

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

// TCs for iot_easysetup_crypto.c
int TC_iot_easysetup_crypto_setup(void **state);
int TC_iot_easysetup_crypto_teardown(void **state);
void TC_iot_es_crypto_load_pk_success(void** state);
void TC_iot_es_crypto_load_pk_invalid_parameters(void **state);
void TC_iot_es_crypto_init_pk(void **state);

// TCs for iot_easysetup_d2d.c
int TC_iot_easysetup_d2d_setup(void **state);
int TC_iot_easysetup_d2d_teardown(void **state);
void TC_iot_easysetup_create_ssid_null_parameters(void **state);
void TC_iot_easysetup_create_ssid_success(void **state);
void TC_iot_easysetup_request_handler_null_parameters(void **state);
void TC_STATIC_es_deviceinfo_handler_null_parameter(void **state);
void TC_STATIC_es_deviceinfo_handler_success(void **state);
void TC_STATIC_es_keyinfo_handler_success(void **state);
void TC_STATIC_es_wifiprovisioninginfo_handler_success(void **state);
void TC_STATIC_es_crypto_cipher_gen_iv_success(void **state);
void TC_STATIC_es_wifiscaninfo_handler_invalid_parameters(void **state);
void TC_STATIC_es_wifiscaninfo_handler_success(void **state);
void TC_STATIC_es_confirminfo_handler_null_parameters(void **state);
void TC_STATIC_es_confirminfo_handler_out_ranged_otm_feature(void **state);
void TC_STATIC_es_confirminfo_handler_justworks_and_pin(void **state);
void TC_STATIC_es_confirminfo_handler_qr_code(void **state);
void TC_STATIC_es_confirminfo_handler_button(void **state);
void TC_STATIC_es_confirm_handler_success(void** state);
void TC_STATIC_es_confirm_handler_invalid_pin(void** state);
void TC_STATIC_es_confirm_handler_non_pin_otm(void** state);

// TCs for iot_main.c
void TC_st_conn_init_null_parameters(void **state);
void TC_st_conn_init_malloc_failure(void **state);
void TC_st_conn_init_wrong_onboarding_config(void **state);
void TC_st_conn_init_wrong_device_info(void **state);

#endif //ST_DEVICE_SDK_C_TCS_H
