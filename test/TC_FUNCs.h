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
void TC_iot_util_dump_mem(void **state);
void TC_iot_util_validate_uuid_format_null_str(void **state);
void TC_iot_util_validate_uuid_format_invalid_clock_seq(void **state);
void TC_iot_util_convert_str_uuid_success(void **state);
void TC_iot_util_convert_str_uuid_null_parameters(void **state);
void TC_iot_util_convert_str_uuid_invalid_length(void **state);
void TC_iot_util_convert_str_uuid_invalid_delimiters(void **state);
void TC_iot_util_convert_str_uuid_invalid_characters(void **state);
void TC_iot_util_convert_str_uuid_invalid_format(void **state);
void TC_iot_util_convert_str_uuid_invalid_version(void **state);
void TC_iot_util_convert_uuid_str_null_uuid(void **state);
void TC_iot_util_convert_uuid_str_null_buffer(void **state);
void TC_iot_util_convert_uuid_str_insufficient_buffer(void **state);
void TC_iot_util_convert_str_mac_success(void **state);
void TC_iot_util_convert_str_mac_null_parameters(void **state);
void TC_iot_util_convert_str_mac_invalid_length(void **state);
void TC_iot_util_convert_str_mac_invalid_format(void **state);
void TC_iot_util_convert_str_mac_invalid_characters(void **state);
void TC_iot_util_convert_str_mac_invalid_segment_format(void **state);
void TC_iot_util_convert_mac_str_null_mac(void **state);
void TC_iot_util_convert_mac_str_null_buffer(void **state);
void TC_iot_util_convert_mac_str_null_output_buffer(void **state);
void TC_iot_util_convert_mac_str_insufficient_buffer(void **state);
void TC_iot_util_convert_mac_str_success(void **state);
void TC_iot_util_convert_channel_freq_success(void **state);
void TC_iot_util_convert_freq_channel_success(void **state);
void TC_iot_util_url_parse_success(void **state);
void TC_iot_util_url_parse_negative_cases(void **state);
void TC_iot_util_queue_create_negative_cases(void **state);
void TC_iot_util_queue_delete_edge_cases(void **state);
void TC_iot_util_queue_send_negative_cases(void **state);
void TC_iot_util_queue_receive_negative_cases(void **state);
void TC_iot_util_generator_backoff(void **state);
void TC_iot_util_get_server_type_success(void **state);
void TC_iot_util_get_server_type_null_url(void **state);
void TC_iot_util_get_server_type_empty_url(void **state);
void TC_iot_util_get_server_type_unknown_domain(void **state);
void TC_iot_util_get_server_type_partial_url(void **state);
void TC_iot_util_get_server_type_wrong_domain(void **state);
void TC_iot_util_print_ssid_secure_positive(void **state);
void TC_iot_util_print_mac_secure_positive(void **state);

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
void TC_iot_api_onboarding_config_invalid_ssid_version(void **state);
void TC_iot_api_onboarding_config_invalid_onboarding_id_length_version_4(void **state);
void TC_iot_api_onboarding_config_valid_onboarding_id_length_version_5(void **state);
void TC_iot_api_onboarding_config_without_mnid(void **state);
void TC_iot_api_onboarding_config_without_dip_id(void **state);
void TC_iot_get_time_in_sec_null_parameters(void **state);
void TC_iot_get_time_in_sec_success(void **state);
void TC_iot_get_time_in_ms_null_parmaeters(void **state);
void TC_iot_get_time_in_ms_success(void **state);
void TC_iot_get_time_in_sec_by_long_null_parameters(void **state);
void TC_iot_get_time_in_sec_by_long_success(void **state);
void TC_iot_easysetup_request_success(void **state);
void TC_iot_misc_info_load_invalid_parameters(void **state);
int TC_iot_misc_info_dip_setup(void **state);
int TC_iot_misc_info_dip_teardown(void **state);
void TC_iot_misc_info_load_success(void **state);
void TC_iot_misc_info_store_invalid_parameters(void **state);
void TC_iot_misc_info_store_success(void **state);
void TC_iot_wifi_ctrl_request_IOT_WIFI_MODE_OFF(void **state);
void TC_iot_wifi_ctrl_request_IOT_WIFI_MODE_SCAN(void **state);
void TC_iot_wifi_get_status_success(void **state);
void TC_iot_state_timeout_change_failure(void **state);
void TC_iot_state_timeout_change_success(void **state);
void TC_iot_misc_info_load_failure(void **state);
void TC_iot_set_st_ecode_invalid_parameters(void **state);
void TC_iot_set_st_ecode_success(void **state);
void TC_iot_set_st_ecode_from_conn_error_success(void **state);
void TC_iot_get_st_ecode_null_parameter(void **state);
void TC_iot_get_st_ecode_success(void **state);
void TC_iot_wifi_ctrl_request_IOT_WIFI_MODE_STATION(void **state);
void TC_iot_wifi_ctrl_request_failure(void **state);
void TC_iot_wifi_ctrl_request_IOT_WIFI_MODE_SOFTAP(void **state);
void TC_iot_cleanup_success(void **state);

// TCs for iot_uuid.c
void TC_iot_get_uuid_from_mac(void **state);
void TC_iot_get_uuid_from_mac_internal_failure(void **state);
void TC_iot_get_uuid_from_mac_null_parameter(void **state);
void TC_iot_get_uuid_from_mac_empty_mac(void **state);
void TC_iot_get_uuid_from_mac_short_mac(void **state);
void TC_iot_get_uuid_from_mac_long_mac(void **state);
void TC_iot_get_random_uuid_from_mac(void **state);
void TC_iot_get_random_uuid_from_mac_internal_failure(void **state);
void TC_iot_get_random_uuid_from_mac_null_parameter(void **state);
void TC_iot_get_random_uuid_from_mac_wifi_failure(void **state);
void TC_iot_get_random_uuid_from_mac_malloc_failure(void **state);
void TC_iot_get_random_uuid_from_mac_invalid_mac(void **state);
void TC_iot_get_random_uuid_from_mac_empty_mac(void **state);
void TC_iot_get_random_uuid_null_parameter(void **state);
void TC_iot_get_random_uuid_random_failure(void **state);
void TC_iot_get_random_uuid_success(void **state);
void TC_iot_get_random_uuid_from_key_null_uuid(void **state);
void TC_iot_get_random_uuid_from_key_null_key(void **state);
void TC_iot_get_random_uuid_from_key_zero_length(void **state);
void TC_iot_get_random_uuid_from_key_large_length(void **state);
void TC_iot_get_random_uuid_from_key_wifi_failure(void **state);
void TC_iot_get_random_uuid_boundary_test(void **state);
void TC_iot_get_random_uuid_from_key_empty_string(void **state);
void TC_iot_get_random_uuid_multiple_calls(void **state);
void TC_iot_get_random_uuid_structure_validation(void **state);

// TCs for iot_capability.c
int TC_iot_capability_setup(void **state);
int TC_iot_capability_teardown(void **state);
void TC_st_cap_create_attr_number_with_unit(void **state);
void TC_st_cap_create_attr_string_with_unit(void **state);
void TC_st_cap_create_attr_with_unit_and_data(void **state);
void TC_st_cap_handle_init_invalid_argument(void **state);
void TC_st_cap_handle_init_internal_failure(void **state);
void TC_st_cap_handle_init_success(void **state);
void TC_st_conn_set_noti_cb_null_parameters(void **state);
void TC_st_conn_set_noti_cb_success(void **state);
void TC_st_cap_cmd_set_cb_invalid_parameters(void **state);
void TC_st_cap_cmd_set_cb_success(void **state);
void TC_st_cap_send_attr_success(void **state);
void TC_st_cap_send_attr_invalid_parameter(void **state);
void TC_iot_cap_sub_cb_success(void **state);
void TC_iot_noti_sub_cb_rate_limit_reached_SUCCESS(void **state);
void TC_iot_parse_noti_data_device_deleted(void **state);
void TC_iot_parse_noti_data_expired_jwt(void **state);
void TC_iot_parse_noti_data_quota_reached(void **state);
void TC_iot_parse_noti_data_rate_limit(void **state);
void TC_st_cap_create_attr_with_id_success(void **state);
void TC_st_cap_create_attr_with_option_null_parameter(void **state);
void TC_st_cap_create_attr_with_option_failure(void **state);
void TC_st_cap_create_attr_with_option_internal_failure(void **state);
void TC_st_cap_create_attr_with_option_success(void **state);
void TC_st_cap_cmd_set_cb_internal_failure(void **state);
void TC_iot_cap_commands_cb_failure(void **state);
void TC_iot_cap_commands_cb_success(void **state);
void TC_iot_parse_noti_data_presference_updated(void **state);
void TC_iot_cap_call_init_cb_null_parameteer(void **state);
void TC_iot_cap_call_init_cb_success(void **state);
void TC_st_cap_send_attr_v2_null_parameter(void **state);
void TC_st_cap_send_attr_v2_failure(void **state);
void TC_st_cap_send_attr_v2_success(void **state);

// TCs for iot_nv_data.c
int TC_iot_nv_data_setup(void **state);
int TC_iot_nv_data_teardown(void **state);
void TC_iot_nv_get_wifi_prov_data_success(void **state);
void TC_iot_nv_get_wifi_prov_data_null_parameters(void **state);
void TC_iot_nv_get_certificate_success(void **state);
void TC_iot_nv_get_certificate_null_parameters(void **state);
void TC_iot_nv_get_certificate_internal_failure(void **state);
void TC_iot_nv_get_serial_number_success(void **state);
void TC_iot_nv_get_serial_number_null_parameters(void **state);
void TC_iot_nv_get_device_id_null_parameters(void **state);
void TC_iot_nv_set_device_id_null_parameter(void **state);
void TC_iot_nv_get_set_erase_device_id_success(void **state);
void TC_iot_nv_erase_internal_failure(void **state);
void TC_iot_nv_get_data_from_device_info_failure(void **state);
void TC_iot_nv_get_data_from_device_info_success(void **state);

// TCs for iot_easysetup_d2d.c
int TC_iot_easysetup_common_setup(void **state);
int TC_iot_easysetup_common_teardown(void **state);
void TC_iot_easysetup_create_ssid_null_parameters(void **state);
void TC_iot_easysetup_create_ssid_success(void **state);
void TC_iot_easysetup_request_handler_invalid_parameters(void **state);
void TC_iot_easysetup_request_handler_step_deviceinfo(void **state);
void TC_STATIC_es_deviceinfo_handler_null_parameter(void **state);
void TC_STATIC_es_deviceinfo_handler_success(void **state);
void TC_STATIC_es_keyinfo_handler_success(void **state);
void TC_STATIC_es_keyinfo_handler_success_with_y2038(void **state);
void TC_STATIC_es_wifiprovisioninginfo_handler_success(void **state);
void TC_STATIC_es_wifiprovisioninginfo_handler_success_without_authtype(void **state);
void TC_STATIC_es_crypto_cipher_gen_iv_success(void **state);
void TC_STATIC_es_wifiscaninfo_handler_invalid_parameters(void **state);
void TC_STATIC_es_wifiscaninfo_handler_success(void **state);
void TC_STATIC_es_confirminfo_handler_null_parameters(void **state);
void TC_STATIC_es_confirminfo_handler_out_ranged_otm_feature(void **state);
void TC_STATIC_es_confirminfo_handler_justworks_and_pin(void **state);
void TC_STATIC_es_confirminfo_handler_qr_code(void **state);
void TC_STATIC_es_confirminfo_handler_serial_number(void **state);
void TC_STATIC_es_confirminfo_handler_button(void **state);
void TC_STATIC_es_confirm_handler_success(void **state);
void TC_STATIC_es_confirm_handler_invalid_pin(void **state);
void TC_STATIC_es_confirm_handler_non_pin_otm(void **state);
void TC_STATIC_es_confirm_handler_invalid_payload(void **state);
void TC_STATIC_es_setupcomplete_handler_success(void **state);
void TC_st_conn_ownership_confirm_SUCCESS(void **state);
void TC_st_conn_ownership_confirm_DENY(void **state);

// TCs for iot_main.c
void TC_st_conn_init_null_parameters(void **state);
void TC_st_conn_init_malloc_failure(void **state);
void TC_st_conn_init_wrong_onboarding_config(void **state);
void TC_st_conn_init_wrong_device_info(void **state);
void TC_st_conn_init_success(void **state);
void TC_st_conn_cleanup_invalid_parameters(void **state);
void TC_st_conn_cleanup_success(void **state);
void TC_easysetup_resources_create_delete_success(void **state);
void TC_check_prov_data_validation(void **state);

// TCs for iot_mqtt_client.c
void TC_st_mqtt_create_success(void **state);
void TC_st_mqtt_create_failure(void **state);
void TC_st_mqtt_connect_with_connack_rc(void **state);
void TC_st_mqtt_disconnect_success(void **state);
void TC_st_mqtt_publish_success(void **state);

// TCs for iot_security_common.c
void TC_iot_security_init_malloc_failure(void **state);
void TC_iot_security_init_success(void **state);
void TC_iot_security_deinit_null_parameters(void **state);
void TC_iot_security_deinit_success(void **state);
void TC_iot_security_check_context_is_valid_null_parameters(void **state);
void TC_iot_security_check_context_is_valid_success(void **state);
void TC_iot_security_check_backend_funcs_entry_is_valid_failure(void **state);
void TC_iot_security_check_backend_funcs_entry_is_valid_success(void **state);

// TCs for iot_security_crypto.c
int TC_iot_security_pk_init_setup(void **state);
int TC_iot_security_pk_init_teardown(void **state);
int TC_iot_security_pk_setup(void **state);
int TC_iot_security_pk_teardown(void **state);
void TC_iot_security_pk_init_null_parameters(void **state);
void TC_iot_security_pk_init_malloc_failure(void **state);
void TC_iot_security_pk_init_success(void **state);
void TC_iot_security_pk_deinit_null_parameters(void **state);
void TC_iot_security_pk_deinit_success(void **state);
void TC_iot_security_pk_get_signature_len_failure(void **state);
void TC_iot_security_pk_get_signature_len_success(void **state);
void TC_iot_security_pk_get_key_type_failure(void **state);
void TC_iot_security_pk_get_key_type_success(void **state);
void TC_iot_security_pk_sign_invalid_parameters(void **state);
void TC_iot_security_pk_sign_null_parameters(void **state);
void TC_iot_security_pk_sign_malloc_failure(void **state);
void TC_iot_security_pk_sign_failure(void **state);
void TC_iot_security_pk_verify_invalid_parameters(void **state);
void TC_iot_security_pk_verify_null_parameters(void **state);
void TC_iot_security_pk_verify_failure(void **state);
void TC_iot_security_pk_success(void **state);

int TC_iot_security_cipher_init_setup(void **state);
int TC_iot_security_cipher_init_teardown(void **state);
int TC_iot_security_cipher_setup(void **state);
int TC_iot_security_cipher_teardown(void **state);
void TC_iot_security_cipher_init_null_parameters(void **state);
void TC_iot_security_cipher_init_malloc_failure(void **state);
void TC_iot_security_cipher_init_success(void **state);
void TC_iot_security_cipher_deinit_null_parameters(void **state);
void TC_iot_security_cipher_deinit_success(void **state);
void TC_iot_security_cipher_set_params_invalid_parameters(void **state);
void TC_iot_security_cipher_set_params_null_parameters(void **state);
void TC_iot_security_cipher_set_params_success(void **state);
void TC_iot_security_cipher_aes_encrypt_invalid_parameters(void **state);
void TC_iot_security_cipher_aes_encrypt_null_parameters(void **state);
void TC_iot_security_cipher_aes_encrypt_malloc_failure(void **state);
void TC_iot_security_cipher_aes_encrypt_failure(void **state);
void TC_iot_security_cipher_aes_decrypt_invalid_parameters(void **state);
void TC_iot_security_cipher_aes_decrypt_null_parameters(void **state);
void TC_iot_security_cipher_aes_decrypt_malloc_failure(void **state);
void TC_iot_security_cipher_aes_decrypt_failure(void **state);
void TC_iot_security_cipher_aes_success(void **state);

// TCs for iot_security_ecdh.c
int TC_iot_security_ecdh_init_setup(void **state);
int TC_iot_security_ecdh_init_teardown(void **state);
int TC_iot_security_ecdh_setup(void **state);
int TC_iot_security_ecdh_teardown(void **state);
void TC_iot_security_ecdh_init_null_parameters(void **state);
void TC_iot_security_ecdh_init_malloc_failure(void **state);
void TC_iot_security_ecdh_init_success(void **state);
void TC_iot_security_ecdh_set_params_null_parameters(void **state);
void TC_iot_security_ecdh_set_params_invalid_parameters(void **state);
void TC_iot_security_ecdh_set_params_success(void **state);
void TC_iot_security_ecdh_compute_shared_secret_null_parameters(void **state);
void TC_iot_security_ecdh_compute_shared_secret_failure(void **state);
void TC_iot_security_ecdh_compute_shared_secret_malloc_failure(void **state);
void TC_iot_security_ecdh_compute_shared_secret_success(void **state);
void TC_iot_security_ecdh_and_dynamic_cipher(void **state);
void TC_iot_security_ecdh_and_static_cipher(void **state);

// TCs for iot_security_manager.c
int TC_iot_security_manager_setup(void **state);
int TC_iot_security_manager_teardown(void **state);
void TC_iot_security_manager_init_null_parameters(void **state);
void TC_iot_security_manager_init_success(void **state);
void TC_iot_security_manager_deinit_null_parameters(void **state);
void TC_iot_security_manager_deinit_success(void **state);
void TC_iot_security_manager_set_key_null_parameters(void **state);
void TC_iot_security_manager_set_key_invalid_parameters(void **state);
void TC_iot_security_manager_set_key_alloc_failure(void **state);
void TC_iot_security_manager_set_key_success(void **state);
void TC_iot_security_manager_get_key_null_parameters(void **state);
void TC_iot_security_manager_get_key_invalid_parameters(void **state);
void TC_iot_security_manager_get_key_alloc_failure(void **state);
void TC_iot_security_manager_get_key_success(void **state);
void TC_iot_security_manager_get_certificate_null_parameters(void **state);
void TC_iot_security_manager_get_certificate_invalid_parameters(void **state);
void TC_iot_security_manager_get_certificate_alloc_failure(void **state);
void TC_iot_security_manager_get_certificate_success(void **state);

// TCs for iot_security_storage.c
int TC_iot_security_storage_init_setup(void **state);
int TC_iot_security_storage_init_teardown(void **state);
int TC_iot_security_storage_setup(void **state);
int TC_iot_security_storage_teardown(void **state);
void TC_iot_security_storage_init_malloc_failure(void **state);
void TC_iot_security_storage_init_null_parameters(void **state);
void TC_iot_security_storage_init_success(void **state);
void TC_iot_security_storage_deinit_null_parameters(void **state);
void TC_iot_security_storage_deinit_success(void **state);
void TC_iot_security_storage_read_malloc_failure(void **state);
void TC_iot_security_storage_read_null_parameters(void **state);
void TC_iot_security_storage_read_invalid_parameters(void **state);
void TC_iot_security_storage_read_failure(void **state);
void TC_iot_security_storage_read_success(void **state);
void TC_iot_security_storage_write_null_parameters(void **state);
void TC_iot_security_storage_write_invalid_parameters(void **state);
void TC_iot_security_storage_write_failure(void **state);
void TC_iot_security_storage_write_success(void **state);
void TC_iot_security_storage_remove_null_parameters(void **state);
void TC_iot_security_storage_remove_invalid_parameters(void **state);
void TC_iot_security_storage_remove_failure(void **state);
void TC_iot_security_storage_remove_success(void **state);

// TCs for iot_security_helper.c
void TC_iot_security_base64_buffer_size(void **state);
void TC_iot_security_base64_invalid_parameter(void **state);
void TC_iot_security_base64_decode_failure(void **state);
void TC_iot_security_base64_decode_urlsafe_failure(void **state);
void TC_iot_security_base64_encode_success(void **state);
void TC_iot_security_base64_decode_success(void **state);
void TC_iot_security_base64_encode_urlsafe_success(void **state);
void TC_iot_security_base64_decode_urlsafe_alloc_failure(void **state);
void TC_iot_security_base64_decode_urlsafe_success(void **state);
void TC_iot_security_sha256_failure(void **state);
void TC_iot_security_sha256_success(void **state);

// TCs for iot_security_helper_ed25519.c
void TC_iot_security_ed25519_convert_seckey_null_parameters(void **state);
void TC_iot_security_ed25519_convert_seckey_success(void **state);

// TCs for iot_security_be_bsp.c
void TC_STATIC_iot_security_be_bsp_fs_storage_id2target_invalid_parameters(void **state);
void TC_STATIC_iot_security_be_bsp_fs_storage_id2target_success(void **state);
void TC_STATIC_iot_security_be_bsp_fs_storage_id2filename_invalid_parameters(void **state);
void TC_STATIC_iot_security_be_bsp_fs_storage_id2filename_success(void **state);
void TC_iot_security_be_bsp_fs_load_malloc_failure(void **state);
void TC_iot_security_be_bsp_fs_load_invalid_parameters(void **state);
void TC_iot_security_be_bsp_fs_load_success(void **state);
void TC_iot_security_be_bsp_fs_store_invalid_parameters(void **state);
void TC_iot_security_be_bsp_fs_store_success(void **state);
void TC_iot_security_be_bsp_fs_remove_invalid_parameters(void **state);
void TC_iot_security_be_bsp_fs_remove_success(void **state);
void TC_iot_security_be_bsp_init_null_parameters(void **state);
void TC_iot_security_be_bsp_init_success(void **state);

// TCs for iot_wt.c
int TC_iot_wt_create_memleak_detect_setup(void **state);
int TC_iot_wt_create_memleak_detect_teardown(void **state);
void TC_iot_wt_create_null_parameters(void **state);
void TC_iot_wt_create_success(void **state);

// TCs for iot_easysetup_httpd
int TC_iot_easysetup_httpd_setup(void **state);
int TC_iot_easysetup_httpd_teardown(void **state);
void TC_iot_easysetup_httpd_invalid_request(void **state);
void TC_iot_easysetup_httpd_deviceinfo_success(void **state);
void TC_iot_easysetup_httpd_keyinfo_single_transfer_success(void **state);
void TC_iot_easysetup_httpd_keyinfo_separated_transfer_success(void **state);

// TCs for iot_dump_log.c
void TC_iot_dump_create_dump_state_failure(void **state);
void TC_iot_dump_create_dump_state_success(void **state);
void TC_iot_dump_log(void **state);

// TCs for iot_easysetup_st_mqtt.c
void TC_STATIC_iot_es_mqtt_registration_SUCCESS(void **state);
void TC_STATIC_iot_parse_sequence_num_SUCCESS(void **state);
void TC_STATIC_iot_parse_sequence_num_FAILURE(void **state);
void TC_STATIC_iot_mqtt_registration_client_callback_SUCCESS(void **state);
void TC_STATIC_iot_parse_sequence_num_NULL_payload(void **state);
void TC_STATIC_iot_parse_sequence_num_empty_string(void **state);
void TC_STATIC_iot_parse_sequence_num_invalid_json(void **state);
void TC_STATIC_iot_parse_sequence_num_no_device_events(void **state);
void TC_STATIC_iot_parse_sequence_num_empty_device_events(void **state);
void TC_STATIC_iot_es_mqtt_registration_json_NULL_context(void **state);
void TC_STATIC_iot_es_mqtt_registration_json_no_serial(void **state);
void TC_STATIC_iot_es_mqtt_registration_json_no_lookup_id(void **state);
void TC_STATIC_iot_es_mqtt_registration_json_no_dip_data(void **state);
void TC_STATIC_iot_mqtt_registration_client_callback_NULL_context(void **state);
void TC_STATIC_iot_mqtt_registration_client_callback_NULL_payload(void **state);
void TC_STATIC_iot_mqtt_registration_client_callback_invalid_event(void **state);
void TC_STATIC_iot_mqtt_registration_client_callback_invalid_json(void **state);
void TC_STATIC_iot_mqtt_registration_client_callback_expired_jwt(void **state);
void TC_STATIC_iot_mqtt_registration_client_callback_error_event(void **state);
void TC_STATIC_check_connection_response_NULL_payload(void **state);
void TC_STATIC_check_connection_response_empty_payload(void **state);
void TC_STATIC_check_connection_response_invalid_json(void **state);
void TC_STATIC_check_connection_response_no_event(void **state);
void TC_STATIC_check_connection_response_expired_jwt_no_current_time(void **state);
void TC_STATIC_check_connection_response_unknown_event(void **state);
void TC_STATIC_iot_es_mqtt_connect_NULL_context(void **state);
void TC_STATIC_iot_es_mqtt_connect_NULL_username(void **state);
void TC_STATIC_iot_es_mqtt_connect_NULL_sign_data(void **state);
void TC_STATIC_iot_es_connect_NULL_context(void **state);
void TC_STATIC_iot_es_connect_invalid_conn_type(void **state);
void TC_STATIC_iot_es_connect_rate_limit(void **state);
void TC_STATIC_iot_es_disconnect_NULL_context(void **state);
void TC_STATIC_iot_es_disconnect_invalid_conn_type(void **state);
void TC_STATIC_iot_es_disconnect_no_mqtt_context(void **state);
void TC_STATIC_iot_es_set_broker_url_port_invalid_server_type(void **state);
void TC_STATIC_iot_es_set_broker_url_port_unsupported_server_type(void **state);
void TC_STATIC_iot_update_dip_NULL_context(void **state);
void TC_STATIC_iot_update_dip_NULL_mqtt_client(void **state);
void TC_STATIC_iot_update_dip_no_dip_data(void **state);
void TC_STATIC_iot_es_mqtt_registration_NULL_context(void **state);
void TC_STATIC_iot_es_mqtt_registration_NULL_mqtt_context(void **state);
void TC_STATIC_iot_es_mqtt_registration_no_serial_numbers(void **state);

// TCs for iot_easysetup_http_parser.c
void TC_es_msg_parser_VALID_GET_METHOD(void **state);
void TC_es_msg_parser_INVALID_GET_METHOD(void **state);
void TC_es_msg_parser_VALID_POST_METHOD(void **state);
void TC_es_msg_parser_INVALID_POST_METHOD(void **state);

// TCs for iot_eassetup_http.c
void TC_iot_easysetup_gen_post_payload_NULL_IN_PAYLOAD(void **state);
void TC_iot_easysetup_gen_post_payload_CMD_INVALID_STEP(void **state);
void TC_iot_easysetup_gen_post_payload_CMD_INVALID_SEQUENCE(void **state);
void TC_iot_easysetup_gen_post_payload_NULL_CONTEXT(void **state);
void TC_iot_easysetup_gen_post_payload_SETUPCOMPLETE_NULL_PAYLOAD(void **state);
void TC_iot_easysetup_gen_get_payload_CMD_INVALID_STEP(void **state);
void TC_iot_easysetup_gen_get_payload_CMD_INVALID_SEQUENCE(void **state);
void TC_iot_easysetup_gen_get_payload_NULL_CONTEXT(void **state);
void TC_http_msg_handler_INVALID_CMD(void **state);
void TC_http_msg_handler_INVALID_TYPE(void **state);
void TC_http_msg_handler_NULL_DATA_BUF_POST(void **state);
void TC_iot_easysetup_init_NULL_CONTEXT(void **state);
void TC_iot_easysetup_deinit_NULL_CONTEXT(void **state);

#endif  // ST_DEVICE_SDK_C_TCS_H
