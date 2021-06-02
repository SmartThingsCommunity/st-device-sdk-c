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
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include "TCs.h"

int TEST_FUNC_iot_api(void)
{
    const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup_teardown(TC_iot_api_device_info_load_null_parameters, TC_iot_api_memleak_detect_setup, TC_iot_api_memleak_detect_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_api_device_info_load_success, TC_iot_api_memleak_detect_setup, TC_iot_api_memleak_detect_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_api_device_info_load_internal_failure, TC_iot_api_memleak_detect_setup, TC_iot_api_memleak_detect_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_api_device_info_load_without_firmware_version, TC_iot_api_memleak_detect_setup, TC_iot_api_memleak_detect_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_api_onboarding_config_load_null_parameters, TC_iot_api_memleak_detect_setup, TC_iot_api_memleak_detect_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_api_onboarding_config_load_template_parameters, TC_iot_api_memleak_detect_setup, TC_iot_api_memleak_detect_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_api_onboarding_config_load_success, TC_iot_api_memleak_detect_setup, TC_iot_api_memleak_detect_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_api_onboarding_config_load_internal_failure, TC_iot_api_memleak_detect_setup, TC_iot_api_memleak_detect_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_api_onboarding_config_without_mnid, TC_iot_api_memleak_detect_setup, TC_iot_api_memleak_detect_teardown),
			cmocka_unit_test_setup_teardown(TC_iot_api_onboarding_config_invalid_ssid_version, TC_iot_api_memleak_detect_setup, TC_iot_api_memleak_detect_teardown),
			cmocka_unit_test_setup_teardown(TC_iot_api_onboarding_config_invalid_onboarding_id_length_version_4, TC_iot_api_memleak_detect_setup, TC_iot_api_memleak_detect_teardown),
			cmocka_unit_test_setup_teardown(TC_iot_api_onboarding_config_valid_onboarding_id_length_version_5, TC_iot_api_memleak_detect_setup, TC_iot_api_memleak_detect_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_api_onboarding_config_without_dip_id, TC_iot_api_memleak_detect_setup, TC_iot_api_memleak_detect_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_get_time_in_sec_null_parameters, TC_iot_api_memleak_detect_setup, TC_iot_api_memleak_detect_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_get_time_in_sec_success, TC_iot_api_memleak_detect_setup, TC_iot_api_memleak_detect_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_get_time_in_ms_null_parmaeters, TC_iot_api_memleak_detect_setup, TC_iot_api_memleak_detect_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_get_time_in_ms_success, TC_iot_api_memleak_detect_setup, TC_iot_api_memleak_detect_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_get_time_in_sec_by_long_null_parameters, TC_iot_api_memleak_detect_setup, TC_iot_api_memleak_detect_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_get_time_in_sec_by_long_success, TC_iot_api_memleak_detect_setup, TC_iot_api_memleak_detect_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_easysetup_request_success, TC_iot_api_memleak_detect_setup, TC_iot_api_memleak_detect_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_misc_info_load_invalid_parameters, TC_iot_misc_info_dip_setup, TC_iot_misc_info_dip_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_misc_info_load_success, TC_iot_misc_info_dip_setup, TC_iot_misc_info_dip_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_misc_info_store_invalid_parameters, TC_iot_api_memleak_detect_setup, TC_iot_api_memleak_detect_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_misc_info_store_success, TC_iot_misc_info_dip_setup, TC_iot_misc_info_dip_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_wifi_ctrl_request_IOT_WIFI_MODE_OFF, TC_iot_api_memleak_detect_setup, TC_iot_api_memleak_detect_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_wifi_ctrl_request_IOT_WIFI_MODE_SCAN, TC_iot_api_memleak_detect_setup, TC_iot_api_memleak_detect_teardown),
    };
    return cmocka_run_group_tests_name("iot_api.c", tests, NULL, NULL);
}

int TEST_FUNC_iot_capability(void)
{
    const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup_teardown(TC_st_cap_create_attr_number_with_unit, TC_iot_capability_setup, TC_iot_capability_teardown),
            cmocka_unit_test_setup_teardown(TC_st_cap_create_attr_string_with_unit, TC_iot_capability_setup, TC_iot_capability_teardown),
            cmocka_unit_test_setup_teardown(TC_st_cap_create_attr_with_unit_and_data, TC_iot_capability_setup, TC_iot_capability_teardown),
            cmocka_unit_test_setup_teardown(TC_st_cap_handle_init_invalid_argument, TC_iot_capability_setup, TC_iot_capability_teardown),
            cmocka_unit_test_setup_teardown(TC_st_cap_handle_init_internal_failure, TC_iot_capability_setup, TC_iot_capability_teardown),
            cmocka_unit_test_setup_teardown(TC_st_cap_handle_init_success, TC_iot_capability_setup, TC_iot_capability_teardown),
            cmocka_unit_test_setup_teardown(TC_st_conn_set_noti_cb_null_parameters, TC_iot_capability_setup, TC_iot_capability_teardown),
            cmocka_unit_test_setup_teardown(TC_st_conn_set_noti_cb_success, TC_iot_capability_setup, TC_iot_capability_teardown),
            cmocka_unit_test_setup_teardown(TC_st_cap_cmd_set_cb_invalid_parameters, TC_iot_capability_setup, TC_iot_capability_teardown),
            cmocka_unit_test_setup_teardown(TC_st_cap_cmd_set_cb_success, TC_iot_capability_setup, TC_iot_capability_teardown),
            cmocka_unit_test_setup_teardown(TC_st_cap_send_attr_success, TC_iot_capability_setup, TC_iot_capability_teardown),
            cmocka_unit_test_setup_teardown(TC_st_cap_send_attr_invalid_parameter, TC_iot_capability_setup, TC_iot_capability_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_cap_sub_cb_success, TC_iot_capability_setup, TC_iot_capability_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_noti_sub_cb_rate_limit_reached_SUCCESS, TC_iot_capability_setup, TC_iot_capability_teardown),
            cmocka_unit_test(TC_iot_parse_noti_data_device_deleted),
            cmocka_unit_test(TC_iot_parse_noti_data_expired_jwt),
            cmocka_unit_test(TC_iot_parse_noti_data_quota_reached),
    };
    return cmocka_run_group_tests_name("iot_capability.c", tests, NULL, NULL);
}

int TEST_FUNC_iot_nv_data(void)
{
    const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup_teardown(TC_iot_nv_get_wifi_prov_data_success, TC_iot_nv_data_setup, TC_iot_nv_data_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_nv_get_wifi_prov_data_null_parameters, TC_iot_nv_data_setup, TC_iot_nv_data_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_nv_get_certificate_success, TC_iot_nv_data_setup, TC_iot_nv_data_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_nv_get_certificate_null_parameters, TC_iot_nv_data_setup, TC_iot_nv_data_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_nv_get_certificate_internal_failure, TC_iot_nv_data_setup, TC_iot_nv_data_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_nv_get_serial_number_success, TC_iot_nv_data_setup, TC_iot_nv_data_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_nv_get_serial_number_null_parameters, TC_iot_nv_data_setup, TC_iot_nv_data_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_nv_get_device_id_null_parameters, TC_iot_nv_data_setup, TC_iot_nv_data_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_nv_set_device_id_null_parameter, TC_iot_nv_data_setup, TC_iot_nv_data_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_nv_get_set_erase_device_id_success, TC_iot_nv_data_setup, TC_iot_nv_data_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_nv_erase_internal_failure, TC_iot_nv_data_setup, TC_iot_nv_data_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_nv_get_data_from_device_info_failure, TC_iot_nv_data_setup, TC_iot_nv_data_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_nv_get_data_from_device_info_success, TC_iot_nv_data_setup, TC_iot_nv_data_teardown),
    };
    return cmocka_run_group_tests_name("iot_nv_data.c", tests, NULL, NULL);
}

int TEST_FUNC_iot_util(void)
{
    const struct CMUnitTest tests[] = {
            cmocka_unit_test(TC_iot_util_get_random_uuid_success),
            cmocka_unit_test(TC_iot_util_get_random_uuid_null_parameter),
            cmocka_unit_test(TC_iot_util_convert_str_mac_success),
            cmocka_unit_test(TC_iot_util_convert_str_mac_invalid_parameters),
            cmocka_unit_test(TC_iot_util_convert_str_uuid_success),
            cmocka_unit_test(TC_iot_util_convert_str_uuid_invalid_parameters),
            cmocka_unit_test(TC_iot_util_convert_channel_freq),
            cmocka_unit_test(TC_iot_util_convert_mac_str_invalid_parameters),
            cmocka_unit_test(TC_iot_util_convert_mac_str_success),
    };
    return cmocka_run_group_tests_name("iot_util.c", tests, NULL, NULL);
}

int TEST_FUNC_iot_uuid(void)
{
    const struct CMUnitTest tests[] = {
            cmocka_unit_test(TC_iot_uuid_from_mac),
            cmocka_unit_test(TC_iot_uuid_from_mac_internal_failure),
            cmocka_unit_test(TC_iot_random_uuid_from_mac),
            cmocka_unit_test(TC_iot_random_uuid_from_mac_internal_failure),
    };
    return cmocka_run_group_tests_name("iot_uuid.c", tests, NULL, NULL);
}

int TEST_FUNC_iot_easysetup_d2d(void)
{
    const struct CMUnitTest tests[] = {
            cmocka_unit_test(TC_iot_easysetup_create_ssid_null_parameters),
            cmocka_unit_test_setup_teardown(TC_iot_easysetup_create_ssid_success, TC_iot_easysetup_common_setup, TC_iot_easysetup_common_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_easysetup_request_handler_invalid_parameters, TC_iot_easysetup_common_setup, TC_iot_easysetup_common_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_easysetup_request_handler_step_deviceinfo, TC_iot_easysetup_common_setup, TC_iot_easysetup_common_teardown),
            cmocka_unit_test(TC_STATIC_es_deviceinfo_handler_null_parameter),
            cmocka_unit_test(TC_STATIC_es_crypto_cipher_gen_iv_success),
            cmocka_unit_test_setup_teardown(TC_STATIC_es_deviceinfo_handler_success, TC_iot_easysetup_common_setup, TC_iot_easysetup_common_teardown),
            cmocka_unit_test_setup_teardown(TC_STATIC_es_keyinfo_handler_success, TC_iot_easysetup_common_setup, TC_iot_easysetup_common_teardown),
            cmocka_unit_test_setup_teardown(TC_STATIC_es_keyinfo_handler_success_with_y2038, TC_iot_easysetup_common_setup, TC_iot_easysetup_common_teardown),
            cmocka_unit_test_setup_teardown(TC_STATIC_es_wifiprovisioninginfo_handler_success, TC_iot_easysetup_common_setup, TC_iot_easysetup_common_teardown),
            cmocka_unit_test_setup_teardown(TC_STATIC_es_wifiprovisioninginfo_handler_success_without_authtype, TC_iot_easysetup_common_setup, TC_iot_easysetup_common_teardown),
            cmocka_unit_test_setup_teardown(TC_STATIC_es_wifiscaninfo_handler_invalid_parameters, TC_iot_easysetup_common_setup, TC_iot_easysetup_common_teardown),
            cmocka_unit_test_setup_teardown(TC_STATIC_es_wifiscaninfo_handler_success, TC_iot_easysetup_common_setup, TC_iot_easysetup_common_teardown),
            cmocka_unit_test_setup_teardown(TC_STATIC_es_confirminfo_handler_null_parameters, TC_iot_easysetup_common_setup, TC_iot_easysetup_common_teardown),
            cmocka_unit_test_setup_teardown(TC_STATIC_es_confirminfo_handler_out_ranged_otm_feature, TC_iot_easysetup_common_setup, TC_iot_easysetup_common_teardown),
            cmocka_unit_test_setup_teardown(TC_STATIC_es_confirminfo_handler_justworks_and_pin, TC_iot_easysetup_common_setup, TC_iot_easysetup_common_teardown),
            cmocka_unit_test_setup_teardown(TC_STATIC_es_confirminfo_handler_qr_code, TC_iot_easysetup_common_setup, TC_iot_easysetup_common_teardown),
            cmocka_unit_test_setup_teardown(TC_STATIC_es_confirminfo_handler_serial_number, TC_iot_easysetup_common_setup, TC_iot_easysetup_common_teardown),
            cmocka_unit_test_setup_teardown(TC_STATIC_es_confirminfo_handler_button, TC_iot_easysetup_common_setup, TC_iot_easysetup_common_teardown),
            cmocka_unit_test_setup_teardown(TC_STATIC_es_confirm_handler_success, TC_iot_easysetup_common_setup, TC_iot_easysetup_common_teardown),
            cmocka_unit_test_setup_teardown(TC_STATIC_es_confirm_handler_invalid_pin, TC_iot_easysetup_common_setup, TC_iot_easysetup_common_teardown),
            cmocka_unit_test_setup_teardown(TC_STATIC_es_confirm_handler_non_pin_otm, TC_iot_easysetup_common_setup, TC_iot_easysetup_common_teardown),
            cmocka_unit_test_setup_teardown(TC_STATIC_es_confirm_handler_invalid_payload, TC_iot_easysetup_common_setup, TC_iot_easysetup_common_teardown),
            cmocka_unit_test_setup_teardown(TC_STATIC_es_setupcomplete_handler_success, TC_iot_easysetup_common_setup, TC_iot_easysetup_common_teardown),
            cmocka_unit_test(TC_st_conn_ownership_confirm_SUCCESS),
            cmocka_unit_test(TC_st_conn_ownership_confirm_DENY),
    };
    return cmocka_run_group_tests_name("iot_easysetup_d2d.c", tests, NULL, NULL);
}

int TEST_FUNC_iot_main()
{
    const struct CMUnitTest tests[] = {
            cmocka_unit_test(TC_st_conn_init_null_parameters),
            cmocka_unit_test(TC_st_conn_init_malloc_failure),
            cmocka_unit_test(TC_st_conn_init_wrong_onboarding_config),
            cmocka_unit_test(TC_st_conn_init_wrong_device_info),
            cmocka_unit_test(TC_st_conn_init_success),
            cmocka_unit_test(TC_st_conn_cleanup_invalid_parameters),
            cmocka_unit_test(TC_st_conn_cleanup_success),
            cmocka_unit_test(TC_easysetup_resources_create_delete_success),
            cmocka_unit_test(TC_do_status_report),
            cmocka_unit_test(TC_check_prov_data_validation),
    };
    return cmocka_run_group_tests_name("iot_main.c", tests, NULL, NULL);
}

int TEST_FUNC_iot_mqtt_client()
{
    const struct CMUnitTest tests[] = {
            cmocka_unit_test(TC_st_mqtt_create_success),
            cmocka_unit_test(TC_st_mqtt_create_failure),
            cmocka_unit_test(TC_st_mqtt_connect_with_connack_rc),
            cmocka_unit_test(TC_st_mqtt_disconnect_success),
            cmocka_unit_test(TC_st_mqtt_publish_success),
    };
    return cmocka_run_group_tests_name("iot_mqtt_client.c", tests, NULL, NULL);
}

int TEST_FUNC_iot_security_common(void)
{
    const struct CMUnitTest tests[] = {
            cmocka_unit_test(TC_iot_security_init_malloc_failure),
            cmocka_unit_test(TC_iot_security_init_success),
            cmocka_unit_test(TC_iot_security_deinit_null_parameters),
            cmocka_unit_test(TC_iot_security_deinit_success),
            cmocka_unit_test(TC_iot_security_check_context_is_valid_null_parameters),
            cmocka_unit_test(TC_iot_security_check_context_is_valid_success),
            cmocka_unit_test(TC_iot_security_check_backend_funcs_entry_is_valid_failure),
            cmocka_unit_test(TC_iot_security_check_backend_funcs_entry_is_valid_success),
    };
    return cmocka_run_group_tests_name("iot_security_common.c", tests, NULL, NULL);
}

int TEST_FUNC_iot_security_crypto(void)
{
    const struct CMUnitTest tests[] = {
            // pk
            cmocka_unit_test_setup_teardown(TC_iot_security_pk_init_null_parameters, TC_iot_security_pk_init_setup, TC_iot_security_pk_init_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_pk_init_malloc_failure, TC_iot_security_pk_init_setup, TC_iot_security_pk_init_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_pk_init_success, TC_iot_security_pk_init_setup, TC_iot_security_pk_init_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_pk_deinit_null_parameters, TC_iot_security_pk_setup, TC_iot_security_pk_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_pk_deinit_success, TC_iot_security_pk_init_setup, TC_iot_security_pk_init_teardown),
            cmocka_unit_test(TC_iot_security_pk_get_signature_len_failure),
            cmocka_unit_test(TC_iot_security_pk_get_signature_len_success),
            cmocka_unit_test_setup_teardown(TC_iot_security_pk_get_key_type_failure, TC_iot_security_pk_init_setup, TC_iot_security_pk_init_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_pk_get_key_type_success, TC_iot_security_pk_setup, TC_iot_security_pk_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_pk_sign_invalid_parameters, TC_iot_security_pk_setup, TC_iot_security_pk_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_pk_sign_null_parameters, TC_iot_security_pk_setup, TC_iot_security_pk_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_pk_sign_malloc_failure, TC_iot_security_pk_setup, TC_iot_security_pk_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_pk_sign_failure, TC_iot_security_pk_init_setup, TC_iot_security_pk_init_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_pk_verify_invalid_parameters, TC_iot_security_pk_setup, TC_iot_security_pk_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_pk_verify_null_parameters, TC_iot_security_pk_setup, TC_iot_security_pk_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_pk_verify_failure, TC_iot_security_pk_init_setup, TC_iot_security_pk_init_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_pk_success, TC_iot_security_pk_setup, TC_iot_security_pk_teardown),
            // cipher
            cmocka_unit_test_setup_teardown(TC_iot_security_cipher_init_null_parameters, TC_iot_security_cipher_init_setup, TC_iot_security_cipher_init_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_cipher_init_malloc_failure, TC_iot_security_cipher_init_setup, TC_iot_security_cipher_init_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_cipher_init_success, TC_iot_security_cipher_init_setup, TC_iot_security_cipher_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_cipher_deinit_null_parameters, TC_iot_security_cipher_setup, TC_iot_security_cipher_init_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_cipher_deinit_success, TC_iot_security_cipher_setup, TC_iot_security_cipher_init_teardown),
            cmocka_unit_test(TC_iot_security_cipher_get_align_size_failure),
            cmocka_unit_test(TC_iot_security_cipher_get_align_size_success),
            cmocka_unit_test_setup_teardown(TC_iot_security_cipher_set_params_invalid_parameters, TC_iot_security_cipher_setup, TC_iot_security_cipher_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_cipher_set_params_null_parameters, TC_iot_security_cipher_setup, TC_iot_security_cipher_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_cipher_set_params_success, TC_iot_security_cipher_setup, TC_iot_security_cipher_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_cipher_aes_encrypt_invalid_parameters, TC_iot_security_cipher_setup, TC_iot_security_cipher_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_cipher_aes_encrypt_null_parameters, TC_iot_security_cipher_setup, TC_iot_security_cipher_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_cipher_aes_encrypt_malloc_failure, TC_iot_security_cipher_setup, TC_iot_security_cipher_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_cipher_aes_encrypt_failure, TC_iot_security_cipher_init_setup, TC_iot_security_cipher_init_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_cipher_aes_decrypt_invalid_parameters, TC_iot_security_cipher_setup, TC_iot_security_cipher_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_cipher_aes_decrypt_null_parameters, TC_iot_security_cipher_setup, TC_iot_security_cipher_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_cipher_aes_decrypt_malloc_failure, TC_iot_security_cipher_setup, TC_iot_security_cipher_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_cipher_aes_decrypt_failure, TC_iot_security_cipher_init_setup, TC_iot_security_cipher_init_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_cipher_aes_success, TC_iot_security_cipher_setup, TC_iot_security_cipher_teardown),
    };
    return cmocka_run_group_tests_name("iot_security_crypto.c", tests, NULL, NULL);
}

int TEST_FUNC_iot_security_ecdh(void)
{
    const struct CMUnitTest tests[] = {
#if defined(CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_ED25519)
            cmocka_unit_test(TC_iot_security_ecdh_init_null_parameters),
            cmocka_unit_test_setup_teardown(TC_iot_security_ecdh_init_malloc_failure, TC_iot_security_ecdh_init_setup, TC_iot_security_ecdh_init_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_ecdh_init_success, TC_iot_security_ecdh_init_setup, TC_iot_security_ecdh_init_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_ecdh_set_params_null_parameters, TC_iot_security_ecdh_setup, TC_iot_security_ecdh_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_ecdh_set_params_invalid_parameters, TC_iot_security_ecdh_setup, TC_iot_security_ecdh_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_ecdh_set_params_success, TC_iot_security_ecdh_setup, TC_iot_security_ecdh_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_ecdh_compute_shared_secret_null_parameters, TC_iot_security_ecdh_setup, TC_iot_security_ecdh_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_ecdh_compute_shared_secret_malloc_failure, TC_iot_security_ecdh_setup, TC_iot_security_ecdh_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_ecdh_compute_shared_secret_failure, TC_iot_security_ecdh_init_setup, TC_iot_security_ecdh_init_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_ecdh_compute_shared_secret_success, TC_iot_security_ecdh_setup, TC_iot_security_ecdh_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_ecdh_and_dynamic_cipher, TC_iot_security_ecdh_setup, TC_iot_security_ecdh_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_ecdh_and_static_cipher, TC_iot_security_ecdh_setup, TC_iot_security_ecdh_teardown),
#endif
    };
    return cmocka_run_group_tests_name("iot_security_ecdh.c", tests, NULL, NULL);
}

int TEST_FUNC_iot_security_manager(void)
{
    const struct CMUnitTest tests[] = {
            cmocka_unit_test(TC_iot_security_manager_init_null_parameters),
            cmocka_unit_test(TC_iot_security_manager_init_success),
            cmocka_unit_test(TC_iot_security_manager_deinit_null_parameters),
            cmocka_unit_test(TC_iot_security_manager_deinit_success),
            cmocka_unit_test_setup_teardown(TC_iot_security_manager_set_key_null_parameters, TC_iot_security_manager_setup, TC_iot_security_manager_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_manager_set_key_invalid_parameters, TC_iot_security_manager_setup, TC_iot_security_manager_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_manager_set_key_success, TC_iot_security_manager_setup, TC_iot_security_manager_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_manager_get_key_null_parameters, TC_iot_security_manager_setup, TC_iot_security_manager_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_manager_get_key_invalid_parameters, TC_iot_security_manager_setup, TC_iot_security_manager_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_manager_get_key_alloc_failure, TC_iot_security_manager_setup, TC_iot_security_manager_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_manager_get_key_success, TC_iot_security_manager_setup, TC_iot_security_manager_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_manager_get_certificate_null_parameters, TC_iot_security_manager_setup, TC_iot_security_manager_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_manager_get_certificate_invalid_parameters, TC_iot_security_manager_setup, TC_iot_security_manager_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_manager_get_certificate_alloc_failure, TC_iot_security_manager_setup, TC_iot_security_manager_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_manager_get_certificate_success, TC_iot_security_manager_setup, TC_iot_security_manager_teardown),
    };
    return cmocka_run_group_tests_name("iot_security_certificate.c", tests, NULL, NULL);
}

int TEST_FUNC_iot_security_storage(void)
{
    const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup_teardown(TC_iot_security_storage_init_malloc_failure, TC_iot_security_storage_init_setup, TC_iot_security_storage_init_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_storage_init_null_parameters, TC_iot_security_storage_init_setup, TC_iot_security_storage_init_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_storage_init_success, TC_iot_security_storage_init_setup, TC_iot_security_storage_init_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_storage_deinit_null_parameters, TC_iot_security_storage_init_setup, TC_iot_security_storage_init_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_storage_deinit_success, TC_iot_security_storage_init_setup, TC_iot_security_storage_init_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_storage_read_malloc_failure, TC_iot_security_storage_setup, TC_iot_security_storage_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_storage_read_null_parameters, TC_iot_security_storage_setup, TC_iot_security_storage_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_storage_read_invalid_parameters, TC_iot_security_storage_setup, TC_iot_security_storage_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_storage_read_failure, TC_iot_security_storage_init_setup, TC_iot_security_storage_init_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_storage_read_success, TC_iot_security_storage_setup, TC_iot_security_storage_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_storage_write_null_parameters, TC_iot_security_storage_setup, TC_iot_security_storage_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_storage_write_invalid_parameters, TC_iot_security_storage_setup, TC_iot_security_storage_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_storage_write_failure, TC_iot_security_storage_setup, TC_iot_security_storage_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_storage_write_success, TC_iot_security_storage_setup, TC_iot_security_storage_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_storage_remove_null_parameters, TC_iot_security_storage_setup, TC_iot_security_storage_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_storage_remove_invalid_parameters, TC_iot_security_storage_setup, TC_iot_security_storage_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_storage_remove_failure, TC_iot_security_storage_setup, TC_iot_security_storage_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_security_storage_remove_success, TC_iot_security_storage_setup, TC_iot_security_storage_teardown),
    };
    return cmocka_run_group_tests_name("iot_security_storage.c", tests, NULL, NULL);
}

int TEST_FUNC_iot_security_helper(void)
{
    const struct CMUnitTest tests[] = {
            cmocka_unit_test(TC_iot_security_base64_buffer_size),
            cmocka_unit_test(TC_iot_security_base64_invalid_parameter),
            cmocka_unit_test(TC_iot_security_base64_encode_success),
            cmocka_unit_test(TC_iot_security_base64_decode_failure),
            cmocka_unit_test(TC_iot_security_base64_decode_success),
            cmocka_unit_test(TC_iot_security_base64_encode_urlsafe_success),
            cmocka_unit_test(TC_iot_security_base64_decode_urlsafe_alloc_failure),
            cmocka_unit_test(TC_iot_security_base64_decode_urlsafe_failure),
            cmocka_unit_test(TC_iot_security_base64_decode_urlsafe_success),
            cmocka_unit_test(TC_iot_security_sha256_failure),
            cmocka_unit_test(TC_iot_security_sha256_success),
    };
    return cmocka_run_group_tests_name("iot_security_helper_xxx.c", tests, NULL, NULL);
}

int TEST_FUNC_iot_security_helper_ed25519(void)
{
    const struct CMUnitTest tests[] = {
            cmocka_unit_test(TC_iot_security_ed25519_convert_pubkey_null_parameters),
            cmocka_unit_test(TC_iot_security_ed25519_convert_pubkey_success),
            cmocka_unit_test(TC_iot_security_ed25519_convert_seckey_null_parameters),
            cmocka_unit_test(TC_iot_security_ed25519_convert_seckey_success),
    };
    return cmocka_run_group_tests_name("iot_security_helper_ed25519.c", tests, NULL, NULL);
}

int TEST_FUNC_iot_security_software_be_bsp(void)
{
    const struct CMUnitTest tests[] = {
#if defined(CONFIG_STDK_IOT_CORE_SECURITY_BACKEND_SOFTWARE)
            cmocka_unit_test(TC_STATIC_iot_security_be_bsp_fs_storage_id2target_invalid_parameters),
            cmocka_unit_test(TC_STATIC_iot_security_be_bsp_fs_storage_id2target_success),
            cmocka_unit_test(TC_STATIC_iot_security_be_bsp_fs_storage_id2filename_invalid_parameters),
            cmocka_unit_test(TC_STATIC_iot_security_be_bsp_fs_storage_id2filename_success),
            cmocka_unit_test(TC_iot_security_be_bsp_fs_load_malloc_failure),
            cmocka_unit_test(TC_iot_security_be_bsp_fs_load_invalid_parameters),
            cmocka_unit_test(TC_iot_security_be_bsp_fs_load_success),
            cmocka_unit_test(TC_iot_security_be_bsp_fs_store_invalid_parameters),
            cmocka_unit_test(TC_iot_security_be_bsp_fs_store_success),
            cmocka_unit_test(TC_iot_security_be_bsp_fs_remove_invalid_parameters),
            cmocka_unit_test(TC_iot_security_be_bsp_fs_remove_success),
            cmocka_unit_test(TC_iot_security_be_bsp_init_null_parameters),
            cmocka_unit_test(TC_iot_security_be_bsp_init_success),
#endif
    };
    return cmocka_run_group_tests_name("iot_security_be_bsp.c", tests, NULL, NULL);
}

int TEST_FUNC_iot_wt(void)
{
    const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup_teardown(TC_iot_wt_create_null_parameters, TC_iot_wt_create_memleak_detect_setup, TC_iot_wt_create_memleak_detect_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_wt_create_success, TC_iot_wt_create_memleak_detect_setup, TC_iot_wt_create_memleak_detect_teardown),
    };
    return cmocka_run_group_tests_name("iot_wt.c", tests, NULL, NULL);
}

int TEST_FUNC_iot_easysetup_httpd(void)
{
    const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup_teardown(TC_iot_easysetup_httpd_invalid_request,
                                            TC_iot_easysetup_httpd_setup, TC_iot_easysetup_httpd_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_easysetup_httpd_deviceinfo_success,
                                            TC_iot_easysetup_httpd_setup, TC_iot_easysetup_httpd_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_easysetup_httpd_keyinfo_single_transfer_success,
                                            TC_iot_easysetup_httpd_setup, TC_iot_easysetup_httpd_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_easysetup_httpd_keyinfo_separated_transfer_success,
                                            TC_iot_easysetup_httpd_setup, TC_iot_easysetup_httpd_teardown),
    };
    return cmocka_run_group_tests_name("iot_easysetup_tcp_httpd.c", tests, NULL, NULL);
}

int TEST_FUNC_iot_dump_log(void)
{
    const struct CMUnitTest tests[] = {
            cmocka_unit_test(TC_iot_dump_create_dump_state_failure),
            cmocka_unit_test(TC_iot_dump_create_dump_state_success),
            cmocka_unit_test(TC_iot_dump_log),
    };
    return cmocka_run_group_tests_name("iot_dump_log.c", tests, NULL, NULL);
}

int TEST_FUNC_iot_easysetup_st_mqtt(void)
{
    const struct CMUnitTest tests[] = {
            cmocka_unit_test(TC_STATIC_iot_es_mqtt_registration_SUCCESS),
            cmocka_unit_test(TC_STATIC_iot_parse_sequence_num_SUCCESS),
            cmocka_unit_test(TC_STATIC_iot_parse_sequence_num_FAILURE),
            cmocka_unit_test(TC_STATIC_iot_mqtt_registration_client_callback_SUCCESS),
    };
    return cmocka_run_group_tests_name("iot_easysetup_st_mqtt.c", tests, NULL, NULL);
}

int TEST_FUNC_iot_easysetup_http_parser(void)
{
    const struct CMUnitTest tests[] = {
            cmocka_unit_test(TC_es_msg_parser_VALID_GET_METHOD),
            cmocka_unit_test(TC_es_msg_parser_INVALID_GET_METHOD),
            cmocka_unit_test(TC_es_msg_parser_VALID_POST_METHOD),
            cmocka_unit_test(TC_es_msg_parser_INVALID_POST_METHOD),
    };
    return cmocka_run_group_tests_name("iot_easysetup_http_parser.c", tests, NULL, NULL);
}

int TEST_FUNC_iot_easysetup_http(void)
{
	const struct CMUnitTest tests[] = {
			cmocka_unit_test(TC_iot_easysetup_gen_post_payload_NULL_REQUEST_QUEUE),
			cmocka_unit_test(TC_iot_easysetup_gen_post_payload_NULL_IN_PAYLOAD),
			cmocka_unit_test(TC_iot_easysetup_gen_post_payload_CMD_INVALID_STEP),
			cmocka_unit_test(TC_iot_easysetup_gen_post_payload_CMD_INVALID_SEQUENCE),
			cmocka_unit_test(TC_iot_easysetup_gen_get_payload_CMD_INVALID_STEP),
			cmocka_unit_test(TC_iot_easysetup_gen_get_payload_CMD_INVALID_SEQUENCE),
			cmocka_unit_test(TC_iot_easysetup_gen_get_payload_STATE_UPDATE_FAILURE),
	};
	return cmocka_run_group_tests_name("iot_easysetup_http.c", tests, NULL, NULL);
}

int main(void) {
    int err = 0;

    err += TEST_FUNC_iot_api();
    err += TEST_FUNC_iot_capability();
    err += TEST_FUNC_iot_nv_data();
    err += TEST_FUNC_iot_util();
    err += TEST_FUNC_iot_uuid();
    err += TEST_FUNC_iot_easysetup_d2d();
    err += TEST_FUNC_iot_main();
    err += TEST_FUNC_iot_mqtt_client();
    err += TEST_FUNC_iot_security_common();
    err += TEST_FUNC_iot_security_crypto();
    err += TEST_FUNC_iot_security_ecdh();
    err += TEST_FUNC_iot_security_storage();
    err += TEST_FUNC_iot_security_manager();
    err += TEST_FUNC_iot_security_helper();
    err += TEST_FUNC_iot_security_helper_ed25519();
    err += TEST_FUNC_iot_security_software_be_bsp();
    err += TEST_FUNC_iot_wt();
    err += TEST_FUNC_iot_easysetup_httpd();
    err += TEST_FUNC_iot_dump_log();
    err += TEST_FUNC_iot_easysetup_st_mqtt();
    err += TEST_FUNC_iot_easysetup_http_parser();
    err += TEST_FUNC_iot_easysetup_http();

    return err;
}
