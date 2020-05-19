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
    };
    return cmocka_run_group_tests_name("iot_api.c", tests, NULL, NULL);
}

int TEST_FUNC_iot_capability(void)
{
    const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup_teardown(TC_st_cap_attr_create_int_null_attribute, TC_iot_capability_setup, TC_iot_capability_teardown),
            cmocka_unit_test_setup_teardown(TC_st_cap_attr_create_int_null_unit, TC_iot_capability_setup, TC_iot_capability_teardown),
            cmocka_unit_test_setup_teardown(TC_st_cap_attr_create_int_with_unit, TC_iot_capability_setup, TC_iot_capability_teardown),
            cmocka_unit_test_setup_teardown(TC_st_cap_attr_create_int_internal_failure, TC_iot_capability_setup, TC_iot_capability_teardown),
            cmocka_unit_test_setup_teardown(TC_st_cap_attr_create_number_null_attribute, TC_iot_capability_setup, TC_iot_capability_teardown),
            cmocka_unit_test_setup_teardown(TC_st_cap_attr_create_number_null_unit, TC_iot_capability_setup, TC_iot_capability_teardown),
            cmocka_unit_test_setup_teardown(TC_st_cap_attr_create_number_with_unit, TC_iot_capability_setup, TC_iot_capability_teardown),
            cmocka_unit_test_setup_teardown(TC_st_cap_attr_create_number_internal_failure, TC_iot_capability_setup, TC_iot_capability_teardown),
            cmocka_unit_test_setup_teardown(TC_st_cap_attr_create_string_null_unit, TC_iot_capability_setup, TC_iot_capability_teardown),
            cmocka_unit_test_setup_teardown(TC_st_cap_attr_create_string_with_unit, TC_iot_capability_setup, TC_iot_capability_teardown),
            cmocka_unit_test_setup_teardown(TC_st_cap_attr_create_string_internal_failure, TC_iot_capability_setup, TC_iot_capability_teardown),
            cmocka_unit_test_setup_teardown(TC_st_cap_attr_create_string_null_parameters, TC_iot_capability_setup, TC_iot_capability_teardown),
            cmocka_unit_test_setup_teardown(TC_st_cap_attr_create_with_unit_and_data, TC_iot_capability_setup, TC_iot_capability_teardown),
            cmocka_unit_test_setup_teardown(TC_st_cap_handle_init_invalid_argument, TC_iot_capability_setup, TC_iot_capability_teardown),
            cmocka_unit_test_setup_teardown(TC_st_cap_handle_init_internal_failure, TC_iot_capability_setup, TC_iot_capability_teardown),
            cmocka_unit_test_setup_teardown(TC_st_cap_handle_init_success, TC_iot_capability_setup, TC_iot_capability_teardown),
            cmocka_unit_test_setup_teardown(TC_st_conn_set_noti_cb_null_parameters, TC_iot_capability_setup, TC_iot_capability_teardown),
            cmocka_unit_test_setup_teardown(TC_st_conn_set_noti_cb_success, TC_iot_capability_setup, TC_iot_capability_teardown),
            cmocka_unit_test_setup_teardown(TC_st_cap_cmd_set_cb_invalid_parameters, TC_iot_capability_setup, TC_iot_capability_teardown),
            cmocka_unit_test_setup_teardown(TC_st_cap_cmd_set_cb_success, TC_iot_capability_setup, TC_iot_capability_teardown),
            cmocka_unit_test_setup_teardown(TC_st_cap_attr_send_success, TC_iot_capability_setup, TC_iot_capability_teardown),
            cmocka_unit_test_setup_teardown(TC_st_cap_attr_send_invalid_parameter, TC_iot_capability_setup, TC_iot_capability_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_cap_sub_cb_success, TC_iot_capability_setup, TC_iot_capability_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_noti_sub_cb_rate_limit_reached_success, TC_iot_capability_setup, TC_iot_capability_teardown),
    };
    return cmocka_run_group_tests_name("iot_capability.c", tests, NULL, NULL);
}

int TEST_FUNC_iot_crypto(void)
{
    const struct CMUnitTest tests[] = {
            cmocka_unit_test(TC_iot_crypto_pk_init_null_parameter),
            cmocka_unit_test(TC_iot_crypto_pk_init_ed25519),
            cmocka_unit_test(TC_iot_crypto_pk_init_invalid_type),
            cmocka_unit_test(TC_iot_crypto_pk_free),
            cmocka_unit_test_setup_teardown(TC_iot_crypto_pk_ed25519_success, TC_iot_crypto_pk_setup, TC_iot_crypto_pk_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_crypto_cipher_aes_null_parameter, TC_iot_crypto_cipher_aes_setup, TC_iot_crypto_cipher_aes_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_crypto_cipher_aes_invalid_parameter, TC_iot_crypto_cipher_aes_setup, TC_iot_crypto_cipher_aes_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_crypto_cipher_aes_success, TC_iot_crypto_cipher_aes_setup, TC_iot_crypto_cipher_aes_teardown),
            cmocka_unit_test(TC_iot_crypto_cipher_get_align_size),
            cmocka_unit_test_setup_teardown(TC_iot_crypto_ecdh_invalid_parameter, TC_iot_crypto_ecdh_setup, TC_iot_crypto_ecdh_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_crypto_ecdh_success, TC_iot_crypto_ecdh_setup, TC_iot_crypto_ecdh_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_crypto_ed25519_keypair_invalid_parameter, TC_iot_crypto_ed25519_keypair_setup, TC_iot_crypto_ed25519_keypair_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_crypto_ed25519_keypair_success, TC_iot_crypto_ed25519_keypair_setup, TC_iot_crypto_ed25519_keypair_teardown),
            cmocka_unit_test(TC_iot_crypto_ed25519_convert_invalid_parameter),
            cmocka_unit_test(TC_iot_crypto_ed25519_convert_success),
            cmocka_unit_test(TC_iot_crypto_base64_invalid_parameter),
            cmocka_unit_test(TC_iot_crypto_base64_failure),
            cmocka_unit_test(TC_iot_crypto_base64_encode_success),
            cmocka_unit_test(TC_iot_crypto_base64_decode_success),
            cmocka_unit_test(TC_iot_crypto_base64_urlsafe_encode_success),
            cmocka_unit_test(TC_iot_crypto_base64_urlsafe_decode_success),
            cmocka_unit_test(TC_iot_crypto_base64_buffer_size),
    };
    return cmocka_run_group_tests_name("iot_crypto.c", tests, NULL, NULL);
}

int TEST_FUNC_iot_nv_data(void)
{
    const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup_teardown(TC_iot_nv_get_wifi_prov_data_success, TC_iot_nv_data_setup, TC_iot_nv_data_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_nv_get_wifi_prov_data_null_parameters, TC_iot_nv_data_setup, TC_iot_nv_data_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_nv_get_root_certificate_success, TC_iot_nv_data_setup, TC_iot_nv_data_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_nv_get_root_certificate_null_parameters, TC_iot_nv_data_setup, TC_iot_nv_data_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_nv_get_root_certificate_internal_failure, TC_iot_nv_data_setup, TC_iot_nv_data_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_nv_get_client_certificate_null_parameters, TC_iot_nv_data_setup, TC_iot_nv_data_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_nv_get_public_key_success, TC_iot_nv_data_setup, TC_iot_nv_data_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_nv_get_public_key_null_parameters, TC_iot_nv_data_setup, TC_iot_nv_data_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_nv_get_serial_number_success, TC_iot_nv_data_setup, TC_iot_nv_data_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_nv_get_serial_number_null_parameters, TC_iot_nv_data_setup, TC_iot_nv_data_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_nv_get_device_id_null_parameters, TC_iot_nv_data_setup, TC_iot_nv_data_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_nv_set_device_id_null_parameter, TC_iot_nv_data_setup, TC_iot_nv_data_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_nv_get_set_erase_device_id_success, TC_iot_nv_data_setup, TC_iot_nv_data_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_nv_erase_internal_failure, TC_iot_nv_data_setup, TC_iot_nv_data_teardown),
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
            cmocka_unit_test_setup_teardown(TC_iot_easysetup_create_ssid_success, TC_iot_easysetup_d2d_setup, TC_iot_easysetup_d2d_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_easysetup_request_handler_invalid_parameters, TC_iot_easysetup_d2d_setup, TC_iot_easysetup_d2d_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_easysetup_request_handler_step_deviceinfo, TC_iot_easysetup_d2d_setup, TC_iot_easysetup_d2d_teardown),
            cmocka_unit_test(TC_STATIC_es_deviceinfo_handler_null_parameter),
            cmocka_unit_test(TC_STATIC_es_crypto_cipher_gen_iv_success),
            cmocka_unit_test_setup_teardown(TC_STATIC_es_deviceinfo_handler_success, TC_iot_easysetup_d2d_setup, TC_iot_easysetup_d2d_teardown),
            cmocka_unit_test_setup_teardown(TC_STATIC_es_keyinfo_handler_success, TC_iot_easysetup_d2d_setup, TC_iot_easysetup_d2d_teardown),
            cmocka_unit_test_setup_teardown(TC_STATIC_es_keyinfo_handler_success_with_y2038, TC_iot_easysetup_d2d_setup, TC_iot_easysetup_d2d_teardown),
            cmocka_unit_test_setup_teardown(TC_STATIC_es_wifiprovisioninginfo_handler_success, TC_iot_easysetup_d2d_setup, TC_iot_easysetup_d2d_teardown),
            cmocka_unit_test_setup_teardown(TC_STATIC_es_wifiprovisioninginfo_handler_success_without_authtype, TC_iot_easysetup_d2d_setup, TC_iot_easysetup_d2d_teardown),
            cmocka_unit_test_setup_teardown(TC_STATIC_es_wifiscaninfo_handler_invalid_parameters, TC_iot_easysetup_d2d_setup, TC_iot_easysetup_d2d_teardown),
            cmocka_unit_test_setup_teardown(TC_STATIC_es_wifiscaninfo_handler_success, TC_iot_easysetup_d2d_setup, TC_iot_easysetup_d2d_teardown),
            cmocka_unit_test_setup_teardown(TC_STATIC_es_confirminfo_handler_null_parameters, TC_iot_easysetup_d2d_setup, TC_iot_easysetup_d2d_teardown),
            cmocka_unit_test_setup_teardown(TC_STATIC_es_confirminfo_handler_out_ranged_otm_feature, TC_iot_easysetup_d2d_setup, TC_iot_easysetup_d2d_teardown),
            cmocka_unit_test_setup_teardown(TC_STATIC_es_confirminfo_handler_justworks_and_pin, TC_iot_easysetup_d2d_setup, TC_iot_easysetup_d2d_teardown),
            cmocka_unit_test_setup_teardown(TC_STATIC_es_confirminfo_handler_qr_code, TC_iot_easysetup_d2d_setup, TC_iot_easysetup_d2d_teardown),
            cmocka_unit_test_setup_teardown(TC_STATIC_es_confirminfo_handler_button, TC_iot_easysetup_d2d_setup, TC_iot_easysetup_d2d_teardown),
            cmocka_unit_test_setup_teardown(TC_STATIC_es_confirm_handler_success, TC_iot_easysetup_d2d_setup, TC_iot_easysetup_d2d_teardown),
            cmocka_unit_test_setup_teardown(TC_STATIC_es_confirm_handler_invalid_pin, TC_iot_easysetup_d2d_setup, TC_iot_easysetup_d2d_teardown),
            cmocka_unit_test_setup_teardown(TC_STATIC_es_confirm_handler_non_pin_otm, TC_iot_easysetup_d2d_setup, TC_iot_easysetup_d2d_teardown),
            cmocka_unit_test_setup_teardown(TC_STATIC_es_confirm_handler_invalid_payload, TC_iot_easysetup_d2d_setup, TC_iot_easysetup_d2d_teardown),
            cmocka_unit_test_setup_teardown(TC_STATIC_es_setupcomplete_handler_success, TC_iot_easysetup_d2d_setup, TC_iot_easysetup_d2d_teardown),
    };
    return cmocka_run_group_tests_name("iot_easysetup_d2d.c", tests, NULL, NULL);
}

int TEST_FUNC_iot_easysetup_crypto(void)
{
    const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup_teardown(TC_iot_es_crypto_load_pk_success, TC_iot_easysetup_crypto_setup, TC_iot_easysetup_crypto_teardown),
            cmocka_unit_test(TC_iot_es_crypto_load_pk_invalid_parameters),
            cmocka_unit_test(TC_iot_es_crypto_init_pk),
    };
    return cmocka_run_group_tests_name("iot_easysetup_crypto.c", tests, NULL, NULL);

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


#if CONFIG_STDK_IOT_CORE_SECURITY_BACKEND == SOFTWARE
int TEST_FUNC_iot_security_software_be_bsp(void)
{
    const struct CMUnitTest tests[] = {
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
    };
    return cmocka_run_group_tests_name("iot_security_be_bsp.c", tests, NULL, NULL);
}
#endif

int TEST_FUNC_iot_wt(void)
{
    const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup_teardown(TC_iot_wt_create_null_parameters, TC_iot_wt_create_memleak_detect_setup, TC_iot_wt_create_memleak_detect_teardown),
    };
    return cmocka_run_group_tests_name("iot_wt.c", tests, NULL, NULL);
}

int TEST_FUNC_iot_easysetup_httpd(void)
{
    const struct CMUnitTest tests[] = {
            cmocka_unit_test(TC_iot_easysetup_httpd_invalid_request),
    };
    return cmocka_run_group_tests_name("iot_easysetup_tcp_httpd.c", tests, TC_iot_easysetup_httpd_group_setup, TC_iot_easysetup_httpd_group_teardown);
}

int main(void) {
    int err = 0;

    err += TEST_FUNC_iot_api();
    err += TEST_FUNC_iot_capability();
    err += TEST_FUNC_iot_crypto();
    err += TEST_FUNC_iot_nv_data();
    err += TEST_FUNC_iot_util();
    err += TEST_FUNC_iot_uuid();
    err += TEST_FUNC_iot_easysetup_d2d();
    err += TEST_FUNC_iot_easysetup_crypto();
    err += TEST_FUNC_iot_main();
    err += TEST_FUNC_iot_mqtt_client();
    err += TEST_FUNC_iot_security_common();
#if defined(CONFIG_STDK_IOT_CORE_SECURITY_BACKEND_SOFTWARE)
    err += TEST_FUNC_iot_security_software_be_bsp();
#endif
    err += TEST_FUNC_iot_wt();
    err += TEST_FUNC_iot_easysetup_httpd();

    return err;
}
