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
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include "TCs.h"

int main(void) {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test(TC_iot_util_get_random_uuid_success),
            cmocka_unit_test(TC_iot_util_get_random_uuid_null_parameter),
            cmocka_unit_test(TC_iot_util_convert_str_mac_success),
            cmocka_unit_test(TC_iot_util_convert_str_mac_invalid_parameters),
            cmocka_unit_test(TC_iot_util_convert_str_uuid_success),
            cmocka_unit_test(TC_iot_util_convert_str_uuid_null_parameters),
            cmocka_unit_test(TC_iot_api_device_info_load_null_parameters),
            cmocka_unit_test(TC_iot_api_device_info_load_success),
            cmocka_unit_test(TC_iot_api_device_info_load_internal_failure),
            cmocka_unit_test(TC_iot_api_device_info_load_without_firmware_version),
            cmocka_unit_test(TC_iot_api_onboarding_config_load_null_parameters),
            cmocka_unit_test(TC_iot_api_onboarding_config_load_template_parameters),
            cmocka_unit_test(TC_iot_api_onboarding_config_load_success),
            cmocka_unit_test(TC_iot_api_onboarding_config_load_internal_failure),
            cmocka_unit_test(TC_iot_api_onboarding_config_without_mnid),
            cmocka_unit_test(TC_iot_get_time_in_sec_null_parameters),
            cmocka_unit_test(TC_iot_get_time_in_sec_success),
            cmocka_unit_test(TC_iot_get_time_in_ms_null_parmaeters),
            cmocka_unit_test(TC_iot_get_time_in_ms_success),
            cmocka_unit_test(TC_iot_get_time_in_sec_by_long_null_parameters),
            cmocka_unit_test(TC_iot_get_time_in_sec_by_long_success),
            cmocka_unit_test(TC_iot_uuid_from_mac),
            cmocka_unit_test(TC_iot_uuid_from_mac_internal_failure),
            cmocka_unit_test(TC_iot_random_uuid_from_mac),
            cmocka_unit_test(TC_iot_random_uuid_from_mac_internal_failure),
            cmocka_unit_test_teardown(TC_st_cap_attr_create_int_null_attribute, TC_iot_capability_teardown),
            cmocka_unit_test_teardown(TC_st_cap_attr_create_int_null_unit, TC_iot_capability_teardown),
            cmocka_unit_test_teardown(TC_st_cap_attr_create_int_with_unit, TC_iot_capability_teardown),
            cmocka_unit_test_teardown(TC_st_cap_attr_create_int_internal_failure, TC_iot_capability_teardown),
            cmocka_unit_test_teardown(TC_st_cap_attr_create_number_null_attribute, TC_iot_capability_teardown),
            cmocka_unit_test_teardown(TC_st_cap_attr_create_number_null_unit, TC_iot_capability_teardown),
            cmocka_unit_test_teardown(TC_st_cap_attr_create_number_with_unit, TC_iot_capability_teardown),
            cmocka_unit_test_teardown(TC_st_cap_attr_create_number_internal_failure, TC_iot_capability_teardown),
            cmocka_unit_test(TC_iot_crypto_pk_init_null_parameter),
            cmocka_unit_test(TC_iot_crypto_pk_init_ed25519),
            cmocka_unit_test(TC_iot_crypto_pk_init_invalid_type),
            cmocka_unit_test(TC_iot_crypto_pk_free),
            cmocka_unit_test_setup_teardown(TC_iot_nv_get_root_certificate_success, TC_iot_nv_data_setup, TC_iot_nv_data_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_nv_get_root_certificate_null_parameters, TC_iot_nv_data_setup, TC_iot_nv_data_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_nv_get_root_certificate_internal_failure, TC_iot_nv_data_setup, TC_iot_nv_data_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_nv_get_public_key_success, TC_iot_nv_data_setup, TC_iot_nv_data_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_nv_get_public_key_null_parameters, TC_iot_nv_data_setup, TC_iot_nv_data_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_nv_get_serial_number_success, TC_iot_nv_data_setup, TC_iot_nv_data_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_nv_get_serial_number_null_parameters, TC_iot_nv_data_setup, TC_iot_nv_data_teardown),
            cmocka_unit_test_setup_teardown(TC_iot_es_crypto_load_pk_success, TC_iot_easysetup_crypto_setup, TC_iot_easysetup_crypto_teardown),
            cmocka_unit_test(TC_iot_es_crypto_load_pk_invalid_parameters),
            cmocka_unit_test(TC_iot_es_crypto_init_pk),
            cmocka_unit_test(TC_iot_easysetup_create_ssid_null_parameters),
            cmocka_unit_test_setup_teardown(TC_iot_easysetup_create_ssid_success, TC_iot_easysetup_create_ssid_setup, TC_iot_easysetup_create_ssid_teardown),
            cmocka_unit_test(TC_iot_easysetup_request_handler_null_parameters),
            cmocka_unit_test_setup_teardown(TC_easysetup_d2d_get_deviceinfo_success, TC_easysetup_d2d_setup, TC_easysetup_d2d_teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}