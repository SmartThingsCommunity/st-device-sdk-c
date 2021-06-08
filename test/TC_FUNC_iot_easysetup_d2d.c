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
#include <string.h>
#include <iot_error.h>
#include <iot_easysetup.h>
#include <iot_nv_data.h>
#include <iot_internal.h>
#include <JSON.h>
#include <bsp/iot_bsp_random.h>
#include <sys/types.h>
#include <regex.h>
#include <errno.h>
#include <iot_util.h>
#include <iot_debug.h>
#include "TC_MOCK_functions.h"
#include "TC_UTIL_easysetup_common.h"

#define UNUSED(x) (void**)(x)

static const char sample_ssid[] = "STDK_E4fTST0016LWpcd226";
static char sample_hashed_sn_b64url[] = "LWpcna0H5C-NEFcoRXRRBUWFqeU1XmOeyaigeYcxl1Q=";

void TC_iot_easysetup_create_ssid_null_parameters(void **state)
{
    iot_error_t err;
    char ssid[33];
    struct iot_devconf_prov_data devconf;
    UNUSED(state);

    // When: All parameters null
    err = iot_easysetup_create_ssid(NULL, NULL, 0);
    // Then: returns error
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // When: devconf is null
    err = iot_easysetup_create_ssid(NULL, ssid, sizeof(ssid));
    // Then: returns error
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // When: ssid is null
    err = iot_easysetup_create_ssid(&devconf, NULL, 0);
    // Then: returns error
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_easysetup_create_ssid_success(void **state)
{
    iot_error_t err;
    char ssid[33];
    struct iot_context *context = (struct iot_context *)*state;
    struct iot_devconf_prov_data *devconf;

    // Given
    devconf = &context->devconf;
    // When: valid parameters
    err = iot_easysetup_create_ssid(devconf, ssid, sizeof(ssid));
    // Then: returns success
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_string_equal(ssid, sample_ssid);
    assert_string_equal(devconf->hashed_sn, sample_hashed_sn_b64url);
}

void TC_iot_easysetup_request_handler_invalid_parameters(void **state)
{
    struct iot_context *context;
    iot_error_t err;
    int rc;
    struct iot_easysetup_payload request;
    struct iot_easysetup_payload response;

    // Given: context is null
    request.step = IOT_EASYSETUP_STEP_DEVICEINFO;
    request.payload = NULL;
    request.err = IOT_ERROR_NONE;
    context = NULL;
    // When
    err = iot_easysetup_request_handler(context, request);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Given: over ranged step
    request.step = IOT_EASYSETUP_STEP_LOG_GET_DUMP + 1;
    request.payload = NULL;
    request.err = IOT_ERROR_NONE;
    context = (struct iot_context *)*state;
    context->easysetup_resp_queue = iot_os_queue_create(1, sizeof(struct iot_easysetup_payload));
    context->iot_events = iot_os_eventgroup_create();
    // When
    err = iot_easysetup_request_handler(context, request);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    rc = iot_os_queue_receive(context->easysetup_resp_queue, &response, 0);
    assert_true(rc > 0);
    assert_int_equal(response.err, IOT_ERROR_EASYSETUP_INTERNAL_SERVER_ERROR);
    // Teardown
    iot_os_queue_delete(context->easysetup_resp_queue);
    iot_os_eventgroup_delete(context->iot_events);
}
static void assert_deviceinfo(char *payload, char *expected_firmware_version, char *expected_hashed_sn);

void TC_iot_easysetup_request_handler_step_deviceinfo(void **state)
{
    struct iot_context *context;
    iot_error_t err;
    int rc;
    struct iot_easysetup_payload request;
    struct iot_easysetup_payload response;
    struct iot_devconf_prov_data *devconf;

    // Given: deviceinfo
    request.step = IOT_EASYSETUP_STEP_DEVICEINFO;
    request.payload = NULL;
    request.err = IOT_ERROR_NONE;
    context = (struct iot_context *)*state;
    devconf = &context->devconf;
    devconf->hashed_sn = sample_hashed_sn_b64url;
    context->easysetup_resp_queue = iot_os_queue_create(1, sizeof(struct iot_easysetup_payload));
    context->iot_events = iot_os_eventgroup_create();
    // When
    err = iot_easysetup_request_handler(context, request);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    rc = iot_os_queue_receive(context->easysetup_resp_queue, &response, 0);
    assert_true(rc > 0);
    assert_int_equal(response.err, IOT_ERROR_NONE);
    assert_deviceinfo(response.payload, TEST_FIRMWARE_VERSION, sample_hashed_sn_b64url);
    // Teardown
    iot_os_queue_delete(context->easysetup_resp_queue);
    iot_os_eventgroup_delete(context->iot_events);
    free(response.payload);
}

// Static function declare for test
extern iot_error_t _es_deviceinfo_handler(struct iot_context *ctx, char **out_payload);

void TC_STATIC_es_deviceinfo_handler_null_parameter(void **state)
{
    iot_error_t err;
    struct iot_context *context;
    char *out_payload = NULL;
    UNUSED(state);

    // Given
    context = NULL;
    // When
    err = _es_deviceinfo_handler(context, &out_payload);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_STATIC_es_deviceinfo_handler_success(void **state)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;
    struct iot_devconf_prov_data *devconf;

    // Given
    context = (struct iot_context *)*state;
    devconf = &context->devconf;
    devconf->hashed_sn = sample_hashed_sn_b64url;
    // When
    err = _es_deviceinfo_handler(context, &out_payload);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_deviceinfo(out_payload, TEST_FIRMWARE_VERSION, sample_hashed_sn_b64url);

    // Local teardown
    free(out_payload);
}

// Static function of STDK declared to test
extern iot_error_t _es_keyinfo_handler(struct iot_context *ctx, char *input_data, char **output_data);
extern iot_error_t _es_crypto_cipher_gen_iv(iot_security_buffer_t *iv_buffer);

void TC_STATIC_es_crypto_cipher_gen_iv_success(void **state)
{
    iot_error_t err;
    iot_security_buffer_t iv_buffer = {0};
    UNUSED(state);

    // When
    err = _es_crypto_cipher_gen_iv(&iv_buffer);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_iv_buffer(iv_buffer);
}

void TC_STATIC_es_keyinfo_handler_success(void **state)
{
    iot_error_t err;
    char *out_payload = NULL;
    char *in_payload = NULL;
    struct iot_context *context;
    iot_security_cipher_params_t *device_cipher;
    iot_security_cipher_params_t *server_cipher;
    char *time_to_set;

    // Given: time is under 32bit time_t (Y2038)
    context = (struct iot_context *)*state;
    device_cipher = _generate_device_cipher(NULL, 0);
    assert_non_null(device_cipher);
    err = iot_security_cipher_set_params(context->easysetup_security_context, device_cipher);
    assert_int_equal(err, IOT_ERROR_NONE);
    server_cipher = _generate_server_cipher(device_cipher->iv.p, device_cipher->iv.len);
    assert_non_null(server_cipher);
    time_to_set = calloc(sizeof(char), 11);
    assert_non_null(time_to_set);
    in_payload = _generate_post_keyinfo_payload(2020, time_to_set, 11);
    expect_string(__wrap_iot_bsp_system_set_time_in_sec, time_in_sec, time_to_set);
    // When
    err = _es_keyinfo_handler(context, in_payload, &out_payload);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(out_payload);
    assert_keyinfo(out_payload, server_cipher, IOT_OVF_TYPE_BUTTON);

    // Local teardown
    _free_cipher(device_cipher);
    _free_cipher(server_cipher);
    free(out_payload);
    free(in_payload);
    free(time_to_set);
}

void TC_STATIC_es_keyinfo_handler_success_with_y2038(void **state)
{
    iot_error_t err;
    char *out_payload = NULL;
    char *in_payload = NULL;
    struct iot_context *context;
    iot_security_cipher_params_t *device_cipher;
    iot_security_cipher_params_t *server_cipher;
    char *time_to_set;

    // Given: time is over 32bit time_t (Y2038)
    context = (struct iot_context *)*state;
    device_cipher = _generate_device_cipher(NULL, 0);
    assert_non_null(device_cipher);
    err = iot_security_cipher_set_params(context->easysetup_security_context, device_cipher);
    assert_int_equal(err, IOT_ERROR_NONE);
    server_cipher = _generate_server_cipher(device_cipher->iv.p, device_cipher->iv.len);
    assert_non_null(server_cipher);
    time_to_set = calloc(sizeof(char), 11);
    assert_non_null(time_to_set);
    in_payload = _generate_post_keyinfo_payload(2038, time_to_set, 11);
    expect_string(__wrap_iot_bsp_system_set_time_in_sec, time_in_sec, time_to_set);
    // When
    err = _es_keyinfo_handler(context, in_payload, &out_payload);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(out_payload);
    assert_keyinfo(out_payload, server_cipher, IOT_OVF_TYPE_BUTTON);

    // Local teardown
    _free_cipher(device_cipher);
    _free_cipher(server_cipher);
    free(out_payload);
    free(in_payload);
    free(time_to_set);
}

struct test_wifi_provisioning_data {
    char *ssid;
    char *password;
    char *mac_address;
    int auth_type;
    char *broker_url;
    char *broker_domain;
    int broker_port;
    char *device_name;
};

// Static function of STDK declared to test
extern iot_error_t _es_wifiprovisioninginfo_handler(struct iot_context *ctx, char *input_data, char **output_data);

// static functions for test
static char* _generate_post_wifiprovisioninginfo_payload(iot_security_cipher_params_t *cipher, struct test_wifi_provisioning_data prov);
static void assert_lookup_id(const char *payload, iot_security_cipher_params_t *cipher);
static void assert_wifi_provisioning(struct iot_context *context, struct test_wifi_provisioning_data prov);

void TC_STATIC_es_wifiprovisioninginfo_handler_success(void **state)
{
    iot_error_t err;
    char *out_payload = NULL;
    char *in_payload = NULL;
    struct iot_context *context;
    iot_security_cipher_params_t *server_cipher;
    iot_security_cipher_params_t *device_cipher;
    unsigned char device_mac[IOT_WIFI_MAX_BSSID_LEN] = { 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x01 };
    struct test_wifi_provisioning_data wifi_prov = {
            .ssid = "fakeSsid_05_XXXXXX",
            .password = "fakePassword",
            .mac_address = "21:32:43:54:65:76",
            .auth_type = IOT_WIFI_AUTH_WPA_WPA2_PSK,
            .broker_url = "https://test.domain.com:5676",
            .device_name = "fakeDevice",
    };
    struct test_wifi_provisioning_data expected_wifi_prov = {
            .ssid = "fakeSsid_05_XXXXXX",
            .password = "fakePassword",
            .mac_address = "21:32:43:54:65:76",
            .auth_type = IOT_WIFI_AUTH_WPA_WPA2_PSK,
            .broker_domain = "test.domain.com",
            .broker_port = 5676,
            .device_name = "fakeDevice",
    };

    // Given
    context = (struct iot_context *)*state;
    device_cipher = _generate_device_cipher(NULL, 0);
    assert_non_null(device_cipher);
    err = iot_security_cipher_set_params(context->easysetup_security_context, device_cipher);
    assert_int_equal(err, IOT_ERROR_NONE);
    server_cipher = _generate_server_cipher(device_cipher->iv.p, device_cipher->iv.len);
    assert_non_null(server_cipher);
    in_payload = _generate_post_wifiprovisioninginfo_payload(server_cipher, wifi_prov);
    will_return(__wrap_iot_bsp_wifi_get_mac, cast_ptr_to_largest_integral_type(device_mac));
    will_return(__wrap_iot_bsp_wifi_get_mac, IOT_ERROR_NONE);
    // When
    err = _es_wifiprovisioninginfo_handler(context, in_payload, &out_payload);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(out_payload);
    assert_lookup_id(out_payload, server_cipher);
    assert_wifi_provisioning(context, expected_wifi_prov);

    // Local teardown
    _free_cipher(device_cipher);
    _free_cipher(server_cipher);
    free(out_payload);
    free(in_payload);
    free(context->scan_result);
}

void TC_STATIC_es_wifiprovisioninginfo_handler_success_without_authtype(void **state)
{
    iot_error_t err;
    char *out_payload = NULL;
    char *in_payload = NULL;
    struct iot_context *context;
    iot_security_cipher_params_t *server_cipher;
    iot_security_cipher_params_t *device_cipher;
    unsigned char device_mac[IOT_WIFI_MAX_BSSID_LEN] = { 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x01 };
    struct test_wifi_provisioning_data sent_wifi_prov = {
            .ssid = "fakeSsid_05_XXXXXX",
            .password = "fakePassword",
            .mac_address = "21:32:43:54:65:76",
            .auth_type = -1,
            .broker_url = "https://test.domain.com:5676",
            .device_name = "fakeDevice",
    };

    struct test_wifi_provisioning_data expected_wifi_prov = {
            .ssid = "fakeSsid_05_XXXXXX",
            .password = "fakePassword",
            .mac_address = "21:32:43:54:65:76",
            .auth_type = IOT_WIFI_AUTH_WPA_WPA2_PSK,
            .broker_domain = "test.domain.com",
            .broker_port = 5676,
            .device_name = "fakeDevice",
    };

    // Given
    context = (struct iot_context *)*state;
    device_cipher = _generate_device_cipher(NULL, 0);
    assert_non_null(device_cipher);
    err = iot_security_cipher_set_params(context->easysetup_security_context, device_cipher);
    assert_int_equal(err, IOT_ERROR_NONE);
    server_cipher = _generate_server_cipher(device_cipher->iv.p, device_cipher->iv.len);
    assert_non_null(server_cipher);
    in_payload = _generate_post_wifiprovisioninginfo_payload(server_cipher, sent_wifi_prov);
    will_return(__wrap_iot_bsp_wifi_get_mac, cast_ptr_to_largest_integral_type(device_mac));
    will_return(__wrap_iot_bsp_wifi_get_mac, IOT_ERROR_NONE);
    // When
    err = _es_wifiprovisioninginfo_handler(context, in_payload, &out_payload);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(out_payload);
    assert_lookup_id(out_payload, server_cipher);
    assert_wifi_provisioning(context, expected_wifi_prov);

    // Local teardown
    _free_cipher(device_cipher);
    _free_cipher(server_cipher);
    free(out_payload);
    free(in_payload);
    free(context->scan_result);
}

// Static function of STDK declared to test
extern iot_error_t _es_wifiscaninfo_handler(struct iot_context *ctx, char **output_data);

static void assert_wifiscaninfo_payload(iot_security_cipher_params_t *cipher, char *payload, int num_of_scanlist);

void TC_STATIC_es_wifiscaninfo_handler_invalid_parameters(void **state)
{
    iot_error_t err;
    struct iot_context *context;
    char *payload;

    // Given: null context, payload
    context = NULL;
    payload = NULL;
    // When
    err = _es_wifiscaninfo_handler(context, &payload);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_STATIC_es_wifiscaninfo_handler_success(void **state)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;
    iot_security_cipher_params_t *device_cipher;
    iot_security_cipher_params_t *server_cipher;

    // Given
    context = (struct iot_context *)*state;
    device_cipher = _generate_device_cipher(NULL, 0);
    assert_non_null(device_cipher);
    err = iot_security_cipher_set_params(context->easysetup_security_context, device_cipher);
    assert_int_equal(err, IOT_ERROR_NONE);
    server_cipher = _generate_server_cipher(device_cipher->iv.p, device_cipher->iv.len);
    assert_non_null(server_cipher);
    will_return(__wrap_iot_bsp_wifi_get_scan_result, 20);
    expect_value(__wrap_iot_bsp_wifi_set_mode, conf->mode, IOT_WIFI_MODE_SCAN);
    will_return(__wrap_iot_bsp_wifi_set_mode, IOT_ERROR_NONE);

    // When
    err = _es_wifiscaninfo_handler(context, &out_payload);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_wifiscaninfo_payload(server_cipher, out_payload, 20);

    // Local teardown
    _free_cipher(device_cipher);
    _free_cipher(server_cipher);
    free(out_payload);
    free(context->scan_result);
}

// Static function of STDK declared to test
extern iot_error_t _es_confirminfo_handler(struct iot_context *ctx, char *input_data, char **output_data);

static char *_generate_confirminfo_payload(iot_security_cipher_params_t *cipher, enum ownership_validation_feature feature,
                                    const char *serial_number_for_qr);
static void assert_empty_json(iot_security_cipher_params_t *cipher, char *payload);

void TC_STATIC_es_confirminfo_handler_null_parameters(void **state)
{
    iot_error_t err;
    char *in_payload;
    char *out_payload;
    struct iot_context *context;
    iot_security_cipher_params_t *device_cipher;
    iot_security_cipher_params_t *server_cipher;

    // Given: in_payload null
    context = (struct iot_context *)*state;
    device_cipher = _generate_device_cipher(NULL, 0);
    assert_non_null(device_cipher);
    err = iot_security_cipher_set_params(context->easysetup_security_context, device_cipher);
    assert_int_equal(err, IOT_ERROR_NONE);
    server_cipher = _generate_server_cipher(device_cipher->iv.p, device_cipher->iv.len);
    assert_non_null(server_cipher);
    in_payload = NULL;
    out_payload = NULL;
    // When
    err = _es_confirminfo_handler(context, in_payload, &out_payload);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    assert_null(out_payload); // out_payload untouched


    // Given: context null
    context = NULL;
    in_payload = _generate_confirminfo_payload(server_cipher, OVF_BIT_MAX_FEATURE, NULL);
    out_payload = NULL;
    // When
    err = _es_confirminfo_handler(context, in_payload, &out_payload);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    assert_null(out_payload); // out_payload untouched

    // Local teardown
    _free_cipher(device_cipher);
    _free_cipher(server_cipher);
    free(in_payload);
}

void TC_STATIC_es_confirminfo_handler_out_ranged_otm_feature(void **state)
{
    iot_error_t err;
    char *in_payload;
    char *out_payload;
    struct iot_context *context;
    iot_security_cipher_params_t *device_cipher;
    iot_security_cipher_params_t *server_cipher;

    // Given
    context = (struct iot_context *)*state;
    device_cipher = _generate_device_cipher(NULL, 0);
    assert_non_null(device_cipher);
    err = iot_security_cipher_set_params(context->easysetup_security_context, device_cipher);
    assert_int_equal(err, IOT_ERROR_NONE);
    server_cipher = _generate_server_cipher(device_cipher->iv.p, device_cipher->iv.len);
    assert_non_null(server_cipher);
    in_payload = _generate_confirminfo_payload(server_cipher, OVF_BIT_SERIAL_NUMBER + 1, NULL);
    out_payload = NULL;
    // When
    err = _es_confirminfo_handler(context, in_payload, &out_payload);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    assert_null(out_payload); // out_payload untouched

    // Local teardown
    _free_cipher(device_cipher);
    _free_cipher(server_cipher);
    free(in_payload);
}

void TC_STATIC_es_confirminfo_handler_justworks_and_pin(void **state)
{
    iot_error_t err;
    char *in_payload;
    char *out_payload;
    struct iot_context *context;
    iot_security_cipher_params_t *device_cipher;
    iot_security_cipher_params_t *server_cipher;

    // Given: common
    context = (struct iot_context *)*state;
    context->usr_events = iot_os_eventgroup_create();
    context->iot_events = iot_os_eventgroup_create();
    context->cmd_queue = iot_os_queue_create(IOT_QUEUE_LENGTH, sizeof(struct iot_command));
    device_cipher = _generate_device_cipher(NULL, 0);
    assert_non_null(device_cipher);
    err = iot_security_cipher_set_params(context->easysetup_security_context, device_cipher);
    assert_int_equal(err, IOT_ERROR_NONE);
    server_cipher = _generate_server_cipher(device_cipher->iv.p, device_cipher->iv.len);
    assert_non_null(server_cipher);

    // Given: justworks payload
    in_payload = _generate_confirminfo_payload(server_cipher, OVF_BIT_JUSTWORKS, NULL);
    out_payload = NULL;
    // When
    err = _es_confirminfo_handler(context, in_payload, &out_payload);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_empty_json(server_cipher, out_payload);
    // Teardown: justworks
    free(in_payload);
    free(out_payload);

    // Given: pin payload
    in_payload = _generate_confirminfo_payload(server_cipher, OVF_BIT_PIN, NULL);
    out_payload = NULL;
    // When
    err = _es_confirminfo_handler(context, in_payload, &out_payload);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_empty_json(server_cipher, out_payload);
    // Teardown: pin
    free(in_payload);
    free(out_payload);

    // Teardown: common
    iot_os_eventgroup_delete(context->usr_events);
    iot_os_eventgroup_delete(context->iot_events);
    iot_os_queue_delete(context->cmd_queue);
    _free_cipher(device_cipher);
    _free_cipher(server_cipher);
}

void TC_STATIC_es_confirminfo_handler_qr_code(void **state)
{
    iot_error_t err;
    char *in_payload;
    char *out_payload;
    struct iot_context *context;
    iot_security_cipher_params_t *device_cipher;
    iot_security_cipher_params_t *server_cipher;

    // Given: common
    context = (struct iot_context *)*state;
    context->usr_events = iot_os_eventgroup_create();
    context->iot_events = iot_os_eventgroup_create();
    context->cmd_queue = iot_os_queue_create(IOT_QUEUE_LENGTH, sizeof(struct iot_command));
    device_cipher = _generate_device_cipher(NULL, 0);
    err = iot_security_cipher_set_params(context->easysetup_security_context, device_cipher);
    assert_int_equal(err, IOT_ERROR_NONE);

    // Given: valid serial number
    server_cipher = _generate_server_cipher(device_cipher->iv.p, device_cipher->iv.len);
    in_payload = _generate_confirminfo_payload(server_cipher, OVF_BIT_QR, TEST_DEVICE_SERIAL_NUMBER);
    out_payload = NULL;
    // When
    err = _es_confirminfo_handler(context, in_payload, &out_payload);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_empty_json(server_cipher, out_payload);

    // Teardown: valid serial number
    free(in_payload);
    free(out_payload);

    // Given: invalid serial number
    server_cipher = _generate_server_cipher(device_cipher->iv.p, device_cipher->iv.len);
    in_payload = _generate_confirminfo_payload(server_cipher, OVF_BIT_QR, "1234"); // invalid sn
    out_payload = NULL;
    // When
    err = _es_confirminfo_handler(context, in_payload, &out_payload);
    // Then
    assert_int_equal(err, IOT_ERROR_EASYSETUP_INVALID_SERIAL_NUMBER);
    assert_null(out_payload); // out_payload untouched

    // Teardown: invalid serial number
    free(in_payload);

    // Teardown: common
    iot_os_eventgroup_delete(context->usr_events);
    iot_os_eventgroup_delete(context->iot_events);
    iot_os_queue_delete(context->cmd_queue);
    _free_cipher(device_cipher);
    _free_cipher(server_cipher);
}

void TC_STATIC_es_confirminfo_handler_serial_number(void **state)
{
	iot_error_t err;
	char *in_payload;
	char *out_payload;
	struct iot_context *context;
	iot_security_cipher_params_t *device_cipher;
	iot_security_cipher_params_t *server_cipher;

	// Given: common
	context = (struct iot_context *)*state;
	context->usr_events = iot_os_eventgroup_create();
	context->iot_events = iot_os_eventgroup_create();
	context->cmd_queue = iot_os_queue_create(IOT_QUEUE_LENGTH, sizeof(struct iot_command));
	device_cipher = _generate_device_cipher(NULL, 0);
	err = iot_security_cipher_set_params(context->easysetup_security_context, device_cipher);
	assert_int_equal(err, IOT_ERROR_NONE);

	// Given: valid serial number
	server_cipher = _generate_server_cipher(device_cipher->iv.p, device_cipher->iv.len);
	in_payload = _generate_confirminfo_payload(server_cipher, OVF_BIT_SERIAL_NUMBER, TEST_DEVICE_SERIAL_NUMBER);
	out_payload = NULL;
	// When
	err = _es_confirminfo_handler(context, in_payload, &out_payload);
	// Then
	assert_int_equal(err, IOT_ERROR_NONE);
	assert_empty_json(server_cipher, out_payload);

	// Teardown: valid serial number
	free(in_payload);
	free(out_payload);

	// Given: invalid serial number
	server_cipher = _generate_server_cipher(device_cipher->iv.p, device_cipher->iv.len);
	in_payload = _generate_confirminfo_payload(server_cipher, OVF_BIT_SERIAL_NUMBER, "1234"); // invalid sn
	out_payload = NULL;
	// When
	err = _es_confirminfo_handler(context, in_payload, &out_payload);
	// Then
	assert_int_equal(err, IOT_ERROR_EASYSETUP_INVALID_SERIAL_NUMBER);
	assert_null(out_payload); // out_payload untouched

	// Teardown: invalid serial number
	free(in_payload);

	// Teardown: common
	iot_os_eventgroup_delete(context->usr_events);
	iot_os_eventgroup_delete(context->iot_events);
	iot_os_queue_delete(context->cmd_queue);
	_free_cipher(device_cipher);
	_free_cipher(server_cipher);
}

static void _wait_and_send_confirm(struct iot_context *context)
{
    unsigned char event;
    event = iot_os_eventgroup_wait_bits(context->usr_events,
        IOT_USR_INTERACT_BIT_PROV_CONFIRM, true, IOT_OS_MAX_DELAY);
    if (event & IOT_USR_INTERACT_BIT_PROV_CONFIRM) {
        iot_os_eventgroup_set_bits(context->iot_events, IOT_EVENT_BIT_EASYSETUP_CONFIRM);
    }
}

void TC_STATIC_es_confirminfo_handler_button(void **state)
{
    iot_error_t err;
    char *in_payload;
    char *out_payload;
    struct iot_context *context;
    iot_security_cipher_params_t *device_cipher;
    iot_security_cipher_params_t *server_cipher;
    iot_os_thread confirm_thread;

    // Given
    context = (struct iot_context *)*state;
    context->usr_events = iot_os_eventgroup_create();
    context->iot_events = iot_os_eventgroup_create();
    context->cmd_queue = iot_os_queue_create(IOT_QUEUE_LENGTH, sizeof(struct iot_command));
    device_cipher = _generate_device_cipher(NULL, 0);
    assert_non_null(device_cipher);
    err = iot_security_cipher_set_params(context->easysetup_security_context, device_cipher);
    assert_int_equal(err, IOT_ERROR_NONE);
    server_cipher = _generate_server_cipher(device_cipher->iv.p, device_cipher->iv.len);
    assert_non_null(server_cipher);
    in_payload = _generate_confirminfo_payload(server_cipher, OVF_BIT_BUTTON, NULL);
    out_payload = NULL;
    iot_os_thread_create(_wait_and_send_confirm, "TC confirminfo", 2048, context, 5, &confirm_thread);
    // When
    err = _es_confirminfo_handler(context, in_payload, &out_payload);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_empty_json(server_cipher, out_payload);

    // Teardown
    iot_os_thread_delete(confirm_thread);
    free(in_payload);
    free(out_payload);
    iot_os_eventgroup_delete(context->usr_events);
    iot_os_eventgroup_delete(context->iot_events);
    iot_os_queue_delete(context->cmd_queue);
    _free_cipher(device_cipher);
    _free_cipher(server_cipher);
}

// Static function of STDK declared to test
extern iot_error_t _es_confirm_handler(struct iot_context *ctx, char *input_data, char **output_data);

static char *_generate_none_container_payload();
static char *_generate_plain_message_payload();
static char *_generate_wrong_container_payload();
static char *_generate_invalid_json_payload(iot_security_cipher_params_t *cipher);
static char *_generate_confirm_payload(iot_security_cipher_params_t *cipher, char *pin_str);

void TC_STATIC_es_confirm_handler_success(void** state)
{
    iot_error_t err;
    char *in_payload;
    char *out_payload;
    struct iot_context *context;
    iot_security_cipher_params_t *device_cipher;
    iot_security_cipher_params_t *server_cipher;
    char pin_for_test[9] = "12345678";

    // Given: valid pin 12345678
    context = (struct iot_context *)*state;
    device_cipher = _generate_device_cipher(NULL, 0);
    assert_non_null(device_cipher);
    err = iot_security_cipher_set_params(context->easysetup_security_context, device_cipher);
    assert_int_equal(err, IOT_ERROR_NONE);
    server_cipher = _generate_server_cipher(device_cipher->iv.p, device_cipher->iv.len);
    assert_non_null(server_cipher);
    in_payload = _generate_confirm_payload(server_cipher, pin_for_test);
    out_payload = NULL;
    context->curr_otm_feature = OVF_BIT_PIN;
    context->devconf.ownership_validation_type = IOT_OVF_TYPE_PIN; // forced overwriting
    context->pin = malloc(sizeof(iot_pin_t));
    memset(context->pin, '\0', sizeof(iot_pin_t));
    memcpy(context->pin->pin, pin_for_test, strlen(pin_for_test));
    context->cmd_queue = iot_os_queue_create(IOT_QUEUE_LENGTH, sizeof(struct iot_command));
    context->iot_events = iot_os_eventgroup_create();
    // When
    err = _es_confirm_handler(context, in_payload, &out_payload);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_empty_json(server_cipher, out_payload);

    // Teardown
    iot_os_eventgroup_delete(context->iot_events);
    iot_os_queue_delete(context->cmd_queue);
    free(context->pin);
    free(in_payload);
    free(out_payload);
    _free_cipher(device_cipher);
    _free_cipher(server_cipher);
}

#define MAX_TEST_PIN_LENGTH 10
void TC_STATIC_es_confirm_handler_invalid_pin(void** state)
{
    iot_error_t err;
    char *in_payload;
    char *out_payload;
    struct iot_context *context;
    iot_security_cipher_params_t *device_cipher;
    iot_security_cipher_params_t *server_cipher;
    iot_pin_t pin_for_device = {
            .pin = "12345678"
    };
    char pin_for_test[][MAX_TEST_PIN_LENGTH] = {
            "123456789", // long pin
            "54321", // short pin
            "ABCDEFGH", // non-numberic pin
            "1234 678", // pin with space
    };

    // Given: common
    context = (struct iot_context *)*state;
    device_cipher = _generate_device_cipher(NULL, 0);
    assert_non_null(device_cipher);
    err = iot_security_cipher_set_params(context->easysetup_security_context, device_cipher);
    assert_int_equal(err, IOT_ERROR_NONE);
    server_cipher = _generate_server_cipher(device_cipher->iv.p, device_cipher->iv.len);
    assert_non_null(server_cipher);
    context->pin = malloc(sizeof(iot_pin_t));
    memset(context->pin, '\0', sizeof(iot_pin_t));
    memcpy(context->pin, &pin_for_device, sizeof(iot_pin_t));
    for (int i = 0; i < sizeof(pin_for_test) / MAX_TEST_PIN_LENGTH; i++)
    {
        // Given
        in_payload = _generate_confirm_payload(server_cipher, pin_for_test[i]);
        out_payload = NULL;
        context->curr_otm_feature = OVF_BIT_PIN;
        context->devconf.ownership_validation_type = IOT_OVF_TYPE_PIN; // forced overwriting
        context->cmd_queue = iot_os_queue_create(IOT_QUEUE_LENGTH, sizeof(struct iot_command));
        context->iot_events = iot_os_eventgroup_create();
        // When
        err = _es_confirm_handler(context, in_payload, &out_payload);
        // Then
        assert_int_not_equal(err, IOT_ERROR_NONE);
        assert_null(out_payload); // out_payload untouched

        // Teardown
        iot_os_eventgroup_delete(context->iot_events);
        iot_os_queue_delete(context->cmd_queue);
        free(in_payload);
    }

    // Teardown: common
    free(context->pin);
    _free_cipher(device_cipher);
    _free_cipher(server_cipher);
}

void TC_STATIC_es_confirm_handler_non_pin_otm(void** state)
{
    iot_error_t err;
    char *in_payload;
    char *out_payload;
    struct iot_context *context;
    iot_security_cipher_params_t *device_cipher;
    iot_security_cipher_params_t *server_cipher;
    char pin_for_test[9] = "12345678";

    // Given: valid pin 12345678
    context = (struct iot_context *)*state;
    device_cipher = _generate_device_cipher(NULL, 0);
    assert_non_null(device_cipher);
    err = iot_security_cipher_set_params(context->easysetup_security_context, device_cipher);
    assert_int_equal(err, IOT_ERROR_NONE);
    server_cipher = _generate_server_cipher(device_cipher->iv.p, device_cipher->iv.len);
    assert_non_null(server_cipher);
    in_payload = _generate_confirm_payload(server_cipher, pin_for_test);
    out_payload = NULL;
    context->curr_otm_feature = OVF_BIT_JUSTWORKS;
    context->devconf.ownership_validation_type = IOT_OVF_TYPE_PIN | IOT_OVF_TYPE_JUSTWORKS; // forced overwriting
    context->pin = malloc(sizeof(iot_pin_t));
    memset(context->pin, '\0', sizeof(iot_pin_t));
    memcpy(context->pin->pin, pin_for_test, strlen(pin_for_test));
    context->cmd_queue = iot_os_queue_create(IOT_QUEUE_LENGTH, sizeof(struct iot_command));
    context->iot_events = iot_os_eventgroup_create();

    // When
    err = _es_confirm_handler(context, in_payload, &out_payload);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    assert_null(out_payload); // out_payload untouched

    // Teardown
    iot_os_eventgroup_delete(context->iot_events);
    iot_os_queue_delete(context->cmd_queue);
    free(context->pin);
    free(in_payload);
    _free_cipher(device_cipher);
    _free_cipher(server_cipher);
}

enum {
    INVALID_PAYLOAD_INVALID_JSON_AT_CONTAINER,
    INVALID_PAYLOAD_PLAIN_MESSAGE_AT_CONTAINER,
    INVALID_PAYLOAD_WRONG_CONTAINER,
    INVALID_PAYLOAD_NONE_CONTAINER,
    INVALID_PAYLOAD_MAX
};

void TC_STATIC_es_confirm_handler_invalid_payload(void** state)
{
    iot_error_t err;
    char *in_payload[INVALID_PAYLOAD_MAX];
    char *out_payload;
    struct iot_context *context;
    iot_security_cipher_params_t *device_cipher;
    iot_security_cipher_params_t *server_cipher;
    char pin_for_test[9] = "12345678";

    // Given: invalid json format
    context = (struct iot_context *)*state;
    device_cipher = _generate_device_cipher(NULL, 0);
    assert_non_null(device_cipher);
    err = iot_security_cipher_set_params(context->easysetup_security_context, device_cipher);
    assert_int_equal(err, IOT_ERROR_NONE);
    server_cipher = _generate_server_cipher(device_cipher->iv.p, device_cipher->iv.len);
    assert_non_null(server_cipher);
    context->curr_otm_feature = OVF_BIT_PIN;
    context->devconf.ownership_validation_type = IOT_OVF_TYPE_PIN; // forced overwriting
    context->pin = malloc(sizeof(iot_pin_t));
    memset(context->pin, '\0', sizeof(iot_pin_t));
    memcpy(context->pin->pin, pin_for_test, strlen(pin_for_test));
    context->cmd_queue = iot_os_queue_create(IOT_QUEUE_LENGTH, sizeof(struct iot_command));
    context->iot_events = iot_os_eventgroup_create();
    out_payload = NULL;
    in_payload[INVALID_PAYLOAD_INVALID_JSON_AT_CONTAINER] = _generate_invalid_json_payload(server_cipher);
    in_payload[INVALID_PAYLOAD_PLAIN_MESSAGE_AT_CONTAINER] = _generate_plain_message_payload();
    in_payload[INVALID_PAYLOAD_NONE_CONTAINER] = _generate_none_container_payload();
    in_payload[INVALID_PAYLOAD_WRONG_CONTAINER] = _generate_wrong_container_payload();
    for (int i = 0; i < INVALID_PAYLOAD_MAX; i++) {
        // When
        err = _es_confirm_handler(context, in_payload[i], &out_payload);
        // Then
        assert_int_not_equal(err, IOT_ERROR_NONE);
        assert_null(out_payload); // out_payload untouched
    }

    // Teardown
    iot_os_eventgroup_delete(context->iot_events);
    iot_os_queue_delete(context->cmd_queue);
    free(context->pin);
    for (int i = 0; i < INVALID_PAYLOAD_MAX; i++) {
        free(in_payload[i]);
    }
    _free_cipher(device_cipher);
    _free_cipher(server_cipher);
}

extern iot_error_t _es_setupcomplete_handler(struct iot_context *ctx, char *input_data, char **output_data);

void TC_STATIC_es_setupcomplete_handler_success(void** state)
{
    iot_error_t err;
    struct iot_context *context;
    iot_security_cipher_params_t *device_cipher;
    iot_security_cipher_params_t *server_cipher;
    char *out_payload;

    // Given
    context = (struct iot_context *)*state;
    device_cipher = _generate_device_cipher(NULL, 0);
    assert_non_null(device_cipher);
    err = iot_security_cipher_set_params(context->easysetup_security_context, device_cipher);
    assert_int_equal(err, IOT_ERROR_NONE);
    server_cipher = _generate_server_cipher(device_cipher->iv.p, device_cipher->iv.len);
    assert_non_null(server_cipher);
    // When
    err = _es_setupcomplete_handler(context, NULL, &out_payload);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_empty_json(server_cipher, out_payload);

    // Teardown
    free(out_payload);
    _free_cipher(device_cipher);
    _free_cipher(server_cipher);
}

static char *_generate_none_container_payload()
{
    return strdup("This is not json");
}

static char *_generate_plain_message_payload()
{
    return strdup("{ \"message\" : \"This is not encoded message\" }");
}

static char *_generate_wrong_container_payload()
{
    return strdup("{ \"key\" : \"value\" }");
}

static char *_generate_invalid_json_payload(iot_security_cipher_params_t *cipher)
{
    JSON_H *root;
    char *plain_message;
    char* encoded_message;
    char* formed_message;

    assert_non_null(cipher);

    plain_message = strdup("{ \"invalid\" { \"json\": \"format\"}");
    assert_non_null(plain_message);
    encoded_message = _encrypt_and_encode_message(cipher, (unsigned char*)plain_message, strlen(plain_message));
    free(plain_message);

    root = JSON_CREATE_OBJECT();
    assert_non_null(root);
    JSON_ADD_ITEM_TO_OBJECT(root, "message", JSON_CREATE_STRING(encoded_message));

    formed_message = JSON_PRINT(root);
    assert_non_null(formed_message);

    free(encoded_message);
    JSON_DELETE(root);

    return formed_message;
}

static char *_generate_confirm_payload(iot_security_cipher_params_t *cipher, char *pin_str)
{
    JSON_H *root;
    char* plain_message;
    char* encoded_message;
    char* formed_message;

    assert_non_null(cipher);

    root = JSON_CREATE_OBJECT();
    assert_non_null(root);
    if (pin_str) {
        JSON_ADD_ITEM_TO_OBJECT(root, "pin", JSON_CREATE_STRING(pin_str));
    } else {
        JSON_ADD_ITEM_TO_OBJECT(root, "pin", JSON_CREATE_STRING(""));
    }
    plain_message = JSON_PRINT(root);
    JSON_DELETE(root);

    encoded_message = _encrypt_and_encode_message(cipher, (unsigned char*)plain_message, strlen(plain_message));
    free(plain_message);

    root = JSON_CREATE_OBJECT();
    assert_non_null(root);
    JSON_ADD_ITEM_TO_OBJECT(root, "message", JSON_CREATE_STRING(encoded_message));

    formed_message = JSON_PRINT(root);
    assert_non_null(formed_message);

    free(encoded_message);
    JSON_DELETE(root);

    return formed_message;
}

static char *_generate_confirminfo_payload(iot_security_cipher_params_t *cipher, enum ownership_validation_feature feature,
                                    const char *serial_number_for_qr)
{
    JSON_H *root;
    JSON_H *item;
    char* plain_message;
    char* encoded_message;
    char* formed_message;

    assert_non_null(cipher);

    root = JSON_CREATE_OBJECT();
    assert_non_null(root);
    item = JSON_CREATE_NUMBER(feature);
    assert_non_null(item);
    JSON_ADD_ITEM_TO_OBJECT(root, "otmSupportFeature", item);
    if (feature == OVF_BIT_QR || feature == OVF_BIT_SERIAL_NUMBER) {
        JSON_ADD_ITEM_TO_OBJECT(root, "sn", JSON_CREATE_STRING(serial_number_for_qr));
    }
    plain_message = JSON_PRINT(root);
    JSON_DELETE(root);

    encoded_message = _encrypt_and_encode_message(cipher, (unsigned char*)plain_message, strlen(plain_message));
    free(plain_message);

    root = JSON_CREATE_OBJECT();
    assert_non_null(root);
    JSON_ADD_ITEM_TO_OBJECT(root, "message", JSON_CREATE_STRING(encoded_message));

    formed_message = JSON_PRINT(root);
    assert_non_null(formed_message);

    free(encoded_message);
    JSON_DELETE(root);

    return formed_message;
}

static char* _generate_post_wifiprovisioninginfo_payload(iot_security_cipher_params_t *cipher, struct test_wifi_provisioning_data prov)
{
    char *post_message;
    char *encoded_message;
    char *plain_message;
    JSON_H *root = NULL;
    JSON_H *wifi_credential = NULL;

    root = JSON_CREATE_OBJECT();
    assert_non_null(root);
    wifi_credential = JSON_CREATE_OBJECT();
    if (prov.ssid) {
        JSON_ADD_ITEM_TO_OBJECT(wifi_credential, "ssid", JSON_CREATE_STRING(prov.ssid));
    }
    if (prov.password) {
        JSON_ADD_ITEM_TO_OBJECT(wifi_credential, "password", JSON_CREATE_STRING(prov.password));
    }
    if (prov.mac_address) {
        JSON_ADD_ITEM_TO_OBJECT(wifi_credential, "macAddress", JSON_CREATE_STRING(prov.mac_address));
    }
    if (prov.auth_type >= 0) {
        JSON_ADD_ITEM_TO_OBJECT(wifi_credential, "authType", JSON_CREATE_NUMBER((double) prov.auth_type));
    }
    JSON_ADD_ITEM_TO_OBJECT(root, "wifiCredential", wifi_credential);
    if (prov.broker_url) {
        JSON_ADD_ITEM_TO_OBJECT(root, "brokerUrl", JSON_CREATE_STRING(prov.broker_url));
    }
    if (prov.device_name) {
        JSON_ADD_ITEM_TO_OBJECT(root, "deviceName", JSON_CREATE_STRING(prov.device_name));
    }
    plain_message = JSON_PRINT(root);
    JSON_DELETE(root);

    encoded_message = _encrypt_and_encode_message(cipher, (unsigned char *) plain_message, strlen(plain_message));
    free(plain_message);

    // { "message": "XXXXX" }
    root = JSON_CREATE_OBJECT();
    assert_non_null(root);
    JSON_ADD_ITEM_TO_OBJECT(root, "message", JSON_CREATE_STRING(encoded_message));

    post_message = JSON_PRINT(root);
    JSON_DELETE(root);
    free(encoded_message);

    return post_message;
}

static void assert_deviceinfo(char *payload, char *expected_firmware_version, char *expected_hashed_sn)
{
    JSON_H *root;
    JSON_H *item;
    assert_non_null(payload);

    root = JSON_PARSE(payload);
    item = JSON_GET_OBJECT_ITEM(root, "error");
    assert_null(item);
    item = JSON_GET_OBJECT_ITEM(root, "firmwareVersion");
    assert_string_equal(JSON_GET_STRING_VALUE(item), expected_firmware_version);
    item = JSON_GET_OBJECT_ITEM(root, "hashedSn");
    assert_string_equal(JSON_GET_STRING_VALUE(item), expected_hashed_sn);
    item = JSON_GET_OBJECT_ITEM(root, "wifiSupportFrequency");
    assert_in_range(item->valueint, 0, 2); // 0 for 2.4GHz, 1 for 5GHz, 2 for All
    item = JSON_GET_OBJECT_ITEM(root, "iv");
    assert_true(strlen(JSON_GET_STRING_VALUE(item)) > 4);

    JSON_DELETE(root);
}

static void assert_uuid_format(char *input_string)
{
    regex_t regex;
    int result;
    const char *uuid_pattern = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$";

    assert_non_null(input_string);
    result = regcomp(&regex, uuid_pattern, REG_EXTENDED);
    assert_return_code(result, errno);
    result = regexec(&regex, input_string, 0, NULL, 0);
    assert_int_not_equal(result, REG_NOMATCH);
    assert_int_equal(result, 0);
}

static void assert_lookup_id(const char *payload, iot_security_cipher_params_t *cipher)
{
    JSON_H *root;
    JSON_H *item;
    unsigned char *b64url_aes256_message;
    char *plain_message;
    assert_non_null(payload);
    assert_non_null(cipher);

    root = JSON_PARSE(payload);
    item = JSON_GET_OBJECT_ITEM(root, "message");
    b64url_aes256_message = (unsigned char*) JSON_GET_STRING_VALUE(item);

    plain_message = _decode_and_decrypt_message(cipher, b64url_aes256_message, strlen((const char*)b64url_aes256_message));
    JSON_DELETE(root);

    root = JSON_PARSE(plain_message);
    item = JSON_GET_OBJECT_ITEM(root, "lookupId");
    assert_non_null(item);
    assert_uuid_format(JSON_GET_STRING_VALUE(item));
    free(plain_message);
    JSON_DELETE(root);
}

static void assert_wifi_provisioning(struct iot_context *context, struct test_wifi_provisioning_data prov)
{
    iot_error_t err;
    struct iot_mac mac;

    err = iot_util_convert_str_mac(prov.mac_address, &mac);
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_memory_equal(context->prov_data.wifi.bssid.addr, mac.addr, IOT_WIFI_MAX_BSSID_LEN);
    assert_string_equal(context->prov_data.wifi.ssid, prov.ssid);
    assert_string_equal(context->prov_data.wifi.password, prov.password);
    assert_int_equal(context->prov_data.wifi.security_type, prov.auth_type);
    assert_string_equal(context->prov_data.wifi.ssid, prov.ssid);

    assert_string_equal(context->prov_data.cloud.broker_url, prov.broker_domain);
    assert_int_equal(context->prov_data.cloud.broker_port, prov.broker_port);
    assert_string_equal(context->prov_data.cloud.label, prov.device_name);
}

extern const iot_wifi_scan_result_t mock_wifi_scan_result[IOT_WIFI_MAX_SCAN_RESULT];
static void assert_wifiscaninfo_with_mocked_item(JSON_H *root, int n_th)
{
    JSON_H *item;
    char wifi_bssid[20] = {0, };

    assert_non_null(root);
    assert_in_range(n_th, 0, IOT_WIFI_MAX_SCAN_RESULT);

    item = JSON_GET_OBJECT_ITEM(root, "bssid");
    assert_non_null(item);
    snprintf(wifi_bssid, sizeof(wifi_bssid), "%02X:%02X:%02X:%02X:%02X:%02X",
             mock_wifi_scan_result[n_th].bssid[0], mock_wifi_scan_result[n_th].bssid[1],
             mock_wifi_scan_result[n_th].bssid[2], mock_wifi_scan_result[n_th].bssid[3],
             mock_wifi_scan_result[n_th].bssid[4], mock_wifi_scan_result[n_th].bssid[5]);
    assert_string_equal(wifi_bssid, JSON_GET_STRING_VALUE(item));

    item = JSON_GET_OBJECT_ITEM(root, "ssid");
    assert_non_null(item);
    assert_string_equal(mock_wifi_scan_result[n_th].ssid, JSON_GET_STRING_VALUE(item));

    item = JSON_GET_OBJECT_ITEM(root, "rssi");
    assert_non_null(item);
    assert_int_equal(mock_wifi_scan_result[n_th].rssi, item->valueint);

    item = JSON_GET_OBJECT_ITEM(root, "frequency");
    assert_non_null(item);
    assert_int_equal(mock_wifi_scan_result[n_th].freq, item->valueint);

    item = JSON_GET_OBJECT_ITEM(root, "authType");
    assert_non_null(item);
    assert_int_equal(mock_wifi_scan_result[n_th].authmode, item->valueint);
}

static void assert_wifiscaninfo_payload(iot_security_cipher_params_t *cipher, char *payload, int num_of_scanlist)
{
    JSON_H* root;
    JSON_H* item;
    JSON_H* array;
    char *plain_message;

    assert_non_null(payload);
    assert_non_null(cipher);

    // {"message":"xxxxx"}
    root = JSON_PARSE(payload);
    assert_non_null(root);

    item = JSON_GET_OBJECT_ITEM(root, "message");
    assert_non_null(item);
    plain_message = _decode_and_decrypt_message(cipher, (unsigned char*)JSON_GET_STRING_VALUE(item), strlen(JSON_GET_STRING_VALUE(item)));
    assert_non_null(plain_message);
    JSON_DELETE(root);

    root = JSON_PARSE(plain_message);
    array = JSON_GET_OBJECT_ITEM(root, "wifiScanInfo");
    assert_non_null(array);
    if (num_of_scanlist == 20) {
        assert_int_equal(JSON_GET_ARRAY_SIZE(array), 19); //20th is enterprise, so it should be ignored from iotcore
    } else {
        assert_int_equal(JSON_GET_ARRAY_SIZE(array), num_of_scanlist);
    }

    for (int i = 0; i < JSON_GET_ARRAY_SIZE(array); i++) {
        item = JSON_GET_ARRAY_ITEM(array, i);
        assert_wifiscaninfo_with_mocked_item(item, i);
    }

    free(plain_message);
    JSON_DELETE(root);
}

static void assert_empty_json(iot_security_cipher_params_t *cipher, char *payload)
{
    JSON_H* root;
    JSON_H* item;
    char *plain_message;

    assert_non_null(payload);
    assert_non_null(cipher);

    // {"message":"xxxxx"}
    root = JSON_PARSE(payload);
    assert_non_null(root);

    item = JSON_GET_OBJECT_ITEM(root, "message");
    assert_non_null(item);
    plain_message = _decode_and_decrypt_message(cipher, (unsigned char*)JSON_GET_STRING_VALUE(item), strlen(JSON_GET_STRING_VALUE(item)));
    assert_non_null(plain_message);
    JSON_DELETE(root);

    assert_string_equal(plain_message, "{}");
    free(plain_message);
}

void TC_st_conn_ownership_confirm_SUCCESS(void **state)
{
    struct iot_context *internal_context;
    IOT_CTX *context;
    unsigned char events = 0;

    // Given
    internal_context = (struct iot_context*) malloc(sizeof(struct iot_context));
    memset(internal_context, '\0', sizeof(struct iot_context));
    internal_context->curr_otm_feature = OVF_BIT_BUTTON;
    internal_context->iot_events = iot_os_eventgroup_create();
    context = (IOT_CTX*) internal_context;
    // When
    st_conn_ownership_confirm(context, true);

    // Then
    events = iot_os_eventgroup_wait_bits(internal_context->iot_events,
                                         IOT_EVENT_BIT_EASYSETUP_CONFIRM | IOT_EVENT_BIT_EASYSETUP_CONFIRM_DENY, false, 100000);
    assert_true(events & IOT_EVENT_BIT_EASYSETUP_CONFIRM);
    assert_false(events & IOT_EVENT_BIT_EASYSETUP_CONFIRM_DENY);

    // Teardown
    iot_os_eventgroup_delete(internal_context->iot_events);
    free(internal_context);
}

void TC_st_conn_ownership_confirm_DENY(void **state)
{
    struct iot_context *internal_context;
    IOT_CTX *context;
    unsigned char events = 0;

    // Given
    internal_context = (struct iot_context*) malloc(sizeof(struct iot_context));
    memset(internal_context, '\0', sizeof(struct iot_context));
    internal_context->curr_otm_feature = OVF_BIT_BUTTON;
    internal_context->iot_events = iot_os_eventgroup_create();
    context = (IOT_CTX*) internal_context;
    // When
    st_conn_ownership_confirm(context, false);

    // Then
    events = iot_os_eventgroup_wait_bits(internal_context->iot_events,
                                         IOT_EVENT_BIT_EASYSETUP_CONFIRM | IOT_EVENT_BIT_EASYSETUP_CONFIRM_DENY, false, 100000);
    assert_true(events & IOT_EVENT_BIT_EASYSETUP_CONFIRM_DENY);
    assert_false(events & IOT_EVENT_BIT_EASYSETUP_CONFIRM);

    // Teardown
    iot_os_eventgroup_delete(internal_context->iot_events);
    free(internal_context);
}


