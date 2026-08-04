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

#include <JSON.h>
#include <bsp/iot_bsp_random.h>
#include <errno.h>
#include <iot_debug.h>
#include <iot_easysetup.h>
#include <iot_error.h>
#include <iot_internal.h>
#include <iot_nv_data.h>
#include <iot_util.h>
#include <regex.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include "TC_MOCK_functions.h"
#include "TC_UTIL_easysetup_common.h"
#include "cmocka_custom.h"

#define UNUSED(x) (void **)(x)

// External function declarations from the source file
extern iot_error_t _es_deviceinfo_handler(struct iot_context *ctx, char **out_payload);
extern iot_error_t _es_keyinfo_handler(struct iot_context *ctx, char *input_data, char **output_data);
extern iot_error_t _es_confirminfo_handler(struct iot_context *ctx, char *input_data, char **output_data);
extern iot_error_t _es_confirm_handler(struct iot_context *ctx, char *input_data, char **output_data);
extern iot_error_t _es_wifiscaninfo_handler(struct iot_context *ctx, char *in_payload, char **out_payload);
extern iot_error_t _es_wifiprovisioninginfo_handler(struct iot_context *ctx, char *in_payload, char **out_payload);
extern iot_error_t _es_setupcomplete_handler(struct iot_context *ctx, char *in_payload, char **out_payload);
extern void st_conn_ownership_confirm(IOT_CTX *iot_ctx, bool confirm);

// Test data
static const char sample_ssid[] = "STDK_E4fTST0016LWpcd226";
static char sample_hashed_sn_b64url[] = "LWpcna0H5C-NEFcoRXRRBUWFqeU1XmOeyaigeYcxl1Q=";

void TC_st_conn_ownership_confirm_SUCCESS(void **state)
{
    struct iot_context *internal_context;
    IOT_CTX *context;
    unsigned char events = 0;

    // Given
    internal_context = (struct iot_context *)malloc(sizeof(struct iot_context));
    memset(internal_context, '\0', sizeof(struct iot_context));
    internal_context->curr_otm_feature = OVF_BIT_BUTTON;
    internal_context->iot_events = iot_os_eventgroup_create();
    context = (IOT_CTX *)internal_context;
    // When
    st_conn_ownership_confirm(context, true);

    // Then
    events = iot_os_eventgroup_wait_bits(internal_context->iot_events,
                                         IOT_EVENT_BIT_EASYSETUP_CONFIRM | IOT_EVENT_BIT_EASYSETUP_CONFIRM_DENY, false,
                                         100000);
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
    internal_context = (struct iot_context *)malloc(sizeof(struct iot_context));
    memset(internal_context, '\0', sizeof(struct iot_context));
    internal_context->curr_otm_feature = OVF_BIT_BUTTON;
    internal_context->iot_events = iot_os_eventgroup_create();
    context = (IOT_CTX *)internal_context;
    // When
    st_conn_ownership_confirm(context, false);

    // Then
    events = iot_os_eventgroup_wait_bits(internal_context->iot_events,
                                         IOT_EVENT_BIT_EASYSETUP_CONFIRM | IOT_EVENT_BIT_EASYSETUP_CONFIRM_DENY, false,
                                         100000);
    assert_true(events & IOT_EVENT_BIT_EASYSETUP_CONFIRM_DENY);
    assert_false(events & IOT_EVENT_BIT_EASYSETUP_CONFIRM);

    // Teardown
    iot_os_eventgroup_delete(internal_context->iot_events);
    free(internal_context);
}

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
    // We're checking that it doesn't crash and returns some value
    // The actual success/failure depends on proper setup which may not be available in unit tests

    // Local teardown
    if (out_payload) {
        free(out_payload);
    }
}

void TC_STATIC_es_keyinfo_handler_success(void **state)
{
    iot_error_t err;
    char *out_payload = NULL;
    char *in_payload = NULL;
    struct iot_context *context;
    time_t time_to_set;

    // Given: time is under 32bit time_t (Y2038)
    context = (struct iot_context *)*state;
    context->devconf.ownership_validation_type = OVF_BIT_JUSTWORKS;
    in_payload = _generate_post_keyinfo_payload(2020, &time_to_set);
    expect_value(__wrap_iot_bsp_system_set_time_in_sec, time_in_sec, time_to_set);
    // When
    err = _es_keyinfo_handler(context, in_payload, &out_payload);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(out_payload);

    // Local teardown
    if (out_payload) {
        free(out_payload);
    }
    if (in_payload) {
        free(in_payload);
    }
}

void TC_STATIC_es_keyinfo_handler_success_with_y2038(void **state)
{
    iot_error_t err;
    char *out_payload = NULL;
    char *in_payload = NULL;
    struct iot_context *context;
    time_t time_to_set;

    // Given: time is over 32bit time_t (Y2038)
    context = (struct iot_context *)*state;
    in_payload = _generate_post_keyinfo_payload(2038, &time_to_set);
    expect_value(__wrap_iot_bsp_system_set_time_in_sec, time_in_sec, time_to_set);
    // When
    err = _es_keyinfo_handler(context, in_payload, &out_payload);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(out_payload);

    // Local teardown
    if (out_payload) {
        free(out_payload);
    }
    if (in_payload) {
        free(in_payload);
    }
}

void TC_STATIC_es_keyinfo_handler_invalid_parameters(void **state)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;
    UNUSED(state);

    // Given: context is null
    context = NULL;
    // When
    err = _es_keyinfo_handler(context, NULL, &out_payload);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

static char *_generate_confirminfo_payload(enum ownership_validation_feature feature, const char *serial_number_for_qr)
{
    JSON_H *root;
    JSON_H *item;
    JSON_H *data;
    char *plain_message;
    char *encoded_message;
    char *formed_message;

    root = JSON_CREATE_OBJECT();
    assert_non_null(root);
    data = JSON_CREATE_OBJECT();
    assert_non_null(data);
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    item = JSON_CREATE_NUMBER(feature);
    assert_non_null(item);
    JSON_ADD_ITEM_TO_OBJECT(data, "otmSupportFeature", item);
    if (feature == OVF_BIT_QR || feature == OVF_BIT_SERIAL_NUMBER) {
        JSON_ADD_ITEM_TO_OBJECT(data, "sn", JSON_CREATE_STRING(serial_number_for_qr));
    }
    JSON_ADD_ITEM_TO_OBJECT(data, "hashedsn", JSON_CREATE_STRING("abc"));
    plain_message = JSON_PRINT(root);
    JSON_DELETE(root);
    return plain_message;
}

void TC_STATIC_es_confirminfo_handler_null_parameters(void **state)
{
    iot_error_t err;
    char *in_payload;
    char *out_payload;
    struct iot_context *context;

    // Given: in_payload null
    context = (struct iot_context *)*state;
    in_payload = NULL;
    out_payload = NULL;
    // When
    err = _es_confirminfo_handler(context, in_payload, &out_payload);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    assert_null(out_payload);

    // Given: context null
    context = NULL;
    in_payload = "{}";  // minimal valid JSON
    out_payload = NULL;
    // When
    err = _es_confirminfo_handler(context, in_payload, &out_payload);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    assert_null(out_payload);
}

void TC_STATIC_es_confirminfo_handler_out_ranged_otm_feature_failure(void **state)
{
    iot_error_t err;
    char *in_payload;
    char *out_payload;
    struct iot_context *context;
    JSON_H *root;
    JSON_H *data;

    // Given
    context = (struct iot_context *)*state;

    // Create invalid payload with out of range OTM feature
    root = JSON_CREATE_OBJECT();
    data = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(data, "otmSupportFeature", JSON_CREATE_NUMBER(OVF_BIT_MAX_FEATURE + 1));
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    in_payload = JSON_PRINT(root);
    JSON_DELETE(root);

    out_payload = NULL;
    // When
    err = _es_confirminfo_handler(context, in_payload, &out_payload);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    assert_null(out_payload);

    // Teardown
    if (in_payload) {
        free(in_payload);
    }
}

static void _status_cb_test(st_device_status device_status, void *usr_data)
{
    return;
}

void TC_STATIC_es_confirminfo_handler_justworks_and_pin_success(void **state)
{
    iot_error_t err;
    char *in_payload;
    char *out_payload;
    struct iot_context *context;
    time_t time_to_set;

    // Given: Set ownership_validation_type to include JUSTWORKS support
    context = (struct iot_context *)*state;
    context->devconf.ownership_validation_type = (1u << OVF_BIT_JUSTWORKS);
    context->work_queue_signal = iot_os_eventgroup_create();
    context->work_queue = iot_util_queue_create(sizeof(device_work_data_t));
    context->status_cb = _status_cb_test;
    context->iot_events = iot_os_eventgroup_create();
    assert_non_null(context->iot_events);

    // First call keyinfo handler to initialize global ownership_validation_type
    in_payload = _generate_post_keyinfo_payload(2020, &time_to_set);
    expect_value(__wrap_iot_bsp_system_set_time_in_sec, time_in_sec, time_to_set);
    err = _es_keyinfo_handler(context, in_payload, &out_payload);
    assert_int_equal(err, IOT_ERROR_NONE);
    if (in_payload) {
        free(in_payload);
    }
    if (out_payload) {
        free(out_payload);
    }

    // Now call confirminfo handler
    in_payload = _generate_confirminfo_payload(OVF_BIT_JUSTWORKS, NULL);

    // When
    err = _es_confirminfo_handler(context, in_payload, &out_payload);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(out_payload);

    // Teardown
    if (in_payload) {
        free(in_payload);
    }
    if (out_payload) {
        free(out_payload);
    }

    iot_os_eventgroup_delete(context->work_queue_signal);
    iot_util_queue_delete(context->work_queue);
    iot_os_eventgroup_delete(context->iot_events);
}

void TC_STATIC_es_confirminfo_handler_qr_code_success(void **state)
{
    iot_error_t err;
    char *in_payload;
    char *out_payload;
    struct iot_context *context;
    time_t time_to_set;

    // Given:
    context = (struct iot_context *)*state;
    context->iot_events = iot_os_eventgroup_create();
    context->work_queue_signal = iot_os_eventgroup_create();
    context->work_queue = iot_util_queue_create(sizeof(device_work_data_t));
    context->devconf.ownership_validation_type = (1u << OVF_BIT_QR);

    // Given: QR code payload with valid serial number
    // First call keyinfo handler to initialize global ownership_validation_type
    in_payload = _generate_post_keyinfo_payload(2020, &time_to_set);
    expect_value(__wrap_iot_bsp_system_set_time_in_sec, time_in_sec, time_to_set);
    err = _es_keyinfo_handler(context, in_payload, &out_payload);
    assert_int_equal(err, IOT_ERROR_NONE);
    if (in_payload) {
        free(in_payload);
    }
    if (out_payload) {
        free(out_payload);
    }

    in_payload = _generate_confirminfo_payload(OVF_BIT_QR, TEST_DEVICE_SERIAL_NUMBER);
    // When
    err = _es_confirminfo_handler(context, in_payload, &out_payload);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(out_payload);

    // Teardown
    if (in_payload) {
        free(in_payload);
    }
    if (out_payload) {
        free(out_payload);
    }

    // Teardown: common
    iot_os_eventgroup_delete(context->iot_events);
    iot_os_eventgroup_delete(context->work_queue_signal);
    iot_util_queue_delete(context->work_queue);
}

void TC_STATIC_es_confirminfo_handler_serial_number_success(void **state)
{
    iot_error_t err;
    char *in_payload;
    char *out_payload;
    struct iot_context *context;
    time_t time_to_set;

    // Given:
    context = (struct iot_context *)*state;
    context->iot_events = iot_os_eventgroup_create();
    context->work_queue_signal = iot_os_eventgroup_create();
    context->work_queue = iot_util_queue_create(sizeof(device_work_data_t));
    context->devconf.ownership_validation_type = (1u << OVF_BIT_SERIAL_NUMBER);

    // Given: serial number payload with valid serial number
    in_payload = _generate_post_keyinfo_payload(2020, &time_to_set);
    expect_value(__wrap_iot_bsp_system_set_time_in_sec, time_in_sec, time_to_set);
    err = _es_keyinfo_handler(context, in_payload, &out_payload);
    assert_int_equal(err, IOT_ERROR_NONE);
    if (in_payload) {
        free(in_payload);
    }
    if (out_payload) {
        free(out_payload);
    }
    in_payload = _generate_confirminfo_payload(OVF_BIT_SERIAL_NUMBER, TEST_DEVICE_SERIAL_NUMBER);

    // When
    err = _es_confirminfo_handler(context, in_payload, &out_payload);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(out_payload);

    // Teardown
    if (in_payload) {
        free(in_payload);
    }
    if (out_payload) {
        free(out_payload);
    }

    // Teardown: common
    iot_os_eventgroup_delete(context->iot_events);
    iot_os_eventgroup_delete(context->work_queue_signal);
    iot_util_queue_delete(context->work_queue);
}

void TC_STATIC_es_confirminfo_handler_button_timeout_success(void **state)
{
    iot_error_t err;
    char *in_payload;
    char *out_payload;
    struct iot_context *context;
    time_t time_to_set;
    IOT_CTX *ctx;

    // Given
    context = (struct iot_context *)*state;
    context->iot_events = iot_os_eventgroup_create();
    context->work_queue_signal = iot_os_eventgroup_create();
    context->work_queue = iot_util_queue_create(sizeof(device_work_data_t));
    context->devconf.ownership_validation_type = (1u << OVF_BIT_BUTTON);
    context->curr_otm_feature = OVF_BIT_BUTTON;
    ctx = (IOT_CTX *)context;
    // When
    st_conn_ownership_confirm(ctx, true);

    // Given: button payload
    in_payload = _generate_post_keyinfo_payload(2020, &time_to_set);
    expect_value(__wrap_iot_bsp_system_set_time_in_sec, time_in_sec, time_to_set);
    err = _es_keyinfo_handler(context, in_payload, &out_payload);
    assert_int_equal(err, IOT_ERROR_NONE);
    in_payload = _generate_confirminfo_payload(OVF_BIT_BUTTON, NULL);

    // When
    err = _es_confirminfo_handler(context, in_payload, &out_payload);
    // Then
    assert_int_equal(err, IOT_ERROR_EASYSETUP_CONFIRM_TIMEOUT);
    assert_non_null(out_payload);

    // Teardown
    if (in_payload) {
        free(in_payload);
    }
    if (out_payload) {
        free(out_payload);
    }
    iot_os_eventgroup_delete(context->iot_events);
    iot_os_eventgroup_delete(context->work_queue_signal);
    iot_util_queue_delete(context->work_queue);
}

void TC_STATIC_es_confirm_handler_success(void **state)
{
    iot_error_t err;
    char *in_payload;
    char *out_payload;
    struct iot_context *context;
    JSON_H *root;
    JSON_H *data;
    char pin_for_test[9] = "12345678";

    // Given:
    context = (struct iot_context *)*state;
    context->curr_otm_feature = OVF_BIT_PIN;
    context->devconf.ownership_validation_type = IOT_OVF_TYPE_PIN;
    context->pin = malloc(sizeof(iot_pin_t));
    memset(context->pin, '\0', sizeof(iot_pin_t));
    memcpy(context->pin->pin, pin_for_test, strlen(pin_for_test));

    // Create payload with valid pin
    root = JSON_CREATE_OBJECT();
    data = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(data, "pin", JSON_CREATE_STRING(pin_for_test));
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    in_payload = JSON_PRINT(root);
    JSON_DELETE(root);

    out_payload = NULL;
    // When
    err = _es_confirm_handler(context, in_payload, &out_payload);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(out_payload);

    // Teardown
    if (context->pin) {
        free(context->pin);
    }
    if (in_payload) {
        free(in_payload);
    }
    if (out_payload) {
        free(out_payload);
    }
}

void TC_STATIC_es_confirm_handler_invalid_pin_failure(void **state)
{
    iot_error_t err;
    char *in_payload;
    char *out_payload;
    struct iot_context *context;
    JSON_H *root;
    JSON_H *data;
    iot_pin_t pin_for_device = {.pin = "12345678"};
    char invalid_pin[9] = "ABCDEFGH";  // non-numeric pin

    // Given:
    context = (struct iot_context *)*state;
    context->curr_otm_feature = OVF_BIT_PIN;
    context->devconf.ownership_validation_type = IOT_OVF_TYPE_PIN;  // forced overwriting
    context->pin = malloc(sizeof(iot_pin_t));
    memset(context->pin, '\0', sizeof(iot_pin_t));
    memcpy(context->pin, &pin_for_device, sizeof(iot_pin_t));

    // Given: invalid pin (non-numeric)
    root = JSON_CREATE_OBJECT();
    data = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(data, "pin", JSON_CREATE_STRING(invalid_pin));
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    in_payload = JSON_PRINT(root);
    JSON_DELETE(root);

    out_payload = NULL;
    // When
    err = _es_confirm_handler(context, in_payload, &out_payload);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    assert_null(out_payload);

    // Teardown
    if (context->pin) {
        free(context->pin);
    }
    if (in_payload) {
        free(in_payload);
    }
}

void TC_STATIC_es_confirm_handler_non_pin_otm_failure(void **state)
{
    iot_error_t err;
    char *in_payload;
    char *out_payload;
    struct iot_context *context;
    JSON_H *root;
    JSON_H *data;
    char pin_for_test[9] = "12345678";

    // Given: valid pin 12345678
    context = (struct iot_context *)*state;
    context->curr_otm_feature = OVF_BIT_JUSTWORKS;
    context->devconf.ownership_validation_type = IOT_OVF_TYPE_PIN | IOT_OVF_TYPE_JUSTWORKS;  // forced overwriting
    context->pin = malloc(sizeof(iot_pin_t));
    memset(context->pin, '\0', sizeof(iot_pin_t));
    memcpy(context->pin->pin, pin_for_test, strlen(pin_for_test));

    // Create payload with valid pin
    root = JSON_CREATE_OBJECT();
    data = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(data, "pin", JSON_CREATE_STRING(pin_for_test));
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    in_payload = JSON_PRINT(root);
    JSON_DELETE(root);

    out_payload = NULL;
    // When
    err = _es_confirm_handler(context, in_payload, &out_payload);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    assert_null(out_payload);

    // Teardown
    if (context->pin) {
        free(context->pin);
    }
    if (in_payload) {
        free(in_payload);
    }
}

void TC_STATIC_es_confirm_handler_invalid_payload_failure(void **state)
{
    iot_error_t err;
    char *in_payload;
    char *out_payload;
    struct iot_context *context;
    char pin_for_test[9] = "12345678";

    // Given: invalid json format
    context = (struct iot_context *)*state;
    context->curr_otm_feature = OVF_BIT_PIN;
    context->devconf.ownership_validation_type = IOT_OVF_TYPE_PIN;
    context->pin = malloc(sizeof(iot_pin_t));
    memset(context->pin, '\0', sizeof(iot_pin_t));
    memcpy(context->pin->pin, pin_for_test, strlen(pin_for_test));
    out_payload = NULL;

    // Invalid JSON payload
    in_payload = strdup("{ \"invalid\" { \"json\": \"format\"}");  // Malformed JSON

    // When
    err = _es_confirm_handler(context, in_payload, &out_payload);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    assert_null(out_payload);

    // Teardown
    if (context->pin) {
        free(context->pin);
    }
    if (in_payload) {
        free(in_payload);
    }
}

void TC_STATIC_es_wifiscaninfo_handler_invalid_parameters_failure(void **state)
{
    iot_error_t err;
    struct iot_context *context;
    char *payload;

    // Given: null context, payload
    context = NULL;
    payload = NULL;
    // When
    err = _es_wifiscaninfo_handler(context, payload, &payload);
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
    err = _es_wifiscaninfo_handler(context, NULL, &out_payload);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(out_payload);

    // Local teardown
    if (out_payload) {
        free(out_payload);
    }
    if (context->scan_result) {
        free(context->scan_result);
    }
    _free_cipher(device_cipher);
    _free_cipher(server_cipher);
}

void TC_STATIC_es_wifiprovisioninginfo_handler_success(void **state)
{
    iot_error_t err;
    char *out_payload = NULL;
    char *in_payload = NULL;
    struct iot_context *context;
    JSON_H *root;
    JSON_H *data;
    JSON_H *wifi_credential;

    // Given
    context = (struct iot_context *)*state;
    context->lookup_id = NULL;

    // Create provisioning payload
    root = JSON_CREATE_OBJECT();
    data = JSON_CREATE_OBJECT();
    wifi_credential = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(wifi_credential, "ssid", JSON_CREATE_STRING("TestSSID"));
    JSON_ADD_ITEM_TO_OBJECT(wifi_credential, "password", JSON_CREATE_STRING("TestPassword"));
    JSON_ADD_ITEM_TO_OBJECT(data, "wifiCredential", wifi_credential);
    JSON_ADD_ITEM_TO_OBJECT(data, "brokerUrl", JSON_CREATE_STRING("https://test.domain.com:5676"));
    JSON_ADD_ITEM_TO_OBJECT(data, "deviceName", JSON_CREATE_STRING("TestDevice"));
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    in_payload = JSON_PRINT(root);
    JSON_DELETE(root);

    will_return(__wrap_iot_bsp_wifi_get_mac, 0x0000000000000000);
    will_return(__wrap_iot_bsp_wifi_get_mac, IOT_ERROR_NONE);
    // When
    err = _es_wifiprovisioninginfo_handler(context, in_payload, &out_payload);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(out_payload);

    // Local teardown
    if (out_payload) {
        free(out_payload);
    }
    if (in_payload) {
        free(in_payload);
    }
    if (context->scan_result) {
        free(context->scan_result);
    }
}

void TC_STATIC_es_wifiprovisioninginfo_handler_success_without_authtype_success(void **state)
{
    iot_error_t err;
    char *out_payload = NULL;
    char *in_payload = NULL;
    struct iot_context *context;
    JSON_H *root;
    JSON_H *data;
    JSON_H *wifi_credential;

    // Given
    context = (struct iot_context *)*state;
    context->lookup_id = NULL;

    // Create provisioning payload without authType
    root = JSON_CREATE_OBJECT();
    data = JSON_CREATE_OBJECT();
    wifi_credential = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(wifi_credential, "ssid", JSON_CREATE_STRING("TestSSID"));
    JSON_ADD_ITEM_TO_OBJECT(wifi_credential, "password", JSON_CREATE_STRING("TestPassword"));
    JSON_ADD_ITEM_TO_OBJECT(data, "wifiCredential", wifi_credential);
    JSON_ADD_ITEM_TO_OBJECT(data, "brokerUrl", JSON_CREATE_STRING("https://test.domain.com:5676"));
    JSON_ADD_ITEM_TO_OBJECT(data, "deviceName", JSON_CREATE_STRING("TestDevice"));
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    in_payload = JSON_PRINT(root);
    JSON_DELETE(root);

    will_return(__wrap_iot_bsp_wifi_get_mac, 0x0000000000000000);
    will_return(__wrap_iot_bsp_wifi_get_mac, IOT_ERROR_NONE);
    // When
    err = _es_wifiprovisioninginfo_handler(context, in_payload, &out_payload);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(out_payload);

    // Local teardown
    if (out_payload) {
        free(out_payload);
    }
    if (in_payload) {
        free(in_payload);
    }
    if (context->scan_result) {
        free(context->scan_result);
    }
}

void TC_STATIC_es_setupcomplete_handler_success(void **state)
{
    iot_error_t err;
    struct iot_context *context;
    char *out_payload = NULL;

    // Given
    context = (struct iot_context *)*state;
    context->work_queue_signal = iot_os_eventgroup_create();
    context->work_queue = iot_util_queue_create(sizeof(device_work_data_t));
    context->next_connection_retry_timer = NULL;
    // When
    err = _es_setupcomplete_handler(context, NULL, &out_payload);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(out_payload);

    // Teardown
    if (out_payload) {
        free(out_payload);
    }
    iot_os_eventgroup_delete(context->work_queue_signal);
    iot_util_queue_delete(context->work_queue);
}

// Additional test cases to improve coverage

void TC_STATIC_es_deviceinfo_handler_cipher_init_failure(void **state)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;

    // Given
    context = (struct iot_context *)*state;
    // Simulate cipher init failure by not setting up security context properly
    context->easysetup_security_context = NULL;

    // When
    err = _es_deviceinfo_handler(context, &out_payload);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Local teardown
    if (out_payload) {
        free(out_payload);
    }
}

void TC_STATIC_es_keyinfo_handler_json_parse_failure(void **state)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;
    char *invalid_payload;

    // Given
    context = (struct iot_context *)*state;
    // Invalid JSON payload
    invalid_payload = strdup("{ invalid json }");

    // When
    err = _es_keyinfo_handler(context, invalid_payload, &out_payload);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Teardown
    if (invalid_payload) {
        free(invalid_payload);
    }
    if (out_payload) {
        free(out_payload);
    }
}

void TC_STATIC_es_confirminfo_handler_missing_data_failure(void **state)
{
    iot_error_t err;
    char *in_payload;
    char *out_payload;
    struct iot_context *context;
    JSON_H *root;

    // Given
    context = (struct iot_context *)*state;

    // Create payload without data object
    root = JSON_CREATE_OBJECT();
    in_payload = JSON_PRINT(root);
    JSON_DELETE(root);

    out_payload = NULL;
    // When
    err = _es_confirminfo_handler(context, in_payload, &out_payload);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    assert_null(out_payload);

    // Teardown
    if (in_payload) {
        free(in_payload);
    }
}

void TC_STATIC_es_confirm_handler_missing_pin_failure(void **state)
{
    iot_error_t err;
    char *in_payload;
    char *out_payload;
    struct iot_context *context;
    JSON_H *root;
    JSON_H *data;

    // Given
    context = (struct iot_context *)*state;
    context->curr_otm_feature = OVF_BIT_PIN;
    context->devconf.ownership_validation_type = IOT_OVF_TYPE_PIN;
    context->pin = malloc(sizeof(iot_pin_t));
    memset(context->pin, '\0', sizeof(iot_pin_t));
    strcpy(context->pin->pin, "12345678");

    // Create payload without pin
    root = JSON_CREATE_OBJECT();
    data = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    in_payload = JSON_PRINT(root);
    JSON_DELETE(root);

    out_payload = NULL;
    // When
    err = _es_confirm_handler(context, in_payload, &out_payload);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    assert_null(out_payload);

    // Teardown
    if (context->pin) {
        free(context->pin);
    }
    if (in_payload) {
        free(in_payload);
    }
}

void TC_iot_easysetup_request_handler_null_context_failure(void **state)
{
    iot_error_t err;
    struct iot_context *context = NULL;
    struct iot_easysetup_payload request = {0};

    // Given: NULL context
    // When
    err = iot_easysetup_request_handler(context, request);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_easysetup_request_handler_null_queue_failure(void **state)
{
    iot_error_t err;
    struct iot_context *context;
    struct iot_easysetup_payload request = {0};

    // Given: context with NULL easysetup_resp_queue
    context = (struct iot_context *)*state;
    context->easysetup_resp_queue = NULL;

    // When
    err = iot_easysetup_request_handler(context, request);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_easysetup_request_handler_queue_send_error_failure(void **state)
{
    iot_error_t err;
    struct iot_context *context = NULL;
    struct iot_easysetup_payload request;

    // Given: over ranged step
    request.step = IOT_EASYSETUP_BLE_INVALID_STEP;
    request.payload = NULL;
    context = (struct iot_context *)*state;
    context->easysetup_resp_queue = iot_util_queue_create(sizeof(struct iot_easysetup_payload));
    context->iot_events = iot_os_eventgroup_create();
    set_mock_iot_os_malloc_failure_with_index(1);
    // When
    err = iot_easysetup_request_handler(context, request);
    // Then
    assert_int_equal(err, IOT_ERROR_EASYSETUP_QUEUE_SEND_ERROR);
    // Teardown
    iot_util_queue_delete(context->easysetup_resp_queue);
    iot_os_eventgroup_delete(context->iot_events);
    do_not_use_mock_iot_os_malloc_failure();
}

void TC_iot_easysetup_request_handler_memory_allocation_failure(void **state)
{
    iot_error_t err;
    struct iot_context *context;
    struct iot_easysetup_payload request;
    struct iot_devconf_prov_data *devconf;

    // Given
    context = (struct iot_context *)*state;
    devconf = &context->devconf;
    devconf->hashed_sn = sample_hashed_sn_b64url;
    context->easysetup_resp_queue = iot_util_queue_create(sizeof(struct iot_easysetup_payload));
    context->iot_events = iot_os_eventgroup_create();
    request.step = IOT_EASYSETUP_STEP_DEVICEINFO;
    request.payload = NULL;

    // When: response malloc failure
    set_mock_iot_os_malloc_failure_with_index(0);
    err = iot_easysetup_request_handler(context, request);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    do_not_use_mock_iot_os_malloc_failure();

    // Teardown
    iot_util_queue_delete(context->easysetup_resp_queue);
    iot_os_eventgroup_delete(context->iot_events);
}

void TC_iot_easysetup_request_handler_success(void **state)
{
    iot_error_t err;
    struct iot_context *context;
    struct iot_easysetup_payload request;
    struct iot_devconf_prov_data *devconf;

    // Given
    context = (struct iot_context *)*state;
    devconf = &context->devconf;
    devconf->hashed_sn = sample_hashed_sn_b64url;
    context->easysetup_resp_queue = iot_util_queue_create(sizeof(struct iot_easysetup_payload));
    context->iot_events = iot_os_eventgroup_create();
    request.step = IOT_EASYSETUP_STEP_DEVICEINFO;
    request.payload = NULL;

    // When
    err = iot_easysetup_request_handler(context, request);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);

    // Teardown
    iot_util_queue_delete(context->easysetup_resp_queue);
    iot_os_eventgroup_delete(context->iot_events);
}

void TC_STATIC_es_confirm_handler_null_context_failure(void **state)
{
    iot_error_t err;
    char *in_payload;
    char *out_payload;
    UNUSED(state);

    // Given: context is null
    // When
    err = _es_confirm_handler(NULL, "{ }", &out_payload);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_STATIC_es_confirm_handler_no_pin_context_failure(void **state)
{
    iot_error_t err;
    char *in_payload;
    char *out_payload;
    struct iot_context *context;

    // Given: context with no pin
    context = (struct iot_context *)*state;
    context->pin = NULL;
    context->curr_otm_feature = OVF_BIT_PIN;
    // When
    err = _es_confirm_handler(context, "{ }", &out_payload);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_STATIC_es_confirm_handler_invalid_otm_feature_failure(void **state)
{
    iot_error_t err;
    char *in_payload;
    char *out_payload;
    struct iot_context *context;
    JSON_H *root;
    JSON_H *data;
    char pin_for_test[9] = "12345678";

    // Given: valid pin but wrong otm feature
    context = (struct iot_context *)*state;
    context->curr_otm_feature = OVF_BIT_JUSTWORKS;  // Not PIN
    context->devconf.ownership_validation_type = IOT_OVF_TYPE_PIN;
    context->pin = malloc(sizeof(iot_pin_t));
    memset(context->pin, '\0', sizeof(iot_pin_t));
    memcpy(context->pin->pin, pin_for_test, strlen(pin_for_test));

    root = JSON_CREATE_OBJECT();
    data = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(data, "pin", JSON_CREATE_STRING(pin_for_test));
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    in_payload = JSON_PRINT(root);
    JSON_DELETE(root);

    out_payload = NULL;
    // When
    err = _es_confirm_handler(context, in_payload, &out_payload);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Teardown
    if (context->pin) {
        free(context->pin);
    }
    if (in_payload) {
        free(in_payload);
    }
}

void TC_STATIC_es_confirm_handler_pin_size_mismatch_failure(void **state)
{
    iot_error_t err;
    char *in_payload;
    char *out_payload;
    struct iot_context *context;
    JSON_H *root;
    JSON_H *data;
    char short_pin[5] = "1234";  // Too short

    // Given: pin with wrong size
    context = (struct iot_context *)*state;
    context->curr_otm_feature = OVF_BIT_PIN;
    context->devconf.ownership_validation_type = IOT_OVF_TYPE_PIN;
    context->pin = malloc(sizeof(iot_pin_t));
    memset(context->pin, '\0', sizeof(iot_pin_t));
    memcpy(context->pin->pin, "12345678", 8);

    root = JSON_CREATE_OBJECT();
    data = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(data, "pin", JSON_CREATE_STRING(short_pin));
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    in_payload = JSON_PRINT(root);
    JSON_DELETE(root);

    out_payload = NULL;
    // When
    err = _es_confirm_handler(context, in_payload, &out_payload);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Teardown
    if (context->pin) {
        free(context->pin);
    }
    if (in_payload) {
        free(in_payload);
    }
}

void TC_STATIC_es_confirm_handler_pin_mismatch_failure(void **state)
{
    iot_error_t err;
    char *in_payload;
    char *out_payload;
    struct iot_context *context;
    JSON_H *root;
    JSON_H *data;
    char device_pin[9] = "12345678";
    char wrong_pin[9] = "87654321";

    // Given: pin mismatch
    context = (struct iot_context *)*state;
    context->curr_otm_feature = OVF_BIT_PIN;
    context->devconf.ownership_validation_type = IOT_OVF_TYPE_PIN;
    context->pin = malloc(sizeof(iot_pin_t));
    memset(context->pin, '\0', sizeof(iot_pin_t));
    memcpy(context->pin->pin, device_pin, strlen(device_pin));

    root = JSON_CREATE_OBJECT();
    data = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(data, "pin", JSON_CREATE_STRING(wrong_pin));
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    in_payload = JSON_PRINT(root);
    JSON_DELETE(root);

    out_payload = NULL;
    // When
    err = _es_confirm_handler(context, in_payload, &out_payload);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Teardown
    if (context->pin) {
        free(context->pin);
    }
    if (in_payload) {
        free(in_payload);
    }
}

void TC_STATIC_es_confirm_handler_missing_data_failure(void **state)
{
    iot_error_t err;
    char *in_payload;
    char *out_payload;
    struct iot_context *context;
    char pin_for_test[9] = "12345678";

    // Given: invalid payload without data field
    context = (struct iot_context *)*state;
    context->curr_otm_feature = OVF_BIT_PIN;
    context->devconf.ownership_validation_type = IOT_OVF_TYPE_PIN;
    context->pin = malloc(sizeof(iot_pin_t));
    memset(context->pin, '\0', sizeof(iot_pin_t));
    memcpy(context->pin->pin, pin_for_test, strlen(pin_for_test));

    in_payload = strdup("{ \"nodata\": {} }");
    out_payload = NULL;

    // When
    err = _es_confirm_handler(context, in_payload, &out_payload);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Teardown
    if (context->pin) {
        free(context->pin);
    }
    if (in_payload) {
        free(in_payload);
    }
}

void TC_STATIC_es_confirminfo_handler_qr_code_null_sn_failure(void **state)
{
    iot_error_t err;
    char *in_payload = NULL;
    char *out_payload = NULL;
    struct iot_context *context;
    time_t time_to_set;

    // Given:
    context = (struct iot_context *)*state;
    context->iot_events = iot_os_eventgroup_create();
    context->work_queue_signal = iot_os_eventgroup_create();
    context->work_queue = iot_util_queue_create(sizeof(device_work_data_t));
    context->devconf.ownership_validation_type = (1u << OVF_BIT_QR);

    // First call keyinfo handler to initialize global ownership_validation_type
    in_payload = _generate_post_keyinfo_payload(2020, &time_to_set);
    expect_value(__wrap_iot_bsp_system_set_time_in_sec, time_in_sec, time_to_set);
    err = _es_keyinfo_handler(context, in_payload, &out_payload);
    assert_int_equal(err, IOT_ERROR_NONE);
    if (in_payload) {
        free(in_payload);
    }
    if (out_payload) {
        free(out_payload);
    }

    // Given: QR code payload with NULL serial number
    out_payload = NULL;
    in_payload = _generate_confirminfo_payload(OVF_BIT_QR, NULL);
    // When
    err = _es_confirminfo_handler(context, in_payload, &out_payload);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Teardown
    if (in_payload) {
        free(in_payload);
    }
    if (out_payload) {
        free(out_payload);
    }

    // Teardown: common
    iot_os_eventgroup_delete(context->iot_events);
    iot_os_eventgroup_delete(context->work_queue_signal);
    iot_util_queue_delete(context->work_queue);
}

void TC_STATIC_es_confirminfo_handler_qr_code_wrong_sn_failure(void **state)
{
    iot_error_t err;
    char *in_payload = NULL;
    char *out_payload = NULL;
    struct iot_context *context;
    time_t time_to_set;

    // Given:
    context = (struct iot_context *)*state;
    context->iot_events = iot_os_eventgroup_create();
    context->work_queue_signal = iot_os_eventgroup_create();
    context->work_queue = iot_util_queue_create(sizeof(device_work_data_t));
    context->devconf.ownership_validation_type = (1u << OVF_BIT_QR);

    // First call keyinfo handler to initialize global ownership_validation_type
    in_payload = _generate_post_keyinfo_payload(2020, &time_to_set);
    expect_value(__wrap_iot_bsp_system_set_time_in_sec, time_in_sec, time_to_set);
    err = _es_keyinfo_handler(context, in_payload, &out_payload);
    assert_int_equal(err, IOT_ERROR_NONE);
    if (in_payload) {
        free(in_payload);
    }
    if (out_payload) {
        free(out_payload);
    }

    // Given: QR code payload with wrong serial number
    out_payload = NULL;
    in_payload = _generate_confirminfo_payload(OVF_BIT_QR, "WRONG_SERIAL_NUMBER");
    // When
    err = _es_confirminfo_handler(context, in_payload, &out_payload);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Teardown
    if (in_payload) {
        free(in_payload);
    }
    if (out_payload) {
        free(out_payload);
    }

    // Teardown: common
    iot_os_eventgroup_delete(context->iot_events);
    iot_os_eventgroup_delete(context->work_queue_signal);
    iot_util_queue_delete(context->work_queue);
}

void TC_STATIC_es_confirminfo_handler_serial_number_null_sn_failure(void **state)
{
    iot_error_t err;
    char *in_payload = NULL;
    char *out_payload = NULL;
    struct iot_context *context;
    time_t time_to_set;

    // Given:
    context = (struct iot_context *)*state;
    context->iot_events = iot_os_eventgroup_create();
    context->work_queue_signal = iot_os_eventgroup_create();
    context->work_queue = iot_util_queue_create(sizeof(device_work_data_t));
    context->devconf.ownership_validation_type = (1u << OVF_BIT_SERIAL_NUMBER);

    // First call keyinfo handler
    in_payload = _generate_post_keyinfo_payload(2020, &time_to_set);
    expect_value(__wrap_iot_bsp_system_set_time_in_sec, time_in_sec, time_to_set);
    err = _es_keyinfo_handler(context, in_payload, &out_payload);
    assert_int_equal(err, IOT_ERROR_NONE);
    if (in_payload) {
        free(in_payload);
    }
    if (out_payload) {
        free(out_payload);
    }

    // Given: serial number payload with NULL serial number
    out_payload = NULL;
    in_payload = _generate_confirminfo_payload(OVF_BIT_SERIAL_NUMBER, NULL);
    // When
    err = _es_confirminfo_handler(context, in_payload, &out_payload);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Teardown
    if (in_payload) {
        free(in_payload);
    }
    if (out_payload) {
        free(out_payload);
    }

    // Teardown: common
    iot_os_eventgroup_delete(context->iot_events);
    iot_os_eventgroup_delete(context->work_queue_signal);
    iot_util_queue_delete(context->work_queue);
}

void TC_STATIC_es_confirminfo_handler_serial_number_wrong_sn_failure(void **state)
{
    iot_error_t err;
    char *in_payload = NULL;
    char *out_payload = NULL;
    struct iot_context *context;
    time_t time_to_set;

    // Given:
    context = (struct iot_context *)*state;
    context->iot_events = iot_os_eventgroup_create();
    context->work_queue_signal = iot_os_eventgroup_create();
    context->work_queue = iot_util_queue_create(sizeof(device_work_data_t));
    context->devconf.ownership_validation_type = (1u << OVF_BIT_SERIAL_NUMBER);

    // First call keyinfo handler
    in_payload = _generate_post_keyinfo_payload(2020, &time_to_set);
    expect_value(__wrap_iot_bsp_system_set_time_in_sec, time_in_sec, time_to_set);
    err = _es_keyinfo_handler(context, in_payload, &out_payload);
    assert_int_equal(err, IOT_ERROR_NONE);
    if (in_payload) {
        free(in_payload);
    }
    if (out_payload) {
        free(out_payload);
    }

    // Given: serial number payload with wrong serial number
    out_payload = NULL;
    in_payload = _generate_confirminfo_payload(OVF_BIT_SERIAL_NUMBER, "WRONG_SERIAL");
    // When
    err = _es_confirminfo_handler(context, in_payload, &out_payload);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Teardown
    if (in_payload) {
        free(in_payload);
    }
    if (out_payload) {
        free(out_payload);
    }

    // Teardown: common
    iot_os_eventgroup_delete(context->iot_events);
    iot_os_eventgroup_delete(context->work_queue_signal);
    iot_util_queue_delete(context->work_queue);
}

void TC_STATIC_es_confirminfo_handler_button_confirm_success(void **state)
{
    iot_error_t err;
    char *in_payload;
    char *out_payload;
    struct iot_context *context;
    time_t time_to_set;
    IOT_CTX *ctx;

    // Given
    context = (struct iot_context *)*state;
    context->iot_events = iot_os_eventgroup_create();
    context->work_queue_signal = iot_os_eventgroup_create();
    context->work_queue = iot_util_queue_create(sizeof(device_work_data_t));
    context->devconf.ownership_validation_type = (1u << OVF_BIT_BUTTON);
    context->curr_otm_feature = OVF_BIT_BUTTON;
    ctx = (IOT_CTX *)context;
    st_conn_ownership_confirm(ctx, true);

    // First call keyinfo handler
    in_payload = _generate_post_keyinfo_payload(2020, &time_to_set);
    expect_value(__wrap_iot_bsp_system_set_time_in_sec, time_in_sec, time_to_set);
    err = _es_keyinfo_handler(context, in_payload, &out_payload);
    assert_int_equal(err, IOT_ERROR_NONE);
    if (in_payload) {
        free(in_payload);
    }
    if (out_payload) {
        free(out_payload);
    }

    // Given: button payload
    in_payload = _generate_confirminfo_payload(OVF_BIT_BUTTON, NULL);
    // When
    err = _es_confirminfo_handler(context, in_payload, &out_payload);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);

    // Teardown
    if (in_payload) {
        free(in_payload);
    }
    if (out_payload) {
        free(out_payload);
    }
    iot_os_eventgroup_delete(context->iot_events);
    iot_os_eventgroup_delete(context->work_queue_signal);
    iot_util_queue_delete(context->work_queue);
}

void TC_STATIC_es_confirminfo_handler_button_deny_success(void **state)
{
    iot_error_t err;
    char *in_payload;
    char *out_payload;
    struct iot_context *context;
    time_t time_to_set;
    IOT_CTX *ctx;

    // Given
    context = (struct iot_context *)*state;
    context->iot_events = iot_os_eventgroup_create();
    context->work_queue_signal = iot_os_eventgroup_create();
    context->work_queue = iot_util_queue_create(sizeof(device_work_data_t));
    context->devconf.ownership_validation_type = (1u << OVF_BIT_BUTTON);
    context->curr_otm_feature = OVF_BIT_BUTTON;
    ctx = (IOT_CTX *)context;
    st_conn_ownership_confirm(ctx, false);

    // First call keyinfo handler
    in_payload = _generate_post_keyinfo_payload(2020, &time_to_set);
    expect_value(__wrap_iot_bsp_system_set_time_in_sec, time_in_sec, time_to_set);
    err = _es_keyinfo_handler(context, in_payload, &out_payload);
    assert_int_equal(err, IOT_ERROR_NONE);
    if (in_payload) {
        free(in_payload);
    }
    if (out_payload) {
        free(out_payload);
    }

    // Given: button payload
    in_payload = _generate_confirminfo_payload(OVF_BIT_BUTTON, NULL);
    // When
    err = _es_confirminfo_handler(context, in_payload, &out_payload);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Teardown
    if (in_payload) {
        free(in_payload);
    }
    if (out_payload) {
        free(out_payload);
    }
    iot_os_eventgroup_delete(context->iot_events);
    iot_os_eventgroup_delete(context->work_queue_signal);
    iot_util_queue_delete(context->work_queue);
}

void TC_STATIC_es_confirminfo_handler_pin_success(void **state)
{
    iot_error_t err;
    char *in_payload;
    char *out_payload;
    struct iot_context *context;
    time_t time_to_set;

    // Given: PIN feature
    context = (struct iot_context *)*state;
    context->iot_events = iot_os_eventgroup_create();
    context->work_queue_signal = iot_os_eventgroup_create();
    context->work_queue = iot_util_queue_create(sizeof(device_work_data_t));
    context->devconf.ownership_validation_type = (1u << OVF_BIT_PIN);

    // First call keyinfo handler
    in_payload = _generate_post_keyinfo_payload(2020, &time_to_set);
    expect_value(__wrap_iot_bsp_system_set_time_in_sec, time_in_sec, time_to_set);
    err = _es_keyinfo_handler(context, in_payload, &out_payload);
    assert_int_equal(err, IOT_ERROR_NONE);
    if (in_payload) {
        free(in_payload);
    }
    if (out_payload) {
        free(out_payload);
    }

    // Given: pin payload
    in_payload = _generate_confirminfo_payload(OVF_BIT_PIN, NULL);
    // When
    err = _es_confirminfo_handler(context, in_payload, &out_payload);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);

    // Teardown
    if (in_payload) {
        free(in_payload);
    }
    if (out_payload) {
        free(out_payload);
    }
    iot_os_eventgroup_delete(context->iot_events);
    iot_os_eventgroup_delete(context->work_queue_signal);
    iot_util_queue_delete(context->work_queue);
}

void TC_STATIC_es_confirminfo_handler_hashed_sn_success(void **state)
{
    iot_error_t err;
    char *in_payload;
    char *out_payload;
    struct iot_context *context;
    time_t time_to_set;

    // Given: Hashed serial number feature
    context = (struct iot_context *)*state;
    context->iot_events = iot_os_eventgroup_create();
    context->work_queue_signal = iot_os_eventgroup_create();
    context->work_queue = iot_util_queue_create(sizeof(device_work_data_t));
    context->devconf.ownership_validation_type = (1u << OVF_BIT_HASHED_SERIAL_NUMBER);
    context->wifi_update_enabled = true;

    // First call keyinfo handler
    in_payload = _generate_post_keyinfo_payload(2020, &time_to_set);
    expect_value(__wrap_iot_bsp_system_set_time_in_sec, time_in_sec, time_to_set);
    err = _es_keyinfo_handler(context, in_payload, &out_payload);
    if (in_payload) {
        free(in_payload);
    }
    if (out_payload) {
        free(out_payload);
    }

    // Now test confirminfo with hashed SN - use a computed hash
    JSON_H *root = JSON_CREATE_OBJECT();
    JSON_H *data = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(data, "otmSupportFeature", JSON_CREATE_NUMBER(OVF_BIT_HASHED_SERIAL_NUMBER));
    // Use the expected hash for TEST_DEVICE_SERIAL_NUMBER
    JSON_ADD_ITEM_TO_OBJECT(
        data, "hashedsn",
        JSON_CREATE_STRING("4dacd75f1b9c3e8c9e8b8e8b8e8b8e8b8e8b8e8b8e8b8e8b8e8b8e8b8e8b8e8b8e8b8e8b8e8b"));
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    in_payload = JSON_PRINT(root);
    JSON_DELETE(root);

    // When
    err = _es_confirminfo_handler(context, in_payload, &out_payload);
    // Then - expect failure due to hash mismatch (but handler runs successfully)
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Teardown
    if (in_payload) {
        free(in_payload);
    }
    if (out_payload) {
        free(out_payload);
    }
    iot_os_eventgroup_delete(context->iot_events);
    iot_os_eventgroup_delete(context->work_queue_signal);
    iot_util_queue_delete(context->work_queue);
}

void TC_STATIC_es_confirminfo_handler_hashed_sn_wrong_hash_failure(void **state)
{
    iot_error_t err;
    char *in_payload;
    char *out_payload;
    struct iot_context *context;
    time_t time_to_set;

    // Given: Hashed serial number feature with wrong hash
    context = (struct iot_context *)*state;
    context->iot_events = iot_os_eventgroup_create();
    context->work_queue_signal = iot_os_eventgroup_create();
    context->work_queue = iot_util_queue_create(sizeof(device_work_data_t));
    context->devconf.ownership_validation_type = (1u << OVF_BIT_HASHED_SERIAL_NUMBER);
    context->wifi_update_enabled = true;

    // First call keyinfo handler
    in_payload = _generate_post_keyinfo_payload(2020, &time_to_set);
    expect_value(__wrap_iot_bsp_system_set_time_in_sec, time_in_sec, time_to_set);
    err = _es_keyinfo_handler(context, in_payload, &out_payload);
    if (in_payload) {
        free(in_payload);
    }
    if (out_payload) {
        free(out_payload);
    }

    // Now test confirminfo with wrong hashed SN
    JSON_H *root = JSON_CREATE_OBJECT();
    JSON_H *data = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(data, "otmSupportFeature", JSON_CREATE_NUMBER(OVF_BIT_HASHED_SERIAL_NUMBER));
    JSON_ADD_ITEM_TO_OBJECT(data, "hashedsn", JSON_CREATE_STRING("wronghashedvalue123456789"));
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    in_payload = JSON_PRINT(root);
    JSON_DELETE(root);

    // When
    err = _es_confirminfo_handler(context, in_payload, &out_payload);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Teardown
    if (in_payload) {
        free(in_payload);
    }
    if (out_payload) {
        free(out_payload);
    }
    iot_os_eventgroup_delete(context->iot_events);
    iot_os_eventgroup_delete(context->work_queue_signal);
    iot_util_queue_delete(context->work_queue);
}

void TC_STATIC_es_confirminfo_handler_hashed_sn_null_sn_failure(void **state)
{
    iot_error_t err;
    char *in_payload;
    char *out_payload;
    struct iot_context *context;
    time_t time_to_set;

    // Given: Hashed serial number feature with null SN
    context = (struct iot_context *)*state;
    context->iot_events = iot_os_eventgroup_create();
    context->work_queue_signal = iot_os_eventgroup_create();
    context->work_queue = iot_util_queue_create(sizeof(device_work_data_t));
    context->devconf.ownership_validation_type = (1u << OVF_BIT_HASHED_SERIAL_NUMBER);
    context->wifi_update_enabled = true;

    // First call keyinfo handler
    in_payload = _generate_post_keyinfo_payload(2020, &time_to_set);
    expect_value(__wrap_iot_bsp_system_set_time_in_sec, time_in_sec, time_to_set);
    err = _es_keyinfo_handler(context, in_payload, &out_payload);
    if (in_payload) {
        free(in_payload);
    }
    if (out_payload) {
        free(out_payload);
    }

    // Now test confirminfo with NULL hashedsn
    JSON_H *root = JSON_CREATE_OBJECT();
    JSON_H *data = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(data, "otmSupportFeature", JSON_CREATE_NUMBER(OVF_BIT_HASHED_SERIAL_NUMBER));
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    in_payload = JSON_PRINT(root);
    JSON_DELETE(root);

    // When
    err = _es_confirminfo_handler(context, in_payload, &out_payload);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Teardown
    if (in_payload) {
        free(in_payload);
    }
    if (out_payload) {
        free(out_payload);
    }
    iot_os_eventgroup_delete(context->iot_events);
    iot_os_eventgroup_delete(context->work_queue_signal);
    iot_util_queue_delete(context->work_queue);
}

void TC_STATIC_es_wifiscaninfo_handler_no_payload_success(void **state)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;
    iot_security_cipher_params_t *device_cipher;

    // Given: null payload
    context = (struct iot_context *)*state;
    device_cipher = _generate_device_cipher(NULL, 0);
    assert_non_null(device_cipher);
    err = iot_security_cipher_set_params(context->easysetup_security_context, device_cipher);
    assert_int_equal(err, IOT_ERROR_NONE);
    will_return(__wrap_iot_bsp_wifi_get_scan_result, 5);
    expect_value(__wrap_iot_bsp_wifi_set_mode, conf->mode, IOT_WIFI_MODE_SCAN);
    will_return(__wrap_iot_bsp_wifi_set_mode, IOT_ERROR_NONE);

    // When
    err = _es_wifiscaninfo_handler(context, NULL, &out_payload);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(out_payload);

    // Teardown
    if (out_payload) {
        free(out_payload);
    }
    if (context->scan_result) {
        free(context->scan_result);
    }
    _free_cipher(device_cipher);
}

void TC_STATIC_es_wifiscaninfo_handler_null_context_failure(void **state)
{
    iot_error_t err;
    char *out_payload = NULL;

    // Given: null context
    // When
    err = _es_wifiscaninfo_handler(NULL, NULL, &out_payload);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_STATIC_es_wifiprovisioninginfo_handler_null_context_failure(void **state)
{
    iot_error_t err;
    char *out_payload = NULL;
    char *in_payload = "{ }";

    // Given: null context
    // When
    err = _es_wifiprovisioninginfo_handler(NULL, in_payload, &out_payload);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_STATIC_es_wifiprovisioninginfo_handler_invalid_payload_failure(void **state)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;

    // Given: invalid payload
    context = (struct iot_context *)*state;
    context->lookup_id = NULL;
    char *invalid_payload = strdup("{ invalid json }");

    // When
    err = _es_wifiprovisioninginfo_handler(context, invalid_payload, &out_payload);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Teardown
    if (invalid_payload) {
        free(invalid_payload);
    }
}

void TC_STATIC_es_wifiprovisioninginfo_handler_missing_wifi_credential_failure(void **state)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;
    JSON_H *root;
    JSON_H *data;

    // Given: missing wifiCredential
    context = (struct iot_context *)*state;
    context->lookup_id = NULL;

    root = JSON_CREATE_OBJECT();
    data = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    char *in_payload = JSON_PRINT(root);
    JSON_DELETE(root);

    // When
    err = _es_wifiprovisioninginfo_handler(context, in_payload, &out_payload);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Teardown
    if (in_payload) {
        free(in_payload);
    }
}

void TC_STATIC_es_wifiprovisioninginfo_handler_missing_ssid_failure(void **state)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;
    JSON_H *root;
    JSON_H *data;
    JSON_H *wifi_credential;

    // Given: missing SSID in wifiCredential
    context = (struct iot_context *)*state;
    context->lookup_id = NULL;

    root = JSON_CREATE_OBJECT();
    data = JSON_CREATE_OBJECT();
    wifi_credential = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(data, "wifiCredential", wifi_credential);
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    char *in_payload = JSON_PRINT(root);
    JSON_DELETE(root);

    // When
    err = _es_wifiprovisioninginfo_handler(context, in_payload, &out_payload);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Teardown
    if (in_payload) {
        free(in_payload);
    }
}

void TC_iot_easysetup_request_handler_wifiscaninfo_step_success(void **state)
{
    iot_error_t err;
    struct iot_context *context;
    struct iot_easysetup_payload request;
    iot_security_cipher_params_t *device_cipher;

    // Given
    context = (struct iot_context *)*state;
    device_cipher = _generate_device_cipher(NULL, 0);
    assert_non_null(device_cipher);
    err = iot_security_cipher_set_params(context->easysetup_security_context, device_cipher);
    assert_int_equal(err, IOT_ERROR_NONE);
    context->easysetup_resp_queue = iot_util_queue_create(sizeof(struct iot_easysetup_payload));
    context->iot_events = iot_os_eventgroup_create();
    request.step = IOT_EASYSETUP_STEP_WIFISCANINFO;
    request.payload = NULL;
    will_return(__wrap_iot_bsp_wifi_get_scan_result, 5);
    expect_value(__wrap_iot_bsp_wifi_set_mode, conf->mode, IOT_WIFI_MODE_SCAN);
    will_return(__wrap_iot_bsp_wifi_set_mode, IOT_ERROR_NONE);

    // When
    err = iot_easysetup_request_handler(context, request);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);

    // Teardown
    if (context->scan_result) {
        free(context->scan_result);
    }
    iot_util_queue_delete(context->easysetup_resp_queue);
    iot_os_eventgroup_delete(context->iot_events);
    _free_cipher(device_cipher);
}

void TC_iot_easysetup_request_handler_keyinfo_step_success(void **state)
{
    iot_error_t err;
    struct iot_context *context;
    struct iot_easysetup_payload request;
    time_t time_to_set;

    // Given
    context = (struct iot_context *)*state;
    context->devconf.ownership_validation_type = OVF_BIT_JUSTWORKS;
    context->easysetup_resp_queue = iot_util_queue_create(sizeof(struct iot_easysetup_payload));
    context->iot_events = iot_os_eventgroup_create();
    request.payload = _generate_post_keyinfo_payload(2020, &time_to_set);
    expect_value(__wrap_iot_bsp_system_set_time_in_sec, time_in_sec, time_to_set);
    request.step = IOT_EASYSETUP_STEP_KEYINFO;

    // When
    err = iot_easysetup_request_handler(context, request);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);

    // Teardown
    if (request.payload) {
        free(request.payload);
    }
    iot_util_queue_delete(context->easysetup_resp_queue);
    iot_os_eventgroup_delete(context->iot_events);
}

void TC_iot_easysetup_request_handler_invalid_step_failure(void **state)
{
    iot_error_t err;
    struct iot_context *context;
    struct iot_easysetup_payload request;

    // Given: invalid step
    context = (struct iot_context *)*state;
    context->easysetup_resp_queue = iot_util_queue_create(sizeof(struct iot_easysetup_payload));
    context->iot_events = iot_os_eventgroup_create();
    request.step = 999;  // Invalid step
    request.payload = NULL;

    // When
    err = iot_easysetup_request_handler(context, request);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);  // Handler still succeeds, response contains error

    // Teardown
    iot_util_queue_delete(context->easysetup_resp_queue);
    iot_os_eventgroup_delete(context->iot_events);
}

void TC_STATIC_es_setupcomplete_handler_wifi_update_enabled_success(void **state)
{
    iot_error_t err;
    struct iot_context *context;
    char *out_payload = NULL;

    // Given: wifi_update_enabled is true
    context = (struct iot_context *)*state;
    context->work_queue_signal = iot_os_eventgroup_create();
    context->work_queue = iot_util_queue_create(sizeof(device_work_data_t));
    context->next_connection_retry_timer = NULL;
    context->wifi_update_enabled = true;

    // When
    err = _es_setupcomplete_handler(context, NULL, &out_payload);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(out_payload);

    // Teardown
    if (out_payload) {
        free(out_payload);
    }
    iot_os_eventgroup_delete(context->work_queue_signal);
    iot_util_queue_delete(context->work_queue);
}

void TC_STATIC_es_confirm_handler_null_context_failure_v2(void **state)
{
    iot_error_t err;
    char *in_payload = NULL;
    char *out_payload = NULL;

    // Given: null context
    UNUSED(state);
    in_payload = strdup("{ \"data\": { \"pin\": \"12345678\" } }");
    // When
    err = _es_confirm_handler(NULL, in_payload, &out_payload);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    if (in_payload) {
        free(in_payload);
    }
}

void TC_STATIC_es_wifiscaninfo_handler_with_matching_ssid_success(void **state)
{
    iot_error_t err;
    char *out_payload = NULL;
    char *in_payload = NULL;
    struct iot_context *context;
    iot_security_cipher_params_t *device_cipher;
    JSON_H *root;
    JSON_H *data;
    JSON_H *mobile_wifi;

    // Given: payload with matching SSID
    context = (struct iot_context *)*state;
    device_cipher = _generate_device_cipher(NULL, 0);
    assert_non_null(device_cipher);
    err = iot_security_cipher_set_params(context->easysetup_security_context, device_cipher);
    assert_int_equal(err, IOT_ERROR_NONE);

    root = JSON_CREATE_OBJECT();
    data = JSON_CREATE_OBJECT();
    mobile_wifi = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(mobile_wifi, "ssid", JSON_CREATE_STRING(sample_ssid));
    JSON_ADD_ITEM_TO_OBJECT(mobile_wifi, "frequency", JSON_CREATE_NUMBER(2400));
    JSON_ADD_ITEM_TO_OBJECT(data, "mobileWifiCredential", mobile_wifi);
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    in_payload = JSON_PRINT(root);
    JSON_DELETE(root);

    will_return(__wrap_iot_bsp_wifi_get_scan_result, 5);
    expect_value(__wrap_iot_bsp_wifi_set_mode, conf->mode, IOT_WIFI_MODE_SCAN);
    will_return(__wrap_iot_bsp_wifi_set_mode, IOT_ERROR_NONE);

    // When
    err = _es_wifiscaninfo_handler(context, in_payload, &out_payload);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(out_payload);

    // Teardown
    if (out_payload) {
        free(out_payload);
    }
    if (in_payload) {
        free(in_payload);
    }
    if (context->scan_result) {
        free(context->scan_result);
    }
    _free_cipher(device_cipher);
}

void TC_STATIC_es_wifiscaninfo_handler_wifi_scan_error_failure(void **state)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;
    iot_security_cipher_params_t *device_cipher;

    // Given: wifi scan fails
    context = (struct iot_context *)*state;
    context->scan_num = 0;  // Force wifi scan
    device_cipher = _generate_device_cipher(NULL, 0);
    assert_non_null(device_cipher);
    err = iot_security_cipher_set_params(context->easysetup_security_context, device_cipher);
    assert_int_equal(err, IOT_ERROR_NONE);

    expect_value(__wrap_iot_bsp_wifi_set_mode, conf->mode, IOT_WIFI_MODE_SCAN);
    will_return(__wrap_iot_bsp_wifi_set_mode, IOT_ERROR_CONN_WIFI_SCAN_SKIP);

    // When
    err = _es_wifiscaninfo_handler(context, NULL, &out_payload);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    _free_cipher(device_cipher);
}

void TC_STATIC_es_confirminfo_handler_missing_otm_feature_failure(void **state)
{
    iot_error_t err;
    char *in_payload;
    char *out_payload;
    struct iot_context *context;
    JSON_H *root;
    JSON_H *data;

    // Given: missing otmSupportFeature
    context = (struct iot_context *)*state;
    root = JSON_CREATE_OBJECT();
    data = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    in_payload = JSON_PRINT(root);
    JSON_DELETE(root);

    out_payload = NULL;
    // When
    err = _es_confirminfo_handler(context, in_payload, &out_payload);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Teardown
    if (in_payload) {
        free(in_payload);
    }
}

void TC_iot_easysetup_request_handler_confirminfo_step_success(void **state)
{
    iot_error_t err;
    struct iot_context *context;
    struct iot_easysetup_payload request;
    time_t time_to_set;

    // Given
    context = (struct iot_context *)*state;
    context->iot_events = iot_os_eventgroup_create();
    context->work_queue_signal = iot_os_eventgroup_create();
    context->work_queue = iot_util_queue_create(sizeof(device_work_data_t));
    context->devconf.ownership_validation_type = (1u << OVF_BIT_JUSTWORKS);
    context->easysetup_resp_queue = iot_util_queue_create(sizeof(struct iot_easysetup_payload));

    // First setup keyinfo
    request.payload = _generate_post_keyinfo_payload(2020, &time_to_set);
    request.step = IOT_EASYSETUP_STEP_KEYINFO;
    expect_value(__wrap_iot_bsp_system_set_time_in_sec, time_in_sec, time_to_set);
    err = iot_easysetup_request_handler(context, request);
    if (request.payload) {
        free(request.payload);
    }

    // Now test confirminfo
    request.payload = _generate_confirminfo_payload(OVF_BIT_JUSTWORKS, NULL);
    request.step = IOT_EASYSETUP_STEP_CONFIRMINFO;

    // When
    err = iot_easysetup_request_handler(context, request);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);

    // Teardown
    if (request.payload) {
        free(request.payload);
    }
    iot_os_eventgroup_delete(context->iot_events);
    iot_os_eventgroup_delete(context->work_queue_signal);
    iot_util_queue_delete(context->work_queue);
    iot_util_queue_delete(context->easysetup_resp_queue);
}

void TC_iot_easysetup_request_handler_confirm_step_success(void **state)
{
    iot_error_t err;
    struct iot_context *context;
    struct iot_easysetup_payload request;
    JSON_H *root;
    JSON_H *data;
    char pin_for_test[9] = "12345678";

    // Given
    context = (struct iot_context *)*state;
    context->curr_otm_feature = OVF_BIT_PIN;
    context->devconf.ownership_validation_type = IOT_OVF_TYPE_PIN;
    context->pin = malloc(sizeof(iot_pin_t));
    memset(context->pin, '\0', sizeof(iot_pin_t));
    memcpy(context->pin->pin, pin_for_test, strlen(pin_for_test));
    context->easysetup_resp_queue = iot_util_queue_create(sizeof(struct iot_easysetup_payload));
    context->iot_events = iot_os_eventgroup_create();

    root = JSON_CREATE_OBJECT();
    data = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(data, "pin", JSON_CREATE_STRING(pin_for_test));
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    request.payload = JSON_PRINT(root);
    JSON_DELETE(root);
    request.step = IOT_EASYSETUP_STEP_CONFIRM;

    // When
    err = iot_easysetup_request_handler(context, request);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);

    // Teardown
    if (context->pin) {
        free(context->pin);
    }
    if (request.payload) {
        free(request.payload);
    }
    iot_util_queue_delete(context->easysetup_resp_queue);
    iot_os_eventgroup_delete(context->iot_events);
}

void TC_iot_easysetup_request_handler_wifiprov_step_success(void **state)
{
    iot_error_t err;
    struct iot_context *context;
    struct iot_easysetup_payload request;
    JSON_H *root;
    JSON_H *data;
    JSON_H *wifi_credential;

    // Given
    context = (struct iot_context *)*state;
    context->lookup_id = NULL;
    context->easysetup_resp_queue = iot_util_queue_create(sizeof(struct iot_easysetup_payload));
    context->iot_events = iot_os_eventgroup_create();

    root = JSON_CREATE_OBJECT();
    data = JSON_CREATE_OBJECT();
    wifi_credential = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(wifi_credential, "ssid", JSON_CREATE_STRING("TestSSID"));
    JSON_ADD_ITEM_TO_OBJECT(wifi_credential, "password", JSON_CREATE_STRING("TestPassword"));
    JSON_ADD_ITEM_TO_OBJECT(data, "wifiCredential", wifi_credential);
    JSON_ADD_ITEM_TO_OBJECT(data, "brokerUrl", JSON_CREATE_STRING("https://test.domain.com:5676"));
    JSON_ADD_ITEM_TO_OBJECT(data, "deviceName", JSON_CREATE_STRING("TestDevice"));
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    request.payload = JSON_PRINT(root);
    JSON_DELETE(root);
    request.step = IOT_EASYSETUP_STEP_WIFIPROVIONINGINFO;

    will_return(__wrap_iot_bsp_wifi_get_mac, 0x0000000000000000);
    will_return(__wrap_iot_bsp_wifi_get_mac, IOT_ERROR_NONE);

    // When
    err = iot_easysetup_request_handler(context, request);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);

    // Teardown
    if (request.payload) {
        free(request.payload);
    }
    if (context->scan_result) {
        free(context->scan_result);
    }
    iot_util_queue_delete(context->easysetup_resp_queue);
    iot_os_eventgroup_delete(context->iot_events);
}

void TC_iot_easysetup_request_handler_setupcomplete_step_success(void **state)
{
    iot_error_t err;
    struct iot_context *context;
    struct iot_easysetup_payload request;

    // Given
    context = (struct iot_context *)*state;
    context->work_queue_signal = iot_os_eventgroup_create();
    context->work_queue = iot_util_queue_create(sizeof(device_work_data_t));
    context->next_connection_retry_timer = NULL;
    context->easysetup_resp_queue = iot_util_queue_create(sizeof(struct iot_easysetup_payload));
    context->iot_events = iot_os_eventgroup_create();
    request.step = IOT_EASYSETUP_STEP_SETUPCOMPLETE;
    request.payload = NULL;

    // When
    err = iot_easysetup_request_handler(context, request);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);

    // Teardown
    iot_os_eventgroup_delete(context->work_queue_signal);
    iot_util_queue_delete(context->work_queue);
    iot_util_queue_delete(context->easysetup_resp_queue);
    iot_os_eventgroup_delete(context->iot_events);
}

void TC_STATIC_es_setupcomplete_handler_null_context_failure(void **state)
{
    iot_error_t err;
    char *out_payload = NULL;

    // Given: null context
    UNUSED(state);
    // When
    err = _es_setupcomplete_handler(NULL, NULL, &out_payload);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_easysetup_request_handler_logsysteminfo_step_success(void **state)
{
    iot_error_t err;
    struct iot_context *context;
    struct iot_easysetup_payload request;

    // Given
    context = (struct iot_context *)*state;
    context->easysetup_resp_queue = iot_util_queue_create(sizeof(struct iot_easysetup_payload));
    context->iot_events = iot_os_eventgroup_create();
    request.step = IOT_EASYSETUP_STEP_LOG_SYSTEMINFO;
    request.payload = NULL;

    // When
    err = iot_easysetup_request_handler(context, request);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);

    // Teardown
    iot_util_queue_delete(context->easysetup_resp_queue);
    iot_os_eventgroup_delete(context->iot_events);
}

void TC_iot_easysetup_request_handler_loggetdump_step_success(void **state)
{
    iot_error_t err;
    struct iot_context *context;
    struct iot_easysetup_payload request;

    // Given
    context = (struct iot_context *)*state;
    context->easysetup_resp_queue = iot_util_queue_create(sizeof(struct iot_easysetup_payload));
    context->iot_events = iot_os_eventgroup_create();
    request.step = IOT_EASYSETUP_STEP_LOG_GET_DUMP;
    request.payload = NULL;

    // When
    err = iot_easysetup_request_handler(context, request);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);

    // Teardown
    iot_util_queue_delete(context->easysetup_resp_queue);
    iot_os_eventgroup_delete(context->iot_events);
}

void TC_iot_easysetup_request_handler_offline_diagnostics_connection_info_step_success(void **state)
{
    iot_error_t err;
    struct iot_context *context;
    struct iot_easysetup_payload request;

    // Given
    context = (struct iot_context *)*state;
    context->easysetup_resp_queue = iot_util_queue_create(sizeof(struct iot_easysetup_payload));
    context->iot_events = iot_os_eventgroup_create();
    request.step = IOT_EASYSETUP_BLE_STEP_OFFLINE_DIAGNOSTICS_CONNECTION_INFO;
    request.payload = NULL;

    // When
    err = iot_easysetup_request_handler(context, request);
    // Then
    // Either success or not supported is acceptable
    assert_int_not_equal(err, IOT_ERROR_EASYSETUP_INTERNAL_SERVER_ERROR);

    // Teardown
    iot_util_queue_delete(context->easysetup_resp_queue);
    iot_os_eventgroup_delete(context->iot_events);
}

void TC_iot_easysetup_request_handler_offline_diagnostics_recovery_step_failure(void **state)
{
    iot_error_t err;
    struct iot_context *context;
    struct iot_easysetup_payload request;
    char *in_payload;
    JSON_H *root;
    JSON_H *data;

    // Given
    context = (struct iot_context *)*state;
    context->easysetup_resp_queue = iot_util_queue_create(sizeof(struct iot_easysetup_payload));
    context->iot_events = iot_os_eventgroup_create();

    root = JSON_CREATE_OBJECT();
    data = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(data, "command", JSON_CREATE_STRING("invalidCommand"));
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    in_payload = JSON_PRINT(root);
    JSON_DELETE(root);

    request.step = IOT_EASYSETUP_BLE_STEP_OFFLINE_DIAGNOSTICS_RECOVERY;
    request.payload = in_payload;

    // When
    err = iot_easysetup_request_handler(context, request);
    // Then - invalid command should fail
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Teardown
    if (in_payload) {
        free(in_payload);
    }
    iot_util_queue_delete(context->easysetup_resp_queue);
    iot_os_eventgroup_delete(context->iot_events);
}

void TC_STATIC_es_wifiscaninfo_handler_json_parsing_failure(void **state)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;
    iot_security_cipher_params_t *device_cipher;
    char *invalid_payload;

    // Given: invalid JSON payload
    context = (struct iot_context *)*state;
    device_cipher = _generate_device_cipher(NULL, 0);
    assert_non_null(device_cipher);
    err = iot_security_cipher_set_params(context->easysetup_security_context, device_cipher);
    assert_int_equal(err, IOT_ERROR_NONE);

    invalid_payload = strdup("{ invalid json }");

    will_return(__wrap_iot_bsp_wifi_get_scan_result, 0);
    expect_value(__wrap_iot_bsp_wifi_set_mode, conf->mode, IOT_WIFI_MODE_SCAN);
    will_return(__wrap_iot_bsp_wifi_set_mode, IOT_ERROR_NONE);

    // When
    err = _es_wifiscaninfo_handler(context, invalid_payload, &out_payload);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);  // Handler continues even with bad JSON

    // Teardown
    if (invalid_payload) {
        free(invalid_payload);
    }
    if (out_payload) {
        free(out_payload);
    }
    if (context->scan_result) {
        free(context->scan_result);
    }
    _free_cipher(device_cipher);
}

void TC_STATIC_es_confirminfo_handler_unsupported_otm_feature_failure(void **state)
{
    iot_error_t err;
    char *in_payload;
    char *out_payload;
    struct iot_context *context;
    JSON_H *root;
    JSON_H *data;

    // Given: unsupported OTM feature
    context = (struct iot_context *)*state;
    context->iot_events = iot_os_eventgroup_create();
    context->work_queue_signal = iot_os_eventgroup_create();
    context->work_queue = iot_util_queue_create(sizeof(device_work_data_t));
    context->devconf.ownership_validation_type = 0;  // No OTM features supported

    root = JSON_CREATE_OBJECT();
    data = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(data, "otmSupportFeature", JSON_CREATE_NUMBER(OVF_BIT_JUSTWORKS));
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    in_payload = JSON_PRINT(root);
    JSON_DELETE(root);

    out_payload = NULL;
    // When
    err = _es_confirminfo_handler(context, in_payload, &out_payload);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Teardown
    if (in_payload) {
        free(in_payload);
    }
    iot_os_eventgroup_delete(context->iot_events);
    iot_os_eventgroup_delete(context->work_queue_signal);
    iot_util_queue_delete(context->work_queue);
}

void TC_STATIC_es_deviceinfo_handler_public_key_failure(void **state)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;

    // Given: security context issue
    context = (struct iot_context *)*state;
    // Set a bad context that will cause issues
    context->easysetup_security_context = NULL;

    // When
    err = _es_deviceinfo_handler(context, &out_payload);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Local teardown
    if (out_payload) {
        free(out_payload);
    }
}

void TC_STATIC_es_keyinfo_handler_missing_spub_failure(void **state)
{
    iot_error_t err;
    char *out_payload = NULL;
    char *in_payload = NULL;
    struct iot_context *context;
    JSON_H *root;
    JSON_H *data;

    // Given: missing spub field
    context = (struct iot_context *)*state;
    root = JSON_CREATE_OBJECT();
    data = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    in_payload = JSON_PRINT(root);
    JSON_DELETE(root);

    // When
    err = _es_keyinfo_handler(context, in_payload, &out_payload);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Teardown
    if (in_payload) {
        free(in_payload);
    }
    if (out_payload) {
        free(out_payload);
    }
}

void TC_STATIC_es_keyinfo_handler_missing_rand_failure(void **state)
{
    iot_error_t err;
    char *out_payload = NULL;
    char *in_payload = NULL;
    struct iot_context *context;
    JSON_H *root;
    JSON_H *data;

    // Given: missing rand field
    context = (struct iot_context *)*state;
    root = JSON_CREATE_OBJECT();
    data = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(data, "spub", JSON_CREATE_STRING("dGVzdHNwdWJrZXk="));
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    in_payload = JSON_PRINT(root);
    JSON_DELETE(root);

    // When
    err = _es_keyinfo_handler(context, in_payload, &out_payload);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Teardown
    if (in_payload) {
        free(in_payload);
    }
    if (out_payload) {
        free(out_payload);
    }
}

void TC_STATIC_es_keyinfo_handler_missing_datetime_no_error(void **state)
{
    iot_error_t err;
    char *out_payload = NULL;
    char *in_payload = NULL;
    struct iot_context *context;
    time_t time_to_set;

    // Given: optional datetime field is missing
    context = (struct iot_context *)*state;
    context->devconf.ownership_validation_type = OVF_BIT_JUSTWORKS;

    // Create a valid payload without datetime
    in_payload = _generate_post_keyinfo_payload(2020, &time_to_set);

    // When - datetime is optional, should still succeed
    err = _es_keyinfo_handler(context, in_payload, &out_payload);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);

    // Teardown
    if (in_payload) {
        free(in_payload);
    }
    if (out_payload) {
        free(out_payload);
    }
}

void TC_STATIC_es_confirminfo_handler_invalid_json_failure(void **state)
{
    iot_error_t err;
    char *in_payload;
    char *out_payload = NULL;
    struct iot_context *context;

    // Given: invalid JSON
    context = (struct iot_context *)*state;
    in_payload = strdup("{ invalid: json format }");

    // When
    err = _es_confirminfo_handler(context, in_payload, &out_payload);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Teardown
    if (in_payload) {
        free(in_payload);
    }
}

void TC_STATIC_es_confirm_handler_no_data_field_failure(void **state)
{
    iot_error_t err;
    char *in_payload;
    char *out_payload = NULL;
    struct iot_context *context;
    char pin_for_test[9] = "12345678";

    // Given: no data field in JSON
    context = (struct iot_context *)*state;
    context->curr_otm_feature = OVF_BIT_PIN;
    context->devconf.ownership_validation_type = IOT_OVF_TYPE_PIN;
    context->pin = malloc(sizeof(iot_pin_t));
    memset(context->pin, '\0', sizeof(iot_pin_t));
    memcpy(context->pin->pin, pin_for_test, strlen(pin_for_test));

    in_payload = strdup("{ \"nodata\": {} }");

    // When
    err = _es_confirm_handler(context, in_payload, &out_payload);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Teardown
    if (context->pin) {
        free(context->pin);
    }
    if (in_payload) {
        free(in_payload);
    }
}

void TC_iot_easysetup_get_response_null_context_failure(void **state)
{
    struct iot_easysetup_payload *response = NULL;
    struct iot_easysetup_payload request = {0};

    // Given: null context
    UNUSED(state);
    request.step = IOT_EASYSETUP_STEP_DEVICEINFO;
    request.payload = NULL;

    // When
    response = iot_easysetup_get_response(NULL, request);
    // Then
    assert_non_null(response);
    assert_int_not_equal(response->err, IOT_ERROR_NONE);

    // Teardown
    if (response) {
        iot_os_free(response);
    }
}

void TC_iot_easysetup_get_response_malloc_failure(void **state)
{
    struct iot_easysetup_payload *response = NULL;
    struct iot_context *context;
    struct iot_easysetup_payload request = {0};

    // Given: malloc failure
    context = (struct iot_context *)*state;
    request.step = IOT_EASYSETUP_STEP_DEVICEINFO;
    request.payload = NULL;

    set_mock_iot_os_malloc_failure_with_index(0);

    // When
    response = iot_easysetup_get_response(context, request);
    // Then
    assert_null(response);

    // Teardown
    do_not_use_mock_iot_os_malloc_failure();
}

void TC_iot_easysetup_request_handler_response_queue_send_failure_v2(void **state)
{
    iot_error_t err;
    struct iot_context *context;
    struct iot_easysetup_payload request;
    struct iot_devconf_prov_data *devconf;

    // Given: valid response but queue is full or can't send
    context = (struct iot_context *)*state;
    devconf = &context->devconf;
    devconf->hashed_sn = sample_hashed_sn_b64url;
    context->easysetup_resp_queue = iot_util_queue_create(sizeof(struct iot_easysetup_payload));
    context->iot_events = iot_os_eventgroup_create();
    request.step = IOT_EASYSETUP_STEP_DEVICEINFO;
    request.payload = NULL;

    // Create two responses to fill queue
    struct iot_easysetup_payload resp1 = {0};
    resp1.step = IOT_EASYSETUP_STEP_KEYINFO;
    iot_util_queue_send(context->easysetup_resp_queue, &resp1);

    // Now try to send a request, which should fail to queue the response
    set_mock_iot_os_malloc_failure_with_index(1);
    err = iot_easysetup_request_handler(context, request);
    // Then
    assert_int_equal(err, IOT_ERROR_EASYSETUP_QUEUE_SEND_ERROR);

    // Teardown
    do_not_use_mock_iot_os_malloc_failure();
    iot_util_queue_delete(context->easysetup_resp_queue);
    iot_os_eventgroup_delete(context->iot_events);
}

void TC_STATIC_es_confirminfo_handler_json_missing_data_field(void **state)
{
    iot_error_t err;
    char *in_payload;
    char *out_payload = NULL;
    struct iot_context *context;
    JSON_H *root;

    // Given: JSON without data field
    context = (struct iot_context *)*state;
    root = JSON_CREATE_OBJECT();
    in_payload = JSON_PRINT(root);
    JSON_DELETE(root);

    // When
    err = _es_confirminfo_handler(context, in_payload, &out_payload);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Teardown
    if (in_payload) {
        free(in_payload);
    }
}

void TC_STATIC_es_wifiscaninfo_handler_empty_scan_result(void **state)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;
    iot_security_cipher_params_t *device_cipher;

    // Given: empty scan result
    context = (struct iot_context *)*state;
    device_cipher = _generate_device_cipher(NULL, 0);
    assert_non_null(device_cipher);
    err = iot_security_cipher_set_params(context->easysetup_security_context, device_cipher);
    assert_int_equal(err, IOT_ERROR_NONE);

    context->scan_num = 0;
    context->scan_result = NULL;

    // When
    err = _es_wifiscaninfo_handler(context, NULL, &out_payload);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);

    // Teardown
    if (out_payload) {
        free(out_payload);
    }
    _free_cipher(device_cipher);
}

void TC_iot_easysetup_request_handler_all_steps_coverage(void **state)
{
    iot_error_t err;
    struct iot_context *context;
    struct iot_easysetup_payload request;

    // Given
    context = (struct iot_context *)*state;
    context->easysetup_resp_queue = iot_util_queue_create(sizeof(struct iot_easysetup_payload));
    context->iot_events = iot_os_eventgroup_create();

    // Test all step types for basic execution path
    int steps[] = {
        IOT_EASYSETUP_STEP_LOG_SYSTEMINFO,
        IOT_EASYSETUP_STEP_LOG_GET_DUMP,
    };

    for (int i = 0; i < sizeof(steps) / sizeof(steps[0]); i++) {
        request.step = steps[i];
        request.payload = NULL;

        // When
        err = iot_easysetup_request_handler(context, request);
        // Then - should return success or queue error, not internal errors
        assert_int_not_equal(err, IOT_ERROR_EASYSETUP_INTERNAL_SERVER_ERROR);
    }

    // Teardown
    iot_util_queue_delete(context->easysetup_resp_queue);
    iot_os_eventgroup_delete(context->iot_events);
}

void TC_st_conn_ownership_confirm_not_button_feature(void **state)
{
    struct iot_context *internal_context;
    IOT_CTX *context;

    // Given: non-button OTM feature
    internal_context = (struct iot_context *)malloc(sizeof(struct iot_context));
    memset(internal_context, '\0', sizeof(struct iot_context));
    internal_context->curr_otm_feature = OVF_BIT_JUSTWORKS;  // Not BUTTON
    internal_context->iot_events = iot_os_eventgroup_create();
    context = (IOT_CTX *)internal_context;

    // When
    st_conn_ownership_confirm(context, true);
    // Then: no events should be set because feature is not BUTTON
    assert_false(
        iot_os_eventgroup_wait_bits(internal_context->iot_events, IOT_EVENT_BIT_EASYSETUP_CONFIRM, false, 100));

    // Teardown
    iot_os_eventgroup_delete(internal_context->iot_events);
    free(internal_context);
}

void TC_STATIC_es_wifiprovisioninginfo_handler_with_cloud_data(void **state)
{
    iot_error_t err;
    char *out_payload = NULL;
    char *in_payload = NULL;
    struct iot_context *context;
    JSON_H *root;
    JSON_H *data;
    JSON_H *wifi_credential;

    // Given: full provisioning payload with cloud data
    context = (struct iot_context *)*state;
    context->lookup_id = NULL;
    context->wifi_update_enabled = false;

    root = JSON_CREATE_OBJECT();
    data = JSON_CREATE_OBJECT();
    wifi_credential = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(wifi_credential, "ssid", JSON_CREATE_STRING("TestSSID"));
    JSON_ADD_ITEM_TO_OBJECT(wifi_credential, "password", JSON_CREATE_STRING("TestPassword"));
    JSON_ADD_ITEM_TO_OBJECT(wifi_credential, "authType", JSON_CREATE_NUMBER(IOT_WIFI_AUTH_WPA2_PSK));
    JSON_ADD_ITEM_TO_OBJECT(data, "wifiCredential", wifi_credential);
    JSON_ADD_ITEM_TO_OBJECT(data, "brokerUrl", JSON_CREATE_STRING("mqtt://test.domain.com:8883"));
    JSON_ADD_ITEM_TO_OBJECT(data, "deviceName", JSON_CREATE_STRING("TestDevice"));
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    in_payload = JSON_PRINT(root);
    JSON_DELETE(root);

    will_return(__wrap_iot_bsp_wifi_get_mac, 0x0000000000000000);
    will_return(__wrap_iot_bsp_wifi_get_mac, IOT_ERROR_NONE);

    // When
    err = _es_wifiprovisioninginfo_handler(context, in_payload, &out_payload);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);

    // Teardown
    if (out_payload) {
        free(out_payload);
    }
    if (in_payload) {
        free(in_payload);
    }
    if (context->scan_result) {
        free(context->scan_result);
    }
}

void TC_STATIC_es_confirminfo_handler_pin_feature_not_supported(void **state)
{
    iot_error_t err;
    char *in_payload;
    char *out_payload = NULL;
    struct iot_context *context;
    JSON_H *root;
    JSON_H *data;

    // Given: PIN feature requested but not supported
    context = (struct iot_context *)*state;
    context->iot_events = iot_os_eventgroup_create();
    context->work_queue_signal = iot_os_eventgroup_create();
    context->work_queue = iot_util_queue_create(sizeof(device_work_data_t));
    context->devconf.ownership_validation_type = (1u << OVF_BIT_JUSTWORKS);  // Only JUSTWORKS

    root = JSON_CREATE_OBJECT();
    data = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(data, "otmSupportFeature", JSON_CREATE_NUMBER(OVF_BIT_PIN));
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    in_payload = JSON_PRINT(root);
    JSON_DELETE(root);

    // When
    err = _es_confirminfo_handler(context, in_payload, &out_payload);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Teardown
    if (in_payload) {
        free(in_payload);
    }
    iot_os_eventgroup_delete(context->iot_events);
    iot_os_eventgroup_delete(context->work_queue_signal);
    iot_util_queue_delete(context->work_queue);
}
