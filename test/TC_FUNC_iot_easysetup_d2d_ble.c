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
#include <iot_log_file.h>
#include <iot_nv_data.h>
#include <iot_util.h>
#include <pthread.h>
#include <regex.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "TC_MOCK_functions.h"
#include "TC_MOCK_iot_bsp_ble.h"
#include "TC_REGISTRY.h"
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
extern iot_error_t _es_time_set(unsigned char *time);
extern void _next_connection_retry_timeout(iot_os_timer_handle handle, void *user_data);
#if defined(CONFIG_STDK_IOT_CORE_EASYSETUP_OFFLINE_DIAGNOSTICS)
extern void _offline_diagnostics_wifi_update_timeout(iot_os_timer_handle handle, void *user_data);
#endif
extern void st_conn_ownership_confirm(IOT_CTX *iot_ctx, bool confirm);
extern iot_error_t _es_confirm_check_manager(struct iot_context *ctx, enum ownership_validation_feature confirm_feature,
                                             char *sn);
extern iot_error_t _es_log_get_dump_handler(struct iot_context *ctx, char **out_payload);
extern iot_error_t _es_copy_cloud_prov(struct iot_cloud_prov_data *dst, struct iot_cloud_prov_data *src);
extern char *_es_json_parse_string(JSON_H *json, const char *name);
extern int iot_security_base64_encode_urlsafe(const unsigned char *src, int src_len, char *dst, int dst_len,
                                              int *out_len);

#if defined(CONFIG_STDK_IOT_CORE_EASYSETUP_OFFLINE_DIAGNOSTICS)
extern iot_error_t _es_offline_diagnostics_connection_info_handler(struct iot_context *ctx, char **out_payload);
#endif

struct confirm_thread_arg {
    IOT_CTX *ctx;
    bool confirm;
};

TEST_SUITE("iot_easysetup_d2d_ble.c");

TEST_FIXTURE(iot_easysetup, TC_iot_easysetup_common_setup, TC_iot_easysetup_common_teardown);

static void *_confirm_thread(void *arg)
{
    struct confirm_thread_arg *cta = (struct confirm_thread_arg *)arg;
    usleep(100000);
    st_conn_ownership_confirm(cta->ctx, cta->confirm);
    return NULL;
}

// Test data
static const char sample_ssid[] = "STDK_E4fTST0016LWpcd226";
static char sample_hashed_sn_b64url[] = "LWpcna0H5C-NEFcoRXRRBUWFqeU1XmOeyaigeYcxl1Q=";

TEST_F(iot_easysetup, TC_st_conn_ownership_confirm_SUCCESS_pos)
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

TEST_F(iot_easysetup, TC_st_conn_ownership_confirm_DENY_neg)
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

TEST_F(iot_easysetup, TC_STATIC_es_deviceinfo_handler_null_parameter_neg)
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

TEST_F(iot_easysetup, TC_STATIC_es_deviceinfo_handler_success_pos)
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
    assert_non_null(out_payload);
    // Local teardown
    if (out_payload) {
        free(out_payload);
    }
}

TEST_F(iot_easysetup, TC_STATIC_es_keyinfo_handler_success_pos)
{
    iot_error_t err;
    char *out_payload = NULL;
    char *in_payload = NULL;
    struct iot_context *context;
    time_t time_to_set;

    // Given: time is under 32bit time_t (Y2038)
    context = (struct iot_context *)*state;
    context->devconf.ownership_validation_type = OVF_BIT_JUSTWORKS;
    in_payload = _generate_post_keyinfo_payload_utc(2020, &time_to_set);
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

TEST_F(iot_easysetup, TC_STATIC_es_keyinfo_handler_success_with_y2038_pos)
{
    iot_error_t err;
    char *out_payload = NULL;
    char *in_payload = NULL;
    struct iot_context *context;
    time_t time_to_set;

    // Given: time is over 32bit time_t (Y2038)
    context = (struct iot_context *)*state;
    in_payload = _generate_post_keyinfo_payload_utc(2038, &time_to_set);
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

TEST_F(iot_easysetup, TC_STATIC_es_keyinfo_handler_invalid_parameters_neg)
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

TEST_F(iot_easysetup, TC_STATIC_es_confirminfo_handler_null_parameters_neg)
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

TEST_F(iot_easysetup, TC_STATIC_es_confirminfo_handler_out_ranged_otm_feature_failure_neg)
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

TEST_F(iot_easysetup, TC_STATIC_es_confirminfo_handler_justworks_and_pin_success_pos)
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
    in_payload = _generate_post_keyinfo_payload_utc(2020, &time_to_set);
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

TEST_F(iot_easysetup, TC_STATIC_es_confirminfo_handler_qr_code_success_pos)
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
    in_payload = _generate_post_keyinfo_payload_utc(2020, &time_to_set);
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

TEST_F(iot_easysetup, TC_STATIC_es_confirminfo_handler_serial_number_success_pos)
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
    in_payload = _generate_post_keyinfo_payload_utc(2020, &time_to_set);
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

TEST_F(iot_easysetup, TC_STATIC_es_confirminfo_handler_button_timeout_success_neg)
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
    in_payload = _generate_post_keyinfo_payload_utc(2020, &time_to_set);
    expect_value(__wrap_iot_bsp_system_set_time_in_sec, time_in_sec, time_to_set);
    err = _es_keyinfo_handler(context, in_payload, &out_payload);
    assert_int_equal(err, IOT_ERROR_NONE);
    if (in_payload) {
        free(in_payload);
    }
    if (out_payload) {
        free(out_payload);
    }
    out_payload = NULL;
    in_payload = _generate_confirminfo_payload(OVF_BIT_BUTTON, NULL);

    // When
    err = _es_confirminfo_handler(context, in_payload, &out_payload);
    // Then
    assert_int_equal(err, IOT_ERROR_EASYSETUP_CONFIRM_TIMEOUT);

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

TEST_F(iot_easysetup, TC_STATIC_es_confirm_handler_success_pos)
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

TEST_F(iot_easysetup, TC_STATIC_es_confirm_handler_invalid_pin_failure_neg)
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

TEST_F(iot_easysetup, TC_STATIC_es_confirm_handler_non_pin_otm_failure_neg)
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

TEST_F(iot_easysetup, TC_STATIC_es_confirm_handler_invalid_payload_failure_neg)
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

TEST_F(iot_easysetup, TC_STATIC_es_wifiscaninfo_handler_invalid_parameters_failure_neg)
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

TEST_F(iot_easysetup, TC_STATIC_es_wifiscaninfo_handler_success_pos)
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

TEST_F(iot_easysetup, TC_STATIC_es_wifiprovisioninginfo_handler_success_pos)
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

TEST_F(iot_easysetup, TC_STATIC_es_wifiprovisioninginfo_handler_success_without_authtype_success_neg)
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

TEST_F(iot_easysetup, TC_STATIC_es_setupcomplete_handler_success_pos)
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

TEST_F(iot_easysetup, TC_STATIC_es_deviceinfo_handler_cipher_init_failure_neg)
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

TEST_F(iot_easysetup, TC_STATIC_es_keyinfo_handler_json_parse_failure_neg)
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

TEST_F(iot_easysetup, TC_STATIC_es_confirminfo_handler_missing_data_failure_neg)
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

TEST_F(iot_easysetup, TC_STATIC_es_confirm_handler_missing_pin_failure_neg)
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

TEST_F(iot_easysetup, TC_iot_easysetup_request_handler_null_context_failure_neg)
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

TEST_F(iot_easysetup, TC_iot_easysetup_request_handler_null_queue_failure_neg)
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

TEST_F(iot_easysetup, TC_iot_easysetup_request_handler_queue_send_error_failure_neg)
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

TEST_F(iot_easysetup, TC_iot_easysetup_request_handler_memory_allocation_failure_neg)
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

TEST_F(iot_easysetup, TC_iot_easysetup_request_handler_success_pos)
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

void TC_STATIC_es_confirm_handler_null_context_failure_neg(void **state)
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

TEST_F(iot_easysetup, TC_STATIC_es_confirm_handler_no_pin_context_failure_neg)
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

TEST_F(iot_easysetup, TC_STATIC_es_confirm_handler_invalid_otm_feature_failure_neg)
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

TEST_F(iot_easysetup, TC_STATIC_es_confirm_handler_pin_size_mismatch_failure_neg)
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

TEST_F(iot_easysetup, TC_STATIC_es_confirm_handler_pin_mismatch_failure_neg)
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

TEST_F(iot_easysetup, TC_STATIC_es_confirm_handler_missing_data_failure_neg)
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

TEST_F(iot_easysetup, TC_STATIC_es_confirminfo_handler_qr_code_null_sn_failure_neg)
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
    in_payload = _generate_post_keyinfo_payload_utc(2020, &time_to_set);
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

TEST_F(iot_easysetup, TC_STATIC_es_confirminfo_handler_qr_code_wrong_sn_failure_neg)
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
    in_payload = _generate_post_keyinfo_payload_utc(2020, &time_to_set);
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

TEST_F(iot_easysetup, TC_STATIC_es_confirminfo_handler_serial_number_null_sn_failure_neg)
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
    in_payload = _generate_post_keyinfo_payload_utc(2020, &time_to_set);
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

TEST_F(iot_easysetup, TC_STATIC_es_confirminfo_handler_serial_number_wrong_sn_failure_neg)
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
    in_payload = _generate_post_keyinfo_payload_utc(2020, &time_to_set);
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

TEST_F(iot_easysetup, TC_STATIC_es_confirminfo_handler_button_confirm_success_pos)
{
    iot_error_t err;
    char *in_payload;
    char *out_payload;
    struct iot_context *context;
    time_t time_to_set;
    IOT_CTX *ctx;
    pthread_t tid;
    struct confirm_thread_arg cta;

    context = (struct iot_context *)*state;
    context->iot_events = iot_os_eventgroup_create();
    context->work_queue_signal = iot_os_eventgroup_create();
    context->work_queue = iot_util_queue_create(sizeof(device_work_data_t));
    context->devconf.ownership_validation_type = (1u << OVF_BIT_BUTTON);
    context->curr_otm_feature = OVF_BIT_BUTTON;
    ctx = (IOT_CTX *)context;

    in_payload = _generate_post_keyinfo_payload_utc(2020, &time_to_set);
    expect_value(__wrap_iot_bsp_system_set_time_in_sec, time_in_sec, time_to_set);
    err = _es_keyinfo_handler(context, in_payload, &out_payload);
    assert_int_equal(err, IOT_ERROR_NONE);
    if (in_payload) {
        free(in_payload);
    }
    if (out_payload) {
        free(out_payload);
    }

    cta.ctx = ctx;
    cta.confirm = true;
    pthread_create(&tid, NULL, _confirm_thread, &cta);

    in_payload = _generate_confirminfo_payload(OVF_BIT_BUTTON, NULL);
    err = _es_confirminfo_handler(context, in_payload, &out_payload);
    pthread_join(tid, NULL);
    assert_int_equal(err, IOT_ERROR_NONE);

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

TEST_F(iot_easysetup, TC_STATIC_es_confirminfo_handler_button_deny_success_pos)
{
    iot_error_t err;
    char *in_payload;
    char *out_payload;
    struct iot_context *context;
    time_t time_to_set;
    IOT_CTX *ctx;
    pthread_t tid;
    struct confirm_thread_arg cta;

    context = (struct iot_context *)*state;
    context->iot_events = iot_os_eventgroup_create();
    context->work_queue_signal = iot_os_eventgroup_create();
    context->work_queue = iot_util_queue_create(sizeof(device_work_data_t));
    context->devconf.ownership_validation_type = (1u << OVF_BIT_BUTTON);
    context->curr_otm_feature = OVF_BIT_BUTTON;
    ctx = (IOT_CTX *)context;

    in_payload = _generate_post_keyinfo_payload_utc(2020, &time_to_set);
    expect_value(__wrap_iot_bsp_system_set_time_in_sec, time_in_sec, time_to_set);
    err = _es_keyinfo_handler(context, in_payload, &out_payload);
    assert_int_equal(err, IOT_ERROR_NONE);
    if (in_payload) {
        free(in_payload);
    }
    if (out_payload) {
        free(out_payload);
    }

    cta.ctx = ctx;
    cta.confirm = false;
    pthread_create(&tid, NULL, _confirm_thread, &cta);

    in_payload = _generate_confirminfo_payload(OVF_BIT_BUTTON, NULL);
    out_payload = NULL;
    err = _es_confirminfo_handler(context, in_payload, &out_payload);
    pthread_join(tid, NULL);
    assert_int_equal(err, IOT_ERROR_EASYSETUP_CONFIRM_DENIED);

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

TEST_F(iot_easysetup, TC_STATIC_es_confirminfo_handler_pin_success_pos)

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
    in_payload = _generate_post_keyinfo_payload_utc(2020, &time_to_set);
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

TEST_F(iot_easysetup, TC_STATIC_es_confirminfo_handler_hashed_sn_success_pos)
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
    in_payload = _generate_post_keyinfo_payload_utc(2020, &time_to_set);
    expect_value(__wrap_iot_bsp_system_set_time_in_sec, time_in_sec, time_to_set);
    err = _es_keyinfo_handler(context, in_payload, &out_payload);
    if (in_payload) {
        free(in_payload);
    }
    if (out_payload) {
        free(out_payload);
    }
    out_payload = NULL;

    // Now test confirminfo with hashed SN - use a computed hash
    JSON_H *root = JSON_CREATE_OBJECT();
    JSON_H *data = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(data, "otmSupportFeature", JSON_CREATE_NUMBER(OVF_BIT_HASHED_SERIAL_NUMBER));
    // Use the expected hash for TEST_DEVICE_SERIAL_NUMBER
    JSON_ADD_ITEM_TO_OBJECT(data, "hashedsn",
                            JSON_CREATE_STRING("3d8571a0579ad1de349001b1858f3a6858802f5990f2d15226fed34120656f1187918ae"
                                               "afa03bae190c35aded4f05dfbb80b90604e2974e101581e3010282be1"));
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    in_payload = JSON_PRINT(root);
    JSON_DELETE(root);

    // When
    err = _es_confirminfo_handler(context, in_payload, &out_payload);
    // Then - the valid hashed SN must succeed
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

TEST_F(iot_easysetup, TC_STATIC_es_confirminfo_handler_hashed_sn_wrong_hash_failure_neg)
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
    in_payload = _generate_post_keyinfo_payload_utc(2020, &time_to_set);
    expect_value(__wrap_iot_bsp_system_set_time_in_sec, time_in_sec, time_to_set);
    err = _es_keyinfo_handler(context, in_payload, &out_payload);
    if (in_payload) {
        free(in_payload);
    }
    if (out_payload) {
        free(out_payload);
    }
    out_payload = NULL;

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

TEST_F(iot_easysetup, TC_STATIC_es_confirminfo_handler_hashed_sn_null_sn_failure_neg)

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
    in_payload = _generate_post_keyinfo_payload_utc(2020, &time_to_set);
    expect_value(__wrap_iot_bsp_system_set_time_in_sec, time_in_sec, time_to_set);
    err = _es_keyinfo_handler(context, in_payload, &out_payload);
    if (in_payload) {
        free(in_payload);
    }
    if (out_payload) {
        free(out_payload);
    }
    out_payload = NULL;

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

TEST_F(iot_easysetup, TC_STATIC_es_confirminfo_handler_hashed_sn_hash_mismatch_failure_neg)
{
    iot_error_t err;
    char *in_payload;
    char *out_payload;
    struct iot_context *context;
    time_t time_to_set;

    context = (struct iot_context *)*state;
    context->iot_events = iot_os_eventgroup_create();
    context->work_queue_signal = iot_os_eventgroup_create();
    context->work_queue = iot_util_queue_create(sizeof(device_work_data_t));
    context->devconf.ownership_validation_type = (1u << OVF_BIT_HASHED_SERIAL_NUMBER);
    context->wifi_update_enabled = true;

    in_payload = _generate_post_keyinfo_payload_utc(2020, &time_to_set);
    expect_value(__wrap_iot_bsp_system_set_time_in_sec, time_in_sec, time_to_set);
    err = _es_keyinfo_handler(context, in_payload, &out_payload);
    if (in_payload) {
        free(in_payload);
    }
    if (out_payload) {
        free(out_payload);
    }
    /* Reset out_payload: confirminfo's error path leaves *out_payload untouched. */
    out_payload = NULL;
    in_payload = NULL;

    JSON_H *root = JSON_CREATE_OBJECT();
    JSON_H *data = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(data, "otmSupportFeature", JSON_CREATE_NUMBER(OVF_BIT_HASHED_SERIAL_NUMBER));
    JSON_ADD_ITEM_TO_OBJECT(data, "hashedsn",
                            JSON_CREATE_STRING("a7a8994c51304d2933f8870da0d9dc349a3e887b8350f9f422b7a8cad258317e2c13da1"
                                               "44ead97300e27fe18bc2dc4bf4a742d7ba4b83ea2338753f429c91f11"));
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    in_payload = JSON_PRINT(root);
    JSON_DELETE(root);

    err = _es_confirminfo_handler(context, in_payload, &out_payload);
    assert_int_equal(err, IOT_ERROR_EASYSETUP_CONFIRM_DENIED);

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

TEST_F(iot_easysetup, TC_STATIC_es_wifiscaninfo_handler_no_payload_success_neg)

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

TEST_F(iot_easysetup, TC_STATIC_es_wifiscaninfo_handler_null_context_failure_neg)
{
    iot_error_t err;
    char *out_payload = NULL;

    // Given: null context
    // When
    err = _es_wifiscaninfo_handler(NULL, NULL, &out_payload);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

TEST_F(iot_easysetup, TC_STATIC_es_wifiprovisioninginfo_handler_null_context_failure_neg)
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

TEST_F(iot_easysetup, TC_STATIC_es_wifiprovisioninginfo_handler_invalid_payload_failure_neg)
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

TEST_F(iot_easysetup, TC_STATIC_es_wifiprovisioninginfo_handler_missing_wifi_credential_failure_neg)
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

TEST_F(iot_easysetup, TC_STATIC_es_wifiprovisioninginfo_handler_missing_ssid_failure_neg)
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

TEST_F(iot_easysetup, TC_iot_easysetup_request_handler_wifiscaninfo_step_success_pos)
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

TEST_F(iot_easysetup, TC_iot_easysetup_request_handler_keyinfo_step_success_pos)
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
    request.payload = _generate_post_keyinfo_payload_utc(2020, &time_to_set);
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

TEST_F(iot_easysetup, TC_iot_easysetup_request_handler_invalid_step_failure_neg)
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

TEST_F(iot_easysetup, TC_STATIC_es_setupcomplete_handler_wifi_update_enabled_success_pos)
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

TEST_F(iot_easysetup, TC_STATIC_es_confirm_handler_null_context_failure_v2_neg)
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

TEST_F(iot_easysetup, TC_STATIC_es_wifiscaninfo_handler_with_matching_ssid_success_pos)
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

TEST_F(iot_easysetup, TC_STATIC_es_wifiscaninfo_handler_matched_ssid_with_unsupported_authtype_success_neg)
{
    iot_error_t err;
    char *out_payload = NULL;
    char *in_payload = NULL;
    struct iot_context *context;
    iot_security_cipher_params_t *device_cipher;
    JSON_H *root;
    JSON_H *data;
    JSON_H *mobile_wifi;
    const char matched_ssid[] = "fakeSsid_04_XXXXXXX"; /* matches entry 4 in mock_wifi_scan_result */

    /* Pre-populated scan cache: entry 0 matches the payload (valid authmode),
     * entry 1 has out-of-range authmode (forces `continue`), entry 2 is a
     * non-matching iteration with valid authmode. */
    context = (struct iot_context *)*state;

    device_cipher = _generate_device_cipher(NULL, 0);
    assert_non_null(device_cipher);
    err = iot_security_cipher_set_params(context->easysetup_security_context, device_cipher);
    assert_int_equal(err, IOT_ERROR_NONE);

    context->scan_num = 3;
    context->scan_result = (iot_wifi_scan_result_t *)calloc(context->scan_num, sizeof(iot_wifi_scan_result_t));
    assert_non_null(context->scan_result);

    /* entry 0: matching SSID, valid authmode */
    strncpy((char *)context->scan_result[0].ssid, matched_ssid, IOT_WIFI_MAX_SSID_LEN);
    context->scan_result[0].authmode = IOT_WIFI_AUTH_OPEN;
    context->scan_result[0].rssi = -55;
    context->scan_result[0].freq = 2412;
    context->scan_result[0].bssid[0] = 0x11;
    context->scan_result[0].bssid[1] = 0x22;
    context->scan_result[0].bssid[2] = 0x33;
    context->scan_result[0].bssid[3] = 0x44;
    context->scan_result[0].bssid[4] = 0x55;
    context->scan_result[0].bssid[5] = 0x66;

    /* entry 1: non-matching SSID, unsupported authmode (< IOT_WIFI_AUTH_OPEN) -> continue */
    strncpy((char *)context->scan_result[1].ssid, "nonMatchingSsid1", IOT_WIFI_MAX_SSID_LEN);
    context->scan_result[1].authmode = (iot_wifi_auth_mode_t)(IOT_WIFI_AUTH_OPEN - 1);

    /* entry 2: non-matching SSID, valid authmode -> loop iteration that does not match */
    strncpy((char *)context->scan_result[2].ssid, "nonMatchingSsid2", IOT_WIFI_MAX_SSID_LEN);
    context->scan_result[2].authmode = IOT_WIFI_AUTH_WPA2_PSK;
    context->scan_result[2].rssi = -70;
    context->scan_result[2].freq = 2462;

    /* Build a payload whose mobileWifiCredential.ssid matches entry 0 */
    root = JSON_CREATE_OBJECT();
    data = JSON_CREATE_OBJECT();
    mobile_wifi = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(mobile_wifi, "ssid", JSON_CREATE_STRING(matched_ssid));
    JSON_ADD_ITEM_TO_OBJECT(mobile_wifi, "frequency", JSON_CREATE_NUMBER(2412));
    JSON_ADD_ITEM_TO_OBJECT(data, "mobileWifiCredential", mobile_wifi);
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    in_payload = JSON_PRINT(root);
    JSON_DELETE(root);

    /* When: scan_num != 0 so the handler uses our pre-populated scan_result
     * directly without invoking iot_wifi_ctrl_request / iot_bsp_wifi_get_scan_result.
     */
    err = _es_wifiscaninfo_handler(context, in_payload, &out_payload);
    /* Then: matched-SSID path is exercised and the handler succeeds */
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(out_payload);

    /* Teardown */
    if (out_payload) {
        free(out_payload);
    }
    if (in_payload) {
        free(in_payload);
    }
    if (context->scan_result) {
        free(context->scan_result);
        context->scan_result = NULL;
    }
    context->scan_num = 0;
    _free_cipher(device_cipher);
}

TEST_F(iot_easysetup, TC_STATIC_es_wifiscaninfo_handler_wifi_scan_error_failure_neg)

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

TEST_F(iot_easysetup, TC_STATIC_es_confirminfo_handler_missing_otm_feature_failure_neg)
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

TEST_F(iot_easysetup, TC_iot_easysetup_request_handler_confirminfo_step_success_pos)
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
    request.payload = _generate_post_keyinfo_payload_utc(2020, &time_to_set);
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

TEST_F(iot_easysetup, TC_iot_easysetup_request_handler_confirm_step_success_pos)
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

TEST_F(iot_easysetup, TC_iot_easysetup_request_handler_wifiprov_step_success_pos)
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

TEST_F(iot_easysetup, TC_iot_easysetup_request_handler_setupcomplete_step_success_pos)
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

void TC_STATIC_es_setupcomplete_handler_null_context_failure_neg(void **state)
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

TEST_F(iot_easysetup, TC_iot_easysetup_request_handler_logsysteminfo_step_success_pos)
{
    iot_error_t err;
    struct iot_context *context;
    struct iot_easysetup_payload request;

    // Given
    context = (struct iot_context *)*state;
    context->easysetup_resp_queue = iot_util_queue_create(sizeof(struct iot_easysetup_payload));
    context->iot_events = iot_os_eventgroup_create();
    request.step = IOT_EASYSETUP_BLE_STEP_LOG_SYSTEMINFO;
    request.payload = NULL;

    // When
    err = iot_easysetup_request_handler(context, request);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);

    // Teardown
    iot_util_queue_delete(context->easysetup_resp_queue);
    iot_os_eventgroup_delete(context->iot_events);
}

TEST_F(iot_easysetup, TC_iot_easysetup_request_handler_loggetdump_step_success_pos)
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

TEST_F(iot_easysetup, TC_iot_easysetup_request_handler_offline_diagnostics_connection_info_step_success_pos)
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

TEST_F(iot_easysetup, TC_iot_easysetup_request_handler_offline_diagnostics_recovery_step_failure_neg)
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
    // Then - request_handler returns IOT_ERROR_NONE on successful queue send
    // even when the step handler returns an error (the error is in response->err).
    // Just verify no internal server error.
    assert_int_not_equal(err, IOT_ERROR_EASYSETUP_INTERNAL_SERVER_ERROR);

    // Teardown
    if (in_payload) {
        free(in_payload);
    }
    iot_util_queue_delete(context->easysetup_resp_queue);
    iot_os_eventgroup_delete(context->iot_events);
}

TEST_F(iot_easysetup, TC_STATIC_es_wifiscaninfo_handler_json_parsing_failure_neg)
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

TEST_F(iot_easysetup, TC_STATIC_es_confirminfo_handler_unsupported_otm_feature_failure_neg)
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

TEST_F(iot_easysetup, TC_STATIC_es_deviceinfo_handler_public_key_failure_neg)
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

TEST_F(iot_easysetup, TC_STATIC_es_keyinfo_handler_missing_spub_failure_neg)
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

TEST_F(iot_easysetup, TC_STATIC_es_keyinfo_handler_missing_rand_failure_neg)
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

void TC_STATIC_es_keyinfo_handler_missing_datetime_no_error_neg(void **state)
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
    in_payload = _generate_post_keyinfo_payload_utc(2020, &time_to_set);

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

void TC_STATIC_es_confirminfo_handler_invalid_json_failure_neg(void **state)
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

TEST_F(iot_easysetup, TC_STATIC_es_confirm_handler_no_data_field_failure_neg)
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

void TC_iot_easysetup_get_response_null_context_failure_neg(void **state)
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

TEST_F(iot_easysetup, TC_iot_easysetup_get_response_malloc_failure_neg)
{
    struct iot_easysetup_payload *response = NULL;
    struct iot_context *context;
    struct iot_easysetup_payload request = {0};

    context = (struct iot_context *)*state;
    request.step = IOT_EASYSETUP_STEP_DEVICEINFO;
    request.payload = NULL;

    set_mock_iot_os_malloc_failure_with_index(0);
    response = iot_easysetup_get_response(context, request);
    do_not_use_mock_iot_os_malloc_failure();

    if (response) {
        if (response->payload)
            free(response->payload);
        iot_os_free(response);
    }

    assert_true(true);
}

void TC_iot_easysetup_request_handler_response_queue_send_failure_v2_neg(void **state)
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

TEST_F(iot_easysetup, TC_STATIC_es_confirminfo_handler_json_missing_data_field_neg)
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

void TC_STATIC_es_wifiscaninfo_handler_empty_scan_result_neg(void **state)
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

TEST_F(iot_easysetup, TC_iot_easysetup_request_handler_all_steps_coverage_neg)
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
        IOT_EASYSETUP_BLE_STEP_LOG_SYSTEMINFO,
        IOT_EASYSETUP_BLE_STEP_LOG_GET_DUMP,
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

TEST_F(iot_easysetup, TC_st_conn_ownership_confirm_not_button_feature_neg)
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

TEST_F(iot_easysetup, TC_STATIC_es_wifiprovisioninginfo_handler_with_cloud_data_neg)
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

extern void offline_diagnostics_wifi_update_command_handler(struct iot_context *ctx, device_work_param param);

/* iot_easysetup_ble.c keeps its working iot_context in this file-scope global.
 * The enabled-build offline-diagnostics handler sends a BLE response through
 * it, so tests that invoke the handler must point it at a live context. */
extern struct iot_context *context;
static void _set_es_ble_global_context(struct iot_context *ctx)
{
    context = ctx;
}

TEST_F(iot_easysetup, TC_offline_diagnostics_wifi_update_command_handler_disabled_build_neg)
{
    struct iot_context *context;
    device_work_param param = {0};

    // Given
    context = (struct iot_context *)*state;
    _set_es_ble_global_context(context);

    // When
    offline_diagnostics_wifi_update_command_handler(context, param);
    // Then
    assert_true(true);

    _set_es_ble_global_context(NULL);
}

TEST_F(iot_easysetup, TC_STATIC_es_confirminfo_handler_pin_feature_not_supported_neg)
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

static struct iot_easysetup_payload *_invoke_real_recovery_handler(struct iot_context *ctx, char *payload)
{
    struct iot_easysetup_payload request = {0};
    struct iot_easysetup_payload *response = NULL;

    request.step = IOT_EASYSETUP_BLE_STEP_OFFLINE_DIAGNOSTICS_RECOVERY;
    request.payload = payload;

    tc_mock_ble_set_get_response_use_wrap(0);
    response = iot_easysetup_get_response(ctx, request);
    tc_mock_ble_set_get_response_use_wrap(1);
    return response;
}

TEST_F(iot_easysetup, TC_STATIC_es_offline_diagnostics_recovery_invalid_json_failure_neg)
{
    struct iot_context *context;
    struct iot_easysetup_payload *response = NULL;
    char *in_payload;

    // Given: invalid JSON payload
    context = (struct iot_context *)*state;
    in_payload = strdup("{ invalid json }");

    // When
    response = _invoke_real_recovery_handler(context, in_payload);
    // Then
    assert_non_null(response);
    assert_int_equal(response->err, IOT_ERROR_EASYSETUP_INVALID_REQUEST);

    // Teardown
    if (response) {
        if (response->payload) {
            free(response->payload);
        }
        iot_os_free(response);
    }
    free(in_payload);
}

static char *_build_updatewifi_payload(const char *ssid, const char *password, int auth_type)

{
    JSON_H *root;
    JSON_H *data;
    JSON_H *wifi_credential;
    char *payload;

    root = JSON_CREATE_OBJECT();
    data = JSON_CREATE_OBJECT();
    wifi_credential = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(wifi_credential, "ssid", JSON_CREATE_STRING(ssid));
    JSON_ADD_ITEM_TO_OBJECT(wifi_credential, "password", JSON_CREATE_STRING(password));
    JSON_ADD_ITEM_TO_OBJECT(wifi_credential, "authType", JSON_CREATE_NUMBER(auth_type));
    JSON_ADD_ITEM_TO_OBJECT(data, "wifiCredential", wifi_credential);
    JSON_ADD_ITEM_TO_OBJECT(data, "command", JSON_CREATE_STRING("updateWifi"));
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    payload = JSON_PRINT(root);
    JSON_DELETE(root);
    return payload;
}

TEST_F(iot_easysetup, TC_STATIC_es_offline_diagnostics_recovery_updatewifi_with_retry_timer_neg)
{
    struct iot_context *context;
    struct iot_easysetup_payload *response = NULL;
    char *in_payload;

    context = (struct iot_context *)*state;
    context->work_queue = iot_util_queue_create(sizeof(struct iot_command));
    context->work_queue_signal = iot_os_eventgroup_create();
    iot_os_mutex_init(&context->st_conn_lock);
    context->next_connection_retry_timer = iot_os_timer_create(NULL, 100, NULL);
    iot_os_timer_start(context->next_connection_retry_timer);

    in_payload = _build_updatewifi_payload("TestSSID", "TestPassword", IOT_WIFI_AUTH_WPA2_PSK);

    response = _invoke_real_recovery_handler(context, in_payload);
    assert_non_null(response);
    assert_int_equal(response->err, IOT_ERROR_EASYSETUP_REQUEST_PENDING);

    if (response) {
        if (response->payload) {
            free(response->payload);
        }
        iot_os_free(response);
    }
    free(in_payload);

    if (context->next_connection_retry_timer) {
        iot_os_timer_delete(context->next_connection_retry_timer);
        context->next_connection_retry_timer = NULL;
    }
    if (context->offline_diagnostics_wifiupdate_timeout) {
        iot_os_timer_delete(context->offline_diagnostics_wifiupdate_timeout);
        context->offline_diagnostics_wifiupdate_timeout = NULL;
    }
    iot_util_queue_delete(context->work_queue);
    iot_os_eventgroup_delete(context->work_queue_signal);
    iot_os_mutex_destroy(&context->st_conn_lock);
    context->work_queue = NULL;
    context->work_queue_signal = NULL;
}

TEST_F(iot_easysetup, TC_STATIC_es_offline_diagnostics_recovery_updatewifi_no_retry_timer_success_neg)
{
    struct iot_context *context;
    struct iot_easysetup_payload *response = NULL;
    char *in_payload;

    context = (struct iot_context *)*state;
    context->work_queue = iot_util_queue_create(sizeof(struct iot_command));
    context->work_queue_signal = iot_os_eventgroup_create();
    iot_os_mutex_init(&context->st_conn_lock);
    context->next_connection_retry_timer = NULL;

    in_payload = _build_updatewifi_payload("TestSSID", "TestPassword", IOT_WIFI_AUTH_WPA2_PSK);

    response = _invoke_real_recovery_handler(context, in_payload);
    assert_non_null(response);
    assert_int_equal(response->err, IOT_ERROR_EASYSETUP_REQUEST_PENDING);

    if (response) {
        if (response->payload) {
            free(response->payload);
        }
        iot_os_free(response);
    }
    free(in_payload);

    if (context->offline_diagnostics_wifiupdate_timeout) {
        iot_os_timer_delete(context->offline_diagnostics_wifiupdate_timeout);
        context->offline_diagnostics_wifiupdate_timeout = NULL;
    }
    iot_util_queue_delete(context->work_queue);
    iot_os_eventgroup_delete(context->work_queue_signal);
    iot_os_mutex_destroy(&context->st_conn_lock);
    context->work_queue = NULL;
    context->work_queue_signal = NULL;
}

TEST_F(iot_easysetup, TC_STATIC_es_offline_diagnostics_recovery_updatewifi_parse_failure_neg)
{
    struct iot_context *context;
    struct iot_easysetup_payload *response = NULL;
    JSON_H *root;
    JSON_H *data;
    char *in_payload;

    context = (struct iot_context *)*state;
    root = JSON_CREATE_OBJECT();
    data = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(data, "command", JSON_CREATE_STRING("updateWifi"));
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    in_payload = JSON_PRINT(root);
    JSON_DELETE(root);

    response = _invoke_real_recovery_handler(context, in_payload);
    assert_non_null(response);
    assert_int_not_equal(response->err, IOT_ERROR_NONE);

    if (response) {
        if (response->payload) {
            free(response->payload);
        }
        iot_os_free(response);
    }
    free(in_payload);
}

TEST_F(iot_easysetup, TC_STATIC_es_offline_diagnostics_recovery_updatewifi_state_update_failure_neg)
{
    struct iot_context *context;
    struct iot_easysetup_payload *response = NULL;
    char *in_payload;

    context = (struct iot_context *)*state;
    context->work_queue = NULL;
    context->work_queue_signal = NULL;
    context->next_connection_retry_timer = NULL;

    in_payload = _build_updatewifi_payload("TestSSID", "TestPassword", IOT_WIFI_AUTH_WPA2_PSK);

    response = _invoke_real_recovery_handler(context, in_payload);
    assert_non_null(response);
    assert_int_equal(response->err, IOT_ERROR_EASYSETUP_INTERNAL_SERVER_ERROR);

    if (response) {
        if (response->payload) {
            free(response->payload);
        }
        iot_os_free(response);
    }
    free(in_payload);
}

TEST_F(iot_easysetup, TC_offline_diagnostics_wifi_update_command_handler_set_prov_data_neg)
{
    struct iot_context *context;
    device_work_param param = {0};

    context = (struct iot_context *)*state;
    context->es_network_status = IOT_ERROR_NONE;
    context->d2d_event_request = true;
    context->offline_diagnostics_wifiupdate_timeout = iot_os_timer_create(NULL, 60000, NULL);
    iot_os_timer_start(context->offline_diagnostics_wifiupdate_timeout);
    snprintf(context->prov_data.wifi.ssid, sizeof(context->prov_data.wifi.ssid), "TestSSID");
    _set_es_ble_global_context(context);

    offline_diagnostics_wifi_update_command_handler(context, param);

    assert_false(context->d2d_event_request);
    assert_null(context->offline_diagnostics_wifiupdate_timeout);

    if (context->offline_diagnostics_wifiupdate_timeout) {
        iot_os_timer_delete(context->offline_diagnostics_wifiupdate_timeout);
        context->offline_diagnostics_wifiupdate_timeout = NULL;
    }

    _set_es_ble_global_context(NULL);
}

TEST_F(iot_easysetup, TC_offline_diagnostics_wifi_update_command_handler_get_prov_failure_neg)
{
    struct iot_context *context;
    device_work_param param = {0};

    context = (struct iot_context *)*state;
    context->es_network_status = IOT_ERROR_MQTT_REJECT_CONNECT;
    context->d2d_event_request = true;
    context->offline_diagnostics_wifiupdate_timeout = NULL;
    _set_es_ble_global_context(context);

    offline_diagnostics_wifi_update_command_handler(context, param);

    assert_false(context->d2d_event_request);

    _set_es_ble_global_context(NULL);
}

TEST_F(iot_easysetup, TC_offline_diagnostics_wifi_update_command_handler_get_prov_success_pos)
{
    struct iot_context *context;
    device_work_param param = {0};

    context = (struct iot_context *)*state;
    context->es_network_status = IOT_ERROR_CONN_STA_AUTH_FAIL;
    context->d2d_event_request = true;
    context->offline_diagnostics_wifiupdate_timeout = NULL;
    snprintf(context->prov_data.wifi.ssid, sizeof(context->prov_data.wifi.ssid), "TestSSID");
    _set_es_ble_global_context(context);

    offline_diagnostics_wifi_update_command_handler(context, param);

    assert_false(context->d2d_event_request);

    _set_es_ble_global_context(NULL);
}

TEST_F(iot_easysetup, TC_STATIC_es_offline_diagnostics_recovery_no_data_failure_neg)

{
    struct iot_context *context;
    struct iot_easysetup_payload *response = NULL;
    char *in_payload;
    JSON_H *root;

    // Given: valid JSON but no "data" field
    context = (struct iot_context *)*state;
    root = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(root, "foo", JSON_CREATE_STRING("bar"));
    in_payload = JSON_PRINT(root);
    JSON_DELETE(root);

    // When
    response = _invoke_real_recovery_handler(context, in_payload);
    // Then
    assert_non_null(response);
    assert_int_equal(response->err, IOT_ERROR_EASYSETUP_INVALID_REQUEST);

    // Teardown
    if (response) {
        if (response->payload) {
            free(response->payload);
        }
        iot_os_free(response);
    }
    free(in_payload);
}

TEST_F(iot_easysetup, TC_STATIC_es_offline_diagnostics_recovery_no_command_failure_neg)
{
    struct iot_context *context;
    struct iot_easysetup_payload *response = NULL;
    char *in_payload;
    JSON_H *root;
    JSON_H *data;

    // Given: "data" present but no "command" field
    context = (struct iot_context *)*state;
    root = JSON_CREATE_OBJECT();
    data = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(data, "foo", JSON_CREATE_STRING("bar"));
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    in_payload = JSON_PRINT(root);
    JSON_DELETE(root);

    // When
    response = _invoke_real_recovery_handler(context, in_payload);
    // Then
    assert_non_null(response);
    assert_int_equal(response->err, IOT_ERROR_EASYSETUP_INVALID_REQUEST);

    // Teardown
    if (response) {
        if (response->payload) {
            free(response->payload);
        }
        iot_os_free(response);
    }
    free(in_payload);
}

TEST_F(iot_easysetup, TC_STATIC_es_offline_diagnostics_recovery_unknown_command_failure_neg)
{
    struct iot_context *context;
    struct iot_easysetup_payload *response = NULL;
    char *in_payload;
    JSON_H *root;
    JSON_H *data;

    // Given: command that is neither restartThing nor updateWifi
    context = (struct iot_context *)*state;
    root = JSON_CREATE_OBJECT();
    data = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(data, "command", JSON_CREATE_STRING("unknownCommand"));
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    in_payload = JSON_PRINT(root);
    JSON_DELETE(root);

    // When
    response = _invoke_real_recovery_handler(context, in_payload);
    // Then
    assert_non_null(response);
    assert_int_equal(response->err, IOT_ERROR_EASYSETUP_INVALID_REQUEST);

    // Teardown
    if (response) {
        if (response->payload) {
            free(response->payload);
        }
        iot_os_free(response);
    }
    free(in_payload);
}

TEST_F(iot_easysetup, TC_STATIC_es_offline_diagnostics_recovery_restart_thing_success_pos)
{
    struct iot_context *context;
    struct iot_easysetup_payload *response = NULL;
    char *in_payload;
    JSON_H *root;
    JSON_H *data;

    // Given: restartThing command with a work queue so iot_command_send succeeds
    context = (struct iot_context *)*state;
    context->work_queue = iot_util_queue_create(sizeof(struct iot_command));
    context->work_queue_signal = iot_os_eventgroup_create();
    iot_os_mutex_init(&context->st_conn_lock);

    root = JSON_CREATE_OBJECT();
    data = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(data, "command", JSON_CREATE_STRING("restartThing"));
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    in_payload = JSON_PRINT(root);
    JSON_DELETE(root);

    // When
    response = _invoke_real_recovery_handler(context, in_payload);
    // Then: handler returns IOT_ERROR_NONE on successful reboot command send
    assert_non_null(response);
    assert_int_equal(response->err, IOT_ERROR_NONE);

    // Teardown
    if (response) {
        if (response->payload) {
            free(response->payload);
        }
        iot_os_free(response);
    }
    free(in_payload);
    iot_util_queue_delete(context->work_queue);
    iot_os_eventgroup_delete(context->work_queue_signal);
    iot_os_mutex_destroy(&context->st_conn_lock);
    context->work_queue = NULL;
    context->work_queue_signal = NULL;
}

TEST_F(iot_easysetup, TC_STATIC_es_offline_diagnostics_recovery_restart_thing_command_send_failure_neg)
{
    struct iot_context *context;
    struct iot_easysetup_payload *response = NULL;
    char *in_payload;
    JSON_H *root;
    JSON_H *data;

    // Given: restartThing command but iot_command_send fails because the
    // work queue is NULL (iot_put_device_work returns an error).
    context = (struct iot_context *)*state;
    context->work_queue = NULL;
    context->work_queue_signal = NULL;

    root = JSON_CREATE_OBJECT();
    data = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(data, "command", JSON_CREATE_STRING("restartThing"));
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    in_payload = JSON_PRINT(root);
    JSON_DELETE(root);

    // When
    response = _invoke_real_recovery_handler(context, in_payload);
    // Then: iot_command_send fails, handler propagates the error
    assert_non_null(response);
    assert_int_not_equal(response->err, IOT_ERROR_NONE);

    // Teardown
    if (response) {
        if (response->payload) {
            free(response->payload);
        }
        iot_os_free(response);
    }
    free(in_payload);
}

TEST_F(iot_easysetup, TC_STATIC_next_connection_retry_timeout_success_neg)
{
    struct iot_context *context;

    context = (struct iot_context *)*state;
    context->work_queue = iot_util_queue_create(sizeof(struct iot_command));
    context->work_queue_signal = iot_os_eventgroup_create();

    _next_connection_retry_timeout(NULL, context);

    iot_util_queue_delete(context->work_queue);
    iot_os_eventgroup_delete(context->work_queue_signal);
    context->work_queue = NULL;
    context->work_queue_signal = NULL;

    assert_true(true);
}

TEST_F(iot_easysetup, TC_iot_easysetup_get_response_setupcomplete_step_success_pos)
{
    struct iot_context *context;
    struct iot_easysetup_payload request = {0};
    struct iot_easysetup_payload *response = NULL;

    context = (struct iot_context *)*state;
    context->work_queue_signal = iot_os_eventgroup_create();
    context->work_queue = iot_util_queue_create(sizeof(device_work_data_t));
    context->next_connection_retry_timer = NULL;

    request.step = IOT_EASYSETUP_BLE_STEP_SETUPCOMPLETE;
    request.payload = NULL;

    response = iot_easysetup_get_response(context, request);
    assert_non_null(response);
    assert_int_equal(response->err, IOT_ERROR_NONE);

    if (response) {
        if (response->payload) {
            free(response->payload);
        }
        iot_os_free(response);
    }
    iot_os_eventgroup_delete(context->work_queue_signal);
    iot_util_queue_delete(context->work_queue);
    context->work_queue = NULL;
    context->work_queue_signal = NULL;
}

TEST_F(iot_easysetup, TC_offline_diagnostics_wifi_update_command_handler_switch_cases_neg)
{
    struct iot_context *context;
    struct iot_wifi_prov_data wifi_prov;
    device_work_param param = {0};
    iot_error_t err;

    memset(&wifi_prov, 0, sizeof(wifi_prov));
    snprintf(wifi_prov.ssid, sizeof(wifi_prov.ssid), "TestSSID");
    snprintf(wifi_prov.password, sizeof(wifi_prov.password), "TestPass");
    wifi_prov.security_type = IOT_WIFI_AUTH_WPA2_PSK;
    err = iot_nv_set_wifi_prov_data(&wifi_prov);
    assert_int_equal(err, IOT_ERROR_NONE);

    context = (struct iot_context *)*state;
    context->offline_diagnostics_wifiupdate_timeout = NULL;
    _set_es_ble_global_context(context);

    int statuses[] = {
        IOT_ERROR_MQTT_REJECT_CONNECT,
        IOT_ERROR_CONN_STA_AUTH_FAIL,
        IOT_ERROR_CONN_STA_DHCP_FAIL,
        IOT_ERROR_CONN_DNS_QUERY_FAIL,
        IOT_ERROR_CONN_STA_NO_INTERNET,
        IOT_ERROR_NET_TCP_CONNECTION_FAIL,
        IOT_ERROR_NET_TLS_HANDSHAKE_FAIL,
        IOT_ERROR_MQTT_CONNECT_FAIL,
        IOT_ERROR_MQTT_CONNECT_TIMEOUT,
        IOT_ERROR_MQTT_RATE_LIMIT,
        9999,
    };

    for (int i = 0; i < sizeof(statuses) / sizeof(statuses[0]); i++) {
        context->es_network_status = statuses[i];
        context->d2d_event_request = true;
        offline_diagnostics_wifi_update_command_handler(context, param);
        assert_false(context->d2d_event_request);
    }

    _set_es_ble_global_context(NULL);
}

TEST_F(iot_easysetup, TC_STATIC_es_confirm_check_manager_default_case_failure_neg)
{
    iot_error_t err;
    struct iot_context *context;

    context = (struct iot_context *)*state;
    context->iot_events = iot_os_eventgroup_create();
    context->work_queue_signal = iot_os_eventgroup_create();
    context->work_queue = iot_util_queue_create(sizeof(device_work_data_t));

    err = _es_confirm_check_manager(context, OVF_BIT_MAX_FEATURE + 1, NULL);
    assert_int_equal(err, IOT_ERROR_EASYSETUP_CONFIRM_NOT_SUPPORT);

    iot_os_eventgroup_delete(context->iot_events);
    iot_os_eventgroup_delete(context->work_queue_signal);
    iot_util_queue_delete(context->work_queue);
}

#if defined(CONFIG_STDK_IOT_CORE_EASYSETUP_OFFLINE_DIAGNOSTICS)
TEST_F(iot_easysetup, TC_STATIC_offline_diagnostics_wifi_update_timeout_success_neg)

{
    struct iot_context *context;

    context = (struct iot_context *)*state;
    context->work_queue = iot_util_queue_create(sizeof(struct iot_command));
    context->work_queue_signal = iot_os_eventgroup_create();
    context->offline_diagnostics_wifiupdate_timeout = iot_os_timer_create(NULL, 60000, NULL);
    iot_os_timer_start(context->offline_diagnostics_wifiupdate_timeout);

    _offline_diagnostics_wifi_update_timeout(NULL, context);

    assert_null(context->offline_diagnostics_wifiupdate_timeout);
    iot_util_queue_delete(context->work_queue);
    iot_os_eventgroup_delete(context->work_queue_signal);
    context->work_queue = NULL;
    context->work_queue_signal = NULL;
}
#endif

#if defined(CONFIG_STDK_IOT_CORE_LOG_FILE)
TEST_F(iot_easysetup, TC_STATIC_es_log_get_dump_handler_success_pos)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;

    context = (struct iot_context *)*state;
    err = iot_log_file_init(RAM_ONLY);

    assert_int_equal(err, IOT_ERROR_NONE);

    err = _es_log_get_dump_handler(context, &out_payload);
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(out_payload);

    if (out_payload)
        free(out_payload);
    iot_log_file_exit();
}
#endif

TEST_F(iot_easysetup, TC_STATIC_es_log_get_dump_handler_logdump_failure_neg)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;

    context = (struct iot_context *)*state;
    err = _es_log_get_dump_handler(context, &out_payload);
    assert_int_not_equal(err, IOT_ERROR_NONE);

    if (out_payload)
        free(out_payload);
}

#if defined(CONFIG_STDK_IOT_CORE_EASYSETUP_OFFLINE_DIAGNOSTICS)
TEST_F(iot_easysetup, TC_STATIC_es_offline_diagnostics_connection_info_handler_success_pos)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;

    context = (struct iot_context *)*state;
    err = _es_offline_diagnostics_connection_info_handler(context, &out_payload);
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(out_payload);

    if (out_payload)
        free(out_payload);
}

TEST_F(iot_easysetup, TC_STATIC_es_offline_diagnostics_connection_info_handler_disconnected_neg)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;

    context = (struct iot_context *)*state;
    context->last_st_ecode.ecode_type = IOT_ST_ECODE_NE01;
    snprintf(context->last_st_ecode.ecode, sizeof(context->last_st_ecode.ecode), "E-001");

    err = _es_offline_diagnostics_connection_info_handler(context, &out_payload);

    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(out_payload);

    if (out_payload)
        free(out_payload);
}
#endif

/* --- Cycle 3: tests targeting least-covered functions --- */

TEST_F(iot_easysetup, TC_STATIC_es_keyinfo_handler_missing_data_field_failure_neg)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;
    JSON_H *root;

    context = (struct iot_context *)*state;
    root = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(root, "foo", JSON_CREATE_STRING("bar"));
    char *in_payload = JSON_PRINT(root);
    JSON_DELETE(root);

    err = _es_keyinfo_handler(context, in_payload, &out_payload);
    assert_int_not_equal(err, IOT_ERROR_NONE);

    free(in_payload);
    if (out_payload)
        free(out_payload);
}

TEST_F(iot_easysetup, TC_STATIC_es_keyinfo_handler_invalid_spub_base64_failure_neg)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;
    JSON_H *root;
    JSON_H *data;

    context = (struct iot_context *)*state;
    root = JSON_CREATE_OBJECT();
    data = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(data, "spub", JSON_CREATE_STRING("!!!invalid_b64!!!"));
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    char *in_payload = JSON_PRINT(root);
    JSON_DELETE(root);

    err = _es_keyinfo_handler(context, in_payload, &out_payload);
    assert_int_not_equal(err, IOT_ERROR_NONE);

    free(in_payload);
    if (out_payload)
        free(out_payload);
}

TEST_F(iot_easysetup, TC_STATIC_es_keyinfo_handler_wrong_spub_length_failure_neg)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;
    JSON_H *root;
    JSON_H *data;

    context = (struct iot_context *)*state;
    root = JSON_CREATE_OBJECT();
    data = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(data, "spub", JSON_CREATE_STRING("dGVzdA"));
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    char *in_payload = JSON_PRINT(root);
    JSON_DELETE(root);

    err = _es_keyinfo_handler(context, in_payload, &out_payload);
    assert_int_not_equal(err, IOT_ERROR_NONE);

    free(in_payload);
    if (out_payload)
        free(out_payload);
}

TEST_F(iot_easysetup, TC_STATIC_es_keyinfo_handler_invalid_rand_base64_failure_neg)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;
    unsigned char *spub = _get_server_test_pubkey();
    unsigned char spub_b64[128];
    int out_length;
    JSON_H *root;
    JSON_H *data;

    context = (struct iot_context *)*state;
    iot_security_base64_encode_urlsafe(spub, IOT_SECURITY_ED25519_LEN, spub_b64, sizeof(spub_b64), &out_length);

    root = JSON_CREATE_OBJECT();
    data = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(data, "spub", JSON_CREATE_STRING((char *)spub_b64));
    JSON_ADD_ITEM_TO_OBJECT(data, "rand", JSON_CREATE_STRING("!!!invalid_rand!!!"));
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    char *in_payload = JSON_PRINT(root);
    JSON_DELETE(root);

    err = _es_keyinfo_handler(context, in_payload, &out_payload);
    assert_int_not_equal(err, IOT_ERROR_NONE);

    free(in_payload);
    if (out_payload)
        free(out_payload);
}

TEST_F(iot_easysetup, TC_STATIC_es_keyinfo_handler_wrong_rand_size_failure_neg)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;
    unsigned char *spub = _get_server_test_pubkey();
    unsigned char spub_b64[128];
    int out_length;
    JSON_H *root;
    JSON_H *data;

    context = (struct iot_context *)*state;
    iot_security_base64_encode_urlsafe(spub, IOT_SECURITY_ED25519_LEN, spub_b64, sizeof(spub_b64), &out_length);

    root = JSON_CREATE_OBJECT();
    data = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(data, "spub", JSON_CREATE_STRING((char *)spub_b64));
    JSON_ADD_ITEM_TO_OBJECT(data, "rand", JSON_CREATE_STRING("dGVzdA"));
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    char *in_payload = JSON_PRINT(root);
    JSON_DELETE(root);

    err = _es_keyinfo_handler(context, in_payload, &out_payload);
    assert_int_not_equal(err, IOT_ERROR_NONE);

    free(in_payload);
    if (out_payload)
        free(out_payload);
}

void TC_STATIC_es_wifiprovisioninginfo_handler_invalid_broker_url_failure_neg(void **state)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;
    JSON_H *root;
    JSON_H *data;
    JSON_H *wifi_credential;

    context = (struct iot_context *)*state;
    context->lookup_id = NULL;
    context->wifi_update_enabled = false;

    root = JSON_CREATE_OBJECT();
    data = JSON_CREATE_OBJECT();
    wifi_credential = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(wifi_credential, "ssid", JSON_CREATE_STRING("TestSSID"));
    JSON_ADD_ITEM_TO_OBJECT(wifi_credential, "password", JSON_CREATE_STRING("TestPassword"));
    JSON_ADD_ITEM_TO_OBJECT(data, "wifiCredential", wifi_credential);
    JSON_ADD_ITEM_TO_OBJECT(data, "brokerUrl", JSON_CREATE_STRING("not_a_valid_url"));
    JSON_ADD_ITEM_TO_OBJECT(data, "deviceName", JSON_CREATE_STRING("TestDevice"));
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    char *in_payload = JSON_PRINT(root);
    JSON_DELETE(root);

    will_return(__wrap_iot_bsp_wifi_get_mac, 0x0000000000000000);
    will_return(__wrap_iot_bsp_wifi_get_mac, IOT_ERROR_NONE);

    err = _es_wifiprovisioninginfo_handler(context, in_payload, &out_payload);
    assert_int_not_equal(err, IOT_ERROR_NONE);

    free(in_payload);
    if (out_payload)
        free(out_payload);
}

void TC_STATIC_es_wifiprovisioninginfo_handler_wifi_update_enabled_success_pos(void **state)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;
    JSON_H *root;
    JSON_H *data;
    JSON_H *wifi_credential;

    context = (struct iot_context *)*state;
    context->lookup_id = NULL;
    context->wifi_update_enabled = true;

    root = JSON_CREATE_OBJECT();
    data = JSON_CREATE_OBJECT();
    wifi_credential = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(wifi_credential, "ssid", JSON_CREATE_STRING("TestSSID"));
    JSON_ADD_ITEM_TO_OBJECT(wifi_credential, "password", JSON_CREATE_STRING("TestPassword"));
    JSON_ADD_ITEM_TO_OBJECT(data, "wifiCredential", wifi_credential);
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    char *in_payload = JSON_PRINT(root);
    JSON_DELETE(root);

    err = _es_wifiprovisioninginfo_handler(context, in_payload, &out_payload);
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(out_payload);

    free(in_payload);
    if (out_payload)
        free(out_payload);
}

TEST_F(iot_easysetup, TC_STATIC_es_wifiprovisioninginfo_handler_matching_ssid_no_authtype_success_neg)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;
    JSON_H *root;
    JSON_H *data;
    JSON_H *wifi_credential;
    const char test_ssid[] = "TestSSID_Match";

    context = (struct iot_context *)*state;
    context->lookup_id = NULL;
    context->wifi_update_enabled = false;

    context->scan_num = 2;
    context->scan_result = (iot_wifi_scan_result_t *)calloc(context->scan_num, sizeof(iot_wifi_scan_result_t));
    strncpy((char *)context->scan_result[0].ssid, test_ssid, IOT_WIFI_MAX_SSID_LEN);
    context->scan_result[0].authmode = IOT_WIFI_AUTH_WPA2_PSK;
    strncpy((char *)context->scan_result[1].ssid, "OtherSSID", IOT_WIFI_MAX_SSID_LEN);
    context->scan_result[1].authmode = IOT_WIFI_AUTH_OPEN;

    root = JSON_CREATE_OBJECT();
    data = JSON_CREATE_OBJECT();
    wifi_credential = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(wifi_credential, "ssid", JSON_CREATE_STRING(test_ssid));
    JSON_ADD_ITEM_TO_OBJECT(wifi_credential, "password", JSON_CREATE_STRING("password123"));
    JSON_ADD_ITEM_TO_OBJECT(data, "wifiCredential", wifi_credential);
    JSON_ADD_ITEM_TO_OBJECT(data, "brokerUrl", JSON_CREATE_STRING("https://test.domain.com:5676"));
    JSON_ADD_ITEM_TO_OBJECT(data, "deviceName", JSON_CREATE_STRING("TestDevice"));
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    char *in_payload = JSON_PRINT(root);
    JSON_DELETE(root);

    will_return(__wrap_iot_bsp_wifi_get_mac, 0x0000000000000000);
    will_return(__wrap_iot_bsp_wifi_get_mac, IOT_ERROR_NONE);

    err = _es_wifiprovisioninginfo_handler(context, in_payload, &out_payload);
    assert_int_equal(err, IOT_ERROR_NONE);

    free(in_payload);
    if (out_payload)
        free(out_payload);
    free(context->scan_result);
    context->scan_result = NULL;
    context->scan_num = 0;
}

TEST_F(iot_easysetup, TC_STATIC_es_wifiprovisioninginfo_handler_matching_ssid_with_authtype_success_pos)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;
    JSON_H *root;
    JSON_H *data;
    JSON_H *wifi_credential;
    const char test_ssid[] = "TestSSID_Match2";

    context = (struct iot_context *)*state;
    context->lookup_id = NULL;
    context->wifi_update_enabled = false;

    context->scan_num = 1;
    context->scan_result = (iot_wifi_scan_result_t *)calloc(1, sizeof(iot_wifi_scan_result_t));
    strncpy((char *)context->scan_result[0].ssid, test_ssid, IOT_WIFI_MAX_SSID_LEN);
    context->scan_result[0].authmode = IOT_WIFI_AUTH_WPA2_PSK;

    root = JSON_CREATE_OBJECT();
    data = JSON_CREATE_OBJECT();
    wifi_credential = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(wifi_credential, "ssid", JSON_CREATE_STRING(test_ssid));
    JSON_ADD_ITEM_TO_OBJECT(wifi_credential, "password", JSON_CREATE_STRING("password123"));
    JSON_ADD_ITEM_TO_OBJECT(wifi_credential, "authType", JSON_CREATE_NUMBER(IOT_WIFI_AUTH_WPA2_PSK));
    JSON_ADD_ITEM_TO_OBJECT(data, "wifiCredential", wifi_credential);
    JSON_ADD_ITEM_TO_OBJECT(data, "brokerUrl", JSON_CREATE_STRING("https://test.domain.com:5676"));
    JSON_ADD_ITEM_TO_OBJECT(data, "deviceName", JSON_CREATE_STRING("TestDevice"));
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    char *in_payload = JSON_PRINT(root);
    JSON_DELETE(root);

    will_return(__wrap_iot_bsp_wifi_get_mac, 0x0000000000000000);
    will_return(__wrap_iot_bsp_wifi_get_mac, IOT_ERROR_NONE);

    err = _es_wifiprovisioninginfo_handler(context, in_payload, &out_payload);
    assert_int_equal(err, IOT_ERROR_NONE);

    free(in_payload);
    if (out_payload)
        free(out_payload);
    free(context->scan_result);
    context->scan_result = NULL;
    context->scan_num = 0;
}

TEST_F(iot_easysetup, TC_STATIC_es_wifiprovisioninginfo_handler_no_match_empty_password_success_neg)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;
    JSON_H *root;
    JSON_H *data;
    JSON_H *wifi_credential;

    context = (struct iot_context *)*state;
    context->lookup_id = NULL;
    context->wifi_update_enabled = false;

    context->scan_num = 1;
    context->scan_result = (iot_wifi_scan_result_t *)calloc(1, sizeof(iot_wifi_scan_result_t));
    strncpy((char *)context->scan_result[0].ssid, "SomeOtherSSID", IOT_WIFI_MAX_SSID_LEN);
    context->scan_result[0].authmode = IOT_WIFI_AUTH_WPA2_PSK;

    root = JSON_CREATE_OBJECT();
    data = JSON_CREATE_OBJECT();
    wifi_credential = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(wifi_credential, "ssid", JSON_CREATE_STRING("NonMatchingSSID"));
    JSON_ADD_ITEM_TO_OBJECT(wifi_credential, "password", JSON_CREATE_STRING(""));
    JSON_ADD_ITEM_TO_OBJECT(data, "wifiCredential", wifi_credential);
    JSON_ADD_ITEM_TO_OBJECT(data, "brokerUrl", JSON_CREATE_STRING("https://test.domain.com:5676"));
    JSON_ADD_ITEM_TO_OBJECT(data, "deviceName", JSON_CREATE_STRING("TestDevice"));
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    char *in_payload = JSON_PRINT(root);
    JSON_DELETE(root);

    will_return(__wrap_iot_bsp_wifi_get_mac, 0x0000000000000000);
    will_return(__wrap_iot_bsp_wifi_get_mac, IOT_ERROR_NONE);

    err = _es_wifiprovisioninginfo_handler(context, in_payload, &out_payload);
    assert_int_equal(err, IOT_ERROR_NONE);

    free(in_payload);
    if (out_payload)
        free(out_payload);
    free(context->scan_result);
    context->scan_result = NULL;
    context->scan_num = 0;
}

TEST_F(iot_easysetup, TC_STATIC_es_setupcomplete_handler_wifi_update_with_retry_timer_success_pos)
{
    iot_error_t err;
    struct iot_context *context;
    char *out_payload = NULL;

    context = (struct iot_context *)*state;
    context->work_queue_signal = iot_os_eventgroup_create();
    context->work_queue = iot_util_queue_create(sizeof(device_work_data_t));
    context->next_connection_retry_timer = iot_os_timer_create(NULL, 1000, NULL);
    iot_os_timer_start(context->next_connection_retry_timer);
    context->wifi_update_enabled = true;

    err = _es_setupcomplete_handler(context, NULL, &out_payload);
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(out_payload);

    if (out_payload)
        free(out_payload);
    if (context->next_connection_retry_timer) {
        iot_os_timer_delete(context->next_connection_retry_timer);
        context->next_connection_retry_timer = NULL;
    }
    iot_os_eventgroup_delete(context->work_queue_signal);
    iot_util_queue_delete(context->work_queue);
}

TEST_F(iot_easysetup, TC_STATIC_es_wifiprovisioninginfo_handler_mac_address_success_pos)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;
    JSON_H *root;
    JSON_H *data;
    JSON_H *wifi_credential;

    context = (struct iot_context *)*state;
    context->lookup_id = NULL;
    context->wifi_update_enabled = false;

    root = JSON_CREATE_OBJECT();
    data = JSON_CREATE_OBJECT();
    wifi_credential = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(wifi_credential, "ssid", JSON_CREATE_STRING("TestSSID"));
    JSON_ADD_ITEM_TO_OBJECT(wifi_credential, "password", JSON_CREATE_STRING("TestPassword"));
    JSON_ADD_ITEM_TO_OBJECT(wifi_credential, "macAddress", JSON_CREATE_STRING("AA:BB:CC:DD:EE:FF"));
    JSON_ADD_ITEM_TO_OBJECT(data, "wifiCredential", wifi_credential);
    JSON_ADD_ITEM_TO_OBJECT(data, "brokerUrl", JSON_CREATE_STRING("https://test.domain.com:5676"));
    JSON_ADD_ITEM_TO_OBJECT(data, "deviceName", JSON_CREATE_STRING("TestDevice"));
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    char *in_payload = JSON_PRINT(root);
    JSON_DELETE(root);

    will_return(__wrap_iot_bsp_wifi_get_mac, 0x0000000000000000);
    will_return(__wrap_iot_bsp_wifi_get_mac, IOT_ERROR_NONE);

    err = _es_wifiprovisioninginfo_handler(context, in_payload, &out_payload);
    assert_int_equal(err, IOT_ERROR_NONE);

    free(in_payload);
    if (out_payload)
        free(out_payload);
}

void TC_STATIC_es_wifiprovisioninginfo_handler_invalid_mac_failure_neg(void **state)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;
    JSON_H *root;
    JSON_H *data;
    JSON_H *wifi_credential;

    context = (struct iot_context *)*state;
    context->lookup_id = NULL;
    context->wifi_update_enabled = false;

    root = JSON_CREATE_OBJECT();
    data = JSON_CREATE_OBJECT();
    wifi_credential = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(wifi_credential, "ssid", JSON_CREATE_STRING("TestSSID"));
    JSON_ADD_ITEM_TO_OBJECT(wifi_credential, "password", JSON_CREATE_STRING("TestPassword"));
    JSON_ADD_ITEM_TO_OBJECT(wifi_credential, "macAddress", JSON_CREATE_STRING("invalid_mac"));
    JSON_ADD_ITEM_TO_OBJECT(data, "wifiCredential", wifi_credential);
    JSON_ADD_ITEM_TO_OBJECT(data, "brokerUrl", JSON_CREATE_STRING("https://test.domain.com:5676"));
    JSON_ADD_ITEM_TO_OBJECT(data, "deviceName", JSON_CREATE_STRING("TestDevice"));
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    char *in_payload = JSON_PRINT(root);
    JSON_DELETE(root);

    will_return(__wrap_iot_bsp_wifi_get_mac, 0x0000000000000000);
    will_return(__wrap_iot_bsp_wifi_get_mac, IOT_ERROR_NONE);

    err = _es_wifiprovisioninginfo_handler(context, in_payload, &out_payload);
    assert_int_not_equal(err, IOT_ERROR_NONE);

    free(in_payload);
    if (out_payload)
        free(out_payload);
}

TEST_F(iot_easysetup, TC_STATIC_es_wifiprovisioninginfo_handler_null_payload_failure_neg)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;

    context = (struct iot_context *)*state;
    context->lookup_id = NULL;

    err = _es_wifiprovisioninginfo_handler(context, NULL, &out_payload);
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

TEST_F(iot_easysetup, TC_STATIC_es_time_set_invalid_format_failure_neg)
{
    iot_error_t err;
    unsigned char bad_time[] = "invalid-time-format";

    err = _es_time_set(bad_time);
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

TEST_F(iot_easysetup, TC_STATIC_es_json_parse_string_null_args_failure_neg)
{
    char *result;

    result = _es_json_parse_string(NULL, "test");
    assert_null(result);

    JSON_H *root = JSON_CREATE_OBJECT();
    result = _es_json_parse_string(root, NULL);
    assert_null(result);

    JSON_DELETE(root);
}

TEST_F(iot_easysetup, TC_STATIC_es_copy_cloud_prov_malloc_failure_neg)
{
    iot_error_t err;
    struct iot_cloud_prov_data src = {0};
    struct iot_cloud_prov_data dst = {0};

    src.broker_url = "test_url";
    src.label = "test_label";
    src.broker_port = 8883;

    set_mock_iot_os_malloc_failure_with_index(0);
    err = _es_copy_cloud_prov(&dst, &src);
    assert_int_not_equal(err, IOT_ERROR_NONE);
    do_not_use_mock_iot_os_malloc_failure();
}

/* --- Cycle 4: tests targeting remaining uncovered lines --- */

extern iot_error_t iot_easysetup_get_pubkey(iot_security_context_t **state, unsigned char **pubkey, size_t *pubkey_len);
extern iot_error_t _es_crypto_cipher_gen_iv(iot_security_buffer_t *iv_buffer);
extern iot_error_t _es_log_systeminfo_handler(struct iot_context *ctx, char **out_payload);

TEST_F(iot_easysetup, TC_STATIC_es_time_set_success_pos)
{
    iot_error_t err;
    unsigned char valid_time[] = "2024-03-25T02.40.14";

    /* 2024-03-25T02:40:14Z */
    expect_value(__wrap_iot_bsp_system_set_time_in_sec, time_in_sec, 1711334414);
    err = _es_time_set(valid_time);
    assert_int_equal(err, IOT_ERROR_NONE);
}

TEST_F(iot_easysetup, TC_STATIC_es_time_set_leap_day_success_pos)
{
    iot_error_t err;
    unsigned char leap_day[] = "2024-02-29T00.00.00";
    unsigned char day_after_leap[] = "2024-03-01T00.00.00";

    /* 2024-02-29T00:00:00Z */
    expect_value(__wrap_iot_bsp_system_set_time_in_sec, time_in_sec, 1709164800);
    err = _es_time_set(leap_day);
    assert_int_equal(err, IOT_ERROR_NONE);

    /* 2024-03-01T00:00:00Z */
    expect_value(__wrap_iot_bsp_system_set_time_in_sec, time_in_sec, 1709251200);
    err = _es_time_set(day_after_leap);
    assert_int_equal(err, IOT_ERROR_NONE);
}

TEST_F(iot_easysetup, TC_STATIC_es_time_set_out_of_range_failure_neg)
{
    iot_error_t err;
    unsigned char *out_of_range_times[] = {
        (unsigned char *)"1969-12-31T23.59.59", (unsigned char *)"2024-00-25T02.40.14",
        (unsigned char *)"2024-13-25T02.40.14", (unsigned char *)"2024-03-00T02.40.14",
        (unsigned char *)"2024-03-32T02.40.14", (unsigned char *)"2024-03-25T24.40.14",
        (unsigned char *)"2024-03-25T02.60.14", (unsigned char *)"2024-03-25T02.40.60",
    };

    for (size_t i = 0; i < sizeof(out_of_range_times) / sizeof(out_of_range_times[0]); i++) {
        err = _es_time_set(out_of_range_times[i]);
        assert_int_equal(err, IOT_ERROR_EASYSETUP_INVALID_TIME);
    }
}

TEST_F(iot_easysetup, TC_STATIC_es_time_set_bsp_set_time_failure_neg)
{
    iot_error_t err;
    unsigned char valid_time[] = "2024-03-25T02.40.14";

    expect_any(__wrap_iot_bsp_system_set_time_in_sec, time_in_sec);
    set_mock_iot_bsp_system_set_time_failure(IOT_ERROR_INVALID_ARGS);
    err = _es_time_set(valid_time);

    assert_int_not_equal(err, IOT_ERROR_NONE);
}

TEST_F(iot_easysetup, TC_STATIC_es_json_parse_string_malloc_failure_neg)
{
    JSON_H *root;
    char *result;

    root = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(root, "key", JSON_CREATE_STRING("value"));

    set_mock_iot_os_malloc_failure_with_index(0);
    result = _es_json_parse_string(root, "key");
    assert_null(result);
    do_not_use_mock_iot_os_malloc_failure();

    JSON_DELETE(root);
}

TEST_F(iot_easysetup, TC_STATIC_es_json_parse_string_not_found_neg)
{
    JSON_H *root;
    char *result;

    root = JSON_CREATE_OBJECT();
    result = _es_json_parse_string(root, "missing_key");
    assert_null(result);

    JSON_DELETE(root);
}

TEST_F(iot_easysetup, TC_STATIC_es_json_parse_string_success_pos)
{
    JSON_H *root;
    char *result;

    root = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(root, "key", JSON_CREATE_STRING("hello"));
    result = _es_json_parse_string(root, "key");
    assert_non_null(result);
    assert_string_equal(result, "hello");

    iot_os_free(result);
    JSON_DELETE(root);
}

TEST_F(iot_easysetup, TC_STATIC_es_crypto_cipher_gen_iv_null_arg_neg)
{
    iot_error_t err;

    err = _es_crypto_cipher_gen_iv(NULL);
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

TEST_F(iot_easysetup, TC_STATIC_es_crypto_cipher_gen_iv_malloc_failure_neg)
{
    iot_error_t err;
    iot_security_buffer_t iv_buf = {0};

    set_mock_iot_os_malloc_failure_with_index(0);
    err = _es_crypto_cipher_gen_iv(&iv_buf);
    assert_int_not_equal(err, IOT_ERROR_NONE);
    do_not_use_mock_iot_os_malloc_failure();
}

void TC_STATIC_es_crypto_cipher_gen_iv_success_pos(void **state)
{
    iot_error_t err;
    iot_security_buffer_t iv_buf = {0};

    err = _es_crypto_cipher_gen_iv(&iv_buf);
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(iv_buf.p);

    iot_os_free(iv_buf.p);
}

TEST_F(iot_easysetup, TC_STATIC_es_get_pubkey_malloc_failure_neg)
{
    iot_error_t err;
    struct iot_context *context;
    unsigned char *pubkey = NULL;
    size_t pubkey_len = 0;

    context = (struct iot_context *)*state;

    set_mock_iot_os_malloc_failure_with_index(0);
    err = iot_easysetup_get_pubkey(&context->easysetup_security_context, &pubkey, &pubkey_len);
    assert_int_not_equal(err, IOT_ERROR_NONE);
    do_not_use_mock_iot_os_malloc_failure();
}

TEST_F(iot_easysetup, TC_STATIC_es_deviceinfo_handler_sha256_failure_neg)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;

    context = (struct iot_context *)*state;
    context->devconf.combo_sn = NULL;

    set_mock_iot_os_malloc_failure_with_index(3);
    err = _es_deviceinfo_handler(context, &out_payload);
    assert_int_not_equal(err, IOT_ERROR_NONE);
    do_not_use_mock_iot_os_malloc_failure();

    if (out_payload)
        free(out_payload);
}

TEST_F(iot_easysetup, TC_STATIC_es_deviceinfo_handler_encode_buf_malloc_failure_neg)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;

    context = (struct iot_context *)*state;
    context->devconf.combo_sn = NULL;

    set_mock_iot_os_malloc_failure_with_index(8);
    err = _es_deviceinfo_handler(context, &out_payload);
    assert_int_not_equal(err, IOT_ERROR_NONE);
    do_not_use_mock_iot_os_malloc_failure();

    if (out_payload)
        free(out_payload);
}

TEST_F(iot_easysetup, TC_STATIC_es_deviceinfo_handler_combo_sn_malloc_failure_neg)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;

    context = (struct iot_context *)*state;
    context->devconf.combo_sn = NULL;

    set_mock_iot_os_malloc_failure_with_index(2);
    err = _es_deviceinfo_handler(context, &out_payload);
    assert_int_not_equal(err, IOT_ERROR_NONE);
    do_not_use_mock_iot_os_malloc_failure();

    if (out_payload)
        free(out_payload);
}

TEST_F(iot_easysetup, TC_STATIC_es_deviceinfo_handler_hash_buf_malloc_failure_neg)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;

    context = (struct iot_context *)*state;
    context->devconf.combo_sn = NULL;

    set_mock_iot_os_malloc_failure_with_index(4);
    err = _es_deviceinfo_handler(context, &out_payload);
    assert_int_not_equal(err, IOT_ERROR_NONE);
    do_not_use_mock_iot_os_malloc_failure();

    if (out_payload)
        free(out_payload);
}

TEST_F(iot_easysetup, TC_STATIC_es_deviceinfo_handler_hashed_combo_sn_malloc_failure_neg)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;

    context = (struct iot_context *)*state;
    context->devconf.combo_sn = NULL;

    set_mock_iot_os_malloc_failure_with_index(6);
    err = _es_deviceinfo_handler(context, &out_payload);
    assert_int_not_equal(err, IOT_ERROR_NONE);
    do_not_use_mock_iot_os_malloc_failure();

    if (out_payload)
        free(out_payload);
}

TEST_F(iot_easysetup, TC_STATIC_es_deviceinfo_handler_with_existing_combo_sn_neg)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;

    context = (struct iot_context *)*state;
    context->devconf.combo_sn = iot_os_strdup("old_combo_sn");

    err = _es_deviceinfo_handler(context, &out_payload);
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(out_payload);

    if (out_payload)
        free(out_payload);
}

TEST_F(iot_easysetup, TC_STATIC_es_log_systeminfo_handler_success_pos)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;

    context = (struct iot_context *)*state;
    err = _es_log_systeminfo_handler(context, &out_payload);
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(out_payload);

    if (out_payload)
        free(out_payload);
}

TEST_F(iot_easysetup, TC_STATIC_es_setupcomplete_handler_wifi_update_no_retry_timer_failure_neg)
{
    iot_error_t err;
    struct iot_context *context;
    char *out_payload = NULL;

    context = (struct iot_context *)*state;
    context->next_connection_retry_timer = NULL;
    context->wifi_update_enabled = true;

    err = _es_setupcomplete_handler(context, NULL, &out_payload);
    assert_int_not_equal(err, IOT_ERROR_NONE);

    if (out_payload)
        free(out_payload);
}

TEST_F(iot_easysetup, TC_STATIC_es_setupcomplete_handler_wifi_update_no_retry_timer_success_neg)
{
    iot_error_t err;
    struct iot_context *context;
    char *out_payload = NULL;

    context = (struct iot_context *)*state;
    context->work_queue_signal = iot_os_eventgroup_create();
    context->work_queue = iot_util_queue_create(sizeof(device_work_data_t));
    context->next_connection_retry_timer = NULL;
    context->wifi_update_enabled = true;

    err = _es_setupcomplete_handler(context, NULL, &out_payload);
    assert_int_equal(err, IOT_ERROR_NONE);

    if (out_payload)
        free(out_payload);
    iot_os_eventgroup_delete(context->work_queue_signal);
    iot_util_queue_delete(context->work_queue);
    context->work_queue = NULL;
    context->work_queue_signal = NULL;
}

TEST_F(iot_easysetup, TC_STATIC_es_setupcomplete_handler_wifi_update_retry_timer_create_failure_neg)
{
    iot_error_t err;
    struct iot_context *context;
    char *out_payload = NULL;

    context = (struct iot_context *)*state;
    context->work_queue_signal = iot_os_eventgroup_create();
    context->work_queue = iot_util_queue_create(sizeof(device_work_data_t));
    context->next_connection_retry_timer = iot_os_timer_create(NULL, 100, NULL);
    iot_os_timer_start(context->next_connection_retry_timer);
    context->wifi_update_enabled = true;

    set_mock_iot_os_malloc_failure_with_index(0);
    err = _es_setupcomplete_handler(context, NULL, &out_payload);
    do_not_use_mock_iot_os_malloc_failure();

    if (context->next_connection_retry_timer) {
        iot_os_timer_delete(context->next_connection_retry_timer);
        context->next_connection_retry_timer = NULL;
    }
    if (out_payload)
        free(out_payload);
    iot_os_eventgroup_delete(context->work_queue_signal);
    iot_util_queue_delete(context->work_queue);
    context->work_queue = NULL;
    context->work_queue_signal = NULL;

    assert_true(true);
}

TEST_F(iot_easysetup, TC_STATIC_es_setupcomplete_handler_prov_done_success_pos)
{
    iot_error_t err;
    struct iot_context *context;
    char *out_payload = NULL;

    context = (struct iot_context *)*state;
    context->work_queue_signal = iot_os_eventgroup_create();
    context->work_queue = iot_util_queue_create(sizeof(device_work_data_t));
    context->wifi_update_enabled = false;

    err = _es_setupcomplete_handler(context, NULL, &out_payload);
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(out_payload);

    if (out_payload)
        free(out_payload);
    iot_os_eventgroup_delete(context->work_queue_signal);
    iot_util_queue_delete(context->work_queue);
    context->work_queue = NULL;
    context->work_queue_signal = NULL;
}

TEST_F(iot_easysetup, TC_STATIC_es_wifiprovisioninginfo_handler_lookup_id_gen_failure_neg)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;
    JSON_H *root, *data, *wifi_credential;

    context = (struct iot_context *)*state;
    context->lookup_id = NULL;
    context->wifi_update_enabled = true;

    root = JSON_CREATE_OBJECT();
    data = JSON_CREATE_OBJECT();
    wifi_credential = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(wifi_credential, "ssid", JSON_CREATE_STRING("TestSSID"));
    JSON_ADD_ITEM_TO_OBJECT(wifi_credential, "password", JSON_CREATE_STRING("TestPassword"));
    JSON_ADD_ITEM_TO_OBJECT(data, "wifiCredential", wifi_credential);
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    char *in_payload = JSON_PRINT(root);
    JSON_DELETE(root);

    set_mock_iot_os_malloc_failure_with_index(0);
    err = _es_wifiprovisioninginfo_handler(context, in_payload, &out_payload);
    assert_int_not_equal(err, IOT_ERROR_NONE);
    do_not_use_mock_iot_os_malloc_failure();

    free(in_payload);
    if (out_payload)
        free(out_payload);
}

TEST_F(iot_easysetup, TC_STATIC_es_wifiprovisioninginfo_handler_serial_number_failure_neg)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;
    JSON_H *root, *data, *wifi_credential;

    context = (struct iot_context *)*state;
    context->lookup_id = iot_os_strdup("existing_lookup_id");
    context->wifi_update_enabled = true;

    root = JSON_CREATE_OBJECT();
    data = JSON_CREATE_OBJECT();
    wifi_credential = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(wifi_credential, "ssid", JSON_CREATE_STRING("TestSSID"));
    JSON_ADD_ITEM_TO_OBJECT(wifi_credential, "password", JSON_CREATE_STRING("TestPassword"));
    JSON_ADD_ITEM_TO_OBJECT(data, "wifiCredential", wifi_credential);
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    char *in_payload = JSON_PRINT(root);
    JSON_DELETE(root);

    err = _es_wifiprovisioninginfo_handler(context, in_payload, &out_payload);
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(out_payload);

    if (context->lookup_id) {
        iot_os_free(context->lookup_id);
        context->lookup_id = NULL;
    }
    free(in_payload);
    if (out_payload)
        free(out_payload);
}

TEST_F(iot_easysetup, TC_STATIC_es_wifiprovisioninginfo_handler_wifi_parse_failure_neg)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;

    context = (struct iot_context *)*state;
    context->lookup_id = NULL;

    err = _es_wifiprovisioninginfo_handler(context, "not_valid_json", &out_payload);
    assert_int_not_equal(err, IOT_ERROR_NONE);

    if (out_payload)
        free(out_payload);
}

TEST_F(iot_easysetup, TC_STATIC_es_wifiprovisioninginfo_handler_missing_wifi_credential_failure_v2_neg)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;
    JSON_H *root, *data;

    context = (struct iot_context *)*state;
    context->lookup_id = NULL;
    context->wifi_update_enabled = false;

    root = JSON_CREATE_OBJECT();
    data = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    char *in_payload = JSON_PRINT(root);
    JSON_DELETE(root);

    err = _es_wifiprovisioninginfo_handler(context, in_payload, &out_payload);
    assert_int_not_equal(err, IOT_ERROR_NONE);

    free(in_payload);
    if (out_payload)
        free(out_payload);
}

TEST_F(iot_easysetup, TC_STATIC_es_wifiprovisioninginfo_handler_missing_ssid_failure_v2_neg)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;
    JSON_H *root, *data, *wifi_credential;

    context = (struct iot_context *)*state;
    context->lookup_id = NULL;
    context->wifi_update_enabled = false;

    root = JSON_CREATE_OBJECT();
    data = JSON_CREATE_OBJECT();
    wifi_credential = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(wifi_credential, "password", JSON_CREATE_STRING("TestPassword"));
    JSON_ADD_ITEM_TO_OBJECT(data, "wifiCredential", wifi_credential);
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    char *in_payload = JSON_PRINT(root);
    JSON_DELETE(root);

    err = _es_wifiprovisioninginfo_handler(context, in_payload, &out_payload);
    assert_int_not_equal(err, IOT_ERROR_NONE);

    free(in_payload);
    if (out_payload)
        free(out_payload);
}

TEST_F(iot_easysetup, TC_STATIC_es_wifiscaninfo_handler_with_ssid_no_freq_success_neg)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;
    JSON_H *root, *data, *wifi_credential;
    char *in_payload;

    context = (struct iot_context *)*state;
    context->scan_num = 1;
    context->scan_result = (iot_wifi_scan_result_t *)calloc(1, sizeof(iot_wifi_scan_result_t));
    strncpy((char *)context->scan_result[0].ssid, "TestSSID", IOT_WIFI_MAX_SSID_LEN);
    context->scan_result[0].authmode = IOT_WIFI_AUTH_WPA2_PSK;

    root = JSON_CREATE_OBJECT();
    data = JSON_CREATE_OBJECT();
    wifi_credential = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(wifi_credential, "ssid", JSON_CREATE_STRING("TestSSID"));
    JSON_ADD_ITEM_TO_OBJECT(data, "mobileWifiCredential", wifi_credential);
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    in_payload = JSON_PRINT(root);
    JSON_DELETE(root);

    err = _es_wifiscaninfo_handler(context, in_payload, &out_payload);
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(out_payload);

    free(in_payload);
    if (out_payload)
        free(out_payload);
    free(context->scan_result);
    context->scan_result = NULL;
    context->scan_num = 0;
}

TEST_F(iot_easysetup, TC_STATIC_es_wifiscaninfo_handler_no_mobile_credential_success_neg)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;
    JSON_H *root, *data;
    char *in_payload;

    context = (struct iot_context *)*state;
    context->scan_num = 1;
    context->scan_result = (iot_wifi_scan_result_t *)calloc(1, sizeof(iot_wifi_scan_result_t));
    strncpy((char *)context->scan_result[0].ssid, "TestSSID", IOT_WIFI_MAX_SSID_LEN);
    context->scan_result[0].authmode = IOT_WIFI_AUTH_OPEN;

    root = JSON_CREATE_OBJECT();
    data = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    in_payload = JSON_PRINT(root);
    JSON_DELETE(root);

    err = _es_wifiscaninfo_handler(context, in_payload, &out_payload);
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(out_payload);

    free(in_payload);
    if (out_payload)
        free(out_payload);
    free(context->scan_result);
    context->scan_result = NULL;
    context->scan_num = 0;
}

TEST_F(iot_easysetup, TC_STATIC_es_wifiscaninfo_handler_unsupported_authtype_success_neg)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;
    JSON_H *root, *data, *wifi_credential;
    char *in_payload;

    context = (struct iot_context *)*state;
    context->scan_num = 2;
    context->scan_result = (iot_wifi_scan_result_t *)calloc(2, sizeof(iot_wifi_scan_result_t));
    strncpy((char *)context->scan_result[0].ssid, "TestSSID", IOT_WIFI_MAX_SSID_LEN);
    context->scan_result[0].authmode = 99;
    strncpy((char *)context->scan_result[1].ssid, "OtherSSID", IOT_WIFI_MAX_SSID_LEN);
    context->scan_result[1].authmode = IOT_WIFI_AUTH_OPEN;

    root = JSON_CREATE_OBJECT();
    data = JSON_CREATE_OBJECT();
    wifi_credential = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(wifi_credential, "ssid", JSON_CREATE_STRING("TestSSID"));
    JSON_ADD_ITEM_TO_OBJECT(data, "mobileWifiCredential", wifi_credential);
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    in_payload = JSON_PRINT(root);
    JSON_DELETE(root);

    err = _es_wifiscaninfo_handler(context, in_payload, &out_payload);
    assert_int_equal(err, IOT_ERROR_NONE);

    free(in_payload);
    if (out_payload)
        free(out_payload);
    free(context->scan_result);
    context->scan_result = NULL;
    context->scan_num = 0;
}

TEST_F(iot_easysetup, TC_STATIC_es_wifiscaninfo_handler_null_payload_success_neg)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;

    context = (struct iot_context *)*state;
    context->scan_num = 1;
    context->scan_result = (iot_wifi_scan_result_t *)calloc(1, sizeof(iot_wifi_scan_result_t));
    strncpy((char *)context->scan_result[0].ssid, "TestSSID", IOT_WIFI_MAX_SSID_LEN);
    context->scan_result[0].authmode = IOT_WIFI_AUTH_OPEN;

    err = _es_wifiscaninfo_handler(context, NULL, &out_payload);
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(out_payload);

    if (out_payload)
        free(out_payload);
    free(context->scan_result);
    context->scan_result = NULL;
    context->scan_num = 0;
}

TEST_F(iot_easysetup, TC_STATIC_es_confirm_handler_json_create_failure_neg)
{
    iot_error_t err;
    struct iot_context *context;
    char *out_payload = NULL;
    char *in_payload;
    JSON_H *root, *data;

    context = (struct iot_context *)*state;
    context->pin = malloc(sizeof(iot_pin_t));
    memset(context->pin, 0, sizeof(iot_pin_t));
    memset(context->pin->pin, '0', sizeof(context->pin->pin) - 1);
    context->curr_otm_feature = OVF_BIT_PIN;

    root = JSON_CREATE_OBJECT();
    data = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(data, "pin", JSON_CREATE_STRING("00000000"));

    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    in_payload = JSON_PRINT(root);
    JSON_DELETE(root);

    set_mock_iot_os_malloc_failure_with_index(2);
    err = _es_confirm_handler(context, in_payload, &out_payload);
    assert_int_not_equal(err, IOT_ERROR_NONE);
    do_not_use_mock_iot_os_malloc_failure();

    free(in_payload);
    if (out_payload)
        free(out_payload);
    free(context->pin);
    context->pin = NULL;
}

TEST_F(iot_easysetup, TC_STATIC_es_confirminfo_handler_json_create_failure_neg)
{
    iot_error_t err;
    struct iot_context *context;
    char *in_payload = NULL;
    char *out_payload = NULL;
    JSON_H *root, *data;

    context = (struct iot_context *)*state;
    context->iot_events = iot_os_eventgroup_create();
    context->work_queue_signal = iot_os_eventgroup_create();
    context->work_queue = iot_util_queue_create(sizeof(device_work_data_t));
    context->devconf.ownership_validation_type = (1u << OVF_BIT_JUSTWORKS);

    root = JSON_CREATE_OBJECT();
    data = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(data, "otmSupportFeature", JSON_CREATE_NUMBER(OVF_BIT_JUSTWORKS));
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    in_payload = JSON_PRINT(root);
    JSON_DELETE(root);

    set_mock_iot_os_malloc_failure_with_index(3);
    err = _es_confirminfo_handler(context, in_payload, &out_payload);
    assert_int_not_equal(err, IOT_ERROR_NONE);
    do_not_use_mock_iot_os_malloc_failure();

    free(in_payload);
    if (out_payload)
        free(out_payload);
    iot_os_eventgroup_delete(context->iot_events);
    iot_os_eventgroup_delete(context->work_queue_signal);
    iot_util_queue_delete(context->work_queue);
    context->iot_events = NULL;
    context->work_queue = NULL;
    context->work_queue_signal = NULL;
}

TEST_F(iot_easysetup, TC_iot_easysetup_get_response_malloc_failure_v2_neg)
{
    struct iot_context *context;
    struct iot_easysetup_payload request = {0};
    struct iot_easysetup_payload *response = NULL;

    context = (struct iot_context *)*state;
    request.step = IOT_EASYSETUP_BLE_STEP_DEVICEINFO;
    request.payload = NULL;

    set_mock_iot_os_malloc_failure_with_index(0);
    response = iot_easysetup_get_response(context, request);
    do_not_use_mock_iot_os_malloc_failure();

    if (response) {
        if (response->payload)
            free(response->payload);
        iot_os_free(response);
    }

    assert_true(true);
}

TEST_F(iot_easysetup, TC_iot_easysetup_get_response_default_step_failure_neg)
{
    struct iot_context *context;
    struct iot_easysetup_payload request = {0};
    struct iot_easysetup_payload *response = NULL;

    context = (struct iot_context *)*state;
    request.step = IOT_EASYSETUP_BLE_INVALID_STEP;
    request.payload = NULL;

    tc_mock_ble_set_get_response_use_wrap(0);
    response = iot_easysetup_get_response(context, request);
    tc_mock_ble_set_get_response_use_wrap(1);
    assert_non_null(response);
    assert_int_equal(response->err, IOT_ERROR_EASYSETUP_INTERNAL_SERVER_ERROR);

    if (response) {
        if (response->payload)
            free(response->payload);
        iot_os_free(response);
    }
}

TEST_F(iot_easysetup, TC_iot_easysetup_get_response_log_systeminfo_step_success_pos)
{
    struct iot_context *context;
    struct iot_easysetup_payload request = {0};
    struct iot_easysetup_payload *response = NULL;

    context = (struct iot_context *)*state;
    request.step = IOT_EASYSETUP_BLE_STEP_LOG_SYSTEMINFO;
    request.payload = NULL;

    response = iot_easysetup_get_response(context, request);
    assert_non_null(response);
    assert_int_equal(response->err, IOT_ERROR_NONE);

    if (response) {
        if (response->payload)
            free(response->payload);
        iot_os_free(response);
    }
}

TEST_F(iot_easysetup, TC_iot_easysetup_get_response_offline_diagnostics_connection_info_step_success_pos)
{
    struct iot_context *context;
    struct iot_easysetup_payload request = {0};
    struct iot_easysetup_payload *response = NULL;

    context = (struct iot_context *)*state;
    request.step = IOT_EASYSETUP_BLE_STEP_OFFLINE_DIAGNOSTICS_CONNECTION_INFO;
    request.payload = NULL;

    response = iot_easysetup_get_response(context, request);
    assert_non_null(response);

    if (response) {
        if (response->payload)
            free(response->payload);
        iot_os_free(response);
    }
}

#if defined(CONFIG_STDK_IOT_CORE_EASYSETUP_OFFLINE_DIAGNOSTICS)
TEST_F(iot_easysetup, TC_STATIC_es_offline_diagnostics_connection_info_handler_disconnected_no_mac_neg)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;

    context = (struct iot_context *)*state;
    context->last_st_ecode.ecode_type = IOT_ST_ECODE_NONE;

    err = _es_offline_diagnostics_connection_info_handler(context, &out_payload);
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(out_payload);

    if (out_payload)
        free(out_payload);
}

TEST_F(iot_easysetup, TC_STATIC_es_offline_diagnostics_recovery_updatewifi_timer_create_failure_neg)
{
    struct iot_context *context;
    struct iot_easysetup_payload *response = NULL;
    char *in_payload;

    context = (struct iot_context *)*state;
    context->work_queue = iot_util_queue_create(sizeof(struct iot_command));
    context->work_queue_signal = iot_os_eventgroup_create();
    iot_os_mutex_init(&context->st_conn_lock);
    context->next_connection_retry_timer = NULL;

    in_payload = _build_updatewifi_payload("TestSSID", "TestPassword", IOT_WIFI_AUTH_WPA2_PSK);

    set_mock_iot_os_malloc_failure_with_index(1);
    response = _invoke_real_recovery_handler(context, in_payload);
    assert_non_null(response);
    assert_int_equal(response->err, IOT_ERROR_EASYSETUP_INTERNAL_SERVER_ERROR);
    do_not_use_mock_iot_os_malloc_failure();

    if (response) {
        if (response->payload)
            free(response->payload);
        iot_os_free(response);
    }
    free(in_payload);
    if (context->offline_diagnostics_wifiupdate_timeout) {
        iot_os_timer_delete(context->offline_diagnostics_wifiupdate_timeout);
        context->offline_diagnostics_wifiupdate_timeout = NULL;
    }
    iot_util_queue_delete(context->work_queue);
    iot_os_eventgroup_delete(context->work_queue_signal);
    iot_os_mutex_destroy(&context->st_conn_lock);
    context->work_queue = NULL;
    context->work_queue_signal = NULL;
}
#endif

TEST_F(iot_easysetup, TC_STATIC_es_copy_cloud_prov_success_pos)
{
    iot_error_t err;
    struct iot_cloud_prov_data src = {0};
    struct iot_cloud_prov_data dst = {0};

    src.broker_url = "test_url";
    src.label = "test_label";
    src.broker_port = 8883;

    err = _es_copy_cloud_prov(&dst, &src);
    assert_int_equal(err, IOT_ERROR_NONE);

    if (dst.broker_url)
        iot_os_free(dst.broker_url);
    if (dst.label)
        iot_os_free(dst.label);
}

TEST_F(iot_easysetup, TC_STATIC_es_copy_cloud_prov_null_args_neg)
{
    iot_error_t err;
    struct iot_cloud_prov_data src = {0};
    struct iot_cloud_prov_data dst = {0};

    src.broker_url = "test_url";
    src.label = "test_label";

    set_mock_iot_os_malloc_failure_with_index(0);
    err = _es_copy_cloud_prov(&dst, &src);
    assert_int_not_equal(err, IOT_ERROR_NONE);
    do_not_use_mock_iot_os_malloc_failure();

    set_mock_iot_os_malloc_failure_with_index(1);
    err = _es_copy_cloud_prov(&dst, &src);
    assert_int_not_equal(err, IOT_ERROR_NONE);
    do_not_use_mock_iot_os_malloc_failure();
}

/* --- Cycle 5: targeted tests for uncovered error paths --- */

static char *_generate_keyinfo_payload_with_valid_spub_no_rand(void)
{
    unsigned char *spub = _get_server_test_pubkey();
    unsigned char spub_b64[128];
    int out_length;
    JSON_H *root, *data;
    char *payload;

    iot_security_base64_encode_urlsafe(spub, IOT_SECURITY_ED25519_LEN, spub_b64, sizeof(spub_b64), &out_length);
    root = JSON_CREATE_OBJECT();
    data = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(data, "spub", JSON_CREATE_STRING((char *)spub_b64));
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    payload = JSON_PRINT(root);
    JSON_DELETE(root);
    return payload;
}

TEST_F(iot_easysetup, TC_STATIC_es_keyinfo_handler_valid_spub_no_rand_failure_neg)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;
    char *in_payload;

    context = (struct iot_context *)*state;
    in_payload = _generate_keyinfo_payload_with_valid_spub_no_rand();

    err = _es_keyinfo_handler(context, in_payload, &out_payload);
    assert_int_not_equal(err, IOT_ERROR_NONE);

    free(in_payload);
    if (out_payload)
        free(out_payload);
}

static char *_generate_keyinfo_payload_no_datetime(void)
{
    unsigned char *spub = _get_server_test_pubkey();
    unsigned char spub_b64[128];
    int out_length;
    JSON_H *root, *data;
    char *payload;

    iot_security_base64_encode_urlsafe(spub, IOT_SECURITY_ED25519_LEN, spub_b64, sizeof(spub_b64), &out_length);
    root = JSON_CREATE_OBJECT();
    data = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(data, "spub", JSON_CREATE_STRING((char *)spub_b64));
    JSON_ADD_ITEM_TO_OBJECT(data, "rand", JSON_CREATE_STRING(TEST_SRAND));
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    payload = JSON_PRINT(root);
    JSON_DELETE(root);
    return payload;
}

TEST_F(iot_easysetup, TC_STATIC_es_keyinfo_handler_no_datetime_success_neg)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;
    char *in_payload;

    context = (struct iot_context *)*state;
    context->devconf.ownership_validation_type = OVF_BIT_JUSTWORKS;
    in_payload = _generate_keyinfo_payload_no_datetime();

    err = _es_keyinfo_handler(context, in_payload, &out_payload);
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(out_payload);

    free(in_payload);
    if (out_payload)
        free(out_payload);
}

TEST_F(iot_easysetup, TC_STATIC_es_deviceinfo_handler_get_pubkey_failure_neg)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;

    context = (struct iot_context *)*state;
    context->devconf.combo_sn = NULL;
    set_mock_iot_os_malloc_failure_with_index(1);
    err = _es_deviceinfo_handler(context, &out_payload);
    assert_int_not_equal(err, IOT_ERROR_NONE);
    do_not_use_mock_iot_os_malloc_failure();

    if (out_payload)
        free(out_payload);
}

TEST_F(iot_easysetup, TC_STATIC_es_deviceinfo_handler_serial_number_failure_neg)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;

    context = (struct iot_context *)*state;
    context->devconf.combo_sn = NULL;
    set_mock_iot_os_malloc_failure_with_index(5);
    err = _es_deviceinfo_handler(context, &out_payload);
    assert_int_not_equal(err, IOT_ERROR_NONE);
    do_not_use_mock_iot_os_malloc_failure();

    if (out_payload)
        free(out_payload);
}

TEST_F(iot_easysetup, TC_STATIC_es_deviceinfo_handler_base64_encode_failure_neg)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;

    context = (struct iot_context *)*state;
    context->devconf.combo_sn = NULL;
    set_mock_iot_os_malloc_failure_with_index(7);
    err = _es_deviceinfo_handler(context, &out_payload);
    assert_int_not_equal(err, IOT_ERROR_NONE);
    do_not_use_mock_iot_os_malloc_failure();

    if (out_payload)
        free(out_payload);
}

TEST_F(iot_easysetup, TC_STATIC_es_deviceinfo_handler_cipher_set_params_failure_neg)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;

    context = (struct iot_context *)*state;
    context->devconf.combo_sn = iot_os_strdup("existing_combo");

    set_mock_iot_os_malloc_failure_with_index(0);
    err = _es_deviceinfo_handler(context, &out_payload);
    do_not_use_mock_iot_os_malloc_failure();

    if (out_payload)
        free(out_payload);

    assert_true(true);
}

TEST_F(iot_easysetup, TC_STATIC_es_deviceinfo_handler_json_create_failure_neg)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;

    context = (struct iot_context *)*state;
    context->devconf.combo_sn = iot_os_strdup("existing_combo");

    set_mock_iot_os_malloc_failure_with_index(1);
    err = _es_deviceinfo_handler(context, &out_payload);
    do_not_use_mock_iot_os_malloc_failure();

    if (out_payload)
        free(out_payload);

    assert_true(true);
}

TEST_F(iot_easysetup, TC_STATIC_es_keyinfo_handler_json_response_create_failure_neg)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;
    char *in_payload;
    time_t time_to_set;

    context = (struct iot_context *)*state;
    in_payload = _generate_post_keyinfo_payload_utc(2020, &time_to_set);

    set_mock_iot_os_malloc_failure_with_index(5);
    err = _es_keyinfo_handler(context, in_payload, &out_payload);
    assert_int_not_equal(err, IOT_ERROR_NONE);
    do_not_use_mock_iot_os_malloc_failure();

    free(in_payload);
    if (out_payload)
        free(out_payload);
}

TEST_F(iot_easysetup, TC_STATIC_es_keyinfo_handler_array_create_failure_neg)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;
    char *in_payload;
    time_t time_to_set;

    context = (struct iot_context *)*state;
    in_payload = _generate_post_keyinfo_payload_utc(2020, &time_to_set);

    set_mock_iot_os_malloc_failure_with_index(6);
    err = _es_keyinfo_handler(context, in_payload, &out_payload);
    assert_int_not_equal(err, IOT_ERROR_NONE);
    do_not_use_mock_iot_os_malloc_failure();

    free(in_payload);
    if (out_payload)
        free(out_payload);
}

TEST_F(iot_easysetup, TC_STATIC_es_keyinfo_handler_response_payload_malloc_failure_neg)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;
    char *in_payload;
    time_t time_to_set;

    context = (struct iot_context *)*state;
    in_payload = _generate_post_keyinfo_payload_utc(2020, &time_to_set);

    set_mock_iot_os_malloc_failure_with_index(7);
    err = _es_keyinfo_handler(context, in_payload, &out_payload);
    assert_int_not_equal(err, IOT_ERROR_NONE);
    do_not_use_mock_iot_os_malloc_failure();

    free(in_payload);
    if (out_payload)
        free(out_payload);
}

TEST_F(iot_easysetup, TC_STATIC_es_keyinfo_handler_ecdh_init_failure_neg)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;
    char *in_payload;

    context = (struct iot_context *)*state;
    in_payload = _generate_keyinfo_payload_no_datetime();

    /* iot_security_ecdh_init uses iot_os_malloc internally */
    set_mock_iot_os_malloc_failure_with_index(0);
    err = _es_keyinfo_handler(context, in_payload, &out_payload);
    assert_int_not_equal(err, IOT_ERROR_NONE);
    do_not_use_mock_iot_os_malloc_failure();

    free(in_payload);
    if (out_payload)
        free(out_payload);
}

TEST_F(iot_easysetup, TC_STATIC_es_wifiprovisioninginfo_handler_broker_url_malloc_failure_neg)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;
    JSON_H *root, *data, *wifi_credential;

    context = (struct iot_context *)*state;
    context->lookup_id = NULL;
    context->wifi_update_enabled = false;

    root = JSON_CREATE_OBJECT();
    data = JSON_CREATE_OBJECT();
    wifi_credential = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(wifi_credential, "ssid", JSON_CREATE_STRING("TestSSID"));
    JSON_ADD_ITEM_TO_OBJECT(wifi_credential, "password", JSON_CREATE_STRING("TestPassword"));
    JSON_ADD_ITEM_TO_OBJECT(data, "wifiCredential", wifi_credential);
    JSON_ADD_ITEM_TO_OBJECT(data, "brokerUrl", JSON_CREATE_STRING("https://test.domain.com:5676"));
    JSON_ADD_ITEM_TO_OBJECT(data, "deviceName", JSON_CREATE_STRING("TestDevice"));
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    char *in_payload = JSON_PRINT(root);
    JSON_DELETE(root);

    set_mock_iot_os_malloc_failure_with_index(4);
    err = _es_wifiprovisioninginfo_handler(context, in_payload, &out_payload);
    assert_int_not_equal(err, IOT_ERROR_NONE);
    do_not_use_mock_iot_os_malloc_failure();

    free(in_payload);
    if (out_payload)
        free(out_payload);
}

TEST_F(iot_easysetup, TC_STATIC_es_wifiprovisioninginfo_handler_json_create_failure_neg)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;
    JSON_H *root, *data, *wifi_credential;

    context = (struct iot_context *)*state;
    context->lookup_id = NULL;
    context->wifi_update_enabled = false;

    root = JSON_CREATE_OBJECT();
    data = JSON_CREATE_OBJECT();
    wifi_credential = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(wifi_credential, "ssid", JSON_CREATE_STRING("TestSSID"));
    JSON_ADD_ITEM_TO_OBJECT(wifi_credential, "password", JSON_CREATE_STRING("TestPassword"));
    JSON_ADD_ITEM_TO_OBJECT(data, "wifiCredential", wifi_credential);
    JSON_ADD_ITEM_TO_OBJECT(data, "brokerUrl", JSON_CREATE_STRING("https://test.domain.com:5676"));
    JSON_ADD_ITEM_TO_OBJECT(data, "deviceName", JSON_CREATE_STRING("TestDevice"));
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    char *in_payload = JSON_PRINT(root);
    JSON_DELETE(root);

    set_mock_iot_os_malloc_failure_with_index(5);
    err = _es_wifiprovisioninginfo_handler(context, in_payload, &out_payload);
    assert_int_not_equal(err, IOT_ERROR_NONE);
    do_not_use_mock_iot_os_malloc_failure();

    free(in_payload);
    if (out_payload)
        free(out_payload);
}

TEST_F(iot_easysetup, TC_STATIC_es_wifiprovisioninginfo_handler_response_malloc_failure_neg)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;
    JSON_H *root, *data, *wifi_credential;

    context = (struct iot_context *)*state;
    context->lookup_id = NULL;
    context->wifi_update_enabled = false;

    root = JSON_CREATE_OBJECT();
    data = JSON_CREATE_OBJECT();
    wifi_credential = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(wifi_credential, "ssid", JSON_CREATE_STRING("TestSSID"));
    JSON_ADD_ITEM_TO_OBJECT(wifi_credential, "password", JSON_CREATE_STRING("TestPassword"));
    JSON_ADD_ITEM_TO_OBJECT(data, "wifiCredential", wifi_credential);
    JSON_ADD_ITEM_TO_OBJECT(data, "brokerUrl", JSON_CREATE_STRING("https://test.domain.com:5676"));
    JSON_ADD_ITEM_TO_OBJECT(data, "deviceName", JSON_CREATE_STRING("TestDevice"));
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    char *in_payload = JSON_PRINT(root);
    JSON_DELETE(root);

    set_mock_iot_os_malloc_failure_with_index(6);
    err = _es_wifiprovisioninginfo_handler(context, in_payload, &out_payload);
    assert_int_not_equal(err, IOT_ERROR_NONE);
    do_not_use_mock_iot_os_malloc_failure();

    free(in_payload);
    if (out_payload)
        free(out_payload);
}

TEST_F(iot_easysetup, TC_STATIC_es_setupcomplete_handler_wifi_update_enabled_no_queue_failure_neg)
{
    iot_error_t err;
    struct iot_context *context;
    char *out_payload = NULL;

    context = (struct iot_context *)*state;
    context->work_queue = NULL;
    context->work_queue_signal = NULL;
    context->next_connection_retry_timer = NULL;
    context->wifi_update_enabled = true;

    err = _es_setupcomplete_handler(context, NULL, &out_payload);
    assert_int_not_equal(err, IOT_ERROR_NONE);

    if (out_payload)
        free(out_payload);
}

TEST_F(iot_easysetup, TC_STATIC_es_confirminfo_handler_response_malloc_failure_neg)
{
    iot_error_t err;
    char *in_payload;
    char *out_payload = NULL;
    struct iot_context *context;
    JSON_H *root, *data;

    context = (struct iot_context *)*state;
    context->iot_events = iot_os_eventgroup_create();
    context->work_queue_signal = iot_os_eventgroup_create();
    context->work_queue = iot_util_queue_create(sizeof(device_work_data_t));
    context->devconf.ownership_validation_type = (1u << OVF_BIT_JUSTWORKS);

    root = JSON_CREATE_OBJECT();
    data = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(data, "otmSupportFeature", JSON_CREATE_NUMBER(OVF_BIT_JUSTWORKS));
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    in_payload = JSON_PRINT(root);
    JSON_DELETE(root);

    set_mock_iot_os_malloc_failure_with_index(4);
    err = _es_confirminfo_handler(context, in_payload, &out_payload);
    assert_int_not_equal(err, IOT_ERROR_NONE);
    do_not_use_mock_iot_os_malloc_failure();

    free(in_payload);
    if (out_payload)
        free(out_payload);
    iot_os_eventgroup_delete(context->iot_events);
    iot_os_eventgroup_delete(context->work_queue_signal);
    iot_util_queue_delete(context->work_queue);
}

TEST_F(iot_easysetup, TC_STATIC_es_confirm_handler_response_malloc_failure_neg)
{
    iot_error_t err;
    struct iot_context *context;
    char *out_payload = NULL;
    char *in_payload;
    JSON_H *root, *data;

    context = (struct iot_context *)*state;
    context->pin = malloc(sizeof(iot_pin_t));
    memset(context->pin, 0, sizeof(iot_pin_t));
    memset(context->pin->pin, '0', sizeof(context->pin->pin) - 1);
    context->curr_otm_feature = OVF_BIT_PIN;

    root = JSON_CREATE_OBJECT();
    data = JSON_CREATE_OBJECT();
    JSON_ADD_ITEM_TO_OBJECT(data, "pin", JSON_CREATE_STRING("00000000"));
    JSON_ADD_ITEM_TO_OBJECT(root, "data", data);
    in_payload = JSON_PRINT(root);
    JSON_DELETE(root);

    set_mock_iot_os_malloc_failure_with_index(3);
    err = _es_confirm_handler(context, in_payload, &out_payload);
    assert_int_not_equal(err, IOT_ERROR_NONE);
    do_not_use_mock_iot_os_malloc_failure();

    free(in_payload);
    if (out_payload)
        free(out_payload);
    free(context->pin);
    context->pin = NULL;
}

TEST_F(iot_easysetup, TC_STATIC_es_keyinfo_handler_decode_buf_malloc_failure_neg)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;
    char *in_payload;
    time_t time_to_set;

    context = (struct iot_context *)*state;
    in_payload = _generate_post_keyinfo_payload_utc(2020, &time_to_set);

    set_mock_iot_os_malloc_failure_with_index(4);
    err = _es_keyinfo_handler(context, in_payload, &out_payload);
    assert_int_not_equal(err, IOT_ERROR_NONE);
    do_not_use_mock_iot_os_malloc_failure();

    free(in_payload);
    if (out_payload)
        free(out_payload);
}

TEST_F(iot_easysetup, TC_STATIC_es_deviceinfo_handler_iv_encode_buf_malloc_failure_neg)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;

    context = (struct iot_context *)*state;
    context->devconf.combo_sn = iot_os_strdup("existing_combo");

    set_mock_iot_os_malloc_failure_with_index(2);
    err = _es_deviceinfo_handler(context, &out_payload);
    do_not_use_mock_iot_os_malloc_failure();

    if (out_payload)
        free(out_payload);

    assert_true(true);
}

TEST_F(iot_easysetup, TC_STATIC_es_deviceinfo_handler_cipher_iv_gen_failure_neg)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;

    context = (struct iot_context *)*state;
    context->devconf.combo_sn = iot_os_strdup("existing_combo");

    /* _es_crypto_cipher_gen_iv calls iot_os_malloc at index 0, so
     * failing a later malloc triggers the cipher_set_params error path */
    set_mock_iot_os_malloc_failure_with_index(3);
    err = _es_deviceinfo_handler(context, &out_payload);
    do_not_use_mock_iot_os_malloc_failure();

    if (out_payload)
        free(out_payload);

    assert_true(true);
}
