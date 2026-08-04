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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "TC_MOCK_functions.h"
#include "TC_MOCK_iot_bsp_ble.h"
#include "cmocka_custom.h"
#include "easysetup_ble.h"
#include "iot_bsp_ble.h"
#include "iot_easysetup.h"
#include "iot_error.h"
#include "iot_main.h"
#include "iot_util.h"
#include "security/iot_security_common.h"
#include "security/iot_security_crypto.h"

#define UNUSED(x) (void)(x)

extern struct iot_context *context;
extern int ref_step;

iot_error_t iot_easysetup_init(struct iot_context *ctx);
void iot_easysetup_deinit(struct iot_context *ctx);
iot_error_t iot_easysetup_ble_send_response(int cmd, char *payload, size_t payload_len);
void iot_easysetup_ble_msg_handler(int cmd, char *data_buf, size_t data_buf_len);
void _ble_deinit_request_handler(struct iot_context *ctx, device_work_param param);
void _send_ble_deinit_request(void);

iot_error_t _iot_easysetup_con_timer_init(struct iot_context *ctx);
void _iot_easysetup_ble_conn_cb(iot_ble_conn_evt_t evt);
iot_error_t _iot_easysetup_gen_payload(struct iot_context *ctx, int cmd, char *in_payload, char **out_payload,
                                       size_t *payload_len);
iot_error_t _iot_easysetup_ble_msg_decrypt(iot_security_context_t *security_context, int cmd,
                                           unsigned char *encrypt_msg, size_t encrypt_msg_len, char **out_msg);
iot_error_t _iot_easysetup_ble_msg_encrypt(struct iot_context *context, int cmd, unsigned char *payload,
                                           size_t payload_len, iot_security_buffer_t **encrypt_buf, int *buf_len);

static struct iot_context *_tc_make_context(void)
{
    struct iot_context *ctx = (struct iot_context *)calloc(1, sizeof(struct iot_context));
    assert_non_null(ctx);
    ctx->iot_events = iot_os_eventgroup_create();
    ctx->work_queue = iot_util_queue_create(sizeof(device_work_data_t));
    ctx->work_queue_signal = iot_os_eventgroup_create();
    ctx->easysetup_security_context = iot_security_init();
    ctx->otm_confirmed = false;
    return ctx;
}

static void _tc_free_context(struct iot_context *ctx)
{
    if (!ctx)
        return;
    if (ctx->easysetup_security_context) {
        iot_security_deinit(ctx->easysetup_security_context);
    }
    if (ctx->work_queue) {
        iot_util_queue_delete(ctx->work_queue);
    }
    if (ctx->work_queue_signal) {
        iot_os_eventgroup_delete(ctx->work_queue_signal);
    }
    if (ctx->iot_events) {
        iot_os_eventgroup_delete(ctx->iot_events);
    }
    if (ctx->cloud_con_timer) {
        iot_os_timer_stop(ctx->cloud_con_timer);
        iot_os_timer_delete(ctx->cloud_con_timer);
        ctx->cloud_con_timer = NULL;
    }
    if (ctx->offline_diagnostics_wifiupdate_timeout) {
        iot_os_timer_delete(ctx->offline_diagnostics_wifiupdate_timeout);
    }
    if (ctx->lookup_id) {
        free(ctx->lookup_id);
    }
    free(ctx);
}

int TC_iot_easysetup_ble_setup(void **state)
{
    tc_mock_ble_reset();
    tc_mock_ble_set_mtu(256);
    context = NULL;
    ref_step = 0;
    struct iot_context *ctx = _tc_make_context();
    *state = ctx;
    return 0;
}

int TC_iot_easysetup_ble_teardown(void **state)
{
    struct iot_context *ctx = (struct iot_context *)*state;
    context = NULL;
    _tc_free_context(ctx);
    *state = NULL;
    return 0;
}

void TC_iot_easysetup_ble_init_null_ctx(void **state)
{
    iot_error_t err;
    UNUSED(state);

    // Given: NULL context
    // When: iot_easysetup_init is called with NULL
    err = iot_easysetup_init(NULL);
    // Then: returns INVALID_ARGS
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);
}

void TC_iot_easysetup_ble_init_success(void **state)
{
    struct iot_context *ctx = (struct iot_context *)*state;
    iot_error_t err;

    // Given: context with es_ble_ready = false
    ctx->es_ble_ready = false;
    // When: iot_easysetup_init is called
    err = iot_easysetup_init(ctx);
    // Then: returns NONE, es_ble_ready is true, global context is set, ref_step is 0
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_true(ctx->es_ble_ready);
    assert_ptr_equal(context, ctx);
    assert_int_equal(ref_step, 0);
}

void TC_iot_easysetup_ble_init_already_ready(void **state)
{
    struct iot_context *ctx = (struct iot_context *)*state;
    iot_error_t err;

    // Given: context with es_ble_ready = true (already initialized)
    ctx->es_ble_ready = true;
    // When: iot_easysetup_init is called again
    err = iot_easysetup_init(ctx);
    // Then: returns NONE but start_adv is skipped
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_int_equal(tc_mock_ble_get_start_adv_call_count(), 0);
}

void TC_iot_easysetup_ble_deinit_null_ctx(void **state)
{
    UNUSED(state);

    // Given: NULL context
    // When: iot_easysetup_deinit is called with NULL
    iot_easysetup_deinit(NULL);
    // Then: must not crash
}

void TC_iot_easysetup_ble_deinit_not_ready(void **state)
{
    struct iot_context *ctx = (struct iot_context *)*state;

    // Given: context with es_ble_ready = false and wifi_update_enabled = true
    context = ctx;
    ctx->es_ble_ready = false;
    ctx->wifi_update_enabled = true;

    // When: iot_easysetup_deinit is called
    iot_easysetup_deinit(ctx);
    // Then: wifi_update_enabled is cleared
    assert_false(ctx->wifi_update_enabled);
}

void TC_iot_easysetup_ble_msg_handler_cmd_below_range(void **state)
{
    struct iot_context *ctx = (struct iot_context *)*state;

    // Given: context is set
    context = ctx;
    // When: msg_handler is called with cmd below valid range
    iot_easysetup_ble_msg_handler(-5, NULL, 0);
    // Then: err_report path is triggered without crash
}

void TC_iot_easysetup_ble_msg_handler_cmd_above_range(void **state)
{
    struct iot_context *ctx = (struct iot_context *)*state;

    // Given: context is set
    context = ctx;
    // When: msg_handler is called with cmd above valid range
    iot_easysetup_ble_msg_handler(IOT_EASYSETUP_BLE_INVALID_STEP + 3, NULL, 0);
    // Then: err_report path is triggered without crash
}

void TC_iot_easysetup_ble_msg_handler_setup_complete_response(void **state)
{
    struct iot_context *ctx = (struct iot_context *)*state;

    // Given: context with es_network_status = NONE
    context = ctx;
    ctx->es_network_status = IOT_ERROR_NONE;
    // When: msg_handler is called with SETUPCOMPLETE_RESPONSE
    iot_easysetup_ble_msg_handler(IOT_EASYSETUP_BLE_STEP_SETUPCOMPLETE_RESPONSE, NULL, 0);
    // Then: handles success status without crash
}

void TC_iot_easysetup_ble_msg_handler_setup_complete_response_mqtt_reject(void **state)
{
    struct iot_context *ctx = (struct iot_context *)*state;

    // Given: context with es_network_status = MQTT_REJECT_CONNECT
    context = ctx;
    ctx->es_network_status = IOT_ERROR_MQTT_REJECT_CONNECT;
    // When: msg_handler is called with SETUPCOMPLETE_RESPONSE
    iot_easysetup_ble_msg_handler(IOT_EASYSETUP_BLE_STEP_SETUPCOMPLETE_RESPONSE, NULL, 0);
    // Then: handles MQTT reject without crash
}

void TC_iot_easysetup_ble_msg_handler_setup_complete_response_auth_fail(void **state)
{
    struct iot_context *ctx = (struct iot_context *)*state;

    // Given: context with es_network_status = AUTH_FAIL
    context = ctx;
    ctx->es_network_status = IOT_ERROR_CONN_STA_AUTH_FAIL;
    // When: msg_handler is called with SETUPCOMPLETE_RESPONSE
    iot_easysetup_ble_msg_handler(IOT_EASYSETUP_BLE_STEP_SETUPCOMPLETE_RESPONSE, NULL, 0);
    // Then: handles auth failure without crash
}

void TC_iot_easysetup_ble_msg_handler_setup_complete_response_dhcp_fail(void **state)
{
    struct iot_context *ctx = (struct iot_context *)*state;

    // Given: context with es_network_status = DHCP_FAIL
    context = ctx;
    ctx->es_network_status = IOT_ERROR_CONN_STA_DHCP_FAIL;
    // When: msg_handler is called with SETUPCOMPLETE_RESPONSE
    iot_easysetup_ble_msg_handler(IOT_EASYSETUP_BLE_STEP_SETUPCOMPLETE_RESPONSE, NULL, 0);
    // Then: handles DHCP failure without crash
}

void TC_iot_easysetup_ble_msg_handler_setup_complete_response_dns_fail(void **state)
{
    struct iot_context *ctx = (struct iot_context *)*state;

    // Given: context with es_network_status = DNS_QUERY_FAIL
    context = ctx;
    ctx->es_network_status = IOT_ERROR_CONN_DNS_QUERY_FAIL;
    // When: msg_handler is called with SETUPCOMPLETE_RESPONSE
    iot_easysetup_ble_msg_handler(IOT_EASYSETUP_BLE_STEP_SETUPCOMPLETE_RESPONSE, NULL, 0);
    // Then: handles DNS failure without crash
}

void TC_iot_easysetup_ble_msg_handler_setup_complete_response_ap_not_found(void **state)
{
    struct iot_context *ctx = (struct iot_context *)*state;

    // Given: context with es_network_status = AP_NOT_FOUND
    context = ctx;
    ctx->es_network_status = IOT_ERROR_CONN_STA_AP_NOT_FOUND;
    // When: msg_handler is called with SETUPCOMPLETE_RESPONSE
    iot_easysetup_ble_msg_handler(IOT_EASYSETUP_BLE_STEP_SETUPCOMPLETE_RESPONSE, NULL, 0);
    // Then: handles AP not found without crash
}

void TC_iot_easysetup_ble_msg_handler_setup_complete_response_operate_fail(void **state)
{
    struct iot_context *ctx = (struct iot_context *)*state;

    // Given: context with es_network_status = OPERATE_FAIL
    context = ctx;
    ctx->es_network_status = IOT_ERROR_CONN_OPERATE_FAIL;
    // When: msg_handler is called with SETUPCOMPLETE_RESPONSE
    iot_easysetup_ble_msg_handler(IOT_EASYSETUP_BLE_STEP_SETUPCOMPLETE_RESPONSE, NULL, 0);
    // Then: handles operate failure without crash
}

void TC_iot_easysetup_ble_msg_handler_setup_complete_response_default(void **state)
{
    struct iot_context *ctx = (struct iot_context *)*state;

    // Given: context with unrecognized es_network_status
    context = ctx;
    ctx->es_network_status = (iot_error_t)0xDEADC0DE;
    // When: msg_handler is called with SETUPCOMPLETE_RESPONSE
    iot_easysetup_ble_msg_handler(IOT_EASYSETUP_BLE_STEP_SETUPCOMPLETE_RESPONSE, NULL, 0);
    // Then: handles default case without crash
}

void TC_iot_easysetup_ble_msg_handler_deviceinfo_success(void **state)
{
    struct iot_context *ctx = (struct iot_context *)*state;

    // Given: context is set, mock get_response returns DEVICEINFO with no error
    context = ctx;
    ref_step = 0;
    tc_mock_ble_set_get_response_step(IOT_EASYSETUP_BLE_STEP_DEVICEINFO);
    tc_mock_ble_set_get_response_err(IOT_ERROR_NONE);

    // When: msg_handler is called with DEVICEINFO
    iot_easysetup_ble_msg_handler(IOT_EASYSETUP_BLE_STEP_DEVICEINFO, NULL, 0);
    // Then: get_response was called once
    assert_int_equal(tc_mock_ble_get_get_response_call_count(), 1);
}

void TC_iot_easysetup_ble_msg_handler_setupcomplete(void **state)
{
    struct iot_context *ctx = (struct iot_context *)*state;

    // Given: context is set, mock get_response returns SETUPCOMPLETE with no error
    context = ctx;
    ref_step = IOT_EASYSETUP_BLE_STEP_SETUPCOMPLETE;
    tc_mock_ble_set_get_response_step(IOT_EASYSETUP_BLE_STEP_SETUPCOMPLETE);
    tc_mock_ble_set_get_response_err(IOT_ERROR_NONE);

    // When: msg_handler is called with SETUPCOMPLETE
    iot_easysetup_ble_msg_handler(IOT_EASYSETUP_BLE_STEP_SETUPCOMPLETE, NULL, 0);
    // Then: cloud_con_timer is initialized
    assert_non_null(ctx->cloud_con_timer);
}

void TC_iot_easysetup_ble_gen_payload_invalid_cmd_while_not_confirmed(void **state)
{
    struct iot_context *ctx = (struct iot_context *)*state;
    char *out_payload = NULL;
    size_t payload_len = 0;
    iot_error_t err;

    // Given: otm not confirmed, ref_step = 0
    context = ctx;
    ctx->otm_confirmed = false;
    ref_step = 0;

    // When: gen_payload is called with WIFISCANINFO (requires otm confirmation)
    err = _iot_easysetup_gen_payload(ctx, IOT_EASYSETUP_BLE_STEP_WIFISCANINFO, NULL, &out_payload, &payload_len);
    // Then: returns INVALID_CMD
    assert_int_equal(err, IOT_ERROR_EASYSETUP_INVALID_CMD);
}

void TC_iot_easysetup_ble_gen_payload_invalid_step_sequence(void **state)
{
    struct iot_context *ctx = (struct iot_context *)*state;
    char *out_payload = NULL;
    size_t payload_len = 0;
    iot_error_t err;

    // Given: otm confirmed, ref_step = 2 (mismatched step)
    context = ctx;
    ctx->otm_confirmed = true;
    ref_step = 2;

    // When: gen_payload is called with KEYINFO (not matching ref_step and not an allowed out-of-sequence step)
    err = _iot_easysetup_gen_payload(ctx, IOT_EASYSETUP_BLE_STEP_KEYINFO, NULL, &out_payload, &payload_len);
    // Then: returns INVALID_CMD
    assert_int_equal(err, IOT_ERROR_EASYSETUP_INVALID_CMD);
}

void TC_iot_easysetup_ble_gen_payload_response_null(void **state)
{
    struct iot_context *ctx = (struct iot_context *)*state;
    char *out_payload = NULL;
    size_t payload_len = 0;
    iot_error_t err;

    // Given: mock get_response returns NULL
    context = ctx;
    ref_step = 0;
    tc_mock_ble_set_get_response_return_null(1);

    // When: gen_payload is called with DEVICEINFO
    err = _iot_easysetup_gen_payload(ctx, IOT_EASYSETUP_BLE_STEP_DEVICEINFO, NULL, &out_payload, &payload_len);
    // Then: returns INTERNAL_SERVER_ERROR
    assert_int_equal(err, IOT_ERROR_EASYSETUP_INTERNAL_SERVER_ERROR);
}

void TC_iot_easysetup_ble_gen_payload_step_mismatch(void **state)
{
    struct iot_context *ctx = (struct iot_context *)*state;
    char *out_payload = NULL;
    size_t payload_len = 0;
    iot_error_t err;

    // Given: mock get_response returns step KEYINFO but request is DEVICEINFO
    context = ctx;
    ref_step = 0;
    tc_mock_ble_set_get_response_step(IOT_EASYSETUP_BLE_STEP_KEYINFO);
    tc_mock_ble_set_get_response_err(IOT_ERROR_NONE);

    // When: gen_payload is called with DEVICEINFO (step mismatch)
    err = _iot_easysetup_gen_payload(ctx, IOT_EASYSETUP_BLE_STEP_DEVICEINFO, NULL, &out_payload, &payload_len);
    // Then: returns INTERNAL_SERVER_ERROR
    assert_int_equal(err, IOT_ERROR_EASYSETUP_INTERNAL_SERVER_ERROR);
}

void TC_iot_easysetup_ble_gen_payload_wifiscaninfo_sync(void **state)
{
    struct iot_context *ctx = (struct iot_context *)*state;
    char *out_payload = NULL;
    size_t payload_len = 0;
    iot_error_t err;

    // Given: otm confirmed, mock get_response returns WIFISCANINFO with no error
    context = ctx;
    ctx->otm_confirmed = true;
    ref_step = 0;
    tc_mock_ble_set_get_response_step(IOT_EASYSETUP_BLE_STEP_WIFISCANINFO);
    tc_mock_ble_set_get_response_err(IOT_ERROR_NONE);

    // When: gen_payload is called with WIFISCANINFO
    err = _iot_easysetup_gen_payload(ctx, IOT_EASYSETUP_BLE_STEP_WIFISCANINFO, NULL, &out_payload, &payload_len);
    // Then: returns NONE
    assert_int_equal(err, IOT_ERROR_NONE);
}

void TC_iot_easysetup_ble_gen_payload_confirminfo_sync(void **state)
{
    struct iot_context *ctx = (struct iot_context *)*state;
    char *out_payload = NULL;
    size_t payload_len = 0;
    iot_error_t err;

    // Given: otm not confirmed, mock get_response returns CONFIRMINFO with no error
    context = ctx;
    ctx->otm_confirmed = false;
    ref_step = 0;
    tc_mock_ble_set_get_response_step(IOT_EASYSETUP_BLE_STEP_CONFIRMINFO);
    tc_mock_ble_set_get_response_err(IOT_ERROR_NONE);

    // When: gen_payload is called with CONFIRMINFO
    err = _iot_easysetup_gen_payload(ctx, IOT_EASYSETUP_BLE_STEP_CONFIRMINFO, NULL, &out_payload, &payload_len);
    // Then: returns NONE
    assert_int_equal(err, IOT_ERROR_NONE);
}

void TC_iot_easysetup_ble_gen_payload_log_systeminfo_allowed_unconfirmed(void **state)
{
    struct iot_context *ctx = (struct iot_context *)*state;
    char *out_payload = NULL;
    size_t payload_len = 0;
    iot_error_t err;

    // Given: otm not confirmed, mock get_response returns LOG_SYSTEMINFO with no error
    context = ctx;
    ctx->otm_confirmed = false;
    ref_step = 0;
    tc_mock_ble_set_get_response_step(IOT_EASYSETUP_BLE_STEP_LOG_SYSTEMINFO);
    tc_mock_ble_set_get_response_err(IOT_ERROR_NONE);

    // When: gen_payload is called with LOG_SYSTEMINFO
    err = _iot_easysetup_gen_payload(ctx, IOT_EASYSETUP_BLE_STEP_LOG_SYSTEMINFO, NULL, &out_payload, &payload_len);
    // Then: returns NONE (LOG_SYSTEMINFO is allowed without otm confirmation)
    assert_int_equal(err, IOT_ERROR_NONE);
}

void TC_iot_easysetup_ble_gen_payload_response_err(void **state)
{
    struct iot_context *ctx = (struct iot_context *)*state;
    char *out_payload = NULL;
    size_t payload_len = 0;
    iot_error_t err;

    // Given: mock get_response returns DEVICEINFO with INVALID_SEQUENCE error
    context = ctx;
    ref_step = 0;
    tc_mock_ble_set_get_response_step(IOT_EASYSETUP_BLE_STEP_DEVICEINFO);
    tc_mock_ble_set_get_response_err(IOT_ERROR_EASYSETUP_INVALID_SEQUENCE);

    // When: gen_payload is called with DEVICEINFO
    err = _iot_easysetup_gen_payload(ctx, IOT_EASYSETUP_BLE_STEP_DEVICEINFO, NULL, &out_payload, &payload_len);
    // Then: returns INVALID_SEQUENCE
    assert_int_equal(err, IOT_ERROR_EASYSETUP_INVALID_SEQUENCE);
}

void TC_iot_easysetup_ble_msg_decrypt_deviceinfo_passthrough(void **state)
{
    struct iot_context *ctx = (struct iot_context *)*state;
    unsigned char enc[] = {'a', 'b', 'c'};
    char *out = NULL;
    iot_error_t err;

    // Given: DEVICEINFO step (passthrough, no decryption needed)
    context = ctx;

    // When: decrypt is called with DEVICEINFO step
    err = _iot_easysetup_ble_msg_decrypt(ctx->easysetup_security_context, IOT_EASYSETUP_BLE_STEP_DEVICEINFO, enc,
                                         sizeof(enc), &out);
    // Then: returns NONE, output points to original input (passthrough)
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_ptr_equal(out, (char *)enc);
}

void TC_iot_easysetup_ble_msg_decrypt_no_cipher_params(void **state)
{
    struct iot_context *ctx = (struct iot_context *)*state;
    unsigned char enc[] = {'a', 'b', 'c'};
    char *out = NULL;
    iot_error_t err;

    // Given: CONFIRMINFO step (requires decryption) but no cipher params set
    context = ctx;

    // When: decrypt is called with CONFIRMINFO step
    err = _iot_easysetup_ble_msg_decrypt(ctx->easysetup_security_context, IOT_EASYSETUP_BLE_STEP_CONFIRMINFO, enc,
                                         sizeof(enc), &out);
    // Then: returns INTERNAL_SERVER_ERROR
    assert_int_equal(err, IOT_ERROR_EASYSETUP_INTERNAL_SERVER_ERROR);
}

void TC_iot_easysetup_ble_msg_encrypt_null_payload(void **state)
{
    struct iot_context *ctx = (struct iot_context *)*state;
    iot_security_buffer_t *enc_buf = NULL;
    int buf_len = 0;
    iot_error_t err;

    // Given: NULL payload
    context = ctx;

    // When: encrypt is called with NULL payload
    err = _iot_easysetup_ble_msg_encrypt(ctx, IOT_EASYSETUP_BLE_STEP_DEVICEINFO, NULL, 0, &enc_buf, &buf_len);
    // Then: returns INVALID_ARGS
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);
}

void TC_iot_easysetup_ble_con_timer_init_success(void **state)
{
    struct iot_context *ctx = (struct iot_context *)*state;
    iot_error_t err;

    // Given: context with no cloud_con_timer
    // When: con_timer_init is called
    err = _iot_easysetup_con_timer_init(ctx);
    // Then: returns NONE and cloud_con_timer is created
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(ctx->cloud_con_timer);

    // When: con_timer_init is called again (replaces existing timer)
    err = _iot_easysetup_con_timer_init(ctx);
    // Then: returns NONE (timer is deleted and recreated)
    assert_int_equal(err, IOT_ERROR_NONE);
}

void TC_iot_easysetup_ble_conn_cb_connected(void **state)
{
    struct iot_context *ctx = (struct iot_context *)*state;

    // Given: context with ref_step = 5
    context = ctx;
    ref_step = 5;

    // When: conn_cb is called with CONNECTED event
    _iot_easysetup_ble_conn_cb(IOT_BLE_CONNECTION_EVENT_CONNECTED);
    // Then: ref_step is reset to 0, ble_connected is true
    assert_int_equal(ref_step, 0);
    assert_true(ctx->ble_connected);
}

void TC_iot_easysetup_ble_conn_cb_disconnected(void **state)
{
    struct iot_context *ctx = (struct iot_context *)*state;

    // Given: context with ble_connected = true, d2d_event_request = true, work item queued
    context = ctx;
    ctx->ble_connected = true;
    ctx->d2d_event_request = true;
    ctx->wifi_update_enabled = false;
    device_work_data_t work = {0};
    iot_util_queue_send(ctx->work_queue, &work);

    // When: conn_cb is called with DISCONNECTED event
    _iot_easysetup_ble_conn_cb(IOT_BLE_CONNECTION_EVENT_DISCONNECTED);
    // Then: ble_connected and d2d_event_request are cleared
    assert_false(ctx->ble_connected);
    assert_false(ctx->d2d_event_request);
}

void TC_iot_easysetup_ble_conn_cb_unknown_event(void **state)
{
    struct iot_context *ctx = (struct iot_context *)*state;

    // Given: context is set
    context = ctx;
    // When: conn_cb is called with unknown event type
    _iot_easysetup_ble_conn_cb((iot_ble_conn_evt_t)99);
    // Then: no crash (event is ignored)
}

void TC_iot_easysetup_ble_send_deinit_request(void **state)
{
    struct iot_context *ctx = (struct iot_context *)*state;

    // Given: context is set
    context = ctx;

    // When: _send_ble_deinit_request is called
    _send_ble_deinit_request();
    // Then: work item was queued and can be received
    device_work_data_t received = {0};
    iot_error_t err = iot_util_queue_receive(ctx->work_queue, &received);
    assert_int_equal(err, IOT_ERROR_NONE);
}

void TC_iot_easysetup_ble_deinit_request_handler(void **state)
{
    struct iot_context *ctx = (struct iot_context *)*state;

    // Given: context with es_ble_ready = true
    context = ctx;
    ctx->es_ble_ready = true;

    // When: _ble_deinit_request_handler is called
    _ble_deinit_request_handler(ctx, NULL);
    // Then: es_ble_ready is cleared
    assert_false(ctx->es_ble_ready);
}

void TC_iot_easysetup_ble_send_response_null_payload(void **state)
{
    struct iot_context *ctx = (struct iot_context *)*state;
    iot_error_t err;

    // Given: context is set with NULL payload
    context = ctx;

    // When: ble_send_response is called with NULL payload
    err = iot_easysetup_ble_send_response(IOT_EASYSETUP_BLE_STEP_DEVICEINFO, NULL, 0);
    // Then: returns error
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

static void _tc_ble_init_cipher(struct iot_context *ctx)
{
    static unsigned char secret_buf[IOT_SECURITY_SECRET_LEN];
    static unsigned char iv_buf[IOT_SECURITY_IV_LEN];
    iot_security_cipher_params_t aes_params = {0};
    iot_error_t err;
    size_t i;

    err = iot_security_cipher_init(ctx->easysetup_security_context);
    assert_int_equal(err, IOT_ERROR_NONE);
    for (i = 0; i < sizeof(secret_buf); i++)
        secret_buf[i] = (unsigned char)(i * 7 + 1);
    for (i = 0; i < sizeof(iv_buf); i++)
        iv_buf[i] = (unsigned char)(i * 11 + 3);

    aes_params.type = IOT_SECURITY_KEY_TYPE_AES256;
    aes_params.key.p = secret_buf;
    aes_params.key.len = sizeof(secret_buf);
    aes_params.iv.p = iv_buf;
    aes_params.iv.len = sizeof(iv_buf);
    err = iot_security_cipher_set_params(ctx->easysetup_security_context, &aes_params);
    assert_int_equal(err, IOT_ERROR_NONE);
}

void TC_iot_easysetup_ble_msg_encrypt_decrypt_roundtrip(void **state)
{
    struct iot_context *ctx = (struct iot_context *)*state;
    unsigned char payload[32];
    iot_security_buffer_t *enc_buf = NULL;
    int buf_len = 0;
    char *decrypted = NULL;
    iot_error_t err;
    size_t i;

    // Given: cipher initialized, CONFIRMINFO step (uses AES), MTU = 256
    context = ctx;
    _tc_ble_init_cipher(ctx);
    for (i = 0; i < sizeof(payload); i++)
        payload[i] = (unsigned char)(i + 1);
    tc_mock_ble_set_mtu(256);

    // When: encrypt with CONFIRMINFO step
    err = _iot_easysetup_ble_msg_encrypt(ctx, IOT_EASYSETUP_BLE_STEP_CONFIRMINFO, payload, sizeof(payload), &enc_buf,
                                         &buf_len);
    // Then: encrypt succeeds
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(enc_buf);
    assert_true(buf_len >= 1);

    // When: decrypt the encrypted buffer
    err = _iot_easysetup_ble_msg_decrypt(ctx->easysetup_security_context, IOT_EASYSETUP_BLE_STEP_CONFIRMINFO,
                                         enc_buf[0].p, enc_buf[0].len, &decrypted);
    // Then: decrypt succeeds
    assert_int_equal(err, IOT_ERROR_NONE);

    // Teardown: free encrypted buffers and decrypted output
    if (enc_buf) {
        for (i = 0; i < (size_t)buf_len; i++) {
            if (enc_buf[i].p)
                iot_os_free(enc_buf[i].p);
        }
        iot_os_free(enc_buf);
    }
    if (decrypted)
        iot_os_free((void *)decrypted);
}

void TC_iot_easysetup_ble_msg_encrypt_deviceinfo_passthrough(void **state)
{
    struct iot_context *ctx = (struct iot_context *)*state;
    unsigned char payload[16];
    iot_security_buffer_t *enc_buf = NULL;
    int buf_len = 0;
    iot_error_t err;
    size_t i;

    // Given: cipher initialized, DEVICEINFO step (no AES, just copy), MTU = 256
    context = ctx;
    _tc_ble_init_cipher(ctx);
    for (i = 0; i < sizeof(payload); i++)
        payload[i] = (unsigned char)(i + 1);
    tc_mock_ble_set_mtu(256);

    // When: encrypt is called with DEVICEINFO step
    err = _iot_easysetup_ble_msg_encrypt(ctx, IOT_EASYSETUP_BLE_STEP_DEVICEINFO, payload, sizeof(payload), &enc_buf,
                                         &buf_len);
    // Then: returns NONE, enc_buf is allocated
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(enc_buf);

    // Teardown: free encrypted buffers
    for (i = 0; i < (size_t)buf_len; i++) {
        if (enc_buf[i].p)
            iot_os_free(enc_buf[i].p);
    }
    iot_os_free(enc_buf);
}

void TC_iot_easysetup_ble_msg_encrypt_small_mtu(void **state)
{
    struct iot_context *ctx = (struct iot_context *)*state;
    unsigned char payload[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    iot_security_buffer_t *enc_buf = NULL;
    int buf_len = 0;
    iot_error_t err;
    size_t i;

    // Given: cipher initialized, MTU = 5 (below MIN_MTU_SIZE, clamped to MIN)
    context = ctx;
    _tc_ble_init_cipher(ctx);

    tc_mock_ble_set_mtu(5);
    // When: encrypt is called with small MTU
    err = _iot_easysetup_ble_msg_encrypt(ctx, IOT_EASYSETUP_BLE_STEP_DEVICEINFO, payload, sizeof(payload), &enc_buf,
                                         &buf_len);
    // Then: returns NONE (MTU is clamped)
    assert_int_equal(err, IOT_ERROR_NONE);

    // Teardown: free encrypted buffers
    for (i = 0; i < (size_t)buf_len; i++) {
        if (enc_buf[i].p)
            iot_os_free(enc_buf[i].p);
    }
    iot_os_free(enc_buf);
}

void TC_iot_easysetup_ble_msg_encrypt_large_mtu(void **state)
{
    struct iot_context *ctx = (struct iot_context *)*state;
    unsigned char payload[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    iot_security_buffer_t *enc_buf = NULL;
    int buf_len = 0;
    iot_error_t err;
    size_t i;

    // Given: cipher initialized, MTU = 1024 (above MAX_ATT_VALUE_LEN, clamped to MAX)
    context = ctx;
    _tc_ble_init_cipher(ctx);

    tc_mock_ble_set_mtu(1024);
    // When: encrypt is called with large MTU
    err = _iot_easysetup_ble_msg_encrypt(ctx, IOT_EASYSETUP_BLE_STEP_DEVICEINFO, payload, sizeof(payload), &enc_buf,
                                         &buf_len);
    // Then: returns NONE (MTU is clamped)
    assert_int_equal(err, IOT_ERROR_NONE);

    // Teardown: free encrypted buffers
    for (i = 0; i < (size_t)buf_len; i++) {
        if (enc_buf[i].p)
            iot_os_free(enc_buf[i].p);
    }
    iot_os_free(enc_buf);
}

void TC_iot_easysetup_ble_msg_encrypt_no_cipher_params(void **state)
{
    struct iot_context *ctx = (struct iot_context *)*state;
    unsigned char payload[4] = {1, 2, 3, 4};
    iot_security_buffer_t *enc_buf = NULL;
    int buf_len = 0;
    iot_error_t err;

    // Given: security_context exists but cipher_params == NULL
    context = ctx;
    tc_mock_ble_set_mtu(128);

    // When: encrypt is called with no cipher params
    err = _iot_easysetup_ble_msg_encrypt(ctx, IOT_EASYSETUP_BLE_STEP_DEVICEINFO, payload, sizeof(payload), &enc_buf,
                                         &buf_len);
    // Then: returns INVALID_ARGS
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);
}

void TC_iot_easysetup_ble_send_response_no_cipher_params(void **state)
{
    struct iot_context *ctx = (struct iot_context *)*state;
    iot_error_t err;

    // Given: context with no cipher params set
    context = ctx;
    tc_mock_ble_set_mtu(128);

    // When: ble_send_response is called with CONFIRMINFO step
    err = iot_easysetup_ble_send_response(IOT_EASYSETUP_BLE_STEP_CONFIRMINFO, "hi", 2);
    // Then: returns INVALID_ARGS
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);
}

void TC_iot_easysetup_ble_send_response_deviceinfo_success(void **state)
{
    struct iot_context *ctx = (struct iot_context *)*state;
    iot_error_t err;

    // Given: cipher initialized, MTU = 256
    context = ctx;
    _tc_ble_init_cipher(ctx);
    tc_mock_ble_set_mtu(256);

    // When: ble_send_response is called with DEVICEINFO step
    err = iot_easysetup_ble_send_response(IOT_EASYSETUP_BLE_STEP_DEVICEINFO, "hello", 5);
    // Then: returns NONE
    assert_int_equal(err, IOT_ERROR_NONE);
}

void TC_iot_easysetup_ble_deinit_ready_network_error(void **state)
{
    struct iot_context *ctx = (struct iot_context *)*state;

    // Given: context with es_ble_ready = true, network error, cipher initialized
    context = ctx;
    _tc_ble_init_cipher(ctx);
    ctx->es_ble_ready = true;
    ctx->es_network_status = IOT_ERROR_CONN_STA_AUTH_FAIL;
    tc_mock_ble_set_mtu(256);

    // When: iot_easysetup_deinit is called
    iot_easysetup_deinit(ctx);
    // Then: goes through encrypt-and-report path then iot_state_update without crash
}

void TC_iot_easysetup_ble_deinit_ready_success(void **state)
{
    struct iot_context *ctx = (struct iot_context *)*state;

    // Given: context with es_ble_ready = true, network success, cipher initialized
    context = ctx;
    _tc_ble_init_cipher(ctx);
    ctx->es_ble_ready = true;
    ctx->es_network_status = IOT_ERROR_NONE;
    tc_mock_ble_set_mtu(256);

    // When: iot_easysetup_deinit is called
    iot_easysetup_deinit(ctx);
    // Then: starts advertisement
    assert_int_equal(tc_mock_ble_get_start_adv_call_count(), 1);
}

void TC_iot_easysetup_ble_conn_cb_disconnected_with_cipher(void **state)
{
    struct iot_context *ctx = (struct iot_context *)*state;

    // Given: context with cipher initialized, ble_connected = true, wifi_update_enabled = true
    context = ctx;
    _tc_ble_init_cipher(ctx);
    ctx->ble_connected = true;
    ctx->wifi_update_enabled = true;

    // When: conn_cb is called with DISCONNECTED event
    _iot_easysetup_ble_conn_cb(IOT_BLE_CONNECTION_EVENT_DISCONNECTED);
    // Then: ble_connected is cleared, cipher_deinit path is covered
    assert_false(ctx->ble_connected);
}

static int tc_status_cb_count;
static void _tc_status_cb(st_device_status status, void *user_data)
{
    (void)status;
    (void)user_data;
    tc_status_cb_count++;
}

void TC_iot_easysetup_ble_msg_handler_deviceinfo_with_status_cb(void **state)
{
    struct iot_context *ctx = (struct iot_context *)*state;

    // Given: context with cipher initialized, status_cb set, mock get_response returns DEVICEINFO
    context = ctx;
    _tc_ble_init_cipher(ctx);
    ctx->status_cb = _tc_status_cb;
    tc_status_cb_count = 0;
    ref_step = 0;
    tc_mock_ble_set_mtu(256);
    tc_mock_ble_set_get_response_step(IOT_EASYSETUP_BLE_STEP_DEVICEINFO);
    tc_mock_ble_set_get_response_err(IOT_ERROR_NONE);

    // When: msg_handler is called with DEVICEINFO
    iot_easysetup_ble_msg_handler(IOT_EASYSETUP_BLE_STEP_DEVICEINFO, NULL, 0);
    // Then: status_cb was called at least once
    assert_true(tc_status_cb_count >= 1);
}

void TC_iot_easysetup_ble_gen_payload_offline_diagnostics_connection_info(void **state)
{
    struct iot_context *ctx = (struct iot_context *)*state;
    char *out_payload = NULL;
    size_t payload_len = 0;
    iot_error_t err;

    // Given: otm confirmed, mock get_response returns OFFLINE_DIAGNOSTICS_CONNECTION_INFO
    context = ctx;
    ctx->otm_confirmed = true;
    ref_step = 0;
    tc_mock_ble_set_get_response_step(IOT_EASYSETUP_BLE_STEP_OFFLINE_DIAGNOSTICS_CONNECTION_INFO);
    tc_mock_ble_set_get_response_err(IOT_ERROR_NONE);

    // When: gen_payload is called with OFFLINE_DIAGNOSTICS_CONNECTION_INFO
    err = _iot_easysetup_gen_payload(ctx, IOT_EASYSETUP_BLE_STEP_OFFLINE_DIAGNOSTICS_CONNECTION_INFO, NULL,
                                     &out_payload, &payload_len);
    // Then: returns NONE, ref_step is reset to 0
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_int_equal(ref_step, 0);
}

void TC_iot_easysetup_ble_msg_encrypt_array_malloc_failure(void **state)
{
    struct iot_context *ctx = (struct iot_context *)*state;
    unsigned char payload[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    iot_security_buffer_t *enc_buf = NULL;
    int buf_len = 0;
    iot_error_t err;

    // Given: cipher initialized, malloc will fail on first allocation
    context = ctx;
    _tc_ble_init_cipher(ctx);
    tc_mock_ble_set_mtu(256);

    set_mock_detect_memory_leak(false);
    do_not_use_mock_iot_os_malloc_failure();
    set_mock_iot_os_malloc_failure_with_index(0);
    // When: encrypt is called with CONFIRMINFO step
    err = _iot_easysetup_ble_msg_encrypt(ctx, IOT_EASYSETUP_BLE_STEP_CONFIRMINFO, payload, sizeof(payload), &enc_buf,
                                         &buf_len);
    do_not_use_mock_iot_os_malloc_failure();
    // Then: returns MEM_ALLOC
    assert_int_equal(err, IOT_ERROR_MEM_ALLOC);
}

void TC_iot_easysetup_ble_msg_decrypt_malloc_failure(void **state)
{
    struct iot_context *ctx = (struct iot_context *)*state;
    unsigned char enc[] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'};
    char *out = NULL;
    iot_error_t err;

    // Given: cipher initialized, malloc will fail on first allocation
    context = ctx;
    _tc_ble_init_cipher(ctx);

    set_mock_detect_memory_leak(false);
    do_not_use_mock_iot_os_malloc_failure();
    set_mock_iot_os_malloc_failure_with_index(0);
    // When: decrypt is called with CONFIRMINFO step
    err = _iot_easysetup_ble_msg_decrypt(ctx->easysetup_security_context, IOT_EASYSETUP_BLE_STEP_CONFIRMINFO, enc,
                                         sizeof(enc), &out);
    do_not_use_mock_iot_os_malloc_failure();
    // Then: returns MEM_ALLOC_ERROR
    assert_int_equal(err, IOT_ERROR_EASYSETUP_MEM_ALLOC_ERROR);
}

void TC_iot_easysetup_ble_msg_decrypt_bad_input(void **state)
{
    struct iot_context *ctx = (struct iot_context *)*state;
    unsigned char enc[] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'};
    char *out = NULL;
    iot_error_t err;

    // Given: cipher initialized, garbage input (not valid encrypted blob)
    context = ctx;
    _tc_ble_init_cipher(ctx);

    // When: decrypt is called with CONFIRMINFO step on garbage input
    err = _iot_easysetup_ble_msg_decrypt(ctx->easysetup_security_context, IOT_EASYSETUP_BLE_STEP_CONFIRMINFO, enc,
                                         sizeof(enc), &out);
    // Then: returns AES256_DECRYPTION_ERROR
    assert_int_equal(err, IOT_ERROR_EASYSETUP_AES256_DECRYPTION_ERROR);
}

void TC_iot_easysetup_ble_msg_handler_with_payload(void **state)
{
    struct iot_context *ctx = (struct iot_context *)*state;
    unsigned char enc[16];
    size_t i;

    // Given: cipher initialized, DEVICEINFO step with non-empty data_buf
    context = ctx;
    _tc_ble_init_cipher(ctx);
    for (i = 0; i < sizeof(enc); i++)
        enc[i] = (unsigned char)(i * 3);
    ref_step = 0;
    tc_mock_ble_set_mtu(256);
    tc_mock_ble_set_get_response_step(IOT_EASYSETUP_BLE_STEP_DEVICEINFO);
    tc_mock_ble_set_get_response_err(IOT_ERROR_NONE);

    // When: msg_handler is called with DEVICEINFO and payload
    iot_easysetup_ble_msg_handler(IOT_EASYSETUP_BLE_STEP_DEVICEINFO, (char *)enc, sizeof(enc));
    // Then: decrypt call in msg_handler is exercised without crash
}

void TC_iot_easysetup_ble_msg_handler_decrypt_error(void **state)
{
    struct iot_context *ctx = (struct iot_context *)*state;
    unsigned char enc[16] = {0};

    // Given: cipher initialized, CONFIRMINFO step with garbage payload
    context = ctx;
    _tc_ble_init_cipher(ctx);
    tc_mock_ble_set_mtu(256);

    // When: msg_handler is called with CONFIRMINFO and garbage payload
    iot_easysetup_ble_msg_handler(IOT_EASYSETUP_BLE_STEP_CONFIRMINFO, (char *)enc, sizeof(enc));
    // Then: decrypt-error early return is covered without crash
}

void TC_iot_easysetup_ble_gen_payload_request_pending(void **state)
{
    struct iot_context *ctx = (struct iot_context *)*state;
    char *out_payload = NULL;
    size_t payload_len = 0;
    iot_error_t err;

    // Given: mock get_response returns DEVICEINFO with REQUEST_PENDING error
    context = ctx;
    ref_step = 0;
    tc_mock_ble_set_get_response_step(IOT_EASYSETUP_BLE_STEP_DEVICEINFO);
    tc_mock_ble_set_get_response_err(IOT_ERROR_EASYSETUP_REQUEST_PENDING);

    // When: gen_payload is called with DEVICEINFO
    err = _iot_easysetup_gen_payload(ctx, IOT_EASYSETUP_BLE_STEP_DEVICEINFO, NULL, &out_payload, &payload_len);
    // Then: returns REQUEST_PENDING
    assert_int_equal(err, IOT_ERROR_EASYSETUP_REQUEST_PENDING);
}
