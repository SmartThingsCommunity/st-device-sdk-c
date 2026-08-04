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
#include "TC_MOCK_iot_bsp_ble.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "iot_bsp_ble.h"
#include "iot_easysetup.h"
#include "iot_error.h"
#include "iot_main.h"
#include "iot_security_common.h"

#define UNUSED(x) (void)(x)

/* Mock state for iot_bsp_ble_get_mtu */
static uint32_t mock_ble_mtu = 0;

/* Mock state for iot_send_indication */
static int mock_send_indication_rc = 0;
static int mock_send_indication_call_count = 0;
static uint32_t mock_send_indication_last_len = 0;

/* Mock state for es_msg_dispatch */
static int mock_es_msg_dispatch_call_count = 0;
static uint8_t mock_es_msg_dispatch_last_cmd_num = 0;
static uint8_t mock_es_msg_dispatch_last_buf_count = 0;
static int mock_es_msg_dispatch_use_wrap = 1; /* 1 = use fake wrap, 0 = call real */

/* Mock state for iot_bsp_ble_deinit */
static int mock_bsp_ble_deinit_call_count = 0;

/* Mock state for iot_security_manager_get_certificate */
static int mock_get_certificate_rc = 0;
static int mock_get_certificate_use_wrap = 0;

/* Mock state for iot_easysetup_get_response */
static int mock_get_response_step = 0;
static int mock_get_response_err = 0;
static int mock_get_response_return_null = 0;
static int mock_get_response_call_count = 0;
static int mock_get_response_last_step = 0;
static int mock_get_response_use_wrap = 1; /* 1 = use fake wrap, 0 = call real */

/* Mock state for iot_easysetup_start_ble_advertisement */
static int mock_start_adv_rc = 0;
static int mock_start_adv_call_count = 0;

/* Forward declarations for the extra mock state that lives below the
 * es_msg_dispatch / indication mocks. */
static void tc_mock_ble_reset_extras(void);

void tc_mock_ble_reset(void)
{
    mock_ble_mtu = 0;
    mock_send_indication_rc = 0;
    mock_send_indication_call_count = 0;
    mock_send_indication_last_len = 0;
    mock_es_msg_dispatch_call_count = 0;
    mock_es_msg_dispatch_last_cmd_num = 0;
    mock_es_msg_dispatch_last_buf_count = 0;
    tc_mock_ble_reset_extras();
}

void tc_mock_ble_set_mtu(uint32_t mtu)
{
    mock_ble_mtu = mtu;
}

void tc_mock_ble_set_send_indication_rc(int rc)
{
    mock_send_indication_rc = rc;
}

int tc_mock_ble_get_send_indication_call_count(void)
{
    return mock_send_indication_call_count;
}

uint32_t tc_mock_ble_get_send_indication_last_len(void)
{
    return mock_send_indication_last_len;
}

int tc_mock_ble_get_es_msg_dispatch_call_count(void)
{
    return mock_es_msg_dispatch_call_count;
}

uint8_t tc_mock_ble_get_es_msg_dispatch_last_cmd_num(void)
{
    return mock_es_msg_dispatch_last_cmd_num;
}

uint8_t tc_mock_ble_get_es_msg_dispatch_last_buf_count(void)
{
    return mock_es_msg_dispatch_last_buf_count;
}

/* Wrap for iot_bsp_ble_get_mtu */
uint32_t __wrap_iot_bsp_ble_get_mtu(void)
{
    return mock_ble_mtu;
}

/* Wrap for iot_send_indication */
int __wrap_iot_send_indication(uint8_t *buf, uint32_t len)
{
    UNUSED(buf);
    mock_send_indication_call_count++;
    mock_send_indication_last_len = len;
    return mock_send_indication_rc;
}

void tc_mock_ble_set_es_msg_dispatch_use_wrap(int use)
{
    mock_es_msg_dispatch_use_wrap = use;
}

/* Real declaration for es_msg_dispatch */
void __real_es_msg_dispatch(iot_security_buffer_t *buf, uint8_t buf_count, uint8_t cmd_num);

/* Wrap for es_msg_dispatch: when use_wrap=1 (default) record the call but do
 * nothing else, so the iot_easysetup_ble.c tests can verify dispatch was
 * triggered without pulling in the full d2d message handler.  When
 * use_wrap=0 call the real implementation so that iot_easysetup_ble_task.c
 * code coverage is measured. */
void __wrap_es_msg_dispatch(iot_security_buffer_t *buf, uint8_t buf_count, uint8_t cmd_num)
{
    mock_es_msg_dispatch_call_count++;
    mock_es_msg_dispatch_last_buf_count = buf_count;
    mock_es_msg_dispatch_last_cmd_num = cmd_num;
    if (!mock_es_msg_dispatch_use_wrap) {
        __real_es_msg_dispatch(buf, buf_count, cmd_num);
    }
}

/* Wrap for iot_bsp_ble_deinit */
void __wrap_iot_bsp_ble_deinit(void)
{
    mock_bsp_ble_deinit_call_count++;
}

int tc_mock_ble_get_bsp_ble_deinit_call_count(void)
{
    return mock_bsp_ble_deinit_call_count;
}

void tc_mock_ble_set_get_certificate_rc(int rc)
{
    mock_get_certificate_rc = rc;
}

void tc_mock_ble_set_get_certificate_use_wrap(int use)
{
    mock_get_certificate_use_wrap = use;
}

iot_error_t __real_iot_security_manager_get_certificate(iot_security_context_t *context, int cert_id,
                                                        iot_security_buffer_t *cert_buf);

iot_error_t __wrap_iot_security_manager_get_certificate(iot_security_context_t *context, int cert_id,
                                                        iot_security_buffer_t *cert_buf)
{
    if (!mock_get_certificate_use_wrap) {
        return __real_iot_security_manager_get_certificate(context, cert_id, cert_buf);
    }
    if (mock_get_certificate_rc != 0) {
        return (iot_error_t)mock_get_certificate_rc;
    }

    /* Produce a small fake certificate blob. */
    static const unsigned char fake_cert[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    cert_buf->len = sizeof(fake_cert);
    cert_buf->p = (unsigned char *)malloc(cert_buf->len);

    if (!cert_buf->p) {
        return IOT_ERROR_MEM_ALLOC;
    }

    memcpy(cert_buf->p, fake_cert, cert_buf->len);
    return IOT_ERROR_NONE;
}

void tc_mock_ble_set_get_response_step(int step)
{
    mock_get_response_step = step;
}

void tc_mock_ble_set_get_response_use_wrap(int use)
{
    mock_get_response_use_wrap = use;
}

void tc_mock_ble_set_get_response_err(int err)
{
    mock_get_response_err = err;
}

void tc_mock_ble_set_get_response_return_null(int null)
{
    mock_get_response_return_null = null;
}

int tc_mock_ble_get_get_response_call_count(void)
{
    return mock_get_response_call_count;
}

int tc_mock_ble_get_get_response_last_step(void)
{
    return mock_get_response_last_step;
}

struct iot_easysetup_payload *__real_iot_easysetup_get_response(struct iot_context *ctx,
                                                                struct iot_easysetup_payload request);

/* Wrap for iot_easysetup_get_response: when use_wrap=1 (default) emulate a
 * controllable response; when use_wrap=0 call the real implementation. */
struct iot_easysetup_payload *__wrap_iot_easysetup_get_response(struct iot_context *ctx,
                                                                struct iot_easysetup_payload request)
{
    mock_get_response_call_count++;
    mock_get_response_last_step = request.step;
    if (!mock_get_response_use_wrap) {
        return __real_iot_easysetup_get_response(ctx, request);
    }
    if (mock_get_response_return_null) {
        return NULL;
    }
    struct iot_easysetup_payload *resp =
        (struct iot_easysetup_payload *)calloc(1, sizeof(struct iot_easysetup_payload));
    if (!resp) {
        return NULL;
    }
    resp->step = mock_get_response_step ? mock_get_response_step : request.step;
    resp->err = mock_get_response_err;
    resp->payload = NULL;
    resp->payload_len = 0;
    return resp;
}

void tc_mock_ble_set_start_adv_rc(int rc)
{
    mock_start_adv_rc = rc;
}

int tc_mock_ble_get_start_adv_call_count(void)
{
    return mock_start_adv_call_count;
}

iot_error_t __wrap_iot_easysetup_start_ble_advertisement(struct iot_context *ctx)
{
    UNUSED(ctx);
    mock_start_adv_call_count++;
    return (iot_error_t)mock_start_adv_rc;
}

static void tc_mock_ble_reset_extras(void)
{
    mock_es_msg_dispatch_use_wrap = 1;
    mock_bsp_ble_deinit_call_count = 0;
    mock_get_certificate_rc = 0;
    mock_get_certificate_use_wrap = 0;
    mock_get_response_step = 0;
    mock_get_response_err = 0;
    mock_get_response_return_null = 0;
    mock_get_response_call_count = 0;
    mock_get_response_last_step = 0;
    mock_get_response_use_wrap = 1;
    mock_start_adv_rc = 0;
    mock_start_adv_call_count = 0;
}
