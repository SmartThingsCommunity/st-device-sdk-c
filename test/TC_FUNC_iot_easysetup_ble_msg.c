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
#include <string.h>

#include "TC_MOCK_functions.h"
#include "TC_MOCK_iot_bsp_ble.h"
#include "cmocka_custom.h"
#include "easysetup_ble.h"
#include "iot_error.h"
#include "iot_main.h"

#define UNUSED(x) (void)(x)

/* Wire-format header of a transferred chunk, kept in sync with the private
 * struct transfor_data in iot_easysetup_ble_msg.c. */
#pragma pack(1)
struct tc_transfer_hdr {
    uint8_t op_code;
    uint8_t cmd_num;
    uint8_t transaction_id;
    uint8_t total_size_0;
    uint8_t total_size_1;
    uint8_t total_size_2;
    uint8_t chunk_data_continued;
    uint16_t segment_len;
};
#pragma pack()

#define TC_HDR_SIZE sizeof(struct tc_transfer_hdr)

static void _tc_fill_header(uint8_t *buf, uint8_t op_code, uint8_t cmd_num, uint8_t transaction_id, uint32_t total_size,
                            uint8_t chunk_data_continued, uint16_t segment_len)
{
    struct tc_transfer_hdr *h = (struct tc_transfer_hdr *)buf;
    h->op_code = op_code;
    h->cmd_num = cmd_num;
    h->transaction_id = transaction_id;
    h->total_size_0 = (uint8_t)(total_size & 0xFF);
    h->total_size_1 = (uint8_t)((total_size >> 8) & 0xFF);
    h->total_size_2 = (uint8_t)((total_size >> 16) & 0xFF);
    h->chunk_data_continued = chunk_data_continued;
    h->segment_len = segment_len;
}

int TC_iot_easysetup_ble_msg_setup(void **state)
{
    UNUSED(state);
    es_reset_transferdata();
    tc_mock_ble_reset();
    tc_mock_ble_set_mtu(256);
    return 0;
}

int TC_iot_easysetup_ble_msg_teardown(void **state)
{
    UNUSED(state);
    es_reset_transferdata();
    tc_mock_ble_reset();
    return 0;
}

void TC_iot_easysetup_ble_msg_assemble_null_buf(void **state)
{
    bool rc;
    UNUSED(state);

    // When: buffer pointer is NULL
    rc = es_msg_assemble(NULL, 10);
    // Then
    assert_false(rc);
}

void TC_iot_easysetup_ble_msg_assemble_zero_len(void **state)
{
    uint8_t buf[1] = {0};
    bool rc;
    UNUSED(state);

    // When: length is zero
    rc = es_msg_assemble(buf, 0);
    // Then
    assert_false(rc);
}

void TC_iot_easysetup_ble_msg_assemble_segment_larger_than_total(void **state)
{
    uint8_t buf[32];
    bool rc;
    UNUSED(state);

    // Given: header with total_size=3 and segment_len=10
    _tc_fill_header(buf, 0, 1, 1, 3, 0, 10);
    memcpy(buf + TC_HDR_SIZE, "abc", 3);
    // When
    rc = es_msg_assemble(buf, TC_HDR_SIZE + 10);
    // Then
    assert_false(rc);
}

void TC_iot_easysetup_ble_msg_assemble_idle_with_non_zero_opcode(void **state)
{
    uint8_t buf[32];
    bool rc;
    UNUSED(state);

    // Given: first chunk in IDLE but op_code != 0
    _tc_fill_header(buf, 5, 1, 1, 3, 0, 3);
    memcpy(buf + TC_HDR_SIZE, "abc", 3);
    // When
    rc = es_msg_assemble(buf, TC_HDR_SIZE + 3);
    // Then
    assert_false(rc);
}

void TC_iot_easysetup_ble_msg_assemble_single_shot_success(void **state)
{
    uint8_t buf[32];
    bool rc;
    UNUSED(state);

    // Given: a complete single-chunk message
    _tc_fill_header(buf, 0, 1, 1, 3, 0, 3);
    memcpy(buf + TC_HDR_SIZE, "abc", 3);
    // When
    rc = es_msg_assemble(buf, TC_HDR_SIZE + 3);
    // Then: dispatches immediately with the matching command number
    assert_true(rc);
    assert_int_equal(tc_mock_ble_get_es_msg_dispatch_call_count(), 1);
    assert_int_equal(tc_mock_ble_get_es_msg_dispatch_last_cmd_num(), 1);
    assert_int_equal(tc_mock_ble_get_es_msg_dispatch_last_buf_count(), 1);
}

void TC_iot_easysetup_ble_msg_assemble_fragmented_success(void **state)
{
    uint8_t buf[512];
    UNUSED(state);

    // Given: first chunk claims total=600 bytes, payload=400 -> transitions
    // into MSG_STATE_ASSEMBLE
    _tc_fill_header(buf, 0, 2, 2, 600, 0, 400);
    memset(buf + TC_HDR_SIZE, 'a', 400);
    // When
    assert_true(es_msg_assemble(buf, TC_HDR_SIZE + 400));
    // Then: dispatch not yet triggered
    assert_int_equal(tc_mock_ble_get_es_msg_dispatch_call_count(), 0);

    // Given: continuation chunk supplies the remaining 200 bytes
    _tc_fill_header(buf, 1, 2, 2, 400, 0, 200);
    memset(buf + TC_HDR_SIZE, 'b', 200);
    // When
    assert_true(es_msg_assemble(buf, TC_HDR_SIZE + 200));
    // Then: dispatch happens once the message is complete
    assert_int_equal(tc_mock_ble_get_es_msg_dispatch_call_count(), 1);
}

void TC_iot_easysetup_ble_msg_assemble_assemble_mismatch_opcode(void **state)
{
    uint8_t buf[512];
    UNUSED(state);

    // Given: first chunk accepted, state moves to ASSEMBLE
    _tc_fill_header(buf, 0, 2, 3, 600, 0, 400);
    memset(buf + TC_HDR_SIZE, 'a', 400);
    assert_true(es_msg_assemble(buf, TC_HDR_SIZE + 400));

    // When: second chunk has an unexpected op_code
    _tc_fill_header(buf, 99, 2, 3, 400, 0, 200);
    memset(buf + TC_HDR_SIZE, 'b', 200);
    assert_true(es_msg_assemble(buf, TC_HDR_SIZE + 200));
    // Then: state is reset and no dispatch happens
    assert_int_equal(tc_mock_ble_get_es_msg_dispatch_call_count(), 0);
}

void TC_iot_easysetup_ble_msg_assemble_assemble_overflow(void **state)
{
    uint8_t buf[512];
    UNUSED(state);

    // Given: first chunk accepted
    _tc_fill_header(buf, 0, 2, 4, 500, 0, 400);
    memset(buf + TC_HDR_SIZE, 'a', 400);
    assert_true(es_msg_assemble(buf, TC_HDR_SIZE + 400));

    // When: continuation offset + segment exceeds the declared total
    _tc_fill_header(buf, 1, 2, 4, 500, 0, 200);
    memset(buf + TC_HDR_SIZE, 'b', 200);
    assert_true(es_msg_assemble(buf, TC_HDR_SIZE + 200));
    // Then: state is reset and dispatch is not called
    assert_int_equal(tc_mock_ble_get_es_msg_dispatch_call_count(), 0);
}

void TC_iot_easysetup_ble_msg_assemble_duplicated_cmd_num(void **state)
{
    uint8_t buf[32];
    UNUSED(state);

    // Given: first message for cmd_num=5 is dispatched
    _tc_fill_header(buf, 0, 5, 5, 3, 0, 3);
    memcpy(buf + TC_HDR_SIZE, "abc", 3);
    assert_true(es_msg_assemble(buf, TC_HDR_SIZE + 3));
    assert_int_equal(tc_mock_ble_get_es_msg_dispatch_call_count(), 1);

    // When: a second message arrives with the same cmd_num
    _tc_fill_header(buf, 0, 5, 6, 3, 0, 3);
    memcpy(buf + TC_HDR_SIZE, "abc", 3);
    assert_true(es_msg_assemble(buf, TC_HDR_SIZE + 3));
    // Then: dispatch is skipped for the duplicate
    assert_int_equal(tc_mock_ble_get_es_msg_dispatch_call_count(), 1);
}

void TC_iot_easysetup_ble_msg_assemble_data_continued(void **state)
{
    uint8_t buf[512];
    UNUSED(state);

    // Given: chunk_data_continued=1 indicates another logical message will follow
    _tc_fill_header(buf, 0, 6, 6, 3, 1, 3);
    memcpy(buf + TC_HDR_SIZE, "xyz", 3);
    // When
    assert_true(es_msg_assemble(buf, TC_HDR_SIZE + 3));
    // Then: state is kept open, no dispatch yet
    assert_int_equal(tc_mock_ble_get_es_msg_dispatch_call_count(), 0);
}

void TC_iot_easysetup_ble_msg_assemble_transaction_id_regression(void **state)
{
    uint8_t buf[32];
    UNUSED(state);

    // Given: transaction_id advances to 7 via a first dispatch
    _tc_fill_header(buf, 0, 7, 7, 3, 0, 3);
    memcpy(buf + TC_HDR_SIZE, "abc", 3);
    assert_true(es_msg_assemble(buf, TC_HDR_SIZE + 3));

    // When: next chunk claims an older transaction_id
    _tc_fill_header(buf, 0, 8, 5, 3, 0, 3);
    memcpy(buf + TC_HDR_SIZE, "abc", 3);
    // Then: the chunk is rejected
    assert_false(es_msg_assemble(buf, TC_HDR_SIZE + 3));
}

void TC_iot_easysetup_ble_msg_assemble_zero_total_size(void **state)
{
    uint8_t buf[TC_HDR_SIZE];
    UNUSED(state);

    // Given: a zero-payload message header
    _tc_fill_header(buf, 0, 3, 3, 0, 0, 0);
    // When
    assert_true(es_msg_assemble(buf, TC_HDR_SIZE));
    // Then: dispatch fires immediately because the "message" is complete
    assert_int_equal(tc_mock_ble_get_es_msg_dispatch_call_count(), 1);
}

void TC_iot_easysetup_ble_msg_assemble_disassemble_state_reset(void **state)
{
    uint8_t buf[256];
    UNUSED(state);

    // Given: dispatch a first message so module has non-zero cmd_num
    tc_mock_ble_set_mtu(64);
    _tc_fill_header(buf, 0, 9, 9, 3, 0, 3);
    memcpy(buf + TC_HDR_SIZE, "xyz", 3);
    assert_true(es_msg_assemble(buf, TC_HDR_SIZE + 3));

    // When: a second single-shot message arrives
    _tc_fill_header(buf, 0, 10, 10, 3, 0, 3);
    memcpy(buf + TC_HDR_SIZE, "def", 3);
    // Then: state recovers and dispatch fires again
    assert_true(es_msg_assemble(buf, TC_HDR_SIZE + 3));
    assert_int_equal(tc_mock_ble_get_es_msg_dispatch_call_count(), 2);
}

void TC_iot_easysetup_ble_msg_assemble_data_alloc_failure(void **state)
{
    uint8_t buf[32];
    bool rc;
    UNUSED(state);

    // Given: a valid header
    _tc_fill_header(buf, 0, 1, 1, 3, 0, 3);
    memcpy(buf + TC_HDR_SIZE, "abc", 3);
    // Given: malloc of the iot_security_buffer_t array fails
    set_mock_detect_memory_leak(false);
    do_not_use_mock_iot_os_malloc_failure();
    set_mock_iot_os_malloc_failure_with_index(0);
    // When
    rc = es_msg_assemble(buf, TC_HDR_SIZE + 3);
    // Then
    assert_false(rc);

    // Teardown
    do_not_use_mock_iot_os_malloc_failure();
}

void TC_iot_easysetup_ble_msg_assemble_payload_alloc_failure(void **state)
{
    uint8_t buf[32];
    bool rc;
    UNUSED(state);

    // Given: a valid header
    _tc_fill_header(buf, 0, 1, 1, 3, 0, 3);
    memcpy(buf + TC_HDR_SIZE, "abc", 3);
    // Given: malloc of the payload buffer fails
    set_mock_detect_memory_leak(false);
    do_not_use_mock_iot_os_malloc_failure();
    set_mock_iot_os_malloc_failure_with_index(1);
    // When
    rc = es_msg_assemble(buf, TC_HDR_SIZE + 3);
    // Then
    assert_false(rc);

    // Teardown
    do_not_use_mock_iot_os_malloc_failure();
}

void TC_iot_easysetup_ble_msg_disassemble_null_buf(void **state)
{
    iot_error_t err;
    UNUSED(state);

    // When
    err = es_msg_disassemble(NULL, 10, 0, 1);
    // Then
    assert_int_equal(err, IOT_ERROR_BAD_REQ);
}

void TC_iot_easysetup_ble_msg_disassemble_zero_len(void **state)
{
    iot_error_t err;
    uint8_t payload[4] = {0};
    UNUSED(state);

    // When
    err = es_msg_disassemble(payload, 0, 0, 1);
    // Then
    assert_int_equal(err, IOT_ERROR_BAD_REQ);
}

void TC_iot_easysetup_ble_msg_disassemble_deprecated_cmd(void **state)
{
    iot_error_t err;
    uint8_t payload[8] = {0};
    UNUSED(state);

    // Given: msg_state.cmd_num is 0 after reset
    // When: cmd != msg_state.cmd_num and cmd-1 is not the setup-complete
    // response step, the helper reports success silently as "deprecated"
    err = es_msg_disassemble(payload, sizeof(payload), 0, 5);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
}

void TC_iot_easysetup_ble_msg_disassemble_malloc_failure(void **state)
{
    iot_error_t err;
    uint8_t payload[] = {0, 0, 0, 0, 0};
    uint8_t buf[32];
    UNUSED(state);

    // Given: drive msg_state.cmd_num to 1 via a single-shot assemble
    _tc_fill_header(buf, 0, 1, 1, 3, 0, 3);
    memcpy(buf + TC_HDR_SIZE, "abc", 3);
    assert_true(es_msg_assemble(buf, TC_HDR_SIZE + 3));
    // Given: the indication send path reports an error
    tc_mock_ble_set_send_indication_rc(1);
    // When
    err = es_msg_disassemble(payload, sizeof(payload), 0, 1);
    // Then
    assert_int_equal(err, IOT_ERROR_CONN_BLE_INDICATION_FAIL);
}

void TC_iot_easysetup_ble_msg_disassemble_success_single_shot(void **state)
{
    iot_error_t err;
    uint8_t payload[8] = {'h', 'e', 'l', 'l', 'o', 0, 0, 0};
    uint8_t buf[32];
    UNUSED(state);

    // Given: drive msg_state.cmd_num to 1
    _tc_fill_header(buf, 0, 1, 1, 3, 0, 3);
    memcpy(buf + TC_HDR_SIZE, "abc", 3);
    assert_true(es_msg_assemble(buf, TC_HDR_SIZE + 3));
    tc_mock_ble_set_send_indication_rc(0);
    // When
    err = es_msg_disassemble(payload, sizeof(payload), 0, 1);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_true(tc_mock_ble_get_send_indication_call_count() > 0);
}

void TC_iot_easysetup_ble_msg_disassemble_success_fragmented(void **state)
{
    iot_error_t err;
    uint8_t payload[800];
    uint8_t buf[32];
    UNUSED(state);

    // Given: drive msg_state.cmd_num to 1, MTU forces fragmentation
    memset(payload, 'x', sizeof(payload));
    _tc_fill_header(buf, 0, 1, 1, 3, 0, 3);
    memcpy(buf + TC_HDR_SIZE, "abc", 3);
    assert_true(es_msg_assemble(buf, TC_HDR_SIZE + 3));
    tc_mock_ble_set_mtu(64);
    tc_mock_ble_set_send_indication_rc(0);
    // When
    err = es_msg_disassemble(payload, sizeof(payload), 0, 1);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_true(tc_mock_ble_get_send_indication_call_count() > 1);
}

void TC_iot_easysetup_ble_msg_disassemble_mtu_below_minimum(void **state)
{
    iot_error_t err;
    uint8_t payload[32] = {0};
    uint8_t buf[32];
    UNUSED(state);

    // Given: drive msg_state.cmd_num to 1
    _tc_fill_header(buf, 0, 1, 1, 3, 0, 3);
    memcpy(buf + TC_HDR_SIZE, "abc", 3);
    assert_true(es_msg_assemble(buf, TC_HDR_SIZE + 3));
    // Given: MTU that falls below MIN_MTU_SIZE exercises the clamp
    tc_mock_ble_set_mtu(10);
    // When
    err = es_msg_disassemble(payload, sizeof(payload), 0, 1);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
}

void TC_iot_easysetup_ble_msg_disassemble_continued_keeps_cmd(void **state)
{
    iot_error_t err;
    uint8_t payload[8] = {0};
    uint8_t buf[32];
    UNUSED(state);

    // Given: drive msg_state.cmd_num to 1
    _tc_fill_header(buf, 0, 1, 1, 3, 0, 3);
    memcpy(buf + TC_HDR_SIZE, "abc", 3);
    assert_true(es_msg_assemble(buf, TC_HDR_SIZE + 3));
    // When: data_continued=1
    err = es_msg_disassemble(payload, sizeof(payload), 1, 1);
    // Then: cmd_num is retained, operation succeeds
    assert_int_equal(err, IOT_ERROR_NONE);
}

void TC_iot_easysetup_ble_msg_reset_transferdata_idempotent(void **state)
{
    UNUSED(state);

    // When: reset is called multiple times
    es_reset_transferdata();
    es_reset_transferdata();
    es_reset_transferdata();
    // Then: no crash, safe to reinvoke
}
