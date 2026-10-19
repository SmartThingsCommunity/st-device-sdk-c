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
#include <string.h>

#include "TC_MOCK_functions.h"
#include "TC_REGISTRY.h"
#include "cmocka_custom.h"
#include "iot_error.h"
#include "iot_sntp.h"

#define UNUSED(x) (void **)(x)

#define SNTP_PACKET_SIZE 48
#define SNTP_LI_VN_MODE_REQUEST 0x23  /* LI=0, VN=4, Mode=3 (client) */
#define SNTP_LI_VN_MODE_RESPONSE 0x24 /* LI=0, VN=4, Mode=4 (server) */
#define SNTP_LI_ALARM 0xc0
#define SNTP_TX_TIMESTAMP_OFFSET 40
#define SNTP_UNIX_OFFSET 2208988800UL
#define SNTP_ERA1_UNIX_BASE 2085978496UL

TEST_SUITE("iot_sntp.c");

static void _build_sntp_response(unsigned char *pkt, unsigned char li_vn_mode, unsigned char stratum, uint32_t tx_secs)
{
    memset(pkt, 0, SNTP_PACKET_SIZE);
    pkt[0] = li_vn_mode;
    pkt[1] = stratum;
    pkt[SNTP_TX_TIMESTAMP_OFFSET] = (unsigned char)(tx_secs >> 24);
    pkt[SNTP_TX_TIMESTAMP_OFFSET + 1] = (unsigned char)(tx_secs >> 16);
    pkt[SNTP_TX_TIMESTAMP_OFFSET + 2] = (unsigned char)(tx_secs >> 8);
    pkt[SNTP_TX_TIMESTAMP_OFFSET + 3] = (unsigned char)tx_secs;
}

static void _expect_sntp_request(void)
{
    static const unsigned char request_first_byte[] = {SNTP_LI_VN_MODE_REQUEST};

    expect_memory(__wrap_port_net_write, buf, request_first_byte, sizeof(request_first_byte));
    expect_value(__wrap_port_net_write, len, SNTP_PACKET_SIZE);
}

TEST(TC_iot_sntp_sync_success_pos)
{
    iot_error_t err;
    unsigned char response[SNTP_PACKET_SIZE];
    uint32_t ntp_secs = (uint32_t)(1767225600UL + SNTP_UNIX_OFFSET); /* 2026-01-01 00:00:00 UTC, era 0 */

    UNUSED(state);

    // Given: first server returns a valid era-0 response
    _build_sntp_response(response, SNTP_LI_VN_MODE_RESPONSE, 2, ntp_secs);
    port_net_mock_reset_socket_status(1);
    port_net_mock_reset_read_stream(response, sizeof(response));

    _expect_sntp_request();
    expect_value(__wrap_iot_bsp_system_set_time_in_sec, time_in_sec, 1767225600UL);

    // When
    err = iot_sntp_sync();

    // Then
    assert_int_equal(err, IOT_ERROR_NONE);

    // Teardown
    port_net_mock_reset_read_stream(NULL, 0);
}

TEST(TC_iot_sntp_sync_era1_rollover_success_pos)
{
    iot_error_t err;
    unsigned char response[SNTP_PACKET_SIZE];
    uint32_t ntp_secs = 100; /* MSB cleared: era 1 (after Feb 2036) */

    UNUSED(state);

    // Given: server timestamp is past the 2036 NTP era rollover
    _build_sntp_response(response, SNTP_LI_VN_MODE_RESPONSE, 2, ntp_secs);
    port_net_mock_reset_socket_status(1);
    port_net_mock_reset_read_stream(response, sizeof(response));

    _expect_sntp_request();
    expect_value(__wrap_iot_bsp_system_set_time_in_sec, time_in_sec, SNTP_ERA1_UNIX_BASE + 100);

    // When
    err = iot_sntp_sync();

    // Then
    assert_int_equal(err, IOT_ERROR_NONE);

    // Teardown
    port_net_mock_reset_read_stream(NULL, 0);
}

TEST(TC_iot_sntp_sync_connect_failure_neg)
{
    iot_error_t err;

    UNUSED(state);

    // Given: connect fails for every server
    port_net_mock_reset_socket_status(0);
    port_net_mock_set_connect_fail_result(PORT_NET_CONNECT_OPERATION_FAIL);
    port_net_mock_reset_read_stream(NULL, 0);

    // When
    err = iot_sntp_sync();

    // Then: no time is set
    assert_int_equal(err, IOT_ERROR_NET_SNTP);
}

TEST(TC_iot_sntp_sync_response_timeout_neg)
{
    iot_error_t err;

    UNUSED(state);

    // Given: connected but no response arrives (empty read stream)
    port_net_mock_reset_socket_status(1);
    port_net_mock_reset_read_stream(NULL, 0);

    _expect_sntp_request();

    // When
    err = iot_sntp_sync();

    // Then
    assert_int_equal(err, IOT_ERROR_NET_SNTP);
}

TEST(TC_iot_sntp_sync_short_response_neg)
{
    iot_error_t err;
    unsigned char response[SNTP_PACKET_SIZE];

    UNUSED(state);

    // Given: server returns fewer bytes than a full SNTP packet
    _build_sntp_response(response, SNTP_LI_VN_MODE_RESPONSE, 2, (uint32_t)SNTP_UNIX_OFFSET);
    port_net_mock_reset_socket_status(1);
    port_net_mock_reset_read_stream(response, SNTP_PACKET_SIZE / 2);

    _expect_sntp_request();

    // When
    err = iot_sntp_sync();

    // Then
    assert_int_equal(err, IOT_ERROR_NET_SNTP);

    // Teardown
    port_net_mock_reset_read_stream(NULL, 0);
}

TEST(TC_iot_sntp_sync_invalid_mode_neg)
{
    iot_error_t err;
    unsigned char response[SNTP_PACKET_SIZE];

    UNUSED(state);

    // Given: response mode is not server (e.g. the request echoed back)
    _build_sntp_response(response, SNTP_LI_VN_MODE_REQUEST, 2, (uint32_t)(1767225600UL + SNTP_UNIX_OFFSET));
    port_net_mock_reset_socket_status(1);
    port_net_mock_reset_read_stream(response, sizeof(response));

    _expect_sntp_request();

    // When
    err = iot_sntp_sync();

    // Then
    assert_int_equal(err, IOT_ERROR_NET_SNTP);

    // Teardown
    port_net_mock_reset_read_stream(NULL, 0);
}

TEST(TC_iot_sntp_sync_kod_stratum_zero_neg)
{
    iot_error_t err;
    unsigned char response[SNTP_PACKET_SIZE];

    UNUSED(state);

    // Given: kiss-of-death response (stratum 0)
    _build_sntp_response(response, SNTP_LI_VN_MODE_RESPONSE, 0, (uint32_t)(1767225600UL + SNTP_UNIX_OFFSET));
    port_net_mock_reset_socket_status(1);
    port_net_mock_reset_read_stream(response, sizeof(response));

    _expect_sntp_request();

    // When
    err = iot_sntp_sync();

    // Then
    assert_int_equal(err, IOT_ERROR_NET_SNTP);

    // Teardown
    port_net_mock_reset_read_stream(NULL, 0);
}

TEST(TC_iot_sntp_sync_clock_unsynchronized_neg)
{
    iot_error_t err;
    unsigned char response[SNTP_PACKET_SIZE];

    UNUSED(state);

    // Given: leap indicator reports the server clock is unsynchronized
    _build_sntp_response(response, SNTP_LI_ALARM | SNTP_LI_VN_MODE_RESPONSE, 2,
                         (uint32_t)(1767225600UL + SNTP_UNIX_OFFSET));
    port_net_mock_reset_socket_status(1);
    port_net_mock_reset_read_stream(response, sizeof(response));

    _expect_sntp_request();

    // When
    err = iot_sntp_sync();

    // Then
    assert_int_equal(err, IOT_ERROR_NET_SNTP);

    // Teardown
    port_net_mock_reset_read_stream(NULL, 0);
}

TEST(TC_iot_sntp_sync_set_time_failure_neg)
{
    iot_error_t err;
    unsigned char response[SNTP_PACKET_SIZE];

    UNUSED(state);

    // Given: valid response but setting the system time fails
    _build_sntp_response(response, SNTP_LI_VN_MODE_RESPONSE, 2, (uint32_t)(1767225600UL + SNTP_UNIX_OFFSET));
    port_net_mock_reset_socket_status(1);
    port_net_mock_reset_read_stream(response, sizeof(response));

    _expect_sntp_request();
    expect_value(__wrap_iot_bsp_system_set_time_in_sec, time_in_sec, 1767225600UL);
    set_mock_iot_bsp_system_set_time_failure(IOT_ERROR_BAD_REQ);

    // When
    err = iot_sntp_sync();

    // Then: the set_time error is propagated
    assert_int_equal(err, IOT_ERROR_BAD_REQ);

    // Teardown
    port_net_mock_reset_read_stream(NULL, 0);
}
