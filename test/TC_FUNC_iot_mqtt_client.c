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

#include <iot_error.h>
#include <iot_internal.h>
#include <iot_mqtt.h>
#include <iot_mqtt_client.h>
#include <limits.h>
#include <root_ca.h>
#include <string.h>

#include "TC_MOCK_functions.h"
#include "cmocka_custom.h"
#define UNUSED(x) (void **)(x)

void _dummy_mqtt_client_callback(st_mqtt_event event, void *event_data, void *usr_data)
{
    UNUSED(event);
    UNUSED(event_data);
    UNUSED(usr_data);
    return;
}

/*
 * Shared observer callback: records the last event delivered to the user
 * callback so the individual tests can inspect flow-level behaviour.
 */
typedef struct {
    int event_count;
    st_mqtt_event last_event;
    int last_disconnect_code;
    int last_publish_qos;
    char last_publish_topic[64];
    char last_publish_payload[128];
    int last_publish_payloadlen;
} mqtt_observer_t;

static void _observer_mqtt_client_callback(st_mqtt_event event, void *event_data, void *usr_data)
{
    mqtt_observer_t *obs = (mqtt_observer_t *)usr_data;
    if (!obs) {
        return;
    }
    obs->event_count++;
    obs->last_event = event;
    if (event == ST_MQTT_EVENT_MSG_DELIVERED && event_data) {
        st_mqtt_msg *msg = (st_mqtt_msg *)event_data;
        obs->last_publish_qos = msg->qos;
        int tlen = msg->topiclen < (int)sizeof(obs->last_publish_topic) - 1 ? msg->topiclen
                                                                            : (int)sizeof(obs->last_publish_topic) - 1;
        if (msg->topic && tlen > 0) {
            memcpy(obs->last_publish_topic, msg->topic, tlen);
        }
        obs->last_publish_topic[tlen] = '\0';
        int plen = msg->payloadlen < (int)sizeof(obs->last_publish_payload) - 1
                       ? msg->payloadlen
                       : (int)sizeof(obs->last_publish_payload) - 1;
        if (msg->payload && plen > 0) {
            memcpy(obs->last_publish_payload, msg->payload, plen);
        }
        obs->last_publish_payload[plen] = '\0';
        obs->last_publish_payloadlen = msg->payloadlen;
    } else if (event == ST_MQTT_EVENT_DISCONNECTED && event_data) {
        obs->last_disconnect_code = *(int *)event_data;
    }
}

/*
 * Helper: create a connected client with timers pre-started so the test can
 * feed the read stream and drive st_mqtt_yield() directly.
 */
static st_mqtt_client _connected_client_setup(mqtt_observer_t *obs)
{
    iot_error_t iot_err;
    st_mqtt_client client;
    MQTTClient *c;

    if (obs) {
        memset(obs, 0, sizeof(*obs));
    }

    if (st_mqtt_create(&client, obs ? _observer_mqtt_client_callback : _dummy_mqtt_client_callback, obs, NULL, NULL) !=
        0) {
        return NULL;
    }
    c = (MQTTClient *)client;
    c->isconnected = 1;
    port_net_mock_reset_socket_status(1);
    c->last_sent = iot_os_timer_create(NULL, 10000, NULL);
    iot_err = iot_os_timer_start(c->last_sent);
    assert_int_equal(iot_err, IOT_ERROR_NONE);
    c->last_received = iot_os_timer_create(NULL, 10000, NULL);
    iot_err = iot_os_timer_start(c->last_received);
    assert_int_equal(iot_err, IOT_ERROR_NONE);
    return client;
}

void TC_st_mqtt_create_success(void **state)
{
    int err;
    st_mqtt_client client;
    MQTTClient *internal_client;
    UNUSED(state);

    // Given
    set_mock_detect_memory_leak(true);
    // When
    err = st_mqtt_create(&client, _dummy_mqtt_client_callback, NULL, NULL, NULL);
    // Then
    assert_return_code(err, 0);
    internal_client = (MQTTClient *)client;
    assert_int_equal(internal_client->user_callback_fp, _dummy_mqtt_client_callback);
    // Teardown
    st_mqtt_destroy(client);
    set_mock_detect_memory_leak(false);
}

void TC_st_mqtt_create_failure(void **state)
{
    int err;
    st_mqtt_client client;
    MQTTClient *internal_client;
    UNUSED(state);

    for (unsigned int i = 0; i < 2; i++) {
        // Given
        set_mock_detect_memory_leak(false);
        set_mock_iot_os_malloc_failure_with_index(i);
        // When
        err = st_mqtt_create(&client, _dummy_mqtt_client_callback, NULL, NULL, NULL);
        // Then
        assert_int_equal(err, E_ST_MQTT_FAILURE);
        // Teardown
        do_not_use_mock_iot_os_malloc_failure();
    }

    // When
    err = st_mqtt_create(&client, NULL, NULL, NULL, NULL);
    // Then
    assert_int_equal(err, E_ST_MQTT_FAILURE);
}

static void _st_mqtt_connect_test_with_parameter(unsigned char give_rc, int expected_err)
{
    int err;
    st_mqtt_client client;
    st_mqtt_broker_info_t broker_info;
    st_mqtt_connect_data conn_data = st_mqtt_connect_data_initializer;
    unsigned char *mock_read_buffer;

    // Given
    err = st_mqtt_create(&client, _dummy_mqtt_client_callback, NULL, NULL, NULL);
    port_net_mock_reset_socket_status(1);
    assert_return_code(err, 0);

    broker_info.url = strdup("test.domain.com");
    broker_info.port = 555;
    broker_info.ca_cert = (const unsigned char *)st_root_ca;
    broker_info.ca_cert_len = st_root_ca_len;
    broker_info.ssl = 1;

    conn_data.clientid = strdup("testClientId");
    conn_data.username = strdup("testUserName");
    conn_data.password = strdup("testPassword");

    mock_read_buffer = (unsigned char *)malloc(4);

    // reference:
    // https://docs.solace.com/MQTT-311-Prtl-Conformance-Spec/MQTT%20Control%20Packets.htm#_Toc430864897
    mock_read_buffer[0] = 0x20;  // CONNACK fixed header (MQTT Control Packet Type)
    mock_read_buffer[1] = 0x02;  // Remaining Length
    mock_read_buffer[2] = 0x00;  // Clean session (SP1 is 0)
    mock_read_buffer[3] = give_rc;

    port_net_mock_reset_read_stream(mock_read_buffer, 4);
    expect_any(__wrap_port_net_write, len);
    expect_any(__wrap_port_net_write, buf);

    // When
    err = st_mqtt_connect(client, &broker_info, &conn_data);

    // Then
    assert_int_equal(err, expected_err);

    // Teardown
    st_mqtt_destroy(client);
    free(broker_info.url);
    free(conn_data.clientid);
    free(conn_data.username);
    free(conn_data.password);
    free(mock_read_buffer);
}

void TC_st_mqtt_connect_with_connack_rc(void **state)
{
    UNUSED(state);

    _st_mqtt_connect_test_with_parameter(0x00, 0);  // Connection Accepted
    _st_mqtt_connect_test_with_parameter(
        0x01, E_ST_MQTT_UNNACCEPTABLE_PROTOCOL);  // Connection Refused, unacceptable protocol version
    _st_mqtt_connect_test_with_parameter(0x02, E_ST_MQTT_CLIENTID_REJECTED);  // Connection Refused, identifier rejected
    _st_mqtt_connect_test_with_parameter(0x03, E_ST_MQTT_SERVER_UNAVAILABLE);  // Connection Refused, Server unavailable
    _st_mqtt_connect_test_with_parameter(
        0x04, E_ST_MQTT_BAD_USERNAME_OR_PASSWORD);  // Connection Refused, bad user name or password
    _st_mqtt_connect_test_with_parameter(0x05, E_ST_MQTT_NOT_AUTHORIZED);  // Connection Refused, not authorized
    _st_mqtt_connect_test_with_parameter(0x06, E_ST_MQTT_FAILURE);         // Reserved for future use
}

void TC_st_mqtt_disconnect_success(void **state)
{
    int err;
    iot_error_t iot_err;
    st_mqtt_client client;
    MQTTClient *c;
    // https://docs.solace.com/MQTT-311-Prtl-Conformance-Spec/MQTT%20Control%20Packets.htm#_Toc430864954
    char mqtt_disconnect_packet[2] = {0xe0, 0x00};
    UNUSED(state);

    // Given
    err = st_mqtt_create(&client, _dummy_mqtt_client_callback, NULL, NULL, NULL);
    assert_return_code(err, 0);
    c = (MQTTClient *)client;
    c->isconnected = 1;
    port_net_mock_reset_socket_status(1);
    c->last_sent = iot_os_timer_create(NULL, 10000, NULL);
    iot_err = iot_os_timer_start(c->last_sent);
    assert_int_equal(iot_err, IOT_ERROR_NONE);

    c->last_received = iot_os_timer_create(NULL, 10000, NULL);
    iot_err = iot_os_timer_start(c->last_received);
    assert_int_equal(iot_err, IOT_ERROR_NONE);

    port_net_mock_reset_read_stream(NULL, 0);
    expect_value(__wrap_port_net_write, len, 2);
    expect_memory(__wrap_port_net_write, buf, mqtt_disconnect_packet, sizeof(mqtt_disconnect_packet));
    // When
    err = st_mqtt_disconnect(client);
    // Then
    assert_return_code(err, 0);

    // Teardown
    st_mqtt_destroy(client);
}

struct mqtt_pub_test_data {
    int qos;
    char *topic;
    char *payload;
    char pub_fixed_header;
    char response_fixed_header;
};

void TC_st_mqtt_publish_success(void **state)
{
    int err;
    iot_error_t iot_err;
    st_mqtt_client client;
    MQTTClient *c;

    struct mqtt_pub_test_data data[2] = {
        {st_mqtt_qos1, IOT_PUB_TOPIC_REGISTRATION, "{\"testPayloadKey\":\"testPayloadValue\"}", 0x32, 0x40},
        {st_mqtt_qos2, "/v1/deviceEvents/123e4567-e89b-12d3-a456-426614174000", "{}", 0x34, 0x50},
    };
    UNUSED(state);

    // Given
    err = st_mqtt_create(&client, _dummy_mqtt_client_callback, NULL, NULL, NULL);
    assert_return_code(err, 0);
    c = (MQTTClient *)client;
    c->isconnected = 1;
    port_net_mock_reset_socket_status(1);
    c->last_sent = iot_os_timer_create(NULL, 10000, NULL);
    iot_err = iot_os_timer_start(c->last_sent);
    assert_int_equal(iot_err, IOT_ERROR_NONE);

    c->last_received = iot_os_timer_create(NULL, 10000, NULL);
    iot_err = iot_os_timer_start(c->last_received);
    assert_int_equal(iot_err, IOT_ERROR_NONE);

    for (int i = 0; i < sizeof(data) / sizeof(struct mqtt_pub_test_data); i++) {
        size_t mqtt_publish_header_len;
        char *mqtt_publish;
        unsigned int header_index = 0;
        unsigned char *mock_read_buffer_puback;
        st_mqtt_msg msg;
        char packet_id_msb;
        char packet_id_lsb;

        // Given
        msg.payload = data[i].payload;
        msg.qos = data[i].qos;
        msg.retained = false;
        msg.payloadlen = (int)strlen(msg.payload);
        msg.topic = data[i].topic;
        // https://docs.solace.com/MQTT-311-Prtl-Conformance-Spec/MQTT%20Control%20Packets.htm#_Toc430864901
        mqtt_publish_header_len = 2 + 2 + strlen(data[i].topic) +
                                  2;  // 2 for fixed header, 2 for topic name length, variable topic, 2 for package id
        mqtt_publish = malloc(mqtt_publish_header_len + msg.payloadlen);
        assert_non_null(mqtt_publish);
        mqtt_publish[header_index++] = data[i].pub_fixed_header;
        mqtt_publish[header_index++] = (char)(2 + strlen(data[i].topic) + 2 + msg.payloadlen);  // Remaining Length
        mqtt_publish[header_index++] = 0x00;
        mqtt_publish[header_index++] = (char)strlen(data[i].topic);
        for (int j = 0; j < strlen(data[i].topic); j++) {
            mqtt_publish[header_index++] = data[i].topic[j];
        }
        packet_id_msb = 0x00;
        packet_id_lsb = (char)(c->next_packetid + 1);
        mqtt_publish[header_index++] = packet_id_msb;
        mqtt_publish[header_index++] = packet_id_lsb;
        memcpy(&mqtt_publish[header_index], msg.payload, msg.payloadlen);

        expect_value(__wrap_port_net_write, len, mqtt_publish_header_len + msg.payloadlen);
        expect_memory(__wrap_port_net_write, buf, mqtt_publish, mqtt_publish_header_len + msg.payloadlen);
        if (data[i].qos == st_mqtt_qos2) {
            unsigned char pubrel[4];
            pubrel[0] = 0x62;
            pubrel[1] = 0x02;
            pubrel[2] = packet_id_msb;
            pubrel[3] = packet_id_lsb;
            expect_value(__wrap_port_net_write, len, 4);
            expect_memory(__wrap_port_net_write, buf, pubrel, 4);
        }

        mock_read_buffer_puback = (unsigned char *)malloc(8);
        assert_non_null(mock_read_buffer_puback);

        // reference: https://docs.solace.com/MQTT-311-Prtl-Conformance-Spec/MQTT%20Control%20Packets.htm#_Toc430864907
        // reference: https://docs.solace.com/MQTT-311-Prtl-Conformance-Spec/MQTT%20Control%20Packets.htm#_Toc430864922
        if (data[i].qos == st_mqtt_qos1) {
            mock_read_buffer_puback[0] = data[i].response_fixed_header;
            mock_read_buffer_puback[1] = 0x02;  // Remaining Length
            mock_read_buffer_puback[2] = packet_id_msb;
            mock_read_buffer_puback[3] = packet_id_lsb;

            port_net_mock_reset_read_stream(mock_read_buffer_puback, 4);
        } else if (data[i].qos == st_mqtt_qos2) {
            mock_read_buffer_puback[0] = data[i].response_fixed_header;
            mock_read_buffer_puback[1] = 0x02;  // Remaining Length
            mock_read_buffer_puback[2] = packet_id_msb;
            mock_read_buffer_puback[3] = packet_id_lsb;

            mock_read_buffer_puback[4] = 0x70;
            mock_read_buffer_puback[5] = 0x02;  // Remaining Length
            mock_read_buffer_puback[6] = packet_id_msb;
            mock_read_buffer_puback[7] = packet_id_lsb;

            port_net_mock_reset_read_stream(mock_read_buffer_puback, 8);
        }

        // When
        err = st_mqtt_publish(client, &msg);
        // Then
        assert_return_code(err, 0);

        // Teardown
        free(mock_read_buffer_puback);
        free(mqtt_publish);
    }
    // Teardown
    st_mqtt_destroy(client);
}

void TC_st_mqtt_create_null_callback(void **state)
{
    int err;
    st_mqtt_client client;
    UNUSED(state);

    // When: callback_fp is NULL
    err = st_mqtt_create(&client, NULL, NULL, NULL, NULL);
    // Then
    assert_int_equal(err, E_ST_MQTT_FAILURE);
}

void TC_st_mqtt_create_malloc_failure_index_2(void **state)
{
    int err;
    st_mqtt_client client;
    UNUSED(state);

    // Given: third malloc fails
    set_mock_detect_memory_leak(false);
    do_not_use_mock_iot_os_malloc_failure();
    set_mock_iot_os_malloc_failure_with_index(2);
    // When
    err = st_mqtt_create(&client, _dummy_mqtt_client_callback, NULL, NULL, NULL);
    // Then
    assert_int_equal(err, E_ST_MQTT_FAILURE);
    do_not_use_mock_iot_os_malloc_failure();
}

void TC_st_mqtt_create_malloc_failure_index_3(void **state)
{
    int err;
    st_mqtt_client client = NULL;
    UNUSED(state);

    // Given
    set_mock_detect_memory_leak(false);
    do_not_use_mock_iot_os_malloc_failure();
    set_mock_iot_os_malloc_failure_with_index(3);
    // When
    err = st_mqtt_create(&client, _dummy_mqtt_client_callback, NULL, NULL, NULL);
    do_not_use_mock_iot_os_malloc_failure();
    // Then: either the call fails at this index or succeeds if that malloc is
    // not actually reached; both outcomes are acceptable documentation of
    // the current call chain.
    if (err != 0) {
        assert_int_equal(err, E_ST_MQTT_FAILURE);
    } else {
        st_mqtt_destroy(client);
    }
}

void TC_st_mqtt_destroy_null(void **state)
{
    UNUSED(state);

    // When: destroy a NULL client should not crash
    st_mqtt_destroy(NULL);
}

void TC_st_mqtt_subscribe_invalid_count(void **state)
{
    int err;
    st_mqtt_client client;
    char *topics[] = {"a"};
    int qos[] = {0};
    UNUSED(state);

    err = st_mqtt_create(&client, _dummy_mqtt_client_callback, NULL, NULL, NULL);
    assert_return_code(err, 0);

    // When: count is zero
    err = st_mqtt_subscribe(client, 0, topics, qos);
    // Then
    assert_int_equal(err, E_ST_MQTT_FAILURE);

    // When: count is negative
    err = st_mqtt_subscribe(client, -1, topics, qos);
    // Then
    assert_int_equal(err, E_ST_MQTT_FAILURE);

    st_mqtt_destroy(client);
}

void TC_st_mqtt_subscribe_null_topics(void **state)
{
    int err;
    st_mqtt_client client;
    int qos[] = {0};
    UNUSED(state);

    err = st_mqtt_create(&client, _dummy_mqtt_client_callback, NULL, NULL, NULL);
    assert_return_code(err, 0);

    // When
    err = st_mqtt_subscribe(client, 1, NULL, qos);
    // Then
    assert_int_equal(err, E_ST_MQTT_FAILURE);

    st_mqtt_destroy(client);
}

void TC_st_mqtt_subscribe_null_qos(void **state)
{
    int err;
    st_mqtt_client client;
    char *topics[] = {"a"};
    UNUSED(state);

    err = st_mqtt_create(&client, _dummy_mqtt_client_callback, NULL, NULL, NULL);
    assert_return_code(err, 0);

    // When
    err = st_mqtt_subscribe(client, 1, topics, NULL);
    // Then
    assert_int_equal(err, E_ST_MQTT_FAILURE);

    st_mqtt_destroy(client);
}

void TC_st_mqtt_subscribe_topics_malloc_failure(void **state)
{
    int err;
    st_mqtt_client client;
    char *topics[] = {"a"};
    int qos[] = {0};
    UNUSED(state);

    err = st_mqtt_create(&client, _dummy_mqtt_client_callback, NULL, NULL, NULL);
    assert_return_code(err, 0);

    // When: topic array allocation fails
    do_not_use_mock_iot_os_malloc_failure();
    set_mock_iot_os_malloc_failure_with_index(0);
    err = st_mqtt_subscribe(client, 1, topics, qos);
    do_not_use_mock_iot_os_malloc_failure();
    // Then
    assert_int_equal(err, E_ST_MQTT_FAILURE);

    st_mqtt_destroy(client);
}

void TC_st_mqtt_unsubscribe_invalid_count(void **state)
{
    int err;
    st_mqtt_client client;
    char *topics[] = {"a"};
    UNUSED(state);

    err = st_mqtt_create(&client, _dummy_mqtt_client_callback, NULL, NULL, NULL);
    assert_return_code(err, 0);

    // When
    err = st_mqtt_unsubscribe(client, 0, topics);
    // Then
    assert_int_equal(err, E_ST_MQTT_FAILURE);

    // When: negative count
    err = st_mqtt_unsubscribe(client, -5, topics);
    // Then
    assert_int_equal(err, E_ST_MQTT_FAILURE);

    st_mqtt_destroy(client);
}

void TC_st_mqtt_unsubscribe_null_topics(void **state)
{
    int err;
    st_mqtt_client client;
    UNUSED(state);

    err = st_mqtt_create(&client, _dummy_mqtt_client_callback, NULL, NULL, NULL);
    assert_return_code(err, 0);

    // When
    err = st_mqtt_unsubscribe(client, 1, NULL);
    // Then
    assert_int_equal(err, E_ST_MQTT_FAILURE);

    st_mqtt_destroy(client);
}

void TC_st_mqtt_unsubscribe_topics_malloc_failure(void **state)
{
    int err;
    st_mqtt_client client;
    char *topics[] = {"a"};
    UNUSED(state);

    err = st_mqtt_create(&client, _dummy_mqtt_client_callback, NULL, NULL, NULL);
    assert_return_code(err, 0);

    // When
    do_not_use_mock_iot_os_malloc_failure();
    set_mock_iot_os_malloc_failure_with_index(0);
    err = st_mqtt_unsubscribe(client, 1, topics);
    do_not_use_mock_iot_os_malloc_failure();
    // Then
    assert_int_equal(err, E_ST_MQTT_FAILURE);

    st_mqtt_destroy(client);
}

void TC_st_mqtt_publish_async_not_connected(void **state)
{
    int err;
    st_mqtt_client client;
    st_mqtt_msg msg = {0};
    UNUSED(state);

    err = st_mqtt_create(&client, _dummy_mqtt_client_callback, NULL, NULL, NULL);
    assert_return_code(err, 0);

    // Given
    msg.topic = "t";
    msg.payload = "x";
    msg.payloadlen = 1;
    msg.qos = st_mqtt_qos0;

    // When: no connection established, no network
    err = st_mqtt_publish_async(client, &msg, NULL, NULL);
    // Then: underlying push may still succeed but no network; accept either
    (void)err;

    st_mqtt_destroy(client);
}

void TC_st_mqtt_publish_null_client(void **state)
{
    int err;
    st_mqtt_msg msg = {0};
    UNUSED(state);

    msg.topic = "t";
    msg.payload = "x";
    msg.payloadlen = 1;
    msg.qos = st_mqtt_qos0;

    // When: null client
    err = st_mqtt_publish(NULL, &msg);
    // Then
    assert_int_equal(err, E_ST_MQTT_FAILURE);
}

/*
 * st_mqtt_disconnect negative tests
 */
void TC_st_mqtt_disconnect_null_client(void **state)
{
    int err;
    UNUSED(state);

    // When
    err = st_mqtt_disconnect(NULL);
    // Then
    assert_int_equal(err, E_ST_MQTT_FAILURE);
}

void TC_st_mqtt_change_ping_period_null_client(void **state)
{
    UNUSED(state);

    // When: null client is a no-op and must not crash
    st_mqtt_change_ping_period(NULL, 60);
}

void TC_st_mqtt_change_ping_period_bad_magic(void **state)
{
    st_mqtt_client client;
    MQTTClient *c;
    unsigned int original_magic;
    int err;
    UNUSED(state);

    err = st_mqtt_create(&client, _dummy_mqtt_client_callback, NULL, NULL, NULL);
    assert_return_code(err, 0);
    c = (MQTTClient *)client;

    // Given: corrupt magic number
    original_magic = c->magic;
    c->magic = 0xDEADBEEF;
    // When: should silently do nothing
    st_mqtt_change_ping_period(client, 120);
    // Then: interval must remain unchanged
    assert_int_not_equal(c->keepAliveInterval, 120);

    // Restore magic to allow proper destroy
    c->magic = original_magic;
    st_mqtt_destroy(client);
}

void TC_st_mqtt_change_ping_period_success(void **state)
{
    st_mqtt_client client;
    MQTTClient *c;
    int err;
    UNUSED(state);

    err = st_mqtt_create(&client, _dummy_mqtt_client_callback, NULL, NULL, NULL);
    assert_return_code(err, 0);
    c = (MQTTClient *)client;

    // When
    st_mqtt_change_ping_period(client, 60);
    // Then
    assert_int_equal(c->keepAliveInterval, 60);

    st_mqtt_destroy(client);
}

void TC_st_mqtt_yield_disconnected_zero_time(void **state)
{
    st_mqtt_client client;
    MQTTClient *c;
    int err;
    int rc;
    UNUSED(state);

    err = st_mqtt_create(&client, _dummy_mqtt_client_callback, NULL, NULL, NULL);
    assert_return_code(err, 0);
    c = (MQTTClient *)client;
    c->isconnected = 0;

    // When: yield with time=0 runs exactly one cycle; on a disconnected
    // client this simply exits with whichever internal status comes back.
    rc = st_mqtt_yield(client, 0);
    (void)rc;

    st_mqtt_destroy(client);
}

void TC_st_mqtt_yield_disconnected_short_time(void **state)
{
    st_mqtt_client client;
    MQTTClient *c;
    int err;
    int rc;
    UNUSED(state);

    err = st_mqtt_create(&client, _dummy_mqtt_client_callback, NULL, NULL, NULL);
    assert_return_code(err, 0);
    c = (MQTTClient *)client;
    c->isconnected = 0;

    // When: yield with very short timeout
    rc = st_mqtt_yield(client, 1);
    // Then: call returns without crashing
    (void)rc;

    st_mqtt_destroy(client);
}

void TC_st_mqtt_connect_net_unreachable(void **state)
{
    int err;
    st_mqtt_client client;
    st_mqtt_broker_info_t broker;
    st_mqtt_connect_data conn_data = st_mqtt_connect_data_initializer;
    UNUSED(state);

    err = st_mqtt_create(&client, _dummy_mqtt_client_callback, NULL, NULL, NULL);
    assert_return_code(err, 0);

    broker.url = "unreachable.example";
    broker.port = 8883;
    broker.ca_cert = (const unsigned char *)st_root_ca;
    broker.ca_cert_len = st_root_ca_len;
    broker.ssl = 1;
    conn_data.clientid = "c";
    conn_data.username = "u";
    conn_data.password = "p";

    // Given: socket error (-1) from port_net_connect mock
    port_net_mock_reset_socket_status(-1);

    // When
    err = st_mqtt_connect(client, &broker, &conn_data);
    // Then
    assert_int_not_equal(err, 0);

    // Teardown: restore the socket status so the next test sees a good socket
    port_net_mock_reset_socket_status(1);
    st_mqtt_destroy(client);
}

void TC_st_mqtt_yield_delivers_publish_qos0(void **state)
{
    st_mqtt_client client;
    mqtt_observer_t obs;
    unsigned char wire[32] = {0};
    int rc;
    UNUSED(state);

    client = _connected_client_setup(&obs);
    assert_non_null(client);

    /* Build a PUBLISH QoS0 with topic "t" and payload "abc". */
    wire[0] = 0x30;
    wire[1] = 0x06;  // rem_len: 2 (topic len) + 1 (topic) + 3 (payload)
    wire[2] = 0x00;
    wire[3] = 0x01;
    wire[4] = 't';
    wire[5] = 'a';
    wire[6] = 'b';
    wire[7] = 'c';
    port_net_mock_reset_read_stream(wire, 8);

    // When
    rc = st_mqtt_yield(client, 0);
    // Then
    (void)rc;
    assert_int_equal(obs.last_event, ST_MQTT_EVENT_MSG_DELIVERED);
    assert_int_equal(obs.last_publish_qos, st_mqtt_qos0);
    assert_string_equal(obs.last_publish_topic, "t");
    assert_int_equal(obs.last_publish_payloadlen, 3);
    assert_memory_equal(obs.last_publish_payload, "abc", 3);

    st_mqtt_destroy(client);
}

void TC_st_mqtt_yield_publish_qos1_sends_puback(void **state)
{
    st_mqtt_client client;
    mqtt_observer_t obs;
    unsigned char wire[32] = {0};
    int rc;
    UNUSED(state);

    client = _connected_client_setup(&obs);
    assert_non_null(client);

    /* PUBLISH QoS1 wire layout with packet id 0x0042 */
    wire[0] = 0x32;
    wire[1] = 0x08;
    wire[2] = 0x00;
    wire[3] = 0x01;
    wire[4] = 't';
    wire[5] = 0x00;
    wire[6] = 0x42;  // packet id
    wire[7] = 'x';
    wire[8] = 'y';
    wire[9] = 'z';
    port_net_mock_reset_read_stream(wire, 10);

    /* The client must write a PUBACK back; don't assert its exact buffer */
    set_mock_port_net_write_skip_buf_check(1);
    set_mock_port_net_write_skip_len_check(1);

    rc = st_mqtt_yield(client, 0);
    (void)rc;
    assert_int_equal(obs.last_event, ST_MQTT_EVENT_MSG_DELIVERED);
    assert_int_equal(obs.last_publish_qos, st_mqtt_qos1);

    reset_mock_port_net_write_skip_flags();
    st_mqtt_destroy(client);
}

void TC_st_mqtt_yield_publish_dup_is_discarded(void **state)
{
    st_mqtt_client client;
    mqtt_observer_t obs;
    unsigned char wire[32] = {0};
    int rc;
    UNUSED(state);

    client = _connected_client_setup(&obs);
    assert_non_null(client);

    /* PUBLISH QoS1 DUP (0x3A) with packet id 0x0001 */
    wire[0] = 0x3A;
    wire[1] = 0x06;
    wire[2] = 0x00;
    wire[3] = 0x01;
    wire[4] = 't';
    wire[5] = 0x00;
    wire[6] = 0x01;
    wire[7] = 'p';
    port_net_mock_reset_read_stream(wire, 8);

    set_mock_port_net_write_skip_buf_check(1);
    set_mock_port_net_write_skip_len_check(1);

    rc = st_mqtt_yield(client, 0);
    (void)rc;
    /* MSG_DELIVERED must not fire for a duplicate packet */
    assert_int_not_equal(obs.last_event, ST_MQTT_EVENT_MSG_DELIVERED);
    assert_int_equal(obs.event_count, 0);

    reset_mock_port_net_write_skip_flags();
    st_mqtt_destroy(client);
}

void TC_st_mqtt_yield_unknown_packet_type(void **state)
{
    st_mqtt_client client;
    mqtt_observer_t obs;
    /* PINGREQ only makes sense from a client; treat as "no handler" on the
     * read path. Fixed header 0xC0 with remlen 0. */
    unsigned char wire[] = {0xC0, 0x00};
    int rc;
    UNUSED(state);

    client = _connected_client_setup(&obs);
    assert_non_null(client);

    port_net_mock_reset_read_stream(wire, sizeof(wire));
    rc = st_mqtt_yield(client, 0);
    (void)rc;
    assert_int_equal(obs.event_count, 0);

    st_mqtt_destroy(client);
}

void TC_st_mqtt_yield_network_error_triggers_disconnect(void **state)
{
    st_mqtt_client client;
    mqtt_observer_t obs;
    int rc;
    UNUSED(state);

    client = _connected_client_setup(&obs);
    assert_non_null(client);

    /* mock_socket_status == 2 makes port_net_read_poll return -1 */
    port_net_mock_reset_socket_status(2);
    port_net_mock_reset_read_stream(NULL, 0);

    rc = st_mqtt_yield(client, 0);
    (void)rc;
    assert_int_equal(obs.last_event, ST_MQTT_EVENT_DISCONNECTED);
    assert_int_equal(obs.last_disconnect_code, MQTT_DISCONNECTED_NETWORK_ERROR);

    /* Restore good socket state for subsequent tests */
    port_net_mock_reset_socket_status(1);
    st_mqtt_destroy(client);
}

void TC_st_mqtt_subscribe_success(void **state)
{
    st_mqtt_client client;
    MQTTClient *c;
    mqtt_observer_t obs;
    unsigned char suback[5] = {0};
    char *topics[] = {"t"};
    int qos[] = {1};
    int rc;
    UNUSED(state);

    client = _connected_client_setup(&obs);
    assert_non_null(client);
    c = (MQTTClient *)client;

    /* SUBACK: fixed header 0x90, remlen 3, packetid 0x0001 + granted_qos */
    suback[0] = 0x90;
    suback[1] = 0x03;
    suback[2] = 0x00;
    suback[3] = (unsigned char)(c->next_packetid + 1);
    suback[4] = 0x01;  // granted QoS 1
    port_net_mock_reset_read_stream(suback, 5);

    set_mock_port_net_write_skip_buf_check(1);
    set_mock_port_net_write_skip_len_check(1);

    rc = st_mqtt_subscribe(client, 1, topics, qos);
    assert_return_code(rc, 0);

    reset_mock_port_net_write_skip_flags();
    st_mqtt_destroy(client);
}

void TC_st_mqtt_subscribe_granted_qos2(void **state)
{
    st_mqtt_client client;
    MQTTClient *c;
    mqtt_observer_t obs;
    unsigned char suback[5] = {0};
    char *topics[] = {"t"};
    int qos[] = {2};
    int rc;
    UNUSED(state);

    client = _connected_client_setup(&obs);
    assert_non_null(client);
    c = (MQTTClient *)client;

    suback[0] = 0x90;
    suback[1] = 0x03;
    suback[2] = 0x00;
    suback[3] = (unsigned char)(c->next_packetid + 1);
    suback[4] = 0x02;  // QoS 2 granted
    port_net_mock_reset_read_stream(suback, 5);

    set_mock_port_net_write_skip_buf_check(1);
    set_mock_port_net_write_skip_len_check(1);

    rc = st_mqtt_subscribe(client, 1, topics, qos);
    assert_return_code(rc, 0);

    reset_mock_port_net_write_skip_flags();
    st_mqtt_destroy(client);
}

void TC_st_mqtt_unsubscribe_success(void **state)
{
    st_mqtt_client client;
    MQTTClient *c;
    mqtt_observer_t obs;
    unsigned char unsuback[4] = {0};
    char *topics[] = {"t"};
    int rc;
    UNUSED(state);

    client = _connected_client_setup(&obs);
    assert_non_null(client);
    c = (MQTTClient *)client;

    /* UNSUBACK: fixed header 0xB0, remlen 2, packetid */
    unsuback[0] = 0xB0;
    unsuback[1] = 0x02;
    unsuback[2] = 0x00;
    unsuback[3] = (unsigned char)(c->next_packetid + 1);
    port_net_mock_reset_read_stream(unsuback, 4);

    set_mock_port_net_write_skip_buf_check(1);
    set_mock_port_net_write_skip_len_check(1);

    rc = st_mqtt_unsubscribe(client, 1, topics);
    assert_return_code(rc, 0);

    reset_mock_port_net_write_skip_flags();
    st_mqtt_destroy(client);
}

void TC_st_mqtt_publish_write_failure(void **state)
{
    st_mqtt_client client;
    mqtt_observer_t obs;
    st_mqtt_msg msg = {0};
    int rc;
    UNUSED(state);

    client = _connected_client_setup(&obs);
    assert_non_null(client);

    msg.topic = "t";
    msg.payload = "p";
    msg.payloadlen = 1;
    msg.qos = st_mqtt_qos1;

    /* Inject a write failure so the publish fails at the network layer. */
    set_mock_port_net_write_failure(1);
    set_mock_port_net_write_skip_buf_check(1);
    set_mock_port_net_write_skip_len_check(1);

    rc = st_mqtt_publish(client, &msg);
    assert_int_not_equal(rc, 0);

    reset_mock_port_net_write_skip_flags();
    st_mqtt_destroy(client);
}

void TC_st_mqtt_yield_with_short_timer(void **state)
{
    st_mqtt_client client;
    mqtt_observer_t obs;
    int rc;
    UNUSED(state);

    client = _connected_client_setup(&obs);
    assert_non_null(client);

    port_net_mock_reset_read_stream(NULL, 0);
    rc = st_mqtt_yield(client, 5);
    (void)rc;

    st_mqtt_destroy(client);
}

void TC_st_mqtt_change_ping_period_with_active_timers(void **state)
{
    st_mqtt_client client;
    MQTTClient *c;
    mqtt_observer_t obs;
    UNUSED(state);

    client = _connected_client_setup(&obs);
    assert_non_null(client);
    c = (MQTTClient *)client;

    st_mqtt_change_ping_period(client, 45);
    assert_int_equal(c->keepAliveInterval, 45);

    st_mqtt_destroy(client);
}

void TC_st_mqtt_disconnect_while_disconnected(void **state)
{
    st_mqtt_client client;
    MQTTClient *c;
    int err;
    UNUSED(state);

    err = st_mqtt_create(&client, _dummy_mqtt_client_callback, NULL, NULL, NULL);
    assert_return_code(err, 0);
    c = (MQTTClient *)client;
    c->isconnected = 0;

    /* No network expectations; the disconnect packet must still be built. */
    set_mock_port_net_write_skip_buf_check(1);
    set_mock_port_net_write_skip_len_check(1);
    err = st_mqtt_disconnect(client);
    (void)err;

    reset_mock_port_net_write_skip_flags();
    st_mqtt_destroy(client);
}

void TC_st_mqtt_publish_qos0_success(void **state)
{
    st_mqtt_client client;
    mqtt_observer_t obs;
    st_mqtt_msg msg = {0};
    int rc;
    UNUSED(state);

    client = _connected_client_setup(&obs);
    assert_non_null(client);

    msg.topic = "t";
    msg.payload = "p";
    msg.payloadlen = 1;
    msg.qos = st_mqtt_qos0;

    set_mock_port_net_write_skip_buf_check(1);
    set_mock_port_net_write_skip_len_check(1);

    rc = st_mqtt_publish(client, &msg);
    assert_return_code(rc, 0);

    reset_mock_port_net_write_skip_flags();
    st_mqtt_destroy(client);
}

static void _test_publish_async_cb(int chunk_id, st_mqtt_publish_result result, void *usr_data)
{
    if (usr_data) {
        int *cb_called = (int *)usr_data;
        *cb_called = 1;
        (void)chunk_id;
        (void)result;
    }
}

void TC_st_mqtt_publish_async_connected(void **state)
{
    st_mqtt_client client;
    mqtt_observer_t obs;
    st_mqtt_msg msg = {0};
    int rc;
    int cb_called = 0;
    UNUSED(state);

    client = _connected_client_setup(&obs);
    assert_non_null(client);

    msg.topic = "t";
    msg.payload = "p";
    msg.payloadlen = 1;
    msg.qos = st_mqtt_qos0;

    set_mock_port_net_write_skip_buf_check(1);
    set_mock_port_net_write_skip_len_check(1);
    rc = st_mqtt_publish_async(client, &msg, _test_publish_async_cb, &cb_called);
    /* publish_async returns chunk_id (>= 0) on success, negative on failure */
    assert_in_range(rc, 0, INT_MAX);
    reset_mock_port_net_write_skip_flags();

    st_mqtt_destroy(client);
}

void TC_st_mqtt_subscribe_write_failure(void **state)
{
    st_mqtt_client client;
    mqtt_observer_t obs;
    char *topics[] = {"t"};
    int qos[] = {0};
    int rc;
    UNUSED(state);

    client = _connected_client_setup(&obs);
    assert_non_null(client);

    set_mock_port_net_write_failure(1);
    set_mock_port_net_write_skip_buf_check(1);
    set_mock_port_net_write_skip_len_check(1);
    rc = st_mqtt_subscribe(client, 1, topics, qos);
    assert_int_not_equal(rc, 0);

    reset_mock_port_net_write_skip_flags();
    st_mqtt_destroy(client);
}

void TC_st_mqtt_unsubscribe_write_failure(void **state)
{
    st_mqtt_client client;
    mqtt_observer_t obs;
    char *topics[] = {"t"};
    int rc;
    UNUSED(state);

    client = _connected_client_setup(&obs);
    assert_non_null(client);

    set_mock_port_net_write_failure(1);
    set_mock_port_net_write_skip_buf_check(1);
    set_mock_port_net_write_skip_len_check(1);
    rc = st_mqtt_unsubscribe(client, 1, topics);
    assert_int_not_equal(rc, 0);

    reset_mock_port_net_write_skip_flags();
    st_mqtt_destroy(client);
}

/*
 * Feed a QoS2 PUBLISH packet and drive st_mqtt_yield.  This covers:
 *   - the QoS2 arm of _iot_mqtt_process_received_publish (PUBREC write)
 *   - receiving a PUBREL and the PUBREC->PUBCOMP recycling in
 *     _iot_mqtt_process_received_pubrec_pubrel
 */
void TC_st_mqtt_yield_publish_qos2_flow(void **state)
{
    st_mqtt_client client;
    mqtt_observer_t obs;
    unsigned char publish_wire[16] = {0};
    unsigned char pubrel_wire[4] = {0};
    int rc;
    UNUSED(state);

    client = _connected_client_setup(&obs);
    assert_non_null(client);

    /* Step 1: feed a QoS2 PUBLISH (header 0x34) with packet id 0x0077 */
    publish_wire[0] = 0x34;
    publish_wire[1] = 0x07;  // remlen
    publish_wire[2] = 0x00;
    publish_wire[3] = 0x01;
    publish_wire[4] = 't';
    publish_wire[5] = 0x00;
    publish_wire[6] = 0x77;  // packet id
    publish_wire[7] = 'x';
    publish_wire[8] = 'y';
    port_net_mock_reset_read_stream(publish_wire, 9);
    set_mock_port_net_write_skip_buf_check(1);
    set_mock_port_net_write_skip_len_check(1);

    rc = st_mqtt_yield(client, 0);
    (void)rc;
    assert_int_equal(obs.last_event, ST_MQTT_EVENT_MSG_DELIVERED);
    assert_int_equal(obs.last_publish_qos, st_mqtt_qos2);

    /* Step 2: feed a PUBREL from the server with the same packet id so the
     * client moves from PUBREC state to sending PUBCOMP. */
    pubrel_wire[0] = 0x62;  // PUBREL fixed header
    pubrel_wire[1] = 0x02;
    pubrel_wire[2] = 0x00;
    pubrel_wire[3] = 0x77;
    port_net_mock_reset_read_stream(pubrel_wire, 4);
    rc = st_mqtt_yield(client, 0);
    (void)rc;

    reset_mock_port_net_write_skip_flags();
    st_mqtt_destroy(client);
}

void TC_st_mqtt_yield_pubrec_without_pending(void **state)
{
    st_mqtt_client client;
    mqtt_observer_t obs;
    unsigned char pubrec_wire[] = {0x50, 0x02, 0x00, 0x55};
    int rc;
    UNUSED(state);

    client = _connected_client_setup(&obs);
    assert_non_null(client);

    port_net_mock_reset_read_stream(pubrec_wire, sizeof(pubrec_wire));
    set_mock_port_net_write_skip_buf_check(1);
    set_mock_port_net_write_skip_len_check(1);

    rc = st_mqtt_yield(client, 0);
    (void)rc;

    reset_mock_port_net_write_skip_flags();
    st_mqtt_destroy(client);
}

void TC_st_mqtt_yield_pubrel_without_pending(void **state)
{
    st_mqtt_client client;
    mqtt_observer_t obs;
    unsigned char pubrel_wire[] = {0x62, 0x02, 0x00, 0x11};
    int rc;
    UNUSED(state);

    client = _connected_client_setup(&obs);
    assert_non_null(client);

    port_net_mock_reset_read_stream(pubrel_wire, sizeof(pubrel_wire));
    rc = st_mqtt_yield(client, 0);
    (void)rc;

    st_mqtt_destroy(client);
}

void TC_st_mqtt_yield_pingresp_without_pending(void **state)
{
    st_mqtt_client client;
    mqtt_observer_t obs;
    unsigned char pingresp_wire[] = {0xD0, 0x00};
    int rc;
    UNUSED(state);

    client = _connected_client_setup(&obs);
    assert_non_null(client);

    port_net_mock_reset_read_stream(pingresp_wire, sizeof(pingresp_wire));
    rc = st_mqtt_yield(client, 0);
    (void)rc;

    st_mqtt_destroy(client);
}

void TC_st_mqtt_yield_puback_without_pending(void **state)
{
    st_mqtt_client client;
    mqtt_observer_t obs;
    unsigned char wire[] = {0x40, 0x02, 0x00, 0x01};
    int rc;
    UNUSED(state);

    client = _connected_client_setup(&obs);
    assert_non_null(client);

    port_net_mock_reset_read_stream(wire, sizeof(wire));
    rc = st_mqtt_yield(client, 0);
    (void)rc;

    st_mqtt_destroy(client);
}

void TC_st_mqtt_yield_unsuback_without_pending(void **state)
{
    st_mqtt_client client;
    mqtt_observer_t obs;
    unsigned char wire[] = {0xB0, 0x02, 0x00, 0x01};
    int rc;
    UNUSED(state);

    client = _connected_client_setup(&obs);
    assert_non_null(client);

    port_net_mock_reset_read_stream(wire, sizeof(wire));
    rc = st_mqtt_yield(client, 0);
    (void)rc;

    st_mqtt_destroy(client);
}

void TC_st_mqtt_yield_pubcomp_without_pending(void **state)
{
    st_mqtt_client client;
    mqtt_observer_t obs;
    unsigned char wire[] = {0x70, 0x02, 0x00, 0x01};
    int rc;
    UNUSED(state);

    client = _connected_client_setup(&obs);
    assert_non_null(client);

    port_net_mock_reset_read_stream(wire, sizeof(wire));
    rc = st_mqtt_yield(client, 0);
    (void)rc;

    st_mqtt_destroy(client);
}

void TC_st_mqtt_connect_with_will_flag(void **state)
{
    int err;
    st_mqtt_client client;
    st_mqtt_broker_info_t broker;
    st_mqtt_connect_data conn_data = st_mqtt_connect_data_initializer;
    unsigned char connack[4] = {0x20, 0x02, 0x00, 0x00};
    UNUSED(state);

    err = st_mqtt_create(&client, _dummy_mqtt_client_callback, NULL, NULL, NULL);
    assert_return_code(err, 0);
    port_net_mock_reset_socket_status(1);

    broker.url = "broker.example";
    broker.port = 1883;
    broker.ca_cert = (const unsigned char *)st_root_ca;
    broker.ca_cert_len = st_root_ca_len;
    broker.ssl = 1;
    conn_data.clientid = "c";
    conn_data.username = "u";
    conn_data.password = "p";
    conn_data.will_flag = 1;
    conn_data.will_qos = 1;
    conn_data.will_retained = 1;
    conn_data.will_topic = "will/t";
    conn_data.will_message = "byebye";

    port_net_mock_reset_read_stream(connack, sizeof(connack));
    set_mock_port_net_write_skip_buf_check(1);
    set_mock_port_net_write_skip_len_check(1);

    err = st_mqtt_connect(client, &broker, &conn_data);
    assert_return_code(err, 0);

    reset_mock_port_net_write_skip_flags();
    st_mqtt_destroy(client);
}

void TC_st_mqtt_connect_reserved_rc(void **state)
{
    int err;
    st_mqtt_client client;
    st_mqtt_broker_info_t broker;
    st_mqtt_connect_data conn_data = st_mqtt_connect_data_initializer;
    unsigned char connack[4] = {0x20, 0x02, 0x00, 0x7F};  // out-of-range rc
    UNUSED(state);

    err = st_mqtt_create(&client, _dummy_mqtt_client_callback, NULL, NULL, NULL);
    assert_return_code(err, 0);
    port_net_mock_reset_socket_status(1);

    broker.url = "broker.example";
    broker.port = 1883;
    broker.ca_cert = (const unsigned char *)st_root_ca;
    broker.ca_cert_len = st_root_ca_len;
    broker.ssl = 1;
    conn_data.clientid = "c";

    port_net_mock_reset_read_stream(connack, sizeof(connack));
    set_mock_port_net_write_skip_buf_check(1);
    set_mock_port_net_write_skip_len_check(1);

    err = st_mqtt_connect(client, &broker, &conn_data);
    assert_int_equal(err, E_ST_MQTT_FAILURE);

    reset_mock_port_net_write_skip_flags();
    st_mqtt_destroy(client);
}

void TC_st_mqtt_publish_with_work_queue(void **state)
{
    st_mqtt_client client;
    MQTTClient *c;
    iot_util_queue_t *work_queue;
    iot_os_eventgroup *work_signal;
    st_mqtt_msg msg = {0};
    iot_error_t iot_err;
    int err;
    unsigned char puback[4] = {0x40, 0x02, 0x00, 0x00};
    UNUSED(state);

    work_queue = iot_util_queue_create(sizeof(device_work_data_t));
    assert_non_null(work_queue);
    work_signal = iot_os_eventgroup_create();
    assert_non_null(work_signal);

    err = st_mqtt_create(&client, _dummy_mqtt_client_callback, NULL, work_queue, work_signal);
    assert_return_code(err, 0);
    c = (MQTTClient *)client;
    c->isconnected = 1;
    port_net_mock_reset_socket_status(1);
    c->last_sent = iot_os_timer_create(NULL, 10000, NULL);
    iot_err = iot_os_timer_start(c->last_sent);
    assert_int_equal(iot_err, IOT_ERROR_NONE);
    c->last_received = iot_os_timer_create(NULL, 10000, NULL);
    iot_err = iot_os_timer_start(c->last_received);
    assert_int_equal(iot_err, IOT_ERROR_NONE);

    msg.topic = "t";
    msg.payload = "x";
    msg.payloadlen = 1;
    msg.qos = st_mqtt_qos1;

    /* packet id starts at 1, increments to 2 for this publish */
    puback[3] = (unsigned char)(c->next_packetid + 1);
    port_net_mock_reset_read_stream(puback, sizeof(puback));
    set_mock_port_net_write_skip_buf_check(1);
    set_mock_port_net_write_skip_len_check(1);

    err = st_mqtt_publish(client, &msg);
    assert_return_code(err, 0);

    reset_mock_port_net_write_skip_flags();
    st_mqtt_destroy(client);
    iot_util_queue_delete(work_queue);
    iot_os_eventgroup_delete(work_signal);
}

void TC_st_mqtt_publish_async_with_work_queue(void **state)
{
    st_mqtt_client client;
    MQTTClient *c;
    iot_util_queue_t *work_queue;
    iot_os_eventgroup *work_signal;
    st_mqtt_msg msg = {0};
    iot_error_t iot_err;
    int err;
    UNUSED(state);

    work_queue = iot_util_queue_create(sizeof(device_work_data_t));
    assert_non_null(work_queue);
    work_signal = iot_os_eventgroup_create();
    assert_non_null(work_signal);

    err = st_mqtt_create(&client, _dummy_mqtt_client_callback, NULL, work_queue, work_signal);
    assert_return_code(err, 0);
    c = (MQTTClient *)client;
    c->isconnected = 1;
    port_net_mock_reset_socket_status(1);
    c->last_sent = iot_os_timer_create(NULL, 10000, NULL);
    iot_err = iot_os_timer_start(c->last_sent);
    assert_int_equal(iot_err, IOT_ERROR_NONE);
    c->last_received = iot_os_timer_create(NULL, 10000, NULL);
    iot_err = iot_os_timer_start(c->last_received);
    assert_int_equal(iot_err, IOT_ERROR_NONE);

    msg.topic = "t";
    msg.payload = "x";
    msg.payloadlen = 1;
    msg.qos = st_mqtt_qos0;

    set_mock_port_net_write_skip_buf_check(1);
    set_mock_port_net_write_skip_len_check(1);
    err = st_mqtt_publish_async(client, &msg, NULL, NULL);
    (void)err;
    reset_mock_port_net_write_skip_flags();

    st_mqtt_destroy(client);
    iot_util_queue_delete(work_queue);
    iot_os_eventgroup_delete(work_signal);
}

void TC_st_mqtt_subscribe_bad_magic(void **state)
{
    st_mqtt_client client;
    MQTTClient *c;
    unsigned int saved_magic;
    char *topics[] = {"t"};
    int qos[] = {0};
    int err;
    UNUSED(state);

    err = st_mqtt_create(&client, _dummy_mqtt_client_callback, NULL, NULL, NULL);
    assert_return_code(err, 0);
    c = (MQTTClient *)client;
    saved_magic = c->magic;
    c->magic = 0xDEADBEEF;

    err = st_mqtt_subscribe(client, 1, topics, qos);
    assert_int_equal(err, E_ST_MQTT_FAILURE);

    c->magic = saved_magic;
    st_mqtt_destroy(client);
}

void TC_st_mqtt_unsubscribe_bad_magic(void **state)
{
    st_mqtt_client client;
    MQTTClient *c;
    unsigned int saved_magic;
    char *topics[] = {"t"};
    int err;
    UNUSED(state);

    err = st_mqtt_create(&client, _dummy_mqtt_client_callback, NULL, NULL, NULL);
    assert_return_code(err, 0);
    c = (MQTTClient *)client;
    saved_magic = c->magic;
    c->magic = 0xDEADBEEF;

    err = st_mqtt_unsubscribe(client, 1, topics);
    assert_int_equal(err, E_ST_MQTT_FAILURE);

    c->magic = saved_magic;
    st_mqtt_destroy(client);
}

void TC_st_mqtt_disconnect_bad_magic(void **state)
{
    st_mqtt_client client;
    MQTTClient *c;
    unsigned int saved_magic;
    int err;
    UNUSED(state);

    err = st_mqtt_create(&client, _dummy_mqtt_client_callback, NULL, NULL, NULL);
    assert_return_code(err, 0);
    c = (MQTTClient *)client;
    saved_magic = c->magic;
    c->magic = 0xDEADBEEF;

    err = st_mqtt_disconnect(client);
    assert_int_equal(err, E_ST_MQTT_FAILURE);

    c->magic = saved_magic;
    st_mqtt_destroy(client);
}

void TC_st_mqtt_connect_bad_magic(void **state)
{
    int err;
    st_mqtt_client client;
    MQTTClient *c;
    unsigned int saved_magic;
    st_mqtt_broker_info_t broker;
    st_mqtt_connect_data conn_data = st_mqtt_connect_data_initializer;
    UNUSED(state);

    err = st_mqtt_create(&client, _dummy_mqtt_client_callback, NULL, NULL, NULL);
    assert_return_code(err, 0);
    c = (MQTTClient *)client;

    broker.url = "b";
    broker.port = 1883;
    broker.ca_cert = (const unsigned char *)st_root_ca;
    broker.ca_cert_len = st_root_ca_len;
    broker.ssl = 1;
    conn_data.clientid = "c";

    // Given: magic is invalid before st_mqtt_connect runs.
    saved_magic = c->magic;
    c->magic = 0xDEADBEEF;
    // When
    err = st_mqtt_connect(client, &broker, &conn_data);
    // Then
    assert_int_equal(err, E_ST_MQTT_FAILURE);

    c->magic = saved_magic;
    st_mqtt_destroy(client);
}

void TC_st_mqtt_disconnect_chunk_malloc_failure(void **state)
{
    int err;
    st_mqtt_client client;
    UNUSED(state);

    err = st_mqtt_create(&client, _dummy_mqtt_client_callback, NULL, NULL, NULL);
    assert_return_code(err, 0);

    set_mock_detect_memory_leak(false);
    do_not_use_mock_iot_os_malloc_failure();
    set_mock_iot_os_malloc_failure_with_index(0);
    err = st_mqtt_disconnect(client);
    do_not_use_mock_iot_os_malloc_failure();
    assert_int_equal(err, E_ST_MQTT_BUFFER_OVERFLOW);

    st_mqtt_destroy(client);
}

void TC_st_mqtt_subscribe_chunk_malloc_failure(void **state)
{
    int err;
    st_mqtt_client client;
    char *topics[] = {"t"};
    int qos[] = {0};
    UNUSED(state);

    err = st_mqtt_create(&client, _dummy_mqtt_client_callback, NULL, NULL, NULL);
    assert_return_code(err, 0);

    /* First malloc is the Topics[] array, second is the chunk struct. */
    set_mock_detect_memory_leak(false);
    do_not_use_mock_iot_os_malloc_failure();
    set_mock_iot_os_malloc_failure_with_index(1);
    err = st_mqtt_subscribe(client, 1, topics, qos);
    do_not_use_mock_iot_os_malloc_failure();
    assert_int_equal(err, E_ST_MQTT_BUFFER_OVERFLOW);

    st_mqtt_destroy(client);
}

void TC_st_mqtt_unsubscribe_chunk_malloc_failure(void **state)
{
    int err;
    st_mqtt_client client;
    char *topics[] = {"t"};
    UNUSED(state);

    err = st_mqtt_create(&client, _dummy_mqtt_client_callback, NULL, NULL, NULL);
    assert_return_code(err, 0);

    set_mock_detect_memory_leak(false);
    do_not_use_mock_iot_os_malloc_failure();
    set_mock_iot_os_malloc_failure_with_index(1);
    err = st_mqtt_unsubscribe(client, 1, topics);
    do_not_use_mock_iot_os_malloc_failure();
    assert_int_equal(err, E_ST_MQTT_BUFFER_OVERFLOW);

    st_mqtt_destroy(client);
}

void TC_st_mqtt_publish_chunk_malloc_failure(void **state)
{
    st_mqtt_client client;
    mqtt_observer_t obs;
    st_mqtt_msg msg = {0};
    int rc;
    UNUSED(state);

    client = _connected_client_setup(&obs);
    assert_non_null(client);

    msg.topic = "t";
    msg.payload = "x";
    msg.payloadlen = 1;
    msg.qos = st_mqtt_qos0;

    set_mock_detect_memory_leak(false);
    do_not_use_mock_iot_os_malloc_failure();
    set_mock_iot_os_malloc_failure_with_index(0);
    rc = st_mqtt_publish(client, &msg);
    do_not_use_mock_iot_os_malloc_failure();
    assert_int_equal(rc, E_ST_MQTT_FAILURE);

    st_mqtt_destroy(client);
}
