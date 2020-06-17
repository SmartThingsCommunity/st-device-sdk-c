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
#include <iot_mqtt.h>
#include <iot_internal.h>
#include <root_ca.h>
#include <mqtt/iot_mqtt_client.h>
#include "TC_MOCK_functions.h"
#define UNUSED(x) (void**)(x)

void _dummy_mqtt_client_callback(st_mqtt_event event, void *event_data, void *usr_data)
{
    UNUSED(event);
    UNUSED(event_data);
    UNUSED(usr_data);
    return;
}

void TC_st_mqtt_create_success(void** state)
{
    int err;
    st_mqtt_client client;
    MQTTClient *internal_client;
    UNUSED(state);

    // Given
    set_mock_detect_memory_leak(true);
    // When
    err = st_mqtt_create(&client, _dummy_mqtt_client_callback, NULL);
    // Then
    assert_return_code(err, 0);
    internal_client = (MQTTClient*) client;
    assert_int_equal(internal_client->user_callback_fp, _dummy_mqtt_client_callback);
    // Teardown
    st_mqtt_destroy(client);
    set_mock_detect_memory_leak(false);
}

void TC_st_mqtt_create_failure(void** state)
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
        err = st_mqtt_create(&client, _dummy_mqtt_client_callback, NULL);
        // Then
        assert_int_equal(err, E_ST_MQTT_FAILURE);
        // Teardown
        do_not_use_mock_iot_os_malloc_failure();
    }

    // When
    err = st_mqtt_create(&client, NULL, NULL);
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
    err = st_mqtt_create(&client, _dummy_mqtt_client_callback, NULL);
    assert_return_code(err, 0);

    broker_info.url = strdup("test.domain.com");
    broker_info.port = 555;
    broker_info.ca_cert = (const unsigned char *)st_root_ca;
    broker_info.ca_cert_len = st_root_ca_len;
    broker_info.ssl = 1;

    conn_data.clientid  = strdup("testClientId");
    conn_data.username = strdup("testUserName");
    conn_data.password  = strdup("testPassword");

    mock_read_buffer = (unsigned char*) malloc(4);

    // reference:
    // https://docs.solace.com/MQTT-311-Prtl-Conformance-Spec/MQTT%20Control%20Packets.htm#_Toc430864897
    mock_read_buffer[0] = 0x20; // CONNACK fixed header (MQTT Control Packet Type)
    mock_read_buffer[1] = 0x02; // Remaining Length
    mock_read_buffer[2] = 0x00; // Clean session (SP1 is 0)
    mock_read_buffer[3] = give_rc;

    reset_mock_net_read_buffer_pointer_index();
    set_mock_net_read_buffer_pointer(0, 0, 1);
    set_mock_net_read_buffer_pointer(1, 1, 1);
    set_mock_net_read_buffer_pointer(2, 2, 2);

    will_return(_iot_net_mock_select, 1);
    will_return_count(_iot_net_mock_read, mock_read_buffer, 3);
    expect_any(_iot_net_mock_write, len);
    expect_any(_iot_net_mock_write, buf);

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
    reset_mock_net_read_buffer_pointer_index();
}

void TC_st_mqtt_connect_with_connack_rc(void** state)
{
    UNUSED(state);

    _st_mqtt_connect_test_with_parameter(0x00, 0); //Connection Accepted
    _st_mqtt_connect_test_with_parameter(0x01, E_ST_MQTT_UNNACCEPTABLE_PROTOCOL); //Connection Refused, unacceptable protocol version
    _st_mqtt_connect_test_with_parameter(0x02, E_ST_MQTT_CLIENTID_REJECTED); //Connection Refused, identifier rejected
    _st_mqtt_connect_test_with_parameter(0x03, E_ST_MQTT_SERVER_UNAVAILABLE); //Connection Refused, Server unavailable
    _st_mqtt_connect_test_with_parameter(0x04, E_ST_MQTT_BAD_USERNAME_OR_PASSWORD); //Connection Refused, bad user name or password
    _st_mqtt_connect_test_with_parameter(0x05, E_ST_MQTT_NOT_AUTHORIZED); //Connection Refused, not authorized
    _st_mqtt_connect_test_with_parameter(0x06, E_ST_MQTT_FAILURE); //Reserved for future use
}

void TC_st_mqtt_disconnect_success(void** state)
{
    int err;
    iot_error_t iot_err;
    st_mqtt_client client;
    MQTTClient *c;
    // https://docs.solace.com/MQTT-311-Prtl-Conformance-Spec/MQTT%20Control%20Packets.htm#_Toc430864954
    char mqtt_disconnect_packet[2] = { 0xe0, 0x00 };
    UNUSED(state);

    // Given
    err = st_mqtt_create(&client, _dummy_mqtt_client_callback, NULL);
    assert_return_code(err, 0);
    c = (MQTTClient*) client;
    c->isconnected = 1;
    iot_err = iot_net_init(c->net);
    assert_int_equal(iot_err, IOT_ERROR_NONE);
    iot_os_timer_count_ms(c->last_sent, 10000);
    iot_os_timer_count_ms(c->last_received, 10000);
    will_return(_iot_net_mock_select, 0);
    expect_value(_iot_net_mock_write, len, 2);
    expect_memory(_iot_net_mock_write, buf, mqtt_disconnect_packet, sizeof(mqtt_disconnect_packet));
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

void TC_st_mqtt_publish_success(void** state)
{
    int err;
    iot_error_t iot_err;
    st_mqtt_client client;
    MQTTClient *c;

    struct mqtt_pub_test_data data[2] = {
        {st_mqtt_qos1, IOT_PUB_TOPIC_REGISTRATION, "{\"testPayloadKey\":\"testPayloadValue\"}", 0x32, 0x40 },
        {st_mqtt_qos2, "/v1/deviceEvents/123e4567-e89b-12d3-a456-426614174000", "{}", 0x34, 0x50 },
    };
    UNUSED(state);

    // Given
    err = st_mqtt_create(&client, _dummy_mqtt_client_callback, NULL);
    assert_return_code(err, 0);
    c = (MQTTClient*) client;
    c->isconnected = 1;
    iot_err = iot_net_init(c->net);
    assert_int_equal(iot_err, IOT_ERROR_NONE);
    iot_os_timer_count_ms(c->last_sent, 10000);
    iot_os_timer_count_ms(c->last_received, 10000);

    for (int i = 0; i < sizeof(data)/sizeof(struct mqtt_pub_test_data); i++)
    {
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
        msg.payloadlen = (int) strlen(msg.payload);
        msg.topic = data[i].topic;
        // https://docs.solace.com/MQTT-311-Prtl-Conformance-Spec/MQTT%20Control%20Packets.htm#_Toc430864901
        mqtt_publish_header_len = 2 + 2 + strlen(data[i].topic) + 2; // 2 for fixed header, 2 for topic name length, variable topic, 2 for package id
        mqtt_publish = malloc(mqtt_publish_header_len + msg.payloadlen);
        assert_non_null(mqtt_publish);
        mqtt_publish[header_index++] = data[i].pub_fixed_header;
        mqtt_publish[header_index++] = (char) (2 + strlen(data[i].topic) + 2 + msg.payloadlen); // Remaining Length
        mqtt_publish[header_index++] = 0x00;
        mqtt_publish[header_index++] = (char) strlen(data[i].topic);
        for (int j = 0 ; j < strlen(data[i].topic); j++) {
            mqtt_publish[header_index++] = data[i].topic[j];
        }
        packet_id_msb = 0x00;
        packet_id_lsb = (char) (c->next_packetid + 1);
        mqtt_publish[header_index++] = packet_id_msb;
        mqtt_publish[header_index++] = packet_id_lsb;
        memcpy(&mqtt_publish[header_index], msg.payload, msg.payloadlen);

        expect_value(_iot_net_mock_write, len, mqtt_publish_header_len + msg.payloadlen);
        expect_memory(_iot_net_mock_write, buf, mqtt_publish, mqtt_publish_header_len + msg.payloadlen);
        if (data[i].qos == st_mqtt_qos2) {
            unsigned char pubrel[4];
            pubrel[0] = 0x62;
            pubrel[1] = 0x02;
            pubrel[2] = packet_id_msb;
            pubrel[3] = packet_id_lsb;
            expect_value(_iot_net_mock_write, len, 4);
            expect_memory(_iot_net_mock_write, buf, pubrel, 4);
        }

        mock_read_buffer_puback = (unsigned char*) malloc(8);
        assert_non_null(mock_read_buffer_puback);

        // reference: https://docs.solace.com/MQTT-311-Prtl-Conformance-Spec/MQTT%20Control%20Packets.htm#_Toc430864907
        // reference: https://docs.solace.com/MQTT-311-Prtl-Conformance-Spec/MQTT%20Control%20Packets.htm#_Toc430864922
        if (data[i].qos == st_mqtt_qos1) {
            mock_read_buffer_puback[0] = data[i].response_fixed_header;
            mock_read_buffer_puback[1] = 0x02; // Remaining Length
            mock_read_buffer_puback[2] = packet_id_msb;
            mock_read_buffer_puback[3] = packet_id_lsb;

            reset_mock_net_read_buffer_pointer_index();
            set_mock_net_read_buffer_pointer(0, 0, 1);
            set_mock_net_read_buffer_pointer(1, 1, 1);
            set_mock_net_read_buffer_pointer(2, 2, 2);

            will_return_count(_iot_net_mock_select, 1, 1);
            will_return_count(_iot_net_mock_read, mock_read_buffer_puback, 3);
        } else if (data[i].qos == st_mqtt_qos2) {
            mock_read_buffer_puback[0] = data[i].response_fixed_header;
            mock_read_buffer_puback[1] = 0x02; // Remaining Length
            mock_read_buffer_puback[2] = packet_id_msb;
            mock_read_buffer_puback[3] = packet_id_lsb;

            mock_read_buffer_puback[4] = 0x70;
            mock_read_buffer_puback[5] = 0x02; // Remaining Length
            mock_read_buffer_puback[6] = packet_id_msb;
            mock_read_buffer_puback[7] = packet_id_lsb;

            reset_mock_net_read_buffer_pointer_index();
            set_mock_net_read_buffer_pointer(0, 0, 1);
            set_mock_net_read_buffer_pointer(1, 1, 1);
            set_mock_net_read_buffer_pointer(2, 2, 2);
            set_mock_net_read_buffer_pointer(3, 4, 1);
            set_mock_net_read_buffer_pointer(4, 5, 1);
            set_mock_net_read_buffer_pointer(5, 6, 2);

            will_return_count(_iot_net_mock_select, 1, 2);
            will_return_count(_iot_net_mock_read, mock_read_buffer_puback, 6);
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