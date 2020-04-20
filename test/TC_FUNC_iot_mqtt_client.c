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

void TC_st_mqtt_create_success(void** state)
{
    int err;
    st_mqtt_client client;
    MQTTClient *internal_client;
    UNUSED(state);

    // Given
    set_mock_detect_memory_leak(true);
    // When
    err = st_mqtt_create(&client, 150);
    // Then
    assert_return_code(err, 0);
    internal_client = (MQTTClient*) client;
    assert_int_equal(internal_client->command_timeout_ms, 150);
    // Teardown
    st_mqtt_destroy(client);
    set_mock_detect_memory_leak(false);
}

static void _st_mqtt_connect_test_with_parameter(unsigned char give_rc, int expected_err)
{
    int err;
    st_mqtt_client client;
    st_mqtt_broker_info_t broker_info;
    st_mqtt_connect_data conn_data = st_mqtt_connect_data_initializer;
    unsigned char *mock_read_buffer;

    // Given
    err = st_mqtt_create(&client, IOT_DEFAULT_TIMEOUT);
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

    will_return_count(_iot_net_mock_read, mock_read_buffer, 3);

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