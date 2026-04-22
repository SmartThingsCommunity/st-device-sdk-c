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
#include <iot_mqtt_packet.h>
#include <iot_mqtt_connect.h>
#include <iot_mqtt_format.h>
#include <string.h>

#include "cmocka_custom.h"

#define UNUSED(x) (void)(x)

/*
 * Tests for MQTTPacket_getName
 */
void TC_MQTTPacket_getName_connect(void **state)
{
    UNUSED(state);
    assert_string_equal(MQTTPacket_getName(1), "CONNECT");
}

void TC_MQTTPacket_getName_publish(void **state)
{
    UNUSED(state);
    assert_string_equal(MQTTPacket_getName(3), "PUBLISH");
}

void TC_MQTTPacket_getName_disconnect(void **state)
{
    UNUSED(state);
    assert_string_equal(MQTTPacket_getName(14), "DISCONNECT");
}

/*
 * Tests for MQTTStringFormat_connack
 */
void TC_MQTTStringFormat_connack_success(void **state)
{
    char buf[64] = {0};
    int n;
    UNUSED(state);

    n = MQTTStringFormat_connack(buf, sizeof(buf), 0, 1);
    assert_true(n > 0);
    assert_non_null(strstr(buf, "CONNACK"));
}

void TC_MQTTStringFormat_connack_truncated(void **state)
{
    char buf[4] = {0};
    int n;
    UNUSED(state);

    n = MQTTStringFormat_connack(buf, sizeof(buf), 0, 0);
    // snprintf returns the required length even when truncated
    assert_true(n > 0);
}

/*
 * Tests for MQTTStringFormat_ack
 */
void TC_MQTTStringFormat_ack_success(void **state)
{
    char buf[64] = {0};
    int n;
    UNUSED(state);

    n = MQTTStringFormat_ack(buf, sizeof(buf), PUBACK, 0, 0x1234);
    assert_true(n > 0);
    assert_non_null(strstr(buf, "PUBACK"));
}

void TC_MQTTStringFormat_ack_with_dup(void **state)
{
    char buf[64] = {0};
    int n;
    UNUSED(state);

    n = MQTTStringFormat_ack(buf, sizeof(buf), PUBREL, 1, 0x0001);
    assert_true(n > 0);
    assert_non_null(strstr(buf, "PUBREL"));
    assert_non_null(strstr(buf, "dup"));
}

void TC_MQTTStringFormat_ack_no_dup_bit(void **state)
{
    char buf[64] = {0};
    int n;
    UNUSED(state);

    n = MQTTStringFormat_ack(buf, sizeof(buf), PUBCOMP, 0, 0x0002);
    assert_true(n > 0);
    assert_null(strstr(buf, "dup"));
}

/*
 * Tests for MQTTStringFormat_publish
 */
void TC_MQTTStringFormat_publish_short_payload(void **state)
{
    char buf[128] = {0};
    MQTTString topic = MQTTString_initializer;
    unsigned char payload[] = "payload";
    int n;
    UNUSED(state);

    topic.lenstring.data = "t";
    topic.lenstring.len = 1;
    n = MQTTStringFormat_publish(buf, sizeof(buf), 0, 0, 0, 0, topic, payload, 7);
    assert_true(n > 0);
    assert_non_null(strstr(buf, "PUBLISH"));
}

void TC_MQTTStringFormat_publish_long_topic(void **state)
{
    char buf[256] = {0};
    char long_topic[32];
    MQTTString topic = MQTTString_initializer;
    unsigned char payload[] = "payload";
    int n;
    UNUSED(state);

    memset(long_topic, 'T', sizeof(long_topic));
    topic.lenstring.data = long_topic;
    topic.lenstring.len = sizeof(long_topic);
    n = MQTTStringFormat_publish(buf, sizeof(buf), 0, 0, 0, 0, topic, payload, 7);
    assert_true(n > 0);
}

void TC_MQTTStringFormat_publish_long_payload(void **state)
{
    char buf[256] = {0};
    MQTTString topic = MQTTString_initializer;
    unsigned char long_payload[64];
    int n;
    UNUSED(state);

    memset(long_payload, 'P', sizeof(long_payload));
    topic.lenstring.data = "t";
    topic.lenstring.len = 1;
    n = MQTTStringFormat_publish(buf, sizeof(buf), 0, 0, 0, 0, topic, long_payload,
                                 sizeof(long_payload));
    assert_true(n > 0);
}

/*
 * Tests for MQTTStringFormat_connect
 */
void TC_MQTTStringFormat_connect_basic(void **state)
{
    char buf[256] = {0};
    MQTTPacket_connectData data = MQTTPacket_connectData_initializer;
    int n;
    UNUSED(state);

    data.clientID.lenstring.data = "cli";
    data.clientID.lenstring.len = 3;
    n = MQTTStringFormat_connect(buf, sizeof(buf), &data);
    assert_true(n > 0);
    assert_non_null(strstr(buf, "CONNECT"));
}

void TC_MQTTStringFormat_connect_with_will(void **state)
{
    char buf[512] = {0};
    MQTTPacket_connectData data = MQTTPacket_connectData_initializer;
    int n;
    UNUSED(state);

    data.clientID.lenstring.data = "id";
    data.clientID.lenstring.len = 2;
    data.willFlag = 1;
    data.will.qos = 1;
    data.will.retained = 1;
    data.will.topicName.lenstring.data = "will/t";
    data.will.topicName.lenstring.len = 6;
    data.will.message.lenstring.data = "msg";
    data.will.message.lenstring.len = 3;
    n = MQTTStringFormat_connect(buf, sizeof(buf), &data);
    assert_true(n > 0);
    assert_non_null(strstr(buf, "will"));
}

void TC_MQTTStringFormat_connect_with_credentials(void **state)
{
    char buf[512] = {0};
    MQTTPacket_connectData data = MQTTPacket_connectData_initializer;
    int n;
    UNUSED(state);

    data.clientID.lenstring.data = "id";
    data.clientID.lenstring.len = 2;
    data.username.lenstring.data = "alice";
    data.username.lenstring.len = 5;
    data.password.lenstring.data = "secret";
    data.password.lenstring.len = 6;
    n = MQTTStringFormat_connect(buf, sizeof(buf), &data);
    assert_true(n > 0);
    assert_non_null(strstr(buf, "alice"));
    assert_non_null(strstr(buf, "secret"));
}

void TC_MQTTStringFormat_connect_no_credentials(void **state)
{
    char buf[256] = {0};
    MQTTPacket_connectData data = MQTTPacket_connectData_initializer;
    int n;
    UNUSED(state);

    data.clientID.lenstring.data = "id";
    data.clientID.lenstring.len = 2;
    n = MQTTStringFormat_connect(buf, sizeof(buf), &data);
    assert_true(n > 0);
    assert_null(strstr(buf, "user name"));
    assert_null(strstr(buf, "password"));
}

/*
 * Tests for MQTTStringFormat_subscribe / suback / unsubscribe
 */
void TC_MQTTStringFormat_subscribe_success(void **state)
{
    char buf[128] = {0};
    MQTTString topics[1];
    int qos[] = {1};
    int n;
    UNUSED(state);

    memset(topics, 0, sizeof(topics));
    topics[0].lenstring.data = "t";
    topics[0].lenstring.len = 1;
    n = MQTTStringFormat_subscribe(buf, sizeof(buf), 0, 0x0010, 1, topics, qos);
    assert_true(n > 0);
    assert_non_null(strstr(buf, "SUBSCRIBE"));
}

void TC_MQTTStringFormat_suback_success(void **state)
{
    char buf[128] = {0};
    int granted[] = {2};
    int n;
    UNUSED(state);

    n = MQTTStringFormat_suback(buf, sizeof(buf), 0x0001, 1, granted);
    assert_true(n > 0);
    assert_non_null(strstr(buf, "SUBACK"));
}

void TC_MQTTStringFormat_unsubscribe_success(void **state)
{
    char buf[128] = {0};
    MQTTString topics[1];
    int n;
    UNUSED(state);

    memset(topics, 0, sizeof(topics));
    topics[0].lenstring.data = "t";
    topics[0].lenstring.len = 1;
    n = MQTTStringFormat_unsubscribe(buf, sizeof(buf), 0, 0x0020, 1, topics);
    assert_true(n > 0);
    assert_non_null(strstr(buf, "UNSUBSCRIBE"));
}

void TC_MQTTStringFormat_subscribe_zero_buffer(void **state)
{
    char buf[1] = {0};
    MQTTString topics[1];
    int qos[] = {1};
    int n;
    UNUSED(state);

    memset(topics, 0, sizeof(topics));
    topics[0].lenstring.data = "t";
    topics[0].lenstring.len = 1;
    // When: truncated buffer, snprintf still returns required length
    n = MQTTStringFormat_subscribe(buf, 1, 0, 0x0010, 1, topics, qos);
    assert_true(n > 0);
    /* the first byte has been set to NUL by snprintf (zero-len output) */
    assert_int_equal(buf[0], '\0');
}

void TC_MQTTStringFormat_suback_zero_buffer(void **state)
{
    char buf[1] = {0};
    int granted[] = {0};
    int n;
    UNUSED(state);

    n = MQTTStringFormat_suback(buf, 1, 0x0001, 1, granted);
    assert_true(n > 0);
    assert_int_equal(buf[0], '\0');
}

void TC_MQTTStringFormat_unsubscribe_zero_buffer(void **state)
{
    char buf[1] = {0};
    MQTTString topics[1];
    int n;
    UNUSED(state);

    memset(topics, 0, sizeof(topics));
    topics[0].lenstring.data = "t";
    topics[0].lenstring.len = 1;
    n = MQTTStringFormat_unsubscribe(buf, 1, 0, 0x0020, 1, topics);
    assert_true(n > 0);
    assert_int_equal(buf[0], '\0');
}
