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
// clang-format off
#include <iot_mqtt_packet.h>
#include <iot_mqtt_connect.h>
#include <iot_mqtt_format.h>
#include <string.h>
// clang-format on

#include "TC_REGISTRY.h"
#include "cmocka_custom.h"

#define UNUSED(x) (void)(x)

/*
 * Tests for MQTTPacket_getName
 */
TEST_SUITE("iot_mqtt_format.c");

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTPacket_getName_connect_pos)
{
    UNUSED(state);
    assert_string_equal(MQTTPacket_getName(1), "CONNECT");
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTPacket_getName_publish_neg)
{
    UNUSED(state);
    assert_string_equal(MQTTPacket_getName(3), "PUBLISH");
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTPacket_getName_disconnect_neg)
{
    UNUSED(state);
    assert_string_equal(MQTTPacket_getName(14), "DISCONNECT");
}

/*
 * Tests for MQTTStringFormat_connack
 */
TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTStringFormat_connack_success_pos)
{
    char buf[64] = {0};
    int n;
    UNUSED(state);

    n = MQTTStringFormat_connack(buf, sizeof(buf), 0, 1);
    assert_true(n > 0);
    assert_non_null(strstr(buf, "CONNACK"));
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTStringFormat_connack_truncated_neg)
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
TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTStringFormat_ack_success_pos)
{
    char buf[64] = {0};
    int n;
    UNUSED(state);

    n = MQTTStringFormat_ack(buf, sizeof(buf), PUBACK, 0, 0x1234);
    assert_true(n > 0);
    assert_non_null(strstr(buf, "PUBACK"));
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTStringFormat_ack_with_dup_neg)
{
    char buf[64] = {0};
    int n;
    UNUSED(state);

    n = MQTTStringFormat_ack(buf, sizeof(buf), PUBREL, 1, 0x0001);
    assert_true(n > 0);
    assert_non_null(strstr(buf, "PUBREL"));
    assert_non_null(strstr(buf, "dup"));
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTStringFormat_ack_no_dup_bit_neg)
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
TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTStringFormat_publish_short_payload_neg)
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

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTStringFormat_publish_long_topic_neg)
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

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTStringFormat_publish_long_payload_neg)
{
    char buf[256] = {0};
    MQTTString topic = MQTTString_initializer;
    unsigned char long_payload[64];
    int n;
    UNUSED(state);

    memset(long_payload, 'P', sizeof(long_payload));
    topic.lenstring.data = "t";
    topic.lenstring.len = 1;
    n = MQTTStringFormat_publish(buf, sizeof(buf), 0, 0, 0, 0, topic, long_payload, sizeof(long_payload));
    assert_true(n > 0);
}

/*
 * Tests for MQTTStringFormat_connect
 */
TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTStringFormat_connect_basic_pos)
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

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTStringFormat_connect_with_will_pos)
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

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTStringFormat_connect_with_credentials_pos)
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

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTStringFormat_connect_no_credentials_neg)
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
TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTStringFormat_subscribe_success_pos)
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

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTStringFormat_suback_success_pos)
{
    char buf[128] = {0};
    int granted[] = {2};
    int n;
    UNUSED(state);

    n = MQTTStringFormat_suback(buf, sizeof(buf), 0x0001, 1, granted);
    assert_true(n > 0);
    assert_non_null(strstr(buf, "SUBACK"));
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTStringFormat_unsubscribe_neg)
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

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTStringFormat_subscribe_zero_buffer_neg)
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

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTStringFormat_suback_zero_buffer_neg)
{
    char buf[1] = {0};
    int granted[] = {0};
    int n;
    UNUSED(state);

    n = MQTTStringFormat_suback(buf, 1, 0x0001, 1, granted);
    assert_true(n > 0);
    assert_int_equal(buf[0], '\0');
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTStringFormat_unsubscribe_zero_buffer_neg)
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

/*
 * Additional negative tests for iot_mqtt_format.c
 */
TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTPacket_getName_reserved_neg)
{
    UNUSED(state);
    // The reserved type 0 must not be reported as a real packet name
    assert_string_equal(MQTTPacket_getName(0), "RESERVED");
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTPacket_getName_all_known_types_neg)
{
    static const char *expected[] = {"RESERVED",    "CONNECT",  "CONNACK", "PUBLISH",   "PUBACK",
                                     "PUBREC",      "PUBREL",   "PUBCOMP", "SUBSCRIBE", "SUBACK",
                                     "UNSUBSCRIBE", "UNSUBACK", "PINGREQ", "PINGRESP",  "DISCONNECT"};
    unsigned short i;
    UNUSED(state);

    for (i = 0; i < sizeof(expected) / sizeof(expected[0]); i++) {
        assert_string_equal(MQTTPacket_getName(i), expected[i]);
    }
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTStringFormat_connack_zero_buffer_neg)
{
    char buf[1] = {0x7f};
    int n;
    UNUSED(state);

    // When: the output buffer length is zero
    n = MQTTStringFormat_connack(buf, 0, 0, 0);
    // Then: nothing is written but the required length is reported
    assert_true(n > 0);
    assert_int_equal(buf[0], 0x7f);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTStringFormat_connack_out_of_range_rc_neg)
{
    char buf[64] = {0};
    UNUSED(state);

    // When: a connack return code outside the specified range is formatted
    assert_true(MQTTStringFormat_connack(buf, sizeof(buf), 0xFF, 0) > 0);
    // Then: it is printed as an unsigned value instead of being rejected
    assert_non_null(strstr(buf, "rc 255"));
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTStringFormat_connack_out_of_range_session_present_neg)
{
    char buf[64] = {0};
    UNUSED(state);

    assert_true(MQTTStringFormat_connack(buf, sizeof(buf), 0, 0xFF) > 0);
    assert_non_null(strstr(buf, "session present 255"));
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTStringFormat_publish_zero_buffer_neg)
{
    MQTTString topic = MQTTString_initializer;
    char buf[1] = {0x7f};
    int n;
    UNUSED(state);

    topic.lenstring.data = "t";
    topic.lenstring.len = 1;
    // When: the output buffer length is zero
    n = MQTTStringFormat_publish(buf, 0, 0, 0, 0, 0, topic, (unsigned char *)"p", 1);
    // Then
    assert_true(n > 0);
    assert_int_equal(buf[0], 0x7f);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTStringFormat_publish_topic_capped_at_20_neg)
{
    MQTTString topic = MQTTString_initializer;
    char buf[256] = {0};
    UNUSED(state);

    // Given: a topic longer than the 20 character cap
    topic.lenstring.data = "0123456789012345678901234567890";
    topic.lenstring.len = 31;
    assert_true(MQTTStringFormat_publish(buf, sizeof(buf), 0, 0, 0, 0, topic, (unsigned char *)"p", 1) > 0);
    // Then: only the first 20 characters of the topic are printed
    assert_non_null(strstr(buf, "topic 01234567890123456789,"));
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTStringFormat_publish_payload_capped_at_20_neg)
{
    MQTTString topic = MQTTString_initializer;
    unsigned char payload[31];
    char buf[256] = {0};
    UNUSED(state);

    memset(payload, 'a', sizeof(payload));
    topic.lenstring.data = "t";
    topic.lenstring.len = 1;
    // Given: a payload longer than the 20 character cap
    assert_true(MQTTStringFormat_publish(buf, sizeof(buf), 0, 0, 0, 0, topic, payload, sizeof(payload)) > 0);
    // Then: the real length is reported but only 20 bytes are printed
    assert_non_null(strstr(buf, "payload length 31"));
    assert_null(strstr(buf, "aaaaaaaaaaaaaaaaaaaaa"));
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTStringFormat_publish_reserved_qos_neg)
{
    MQTTString topic = MQTTString_initializer;
    char buf[256] = {0};
    UNUSED(state);

    topic.lenstring.data = "t";
    topic.lenstring.len = 1;
    // When: the reserved qos value 3 is formatted
    assert_true(MQTTStringFormat_publish(buf, sizeof(buf), 0, 3, 0, 0, topic, (unsigned char *)"p", 1) > 0);
    // Then: it is printed as-is instead of being rejected
    assert_non_null(strstr(buf, "QoS 3"));
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTStringFormat_publish_negative_qos_neg)
{
    MQTTString topic = MQTTString_initializer;
    char buf[256] = {0};
    UNUSED(state);

    topic.lenstring.data = "t";
    topic.lenstring.len = 1;
    // When: a negative qos is formatted
    assert_true(MQTTStringFormat_publish(buf, sizeof(buf), 0, -1, 0, 0, topic, (unsigned char *)"p", 1) > 0);
    assert_non_null(strstr(buf, "QoS -1"));
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTStringFormat_publish_zero_length_topic_neg)
{
    MQTTString topic = MQTTString_initializer;
    char buf[256] = {0};
    UNUSED(state);

    // Given: an empty topic
    topic.lenstring.data = NULL;
    topic.lenstring.len = 0;
    assert_true(MQTTStringFormat_publish(buf, sizeof(buf), 0, 0, 0, 0, topic, (unsigned char *)"p", 1) > 0);
    assert_non_null(strstr(buf, "topic ,"));
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTStringFormat_publish_dup_and_retained_neg)
{
    MQTTString topic = MQTTString_initializer;
    char buf[256] = {0};
    UNUSED(state);

    topic.lenstring.data = "t";
    topic.lenstring.len = 1;
    assert_true(MQTTStringFormat_publish(buf, sizeof(buf), 1, 1, 1, 0xFFFF, topic, (unsigned char *)"p", 1) > 0);
    assert_non_null(strstr(buf, "dup 1"));
    assert_non_null(strstr(buf, "retained 1"));
    assert_non_null(strstr(buf, "packet id 65535"));
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTStringFormat_ack_zero_buffer_neg)
{
    char buf[1] = {0x7f};
    int n;
    UNUSED(state);

    // When: the output buffer length is zero and dup is clear
    n = MQTTStringFormat_ack(buf, 0, PUBACK, 0, 1);
    // Then
    assert_true(n > 0);
    assert_int_equal(buf[0], 0x7f);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTStringFormat_ack_reserved_type_neg)
{
    char buf[64] = {0};
    UNUSED(state);

    // When: the reserved type 0 is formatted as an ack
    assert_true(MQTTStringFormat_ack(buf, sizeof(buf), 0, 0, 1) > 0);
    // Then: it is printed as RESERVED instead of being rejected
    assert_non_null(strstr(buf, "RESERVED"));
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTStringFormat_ack_max_packetid_neg)
{
    char buf[64] = {0};
    UNUSED(state);

    assert_true(MQTTStringFormat_ack(buf, sizeof(buf), PUBREL, 0, 0xFFFF) > 0);
    assert_non_null(strstr(buf, "packet id 65535"));
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTStringFormat_ack_zero_packetid_neg)
{
    char buf[64] = {0};
    UNUSED(state);

    // A zero packet id is invalid per the spec but is still formatted
    assert_true(MQTTStringFormat_ack(buf, sizeof(buf), PUBACK, 0, 0) > 0);
    assert_non_null(strstr(buf, "packet id 0"));
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTStringFormat_subscribe_zero_count_neg)
{
    MQTTString filters[1];
    int qos[1] = {0};
    char buf[128] = {0};
    UNUSED(state);

    memset(filters, 0, sizeof(filters));
    // When: the filter count is zero
    assert_true(MQTTStringFormat_subscribe(buf, sizeof(buf), 0, 1, 0, filters, qos) > 0);
    // Then: the count is reported but the first filter is still dereferenced
    assert_non_null(strstr(buf, "count 0"));
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTStringFormat_subscribe_negative_count_neg)
{
    MQTTString filters[1];
    int qos[1] = {0};
    char buf[128] = {0};
    UNUSED(state);

    memset(filters, 0, sizeof(filters));
    // When: a negative filter count is passed
    assert_true(MQTTStringFormat_subscribe(buf, sizeof(buf), 0, 1, -1, filters, qos) > 0);
    assert_non_null(strstr(buf, "count -1"));
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTStringFormat_subscribe_reserved_qos_neg)
{
    MQTTString filters[1];
    int qos[1] = {3};
    char buf[128] = {0};
    UNUSED(state);

    memset(filters, 0, sizeof(filters));
    filters[0].lenstring.data = "t";
    filters[0].lenstring.len = 1;
    // When: the reserved qos value is formatted
    assert_true(MQTTStringFormat_subscribe(buf, sizeof(buf), 0, 1, 1, filters, qos) > 0);
    assert_non_null(strstr(buf, "qos 3"));
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTStringFormat_subscribe_dup_set_neg)
{
    MQTTString filters[1];
    int qos[1] = {1};
    char buf[128] = {0};
    UNUSED(state);

    memset(filters, 0, sizeof(filters));
    filters[0].lenstring.data = "t";
    filters[0].lenstring.len = 1;
    assert_true(MQTTStringFormat_subscribe(buf, sizeof(buf), 1, 0xFFFF, 1, filters, qos) > 0);
    assert_non_null(strstr(buf, "dup 1"));
    assert_non_null(strstr(buf, "packet id 65535"));
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTStringFormat_suback_zero_count_neg)
{
    int qos[1] = {0};
    char buf[128] = {0};
    UNUSED(state);

    // When: no granted qos is reported
    assert_true(MQTTStringFormat_suback(buf, sizeof(buf), 1, 0, qos) > 0);
    assert_non_null(strstr(buf, "count 0"));
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTStringFormat_suback_failure_qos_neg)
{
    int qos[1] = {0x80};
    char buf[128] = {0};
    UNUSED(state);

    // When: the subscription failure code 0x80 is reported as granted qos
    assert_true(MQTTStringFormat_suback(buf, sizeof(buf), 1, 1, qos) > 0);
    assert_non_null(strstr(buf, "granted qos 128"));
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTStringFormat_suback_negative_count_neg)
{
    int qos[1] = {0};
    char buf[128] = {0};
    UNUSED(state);

    assert_true(MQTTStringFormat_suback(buf, sizeof(buf), 1, -1, qos) > 0);
    assert_non_null(strstr(buf, "count -1"));
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTStringFormat_unsubscribe_zero_count_neg)
{
    MQTTString filters[1];
    char buf[128] = {0};
    UNUSED(state);

    memset(filters, 0, sizeof(filters));
    assert_true(MQTTStringFormat_unsubscribe(buf, sizeof(buf), 0, 1, 0, filters) > 0);
    assert_non_null(strstr(buf, "count 0"));
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_unsubscribe_negative_count_neg)
{
    MQTTString filters[1];
    char buf[128] = {0};
    UNUSED(state);

    memset(filters, 0, sizeof(filters));
    assert_true(MQTTStringFormat_unsubscribe(buf, sizeof(buf), 0, 1, -1, filters) > 0);
    assert_non_null(strstr(buf, "count -1"));
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTStringFormat_unsubscribe_dup_set_neg)
{
    MQTTString filters[1];
    char buf[128] = {0};
    UNUSED(state);

    memset(filters, 0, sizeof(filters));
    filters[0].lenstring.data = "t";
    filters[0].lenstring.len = 1;
    assert_true(MQTTStringFormat_unsubscribe(buf, sizeof(buf), 1, 0xFFFF, 1, filters) > 0);
    assert_non_null(strstr(buf, "dup 1"));
    assert_non_null(strstr(buf, "packet id 65535"));
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTStringFormat_connect_zero_buffer_neg)
{
    MQTTPacket_connectData data = MQTTPacket_connectData_initializer;
    char buf[1] = {0x7f};
    int n;
    UNUSED(state);

    data.MQTTVersion = 4;
    // When: the output buffer length is zero and no optional field follows
    n = MQTTStringFormat_connect(buf, 0, &data);
    // Then
    assert_true(n > 0);
    assert_int_equal(buf[0], 0x7f);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTStringFormat_connect_empty_client_id_neg)
{
    MQTTPacket_connectData data = MQTTPacket_connectData_initializer;
    char buf[256] = {0};
    UNUSED(state);

    // Given: no client id at all
    data.MQTTVersion = 4;
    assert_true(MQTTStringFormat_connect(buf, sizeof(buf), &data) > 0);
    // Then: an empty client id is formatted instead of being rejected
    assert_non_null(strstr(buf, "client id ,"));
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTStringFormat_connect_unknown_version_neg)
{
    MQTTPacket_connectData data = MQTTPacket_connectData_initializer;
    char buf[256] = {0};
    UNUSED(state);

    // When: an MQTT version this parser does not implement is formatted
    data.MQTTVersion = 5;
    assert_true(MQTTStringFormat_connect(buf, sizeof(buf), &data) > 0);
    assert_non_null(strstr(buf, "MQTT version 5"));
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTStringFormat_connect_will_flag_without_will_neg)
{
    MQTTPacket_connectData data = MQTTPacket_connectData_initializer;
    char buf[256] = {0};
    UNUSED(state);

    // Given: the will flag is set but the will fields are empty
    data.MQTTVersion = 4;
    data.willFlag = 1;
    assert_true(MQTTStringFormat_connect(buf, sizeof(buf), &data) > 0);
    // Then: the will section is emitted with empty topic and message
    assert_non_null(strstr(buf, "will topic ,"));
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTStringFormat_connect_password_without_username_neg)
{
    MQTTPacket_connectData data = MQTTPacket_connectData_initializer;
    char buf[256] = {0};
    UNUSED(state);

    // Given: a password but no user name, which is invalid per the spec
    data.MQTTVersion = 4;
    data.password.lenstring.data = "pass";
    data.password.lenstring.len = 4;
    assert_true(MQTTStringFormat_connect(buf, sizeof(buf), &data) > 0);
    // Then: it is formatted anyway
    assert_null(strstr(buf, "user name"));
    assert_non_null(strstr(buf, "password pass"));
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTStringFormat_connect_zero_length_username_neg)
{
    MQTTPacket_connectData data = MQTTPacket_connectData_initializer;
    char buf[256] = {0};
    UNUSED(state);

    // Given: a user name pointer with a zero length
    data.MQTTVersion = 4;
    data.username.lenstring.data = "user";
    data.username.lenstring.len = 0;
    assert_true(MQTTStringFormat_connect(buf, sizeof(buf), &data) > 0);
    // Then: the empty user name is skipped
    assert_null(strstr(buf, "user name"));
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTStringFormat_connect_null_username_pointer_neg)
{
    MQTTPacket_connectData data = MQTTPacket_connectData_initializer;
    char buf[256] = {0};
    UNUSED(state);

    // Given: a non zero user name length with a null pointer
    data.MQTTVersion = 4;
    data.username.lenstring.data = NULL;
    data.username.lenstring.len = 4;
    assert_true(MQTTStringFormat_connect(buf, sizeof(buf), &data) > 0);
    // Then: the null pointer guard prevents the user name from being printed
    assert_null(strstr(buf, "user name"));
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTStringFormat_connect_wrapped_keepalive_neg)
{
    MQTTPacket_connectData data = MQTTPacket_connectData_initializer;
    char buf[256] = {0};
    UNUSED(state);

    // When: a negative keep alive interval is assigned to the unsigned field
    data.MQTTVersion = 4;
    data.keepAliveInterval = (unsigned short)-1;
    assert_true(MQTTStringFormat_connect(buf, sizeof(buf), &data) > 0);
    // Then: it wraps to the maximum instead of being rejected
    assert_non_null(strstr(buf, "keep alive 65535"));
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTStringFormat_connect_reserved_will_qos_neg)
{
    MQTTPacket_connectData data = MQTTPacket_connectData_initializer;
    char buf[256] = {0};
    UNUSED(state);

    // When: the reserved will qos value is formatted
    data.MQTTVersion = 4;
    data.willFlag = 1;
    data.will.qos = 3;
    data.will.topicName.lenstring.data = "w";
    data.will.topicName.lenstring.len = 1;
    data.will.message.lenstring.data = "m";
    data.will.message.lenstring.len = 1;
    assert_true(MQTTStringFormat_connect(buf, sizeof(buf), &data) > 0);
    assert_non_null(strstr(buf, "will QoS 3"));
}
