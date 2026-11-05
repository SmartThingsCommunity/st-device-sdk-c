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
#include <string.h>

#include "TC_REGISTRY.h"
#include "cmocka_custom.h"

/* Not declared in the public header but defined in iot_mqtt_serialize_publish.c */
extern int MQTTSerialize_publishLength(int qos, MQTTString topicName, int payloadlen);

#define UNUSED(x) (void)(x)

/*
 * Tests for MQTTSerialize_publishLength / MQTTSerialize_publish_size
 */
TEST_SUITE("iot_mqtt_serialize_publish.c");

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_publishLength_qos0_neg)
{
    MQTTString topic = MQTTString_initializer;
    int len;
    UNUSED(state);

    topic.cstring = "t";
    len = MQTTSerialize_publishLength(0, topic, 3);
    // Then: 2 (len) + 1 (topic) + 3 (payload) = 6, no packetid since QoS0
    assert_int_equal(len, 6);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_publishLength_qos1_neg)
{
    MQTTString topic = MQTTString_initializer;
    int len;
    UNUSED(state);

    topic.cstring = "t";
    len = MQTTSerialize_publishLength(1, topic, 3);
    // Then: 6 + 2 (packetid) = 8
    assert_int_equal(len, 8);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_publish_size_qos0_neg)
{
    MQTTString topic = MQTTString_initializer;
    int size;
    UNUSED(state);

    topic.cstring = "topic";
    size = MQTTSerialize_publish_size(0, topic, 4);
    // Then: header(1) + remlen byte(1) + rem_len(2 + 5 + 4) = 13
    assert_int_equal(size, 13);
}

/*
 * Tests for MQTTSerialize_publish
 */
TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_publish_qos0_success_pos)
{
    MQTTString topic = MQTTString_initializer;
    unsigned char payload[] = {'x', 'y', 'z'};
    unsigned char buf[32] = {0};
    int rc;
    UNUSED(state);

    topic.cstring = "t";
    rc = MQTTSerialize_publish(buf, sizeof(buf), 0, 0, 0, 0, topic, payload, sizeof(payload));
    assert_true(rc > 0);
    assert_int_equal((buf[0] & 0xF0) >> 4, PUBLISH);
    /* qos bits at 1..2, should be 0 */
    assert_int_equal(buf[0] & 0x06, 0);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_publish_qos1_success_pos)
{
    MQTTString topic = MQTTString_initializer;
    unsigned char payload[] = {0xAA, 0xBB};
    unsigned char buf[32] = {0};
    int rc;
    UNUSED(state);

    topic.cstring = "test";
    rc = MQTTSerialize_publish(buf, sizeof(buf), 0, 1, 0, 0x1234, topic, payload, sizeof(payload));
    assert_true(rc > 0);
    /* qos bit 1 should be set */
    assert_int_equal((buf[0] & 0x06) >> 1, 1);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_publish_retained_flag_neg)
{
    MQTTString topic = MQTTString_initializer;
    unsigned char payload[] = {0x01};
    unsigned char buf[16] = {0};
    int rc;
    UNUSED(state);

    topic.cstring = "r";
    rc = MQTTSerialize_publish(buf, sizeof(buf), 0, 0, 1, 0, topic, payload, sizeof(payload));
    assert_true(rc > 0);
    /* retained is bit 0 */
    assert_int_equal(buf[0] & 0x01, 1);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_publish_buffer_too_short_neg)
{
    MQTTString topic = MQTTString_initializer;
    unsigned char payload[8] = {0};
    unsigned char buf[4] = {0};
    int rc;
    UNUSED(state);

    topic.cstring = "topic";
    rc = MQTTSerialize_publish(buf, sizeof(buf), 0, 0, 0, 0, topic, payload, sizeof(payload));
    assert_int_equal(rc, MQTTPACKET_BUFFER_TOO_SHORT);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_publish_zero_buffer_neg)
{
    MQTTString topic = MQTTString_initializer;
    unsigned char payload[1] = {0};
    unsigned char buf[16] = {0};
    int rc;
    UNUSED(state);

    topic.cstring = "a";
    // When: buflen = 0
    rc = MQTTSerialize_publish(buf, 0, 0, 0, 0, 0, topic, payload, sizeof(payload));
    assert_int_equal(rc, MQTTPACKET_BUFFER_TOO_SHORT);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_publish_dup_flag_neg)
{
    MQTTString topic = MQTTString_initializer;
    unsigned char payload[1] = {0};
    unsigned char buf[16] = {0};
    int rc;
    UNUSED(state);

    topic.cstring = "d";
    rc = MQTTSerialize_publish(buf, sizeof(buf), 1, 1, 0, 42, topic, payload, sizeof(payload));
    assert_true(rc > 0);
    /* dup is bit 3 */
    assert_int_equal(buf[0] & 0x08, 0x08);
}

/*
 * Tests for MQTTSerialize_publish_header
 */
TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_publish_header_qos0_neg)
{
    MQTTString topic = MQTTString_initializer;
    unsigned char buf[16] = {0};
    int rc;
    UNUSED(state);

    topic.cstring = "h";
    rc = MQTTSerialize_publish_header(buf, 0, 0, 0, 0, topic, 5);
    assert_true(rc > 0);
    assert_int_equal((buf[0] & 0xF0) >> 4, PUBLISH);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_publish_header_qos1_has_packetid_neg)
{
    MQTTString topic = MQTTString_initializer;
    unsigned char buf[32] = {0};
    int rc;
    UNUSED(state);

    topic.cstring = "topic";
    rc = MQTTSerialize_publish_header(buf, 0, 1, 0, 0x0055, topic, 2);
    assert_true(rc > 0);
    /* last two bytes of the output contain packet id high,low */
    assert_int_equal(buf[rc - 2], 0x00);
    assert_int_equal(buf[rc - 1], 0x55);
}

/*
 * Tests for MQTTSerialize_ack / _puback / _pubrel / _pubcomp
 */
TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_ack_success_pos)
{
    unsigned char buf[4] = {0};
    int rc;
    UNUSED(state);

    rc = MQTTSerialize_ack(buf, sizeof(buf), PUBACK, 0, 0x0042);
    assert_int_equal(rc, 4);
    assert_int_equal((buf[0] & 0xF0) >> 4, PUBACK);
    assert_int_equal(buf[1], 2);
    assert_int_equal(buf[2], 0x00);
    assert_int_equal(buf[3], 0x42);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_ack_buffer_too_short_neg)
{
    unsigned char buf[2] = {0};
    int rc;
    UNUSED(state);

    rc = MQTTSerialize_ack(buf, sizeof(buf), PUBACK, 0, 0x0001);
    assert_int_equal(rc, MQTTPACKET_BUFFER_TOO_SHORT);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_ack_zero_buffer_neg)
{
    unsigned char buf[4] = {0};
    int rc;
    UNUSED(state);

    rc = MQTTSerialize_ack(buf, 0, PUBACK, 0, 0x0001);
    assert_int_equal(rc, MQTTPACKET_BUFFER_TOO_SHORT);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_ack_pubrel_forces_qos1_neg)
{
    unsigned char buf[4] = {0};
    int rc;
    UNUSED(state);

    rc = MQTTSerialize_ack(buf, sizeof(buf), PUBREL, 0, 0x0001);
    assert_int_equal(rc, 4);
    /* qos bits at positions 1..2 */
    assert_int_equal((buf[0] & 0x06) >> 1, 1);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_ack_with_dup_neg)
{
    unsigned char buf[4] = {0};
    int rc;
    UNUSED(state);

    rc = MQTTSerialize_ack(buf, sizeof(buf), PUBREL, 1, 0x0001);
    assert_int_equal(rc, 4);
    assert_int_equal(buf[0] & 0x08, 0x08);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_puback_success_pos)
{
    unsigned char buf[4] = {0};
    int rc;
    UNUSED(state);

    rc = MQTTSerialize_puback(buf, sizeof(buf), 0x0001);
    assert_int_equal(rc, 4);
    assert_int_equal((buf[0] & 0xF0) >> 4, PUBACK);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_puback_buffer_too_short_neg)
{
    unsigned char buf[3] = {0};
    int rc;
    UNUSED(state);

    rc = MQTTSerialize_puback(buf, sizeof(buf), 0x0001);
    assert_int_equal(rc, MQTTPACKET_BUFFER_TOO_SHORT);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_pubrel_success_pos)
{
    unsigned char buf[4] = {0};
    int rc;
    UNUSED(state);

    rc = MQTTSerialize_pubrel(buf, sizeof(buf), 0, 0x0077);
    assert_int_equal(rc, 4);
    assert_int_equal((buf[0] & 0xF0) >> 4, PUBREL);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_pubrel_buffer_too_short_neg)
{
    unsigned char buf[2] = {0};
    int rc;
    UNUSED(state);

    rc = MQTTSerialize_pubrel(buf, sizeof(buf), 0, 0x0001);
    assert_int_equal(rc, MQTTPACKET_BUFFER_TOO_SHORT);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_pubcomp_success_pos)
{
    unsigned char buf[4] = {0};
    int rc;
    UNUSED(state);

    rc = MQTTSerialize_pubcomp(buf, sizeof(buf), 0x0088);
    assert_int_equal(rc, 4);
    assert_int_equal((buf[0] & 0xF0) >> 4, PUBCOMP);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_pubcomp_buffer_too_short_neg)
{
    unsigned char buf[1] = {0};
    int rc;
    UNUSED(state);

    rc = MQTTSerialize_pubcomp(buf, sizeof(buf), 0x0001);
    assert_int_equal(rc, MQTTPACKET_BUFFER_TOO_SHORT);
}

/*
 * Additional negative and boundary tests for iot_mqtt_serialize_publish.c
 */
TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_publishLength_negative_qos_neg)
{
    MQTTString topic = MQTTString_initializer;
    UNUSED(state);

    topic.cstring = "t";
    // When: a negative qos is passed
    // Then: no packet id room is reserved
    assert_int_equal(MQTTSerialize_publishLength(-1, topic, 3), 6);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_publishLength_zero_payload_neg)
{
    MQTTString topic = MQTTString_initializer;
    UNUSED(state);

    topic.cstring = "t";
    // When: there is no payload at all
    assert_int_equal(MQTTSerialize_publishLength(0, topic, 0), 3);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_publishLength_lenstring_topic_neg)
{
    MQTTString topic = MQTTString_initializer;
    UNUSED(state);

    // Given: the topic is given as a length prefixed string, not a c string
    topic.lenstring.data = "abcd";
    topic.lenstring.len = 4;
    // Then: the length must account for the lenstring form as well
    assert_int_equal(MQTTSerialize_publishLength(0, topic, 1), 7);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_publish_size_qos1_neg)
{
    MQTTString topic = MQTTString_initializer;
    UNUSED(state);

    topic.cstring = "topic";
    // Then: header(1) + remlen(1) + 2 + 5 + 4 + packetid(2) = 15
    assert_int_equal(MQTTSerialize_publish_size(1, topic, 4), 15);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_publish_size_two_byte_remlen_neg)
{
    MQTTString topic = MQTTString_initializer;
    UNUSED(state);

    topic.cstring = "t";
    // Given: a payload that pushes the remaining length past one byte
    // Then: header(1) + remlen(2) + 2 + 1 + 200 = 206
    assert_int_equal(MQTTSerialize_publish_size(0, topic, 200), 206);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_publish_one_byte_short_neg)
{
    MQTTString topic = MQTTString_initializer;
    unsigned char payload[] = {'x', 'y', 'z'};
    unsigned char buf[32] = {0};
    int required;
    UNUSED(state);

    topic.cstring = "topic";
    required = MQTTSerialize_publish_size(0, topic, sizeof(payload));
    assert_true(required <= (int)sizeof(buf));

    // When: the buffer is one byte smaller than required
    assert_int_equal(MQTTSerialize_publish(buf, required - 1, 0, 0, 0, 0, topic, payload, sizeof(payload)),
                     MQTTPACKET_BUFFER_TOO_SHORT);
    // and nothing was written
    assert_int_equal(buf[0], 0);
    // When: the buffer is exactly the required size
    assert_int_equal(MQTTSerialize_publish(buf, required, 0, 0, 0, 0, topic, payload, sizeof(payload)), required);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_publish_negative_buflen_neg)
{
    MQTTString topic = MQTTString_initializer;
    unsigned char payload[] = {'x'};
    unsigned char buf[32] = {0};
    UNUSED(state);

    topic.cstring = "t";
    // When: a negative buffer length is passed
    assert_int_equal(MQTTSerialize_publish(buf, -1, 0, 0, 0, 0, topic, payload, sizeof(payload)),
                     MQTTPACKET_BUFFER_TOO_SHORT);
    assert_int_equal(buf[0], 0);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_publish_reserved_qos_neg)
{
    MQTTString topic = MQTTString_initializer;
    unsigned char payload[] = {'x'};
    unsigned char buf[32] = {0};
    int rc;
    UNUSED(state);

    topic.cstring = "t";
    // When: the reserved qos value 3 is requested
    rc = MQTTSerialize_publish(buf, sizeof(buf), 0, 3, 0, 0x1234, topic, payload, sizeof(payload));
    // Then: it is written to the wire as-is instead of being rejected
    assert_true(rc > 0);
    assert_int_equal((buf[0] & MQTT_FIXED_HEADER_QOS_MASK) >> MQTT_FIXED_HEADER_QOS_OFFSET, 3);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_publish_empty_topic_neg)
{
    MQTTString topic = MQTTString_initializer;
    unsigned char payload[] = {'x'};
    unsigned char buf[32] = {0};
    int rc;
    UNUSED(state);

    // Given: neither cstring nor lenstring is set
    // When
    rc = MQTTSerialize_publish(buf, sizeof(buf), 0, 0, 0, 0, topic, payload, sizeof(payload));
    // Then: an empty topic is accepted and encoded as a zero length string
    assert_int_equal(rc, 5);
    assert_int_equal(buf[2], 0);
    assert_int_equal(buf[3], 0);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_publish_header_dup_and_retain_neg)
{
    MQTTString topic = MQTTString_initializer;
    unsigned char buf[32] = {0};
    int rc;
    UNUSED(state);

    topic.cstring = "t";
    // When: dup and retain are both requested
    rc = MQTTSerialize_publish_header(buf, 1, 1, 1, 0x0007, topic, 4);
    // Then: both flag bits appear in the fixed header
    assert_true(rc > 0);
    assert_int_equal((buf[0] & MQTT_FIXED_HEADER_DUP_MASK) >> MQTT_FIXED_HEADER_DUP_OFFSET, 1);
    assert_int_equal(buf[0] & 0x01, 1);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_ack_negative_buflen_neg)
{
    unsigned char buf[8] = {0};
    UNUSED(state);

    // When: a negative buffer length is passed
    assert_int_equal(MQTTSerialize_ack(buf, -1, PUBACK, 0, 0x0001), MQTTPACKET_BUFFER_TOO_SHORT);
    assert_int_equal(buf[0], 0);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_ack_out_of_range_packettype_neg)
{
    unsigned char buf[8] = {0};
    int rc;
    UNUSED(state);

    // When: a packet type that does not fit the 4 bit field is requested
    rc = MQTTSerialize_ack(buf, sizeof(buf), 0xFF, 0, 0x0001);
    // Then: the type is silently truncated to the low nibble
    assert_int_equal(rc, 4);
    assert_int_equal((buf[0] & MQTT_FIXED_HEADER_PACKET_TYPE_MASK) >> MQTT_FIXED_HEADER_PACKET_TYPE_OFFSET, 0x0F);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_puback_zero_buffer_neg)
{
    unsigned char buf[8] = {0};
    UNUSED(state);

    assert_int_equal(MQTTSerialize_puback(buf, 0, 0x0001), MQTTPACKET_BUFFER_TOO_SHORT);
    assert_int_equal(buf[0], 0);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_pubrel_zero_buffer_neg)
{
    unsigned char buf[8] = {0};
    UNUSED(state);

    assert_int_equal(MQTTSerialize_pubrel(buf, 0, 0, 0x0001), MQTTPACKET_BUFFER_TOO_SHORT);
    assert_int_equal(buf[0], 0);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_pubcomp_zero_buffer_neg)
{
    unsigned char buf[8] = {0};
    UNUSED(state);

    assert_int_equal(MQTTSerialize_pubcomp(buf, 0, 0x0001), MQTTPACKET_BUFFER_TOO_SHORT);
    assert_int_equal(buf[0], 0);
}
