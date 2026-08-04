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

#include "cmocka_custom.h"

/* Not declared in the public header but defined in iot_mqtt_serialize_publish.c */
extern int MQTTSerialize_publishLength(int qos, MQTTString topicName, int payloadlen);

#define UNUSED(x) (void)(x)

/*
 * Tests for MQTTSerialize_publishLength / MQTTSerialize_publish_size
 */
void TC_MQTTSerialize_publishLength_qos0(void **state)
{
    MQTTString topic = MQTTString_initializer;
    int len;
    UNUSED(state);

    topic.cstring = "t";
    len = MQTTSerialize_publishLength(0, topic, 3);
    // Then: 2 (len) + 1 (topic) + 3 (payload) = 6, no packetid since QoS0
    assert_int_equal(len, 6);
}

void TC_MQTTSerialize_publishLength_qos1(void **state)
{
    MQTTString topic = MQTTString_initializer;
    int len;
    UNUSED(state);

    topic.cstring = "t";
    len = MQTTSerialize_publishLength(1, topic, 3);
    // Then: 6 + 2 (packetid) = 8
    assert_int_equal(len, 8);
}

void TC_MQTTSerialize_publish_size_qos0(void **state)
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
void TC_MQTTSerialize_publish_qos0_success(void **state)
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

void TC_MQTTSerialize_publish_qos1_success(void **state)
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

void TC_MQTTSerialize_publish_retained_flag(void **state)
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

void TC_MQTTSerialize_publish_buffer_too_short(void **state)
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

void TC_MQTTSerialize_publish_zero_buffer(void **state)
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

void TC_MQTTSerialize_publish_dup_flag(void **state)
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
void TC_MQTTSerialize_publish_header_qos0(void **state)
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

void TC_MQTTSerialize_publish_header_qos1_has_packetid(void **state)
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
void TC_MQTTSerialize_ack_success(void **state)
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

void TC_MQTTSerialize_ack_buffer_too_short(void **state)
{
    unsigned char buf[2] = {0};
    int rc;
    UNUSED(state);

    rc = MQTTSerialize_ack(buf, sizeof(buf), PUBACK, 0, 0x0001);
    assert_int_equal(rc, MQTTPACKET_BUFFER_TOO_SHORT);
}

void TC_MQTTSerialize_ack_zero_buffer(void **state)
{
    unsigned char buf[4] = {0};
    int rc;
    UNUSED(state);

    rc = MQTTSerialize_ack(buf, 0, PUBACK, 0, 0x0001);
    assert_int_equal(rc, MQTTPACKET_BUFFER_TOO_SHORT);
}

void TC_MQTTSerialize_ack_pubrel_forces_qos1(void **state)
{
    unsigned char buf[4] = {0};
    int rc;
    UNUSED(state);

    rc = MQTTSerialize_ack(buf, sizeof(buf), PUBREL, 0, 0x0001);
    assert_int_equal(rc, 4);
    /* qos bits at positions 1..2 */
    assert_int_equal((buf[0] & 0x06) >> 1, 1);
}

void TC_MQTTSerialize_ack_with_dup(void **state)
{
    unsigned char buf[4] = {0};
    int rc;
    UNUSED(state);

    rc = MQTTSerialize_ack(buf, sizeof(buf), PUBREL, 1, 0x0001);
    assert_int_equal(rc, 4);
    assert_int_equal(buf[0] & 0x08, 0x08);
}

void TC_MQTTSerialize_puback_success(void **state)
{
    unsigned char buf[4] = {0};
    int rc;
    UNUSED(state);

    rc = MQTTSerialize_puback(buf, sizeof(buf), 0x0001);
    assert_int_equal(rc, 4);
    assert_int_equal((buf[0] & 0xF0) >> 4, PUBACK);
}

void TC_MQTTSerialize_puback_buffer_too_short(void **state)
{
    unsigned char buf[3] = {0};
    int rc;
    UNUSED(state);

    rc = MQTTSerialize_puback(buf, sizeof(buf), 0x0001);
    assert_int_equal(rc, MQTTPACKET_BUFFER_TOO_SHORT);
}

void TC_MQTTSerialize_pubrel_success(void **state)
{
    unsigned char buf[4] = {0};
    int rc;
    UNUSED(state);

    rc = MQTTSerialize_pubrel(buf, sizeof(buf), 0, 0x0077);
    assert_int_equal(rc, 4);
    assert_int_equal((buf[0] & 0xF0) >> 4, PUBREL);
}

void TC_MQTTSerialize_pubrel_buffer_too_short(void **state)
{
    unsigned char buf[2] = {0};
    int rc;
    UNUSED(state);

    rc = MQTTSerialize_pubrel(buf, sizeof(buf), 0, 0x0001);
    assert_int_equal(rc, MQTTPACKET_BUFFER_TOO_SHORT);
}

void TC_MQTTSerialize_pubcomp_success(void **state)
{
    unsigned char buf[4] = {0};
    int rc;
    UNUSED(state);

    rc = MQTTSerialize_pubcomp(buf, sizeof(buf), 0x0088);
    assert_int_equal(rc, 4);
    assert_int_equal((buf[0] & 0xF0) >> 4, PUBCOMP);
}

void TC_MQTTSerialize_pubcomp_buffer_too_short(void **state)
{
    unsigned char buf[1] = {0};
    int rc;
    UNUSED(state);

    rc = MQTTSerialize_pubcomp(buf, sizeof(buf), 0x0001);
    assert_int_equal(rc, MQTTPACKET_BUFFER_TOO_SHORT);
}
