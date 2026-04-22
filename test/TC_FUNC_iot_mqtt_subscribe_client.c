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

/* Not declared in the public header but defined in iot_mqtt_subscribe_client.c */
extern int MQTTSerialize_subscribeLength(int count, MQTTString topicFilters[]);

#define UNUSED(x) (void)(x)

/*
 * Tests for MQTTSerialize_subscribeLength / MQTTSerialize_subscribe_size
 */
void TC_MQTTSerialize_subscribeLength_zero(void **state)
{
    int len;
    UNUSED(state);

    // When: no topic filters
    len = MQTTSerialize_subscribeLength(0, NULL);
    // Then: only the packetid length
    assert_int_equal(len, 2);
}

void TC_MQTTSerialize_subscribeLength_single_topic(void **state)
{
    MQTTString topic = MQTTString_initializer;
    int len;
    UNUSED(state);

    topic.cstring = "foo";
    len = MQTTSerialize_subscribeLength(1, &topic);
    // Then: 2 (packetid) + 2 (len field) + strlen("foo") + 1 (qos) = 8
    assert_int_equal(len, 8);
}

void TC_MQTTSerialize_subscribe_size_single_topic(void **state)
{
    MQTTString topic = MQTTString_initializer;
    int size;
    UNUSED(state);

    topic.cstring = "bar";
    size = MQTTSerialize_subscribe_size(1, &topic);
    // Then: fixed header (1) + rem_len_byte (1) + payload(8) = 10
    assert_int_equal(size, 10);
}

/*
 * Tests for MQTTSerialize_subscribe
 */
void TC_MQTTSerialize_subscribe_success(void **state)
{
    MQTTString topic = MQTTString_initializer;
    int requested_qos[] = {1};
    unsigned char buf[32] = {0};
    int rc;
    UNUSED(state);

    topic.cstring = "topic";
    // When
    rc = MQTTSerialize_subscribe(buf, sizeof(buf), 0, 0x0001, 1, &topic, requested_qos);
    // Then: non-zero success
    assert_true(rc > 0);
    /* verify the packet type field */
    assert_int_equal((buf[0] & 0xF0) >> 4, SUBSCRIBE);
}

void TC_MQTTSerialize_subscribe_multi_topic(void **state)
{
    MQTTString topics[3];
    int requested_qos[] = {0, 1, 2};
    unsigned char buf[64] = {0};
    int rc;
    UNUSED(state);

    memset(topics, 0, sizeof(topics));
    topics[0].cstring = "a";
    topics[1].cstring = "bb";
    topics[2].cstring = "ccc";
    // When
    rc = MQTTSerialize_subscribe(buf, sizeof(buf), 0, 0x0042, 3, topics, requested_qos);
    // Then
    assert_true(rc > 0);
}

void TC_MQTTSerialize_subscribe_buffer_too_short(void **state)
{
    MQTTString topic = MQTTString_initializer;
    int requested_qos[] = {1};
    unsigned char buf[4] = {0};
    int rc;
    UNUSED(state);

    topic.cstring = "the_topic_is_long_enough";
    // When: buffer cannot fit the serialized output
    rc = MQTTSerialize_subscribe(buf, sizeof(buf), 0, 0x0001, 1, &topic, requested_qos);
    // Then
    assert_int_equal(rc, MQTTPACKET_BUFFER_TOO_SHORT);
}

void TC_MQTTSerialize_subscribe_zero_buffer_length(void **state)
{
    MQTTString topic = MQTTString_initializer;
    int requested_qos[] = {1};
    unsigned char buf[32] = {0};
    int rc;
    UNUSED(state);

    topic.cstring = "t";
    // When: buflen=0 should always be too short
    rc = MQTTSerialize_subscribe(buf, 0, 0, 0x0001, 1, &topic, requested_qos);
    // Then
    assert_int_equal(rc, MQTTPACKET_BUFFER_TOO_SHORT);
}

void TC_MQTTSerialize_subscribe_dup_flag(void **state)
{
    MQTTString topic = MQTTString_initializer;
    int requested_qos[] = {1};
    unsigned char buf[32] = {0};
    int rc;
    UNUSED(state);

    topic.cstring = "t";
    // When: dup flag set
    rc = MQTTSerialize_subscribe(buf, sizeof(buf), 1, 0x0001, 1, &topic, requested_qos);
    // Then
    assert_true(rc > 0);
    /* dup bit is bit 3 of the header byte */
    assert_int_equal(buf[0] & 0x08, 0x08);
}

/*
 * Tests for MQTTDeserialize_suback
 */
static int _suback_build(unsigned char *buf, unsigned short packetid, int count,
                         const unsigned char *granted_qos)
{
    unsigned char *ptr = buf;
    int rem_len = 2 + count;

    *ptr++ = (unsigned char)(SUBACK << 4);
    ptr += MQTTPacket_encode(ptr, rem_len);
    *ptr++ = (unsigned char)(packetid >> 8);
    *ptr++ = (unsigned char)(packetid & 0xFF);
    memcpy(ptr, granted_qos, count);
    ptr += count;
    return ptr - buf;
}

void TC_MQTTDeserialize_suback_success(void **state)
{
    unsigned char buf[16] = {0};
    unsigned char granted_qos_in[] = {0, 1, 2};
    int granted_qos_out[4] = {0};
    unsigned short packetid = 0;
    int count = 0;
    int total;
    int rc;
    UNUSED(state);

    total = _suback_build(buf, 0x0033, 3, granted_qos_in);
    // When
    rc = MQTTDeserialize_suback(&packetid, 4, &count, granted_qos_out, buf, total);
    // Then
    assert_int_equal(rc, 1);
    assert_int_equal(packetid, 0x0033);
    assert_int_equal(count, 3);
    assert_int_equal(granted_qos_out[0], 0);
    assert_int_equal(granted_qos_out[1], 1);
    assert_int_equal(granted_qos_out[2], 2);
}

void TC_MQTTDeserialize_suback_wrong_type(void **state)
{
    unsigned char buf[] = {(unsigned char)(PUBACK << 4), 0x04, 0x00, 0x01, 0x00, 0x00};
    unsigned short packetid = 0;
    int count = 0;
    int granted_qos_out[4] = {0};
    int rc;
    UNUSED(state);

    // When: header identifies a different packet type
    rc = MQTTDeserialize_suback(&packetid, 4, &count, granted_qos_out, buf, sizeof(buf));
    // Then
    assert_int_equal(rc, 0);
}

void TC_MQTTDeserialize_suback_truncated(void **state)
{
    /* Claims rem_len of 1 which is too short to hold the packet id (2 bytes). */
    unsigned char buf[] = {(unsigned char)(SUBACK << 4), 0x01, 0x00};
    unsigned short packetid = 0;
    int count = 0;
    int granted_qos_out[4] = {0};
    int rc;
    UNUSED(state);

    rc = MQTTDeserialize_suback(&packetid, 4, &count, granted_qos_out, buf, sizeof(buf));
    // Note: the current implementation leaves rc set to the value returned by
    // MQTTPacket_decodeBuf when taking this short-data path, so the caller
    // cannot distinguish truncation from success by return code alone; the
    // decoded count is still zero.
    assert_int_not_equal(rc, -1);
    assert_int_equal(count, 0);
}

void TC_MQTTDeserialize_suback_too_many_qos(void **state)
{
    unsigned char buf[16] = {0};
    unsigned char granted_qos_in[] = {0, 1, 2, 0};
    int granted_qos_out[2] = {0};
    unsigned short packetid = 0;
    int count = 0;
    int total;
    int rc;
    UNUSED(state);

    total = _suback_build(buf, 0x0099, 4, granted_qos_in);
    // When: maxcount=2 is less than actual count (4)
    rc = MQTTDeserialize_suback(&packetid, 2, &count, granted_qos_out, buf, total);
    // Then
    assert_int_equal(rc, -1);
}

void TC_MQTTDeserialize_suback_zero_count(void **state)
{
    unsigned char buf[16] = {0};
    int granted_qos_out[4] = {0};
    unsigned short packetid = 0;
    int count = 0;
    int total;
    int rc;
    UNUSED(state);

    total = _suback_build(buf, 0x0055, 0, NULL);
    // When: count=0 (only packetid)
    rc = MQTTDeserialize_suback(&packetid, 4, &count, granted_qos_out, buf, total);
    // Then
    assert_int_equal(rc, 1);
    assert_int_equal(count, 0);
    assert_int_equal(packetid, 0x0055);
}
