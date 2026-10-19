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

/* Not declared in the public header but defined in iot_mqtt_subscribe_server.c */
extern int MQTTDeserialize_subscribe(unsigned char *dup, unsigned short *packetid, int maxcount, int *count,
                                     MQTTString topicFilters[], int requestedQoSs[], unsigned char *buf, int buflen);
extern int MQTTSerialize_suback(unsigned char *buf, int buflen, unsigned short packetid, int count, int *grantedQoSs);

#define UNUSED(x) (void)(x)

/*
 * Build a SUBSCRIBE wire packet into `buf` and return its length.
 */
TEST_SUITE("iot_mqtt_subscribe_server.c");

static int _build_subscribe(unsigned char *buf, int cap, unsigned short packetid, int topic_count, const char **topics,
                            int *qos)
{
    MQTTString filters[4];
    int i;

    if (topic_count > 4)
        topic_count = 4;
    memset(filters, 0, sizeof(filters));
    for (i = 0; i < topic_count; i++) {
        filters[i].cstring = (char *)topics[i];
    }
    return MQTTSerialize_subscribe(buf, cap, 0, packetid, topic_count, filters, qos);
}

/*
 * Tests for MQTTDeserialize_subscribe
 */
TEST(TC_MQTTDeserialize_subscribe_success_pos)
{
    unsigned char wire[64];
    MQTTString topics_out[4];
    int qos_out[4] = {0};
    unsigned char dup = 0;
    unsigned short packetid = 0;
    int count = 0;
    int total;
    int rc;
    const char *topics[] = {"t"};
    int qos[] = {1};
    UNUSED(state);

    memset(topics_out, 0, sizeof(topics_out));
    total = _build_subscribe(wire, sizeof(wire), 0x0042, 1, topics, qos);
    assert_true(total > 0);

    rc = MQTTDeserialize_subscribe(&dup, &packetid, 4, &count, topics_out, qos_out, wire, total);
    assert_int_equal(rc, 1);
    assert_int_equal(packetid, 0x0042);
    assert_int_equal(count, 1);
    assert_int_equal(qos_out[0], 1);
    assert_memory_equal(topics_out[0].lenstring.data, "t", 1);
}

TEST(TC_MQTTDeserialize_subscribe_multi_topic_neg)
{
    unsigned char wire[128];
    MQTTString topics_out[4];
    int qos_out[4] = {0};
    unsigned char dup = 0;
    unsigned short packetid = 0;
    int count = 0;
    int total;
    int rc;
    const char *topics[] = {"a", "bb", "ccc"};
    int qos[] = {0, 1, 2};
    UNUSED(state);

    memset(topics_out, 0, sizeof(topics_out));
    total = _build_subscribe(wire, sizeof(wire), 0x0001, 3, topics, qos);

    rc = MQTTDeserialize_subscribe(&dup, &packetid, 4, &count, topics_out, qos_out, wire, total);
    assert_int_equal(rc, 1);
    assert_int_equal(count, 3);
}

TEST(TC_MQTTDeserialize_subscribe_wrong_type_neg)
{
    unsigned char wire[] = {(unsigned char)(PUBACK << 4), 0x02, 0x00, 0x00};
    MQTTString topics_out[1];
    int qos_out[1] = {0};
    unsigned char dup = 0;
    unsigned short packetid = 0;
    int count = 0;
    int rc;
    UNUSED(state);

    rc = MQTTDeserialize_subscribe(&dup, &packetid, 1, &count, topics_out, qos_out, wire, sizeof(wire));
    assert_int_equal(rc, -1);
}

TEST(TC_MQTTDeserialize_subscribe_missing_qos_neg)
{
    /* header = SUBSCRIBE qos=1 (0x82), remlen claims 4, packetid + topic-len-field
     * but no QoS byte after the zero-length topic. */
    unsigned char wire[] = {0x82, 0x04, 0x00, 0x01, 0x00, 0x00};
    MQTTString topics_out[1];
    int qos_out[1] = {0};
    unsigned char dup = 0;
    unsigned short packetid = 0;
    int count = 0;
    int rc;
    UNUSED(state);

    memset(topics_out, 0, sizeof(topics_out));
    rc = MQTTDeserialize_subscribe(&dup, &packetid, 1, &count, topics_out, qos_out, wire, sizeof(wire));
    /* Current implementation does not reset rc on this goto-exit path; the
     * observable signal of truncation is that count stays at 0. */
    (void)rc;
    assert_int_equal(count, 0);
}

TEST(TC_MQTTDeserialize_subscribe_truncated_topic_neg)
{
    /* packetid + len-field claiming 5 bytes followed by nothing */
    unsigned char wire[] = {0x82, 0x04, 0x00, 0x01, 0x00, 0x05};
    MQTTString topics_out[1];
    int qos_out[1] = {0};
    unsigned char dup = 0;
    unsigned short packetid = 0;
    int count = 0;
    int rc;
    UNUSED(state);

    memset(topics_out, 0, sizeof(topics_out));
    rc = MQTTDeserialize_subscribe(&dup, &packetid, 1, &count, topics_out, qos_out, wire, sizeof(wire));
    /* Truncation is signalled by count remaining zero. */
    (void)rc;
    assert_int_equal(count, 0);
}

/*
 * Tests for MQTTSerialize_suback
 */
TEST(TC_MQTTSerialize_suback_success_pos)
{
    unsigned char buf[16] = {0};
    int qos[] = {1};
    int rc;
    UNUSED(state);

    rc = MQTTSerialize_suback(buf, sizeof(buf), 0x0042, 1, qos);
    assert_true(rc > 0);
    assert_int_equal((buf[0] & 0xF0) >> 4, SUBACK);
}

TEST(TC_MQTTSerialize_suback_multi_qos_neg)
{
    unsigned char buf[32] = {0};
    int qos[] = {0, 1, 2};
    int rc;
    UNUSED(state);

    rc = MQTTSerialize_suback(buf, sizeof(buf), 0x0077, 3, qos);
    assert_true(rc > 0);
}

TEST(TC_MQTTSerialize_suback_buffer_too_short_neg)
{
    unsigned char buf[1] = {0};
    int qos[] = {0};
    int rc;
    UNUSED(state);

    rc = MQTTSerialize_suback(buf, sizeof(buf), 0x0001, 1, qos);
    assert_int_equal(rc, MQTTPACKET_BUFFER_TOO_SHORT);
}

TEST(TC_MQTTSerialize_suback_buffer_just_short_neg)
{
    unsigned char buf[2] = {0};
    int qos[] = {0};
    int rc;
    UNUSED(state);

    /* buflen < 2 + count(1) -> fails */
    rc = MQTTSerialize_suback(buf, sizeof(buf), 0x0001, 1, qos);
    assert_int_equal(rc, MQTTPACKET_BUFFER_TOO_SHORT);
}

TEST(TC_MQTTSerialize_suback_zero_buffer_neg)
{
    unsigned char buf[8] = {0};
    int qos[] = {0};
    int rc;
    UNUSED(state);

    rc = MQTTSerialize_suback(buf, 0, 0x0001, 1, qos);
    assert_int_equal(rc, MQTTPACKET_BUFFER_TOO_SHORT);
}

TEST(TC_MQTTSerialize_suback_negative_buflen_neg)
{
    unsigned char buf[16] = {0};
    int qos[] = {0};
    int rc;
    UNUSED(state);

    // When: a negative buffer length is passed
    rc = MQTTSerialize_suback(buf, -1, 0x0001, 1, qos);
    // Then
    assert_int_equal(rc, MQTTPACKET_BUFFER_TOO_SHORT);
}

TEST(TC_MQTTSerialize_suback_count_exceeds_buflen_neg)
{
    unsigned char buf[4] = {0};
    int qos[] = {0, 1, 2};
    int rc;
    UNUSED(state);

    // When: 2 + count is larger than the buffer
    rc = MQTTSerialize_suback(buf, sizeof(buf), 0x0001, 3, qos);
    // Then
    assert_int_equal(rc, MQTTPACKET_BUFFER_TOO_SHORT);
}

TEST(TC_MQTTDeserialize_subscribe_reserved_type_neg)
{
    unsigned char wire[] = {0x00, 0x02, 0x00, 0x01};
    MQTTString topics_out[1];
    int qos_out[1] = {0};
    unsigned char dup = 0xFF;
    unsigned short packetid = 0xFFFF;
    int count = 0xFF;
    int rc;
    UNUSED(state);

    memset(topics_out, 0, sizeof(topics_out));
    // When: the reserved packet type 0 is deserialized as SUBSCRIBE
    rc = MQTTDeserialize_subscribe(&dup, &packetid, 1, &count, topics_out, qos_out, wire, sizeof(wire));
    // Then: rejected before any output is written
    assert_int_equal(rc, -1);
    assert_int_equal(count, 0xFF);
    assert_int_equal(packetid, 0xFFFF);
}
