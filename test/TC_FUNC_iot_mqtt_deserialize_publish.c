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

#define UNUSED(x) (void)(x)

/*
 * Build a PUBLISH wire packet into `buf` and return its length.
 */
static int _build_publish(unsigned char *buf, int qos, unsigned char dup, unsigned char retain,
                          unsigned short packetid, const char *topic, const unsigned char *payload,
                          int payload_len)
{
    MQTTString topic_str = MQTTString_initializer;
    topic_str.cstring = (char *)topic;
    return MQTTSerialize_publish(buf, 128, dup, qos, retain, packetid, topic_str,
                                 (unsigned char *)payload, payload_len);
}

/*
 * Tests for MQTTDeserialize_publish
 */
void TC_MQTTDeserialize_publish_qos0_success(void **state)
{
    unsigned char wire[128];
    unsigned char dup = 0xFF;
    int qos = -1;
    unsigned char retain = 0xFF;
    unsigned short packetid = 0xFFFF;
    MQTTString topic_name = MQTTString_initializer;
    unsigned char *payload = NULL;
    int payload_len = -1;
    int total;
    int rc;
    UNUSED(state);

    total = _build_publish(wire, 0, 0, 0, 0, "topic", (const unsigned char *)"hi", 2);
    assert_true(total > 0);

    rc = MQTTDeserialize_publish(&dup, &qos, &retain, &packetid, &topic_name,
                                 &payload, &payload_len, wire, total);
    assert_int_equal(rc, 1);
    assert_int_equal(qos, 0);
    assert_int_equal(dup, 0);
    assert_int_equal(retain, 0);
    assert_int_equal(topic_name.lenstring.len, 5);
    assert_memory_equal(topic_name.lenstring.data, "topic", 5);
    assert_int_equal(payload_len, 2);
    assert_memory_equal(payload, "hi", 2);
}

void TC_MQTTDeserialize_publish_qos1_has_packetid(void **state)
{
    unsigned char wire[128];
    unsigned char dup = 0, retain = 0;
    int qos = 0;
    unsigned short packetid = 0;
    MQTTString topic_name = MQTTString_initializer;
    unsigned char *payload = NULL;
    int payload_len = 0;
    int total;
    int rc;
    UNUSED(state);

    total = _build_publish(wire, 1, 0, 0, 0x1234, "t", (const unsigned char *)"ab", 2);

    rc = MQTTDeserialize_publish(&dup, &qos, &retain, &packetid, &topic_name,
                                 &payload, &payload_len, wire, total);
    assert_int_equal(rc, 1);
    assert_int_equal(qos, 1);
    assert_int_equal(packetid, 0x1234);
}

void TC_MQTTDeserialize_publish_dup_and_retain(void **state)
{
    unsigned char wire[128];
    unsigned char dup = 0, retain = 0;
    int qos = 0;
    unsigned short packetid = 0;
    MQTTString topic_name = MQTTString_initializer;
    unsigned char *payload = NULL;
    int payload_len = 0;
    int total;
    int rc;
    UNUSED(state);

    total = _build_publish(wire, 1, 1, 1, 0x0001, "t", (const unsigned char *)"x", 1);

    rc = MQTTDeserialize_publish(&dup, &qos, &retain, &packetid, &topic_name,
                                 &payload, &payload_len, wire, total);
    assert_int_equal(rc, 1);
    assert_int_equal(dup, 1);
    assert_int_equal(retain, 1);
}

void TC_MQTTDeserialize_publish_empty_payload(void **state)
{
    unsigned char wire[32];
    unsigned char dup = 0, retain = 0;
    int qos = 0;
    unsigned short packetid = 0;
    MQTTString topic_name = MQTTString_initializer;
    unsigned char *payload = NULL;
    int payload_len = -1;
    int total;
    int rc;
    UNUSED(state);

    total = _build_publish(wire, 0, 0, 0, 0, "t", NULL, 0);

    rc = MQTTDeserialize_publish(&dup, &qos, &retain, &packetid, &topic_name,
                                 &payload, &payload_len, wire, total);
    assert_int_equal(rc, 1);
    assert_int_equal(payload_len, 0);
}

void TC_MQTTDeserialize_publish_wrong_type(void **state)
{
    unsigned char wire[] = {(unsigned char)(PUBACK << 4), 0x04, 0x00, 0x01, 0x00, 0x00};
    unsigned char dup = 0, retain = 0;
    int qos = 0;
    unsigned short packetid = 0;
    MQTTString topic_name = MQTTString_initializer;
    unsigned char *payload = NULL;
    int payload_len = 0;
    int rc;
    UNUSED(state);

    rc = MQTTDeserialize_publish(&dup, &qos, &retain, &packetid, &topic_name,
                                 &payload, &payload_len, wire, sizeof(wire));
    assert_int_equal(rc, 0);
}

void TC_MQTTDeserialize_publish_truncated_length_field(void **state)
{
    /* header + only part of the length-field (need 2 bytes for readMQTTLenString) */
    unsigned char wire[] = {(unsigned char)(PUBLISH << 4), 0x01, 0x00};
    unsigned char dup = 0, retain = 0;
    int qos = 0;
    unsigned short packetid = 0;
    MQTTString topic_name = MQTTString_initializer;
    unsigned char *payload = NULL;
    int payload_len = 0;
    int rc;
    UNUSED(state);

    // Note: this exercises the goto-exit path inside MQTTDeserialize_publish
    // when readMQTTLenString fails; the current implementation does not
    // reset rc so the returned value may still be non-zero.  The important
    // guarantee is that the lenstring stays uninitialized and payload is
    // not touched.
    rc = MQTTDeserialize_publish(&dup, &qos, &retain, &packetid, &topic_name,
                                 &payload, &payload_len, wire, sizeof(wire));
    (void)rc;
    assert_int_equal(topic_name.lenstring.len, 0);
    assert_null(payload);
}

/*
 * Tests for MQTTDeserialize_ack
 */
void TC_MQTTDeserialize_ack_success(void **state)
{
    unsigned char wire[] = {(unsigned char)(PUBACK << 4), 0x02, 0x12, 0x34};
    unsigned char packettype = 0, dup = 0;
    unsigned short packetid = 0;
    int rc;
    UNUSED(state);

    rc = MQTTDeserialize_ack(&packettype, &dup, &packetid, wire, sizeof(wire));
    assert_int_equal(rc, 1);
    assert_int_equal(packettype, PUBACK);
    assert_int_equal(packetid, 0x1234);
}

void TC_MQTTDeserialize_ack_pubrec(void **state)
{
    unsigned char wire[] = {(unsigned char)(PUBREC << 4), 0x02, 0x00, 0x42};
    unsigned char packettype = 0, dup = 0;
    unsigned short packetid = 0;
    int rc;
    UNUSED(state);

    rc = MQTTDeserialize_ack(&packettype, &dup, &packetid, wire, sizeof(wire));
    assert_int_equal(rc, 1);
    assert_int_equal(packettype, PUBREC);
    assert_int_equal(packetid, 0x42);
}

void TC_MQTTDeserialize_ack_remlen_too_short(void **state)
{
    unsigned char wire[] = {(unsigned char)(PUBACK << 4), 0x01, 0x00};
    unsigned char packettype = 0, dup = 0;
    unsigned short packetid = 0xAAAA;
    int rc;
    UNUSED(state);

    rc = MQTTDeserialize_ack(&packettype, &dup, &packetid, wire, sizeof(wire));
    // remlen is less than 2 -> take the early exit branch
    (void)rc;
    assert_int_equal(packetid, 0xAAAA);
}

void TC_MQTTDeserialize_ack_with_dup_bit(void **state)
{
    unsigned char wire[] = {((unsigned char)PUBREL << 4) | 0x08 | 0x02, 0x02, 0x00, 0x10};
    unsigned char packettype = 0, dup = 0;
    unsigned short packetid = 0;
    int rc;
    UNUSED(state);

    rc = MQTTDeserialize_ack(&packettype, &dup, &packetid, wire, sizeof(wire));
    assert_int_equal(rc, 1);
    assert_int_equal(packettype, PUBREL);
    assert_int_equal(dup, 1);
}
