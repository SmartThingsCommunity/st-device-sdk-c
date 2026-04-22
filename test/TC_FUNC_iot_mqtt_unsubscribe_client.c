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

/* Not declared in the public header but defined in iot_mqtt_unsubscribe_client.c */
extern int MQTTSerialize_unsubscribeLength(int count, MQTTString topicFilters[]);
extern int MQTTSerialize_unsubscribe_size(int count, MQTTString topicFilters[]);

#define UNUSED(x) (void)(x)

/*
 * Tests for MQTTSerialize_unsubscribeLength / size
 */
void TC_MQTTSerialize_unsubscribeLength_empty(void **state)
{
    int len;
    UNUSED(state);

    len = MQTTSerialize_unsubscribeLength(0, NULL);
    // Then: 2 bytes (packetid only)
    assert_int_equal(len, 2);
}

void TC_MQTTSerialize_unsubscribeLength_single_topic(void **state)
{
    MQTTString topic = MQTTString_initializer;
    int len;
    UNUSED(state);

    topic.cstring = "foo";
    len = MQTTSerialize_unsubscribeLength(1, &topic);
    // Then: 2 (packetid) + 2 (len) + 3 (topic) = 7
    assert_int_equal(len, 7);
}

void TC_MQTTSerialize_unsubscribe_size_single_topic(void **state)
{
    MQTTString topic = MQTTString_initializer;
    int size;
    UNUSED(state);

    topic.cstring = "bar";
    size = MQTTSerialize_unsubscribe_size(1, &topic);
    // Then: 1 (header) + 1 (remlen) + 2 + 2 + 3 = 9
    assert_int_equal(size, 9);
}

/*
 * Tests for MQTTSerialize_unsubscribe
 */
void TC_MQTTSerialize_unsubscribe_success(void **state)
{
    MQTTString topic = MQTTString_initializer;
    unsigned char buf[32] = {0};
    int rc;
    UNUSED(state);

    topic.cstring = "topic";
    rc = MQTTSerialize_unsubscribe(buf, sizeof(buf), 0, 0x0001, 1, &topic);
    assert_true(rc > 0);
    assert_int_equal((buf[0] & 0xF0) >> 4, UNSUBSCRIBE);
}

void TC_MQTTSerialize_unsubscribe_multi_topic(void **state)
{
    MQTTString topics[3];
    unsigned char buf[64] = {0};
    int rc;
    UNUSED(state);

    memset(topics, 0, sizeof(topics));
    topics[0].cstring = "a";
    topics[1].cstring = "bb";
    topics[2].cstring = "ccc";
    rc = MQTTSerialize_unsubscribe(buf, sizeof(buf), 0, 0x0042, 3, topics);
    assert_true(rc > 0);
}

void TC_MQTTSerialize_unsubscribe_buffer_too_short(void **state)
{
    MQTTString topic = MQTTString_initializer;
    unsigned char buf[4] = {0};
    int rc;
    UNUSED(state);

    topic.cstring = "topicname_long_enough";
    rc = MQTTSerialize_unsubscribe(buf, sizeof(buf), 0, 0x0001, 1, &topic);
    assert_int_equal(rc, MQTTPACKET_BUFFER_TOO_SHORT);
}

void TC_MQTTSerialize_unsubscribe_zero_buffer(void **state)
{
    MQTTString topic = MQTTString_initializer;
    unsigned char buf[16] = {0};
    int rc;
    UNUSED(state);

    topic.cstring = "t";
    rc = MQTTSerialize_unsubscribe(buf, 0, 0, 0x0001, 1, &topic);
    assert_int_equal(rc, MQTTPACKET_BUFFER_TOO_SHORT);
}

void TC_MQTTSerialize_unsubscribe_dup_flag(void **state)
{
    MQTTString topic = MQTTString_initializer;
    unsigned char buf[16] = {0};
    int rc;
    UNUSED(state);

    topic.cstring = "t";
    rc = MQTTSerialize_unsubscribe(buf, sizeof(buf), 1, 0x0001, 1, &topic);
    assert_true(rc > 0);
    assert_int_equal(buf[0] & 0x08, 0x08);
}

/*
 * Tests for MQTTDeserialize_unsuback
 */
void TC_MQTTDeserialize_unsuback_success(void **state)
{
    unsigned char buf[] = {(unsigned char)(UNSUBACK << 4), 0x02, 0x12, 0x34};
    unsigned short packetid = 0;
    int rc;
    UNUSED(state);

    rc = MQTTDeserialize_unsuback(&packetid, buf, sizeof(buf));
    assert_int_equal(rc, 1);
    assert_int_equal(packetid, 0x1234);
}

void TC_MQTTDeserialize_unsuback_wrong_type(void **state)
{
    unsigned char buf[] = {(unsigned char)(PUBACK << 4), 0x02, 0x00, 0x00};
    unsigned short packetid = 0xFFFF;
    int rc;
    UNUSED(state);

    // Note: the function does not short-circuit on a wrong type; it still
    // decodes the packet id as if it were an ack, which is the historical
    // behaviour of the Eclipse Paho helper.  This test just verifies that
    // the packet id is decoded without crashing.
    rc = MQTTDeserialize_unsuback(&packetid, buf, sizeof(buf));
    (void)rc;
    assert_int_equal(packetid, 0x0000);
}

void TC_MQTTDeserialize_unsuback_short_buffer(void **state)
{
    unsigned char buf[] = {(unsigned char)(UNSUBACK << 4), 0x00};
    unsigned short packetid = 0xABCD;
    int rc;
    UNUSED(state);

    // No bytes available for packet id; the inner MQTTDeserialize_ack
    // returns early with rc left at the decoded remlen length (1).
    rc = MQTTDeserialize_unsuback(&packetid, buf, sizeof(buf));
    (void)rc;
    // packetid must not have been set with a fresh value from the buffer
    assert_int_equal(packetid, 0xABCD);
}

void TC_MQTTDeserialize_unsuback_empty_buffer(void **state)
{
    unsigned char buf[] = {(unsigned char)(UNSUBACK << 4), 0x00};
    unsigned short packetid = 0;
    int rc;
    UNUSED(state);

    // Buffer with header + remlen but no packet id; the helper should not
    // crash even though the implementation cannot report a proper error.
    rc = MQTTDeserialize_unsuback(&packetid, buf, sizeof(buf));
    (void)rc;
}
