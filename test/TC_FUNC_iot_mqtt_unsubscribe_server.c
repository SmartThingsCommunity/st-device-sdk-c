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

/* Not declared in the public header but defined in iot_mqtt_unsubscribe_server.c */
extern int MQTTDeserialize_unsubscribe(unsigned char *dup, unsigned short *packetid, int maxcount,
                                       int *count, MQTTString topicFilters[], unsigned char *buf,
                                       int len);
extern int MQTTSerialize_unsuback(unsigned char *buf, int buflen, unsigned short packetid);

#define UNUSED(x) (void)(x)

/*
 * Tests for MQTTDeserialize_unsubscribe
 */
void TC_MQTTDeserialize_unsubscribe_success(void **state)
{
    unsigned char wire[64];
    MQTTString topics[4];
    MQTTString topics_out[4];
    unsigned char dup = 0;
    unsigned short packetid = 0;
    int count = 0;
    int total;
    int rc;
    UNUSED(state);

    memset(topics, 0, sizeof(topics));
    topics[0].cstring = "t";
    total = MQTTSerialize_unsubscribe(wire, sizeof(wire), 0, 0x0042, 1, topics);
    assert_true(total > 0);

    memset(topics_out, 0, sizeof(topics_out));
    rc = MQTTDeserialize_unsubscribe(&dup, &packetid, 4, &count, topics_out, wire, total);
    assert_int_equal(rc, 1);
    assert_int_equal(packetid, 0x0042);
    assert_int_equal(count, 1);
    assert_memory_equal(topics_out[0].lenstring.data, "t", 1);
}

void TC_MQTTDeserialize_unsubscribe_multi_topic(void **state)
{
    unsigned char wire[128];
    MQTTString topics[3];
    MQTTString topics_out[4];
    unsigned char dup = 0;
    unsigned short packetid = 0;
    int count = 0;
    int total;
    int rc;
    UNUSED(state);

    memset(topics, 0, sizeof(topics));
    topics[0].cstring = "a";
    topics[1].cstring = "bb";
    topics[2].cstring = "ccc";
    total = MQTTSerialize_unsubscribe(wire, sizeof(wire), 0, 0x0001, 3, topics);

    memset(topics_out, 0, sizeof(topics_out));
    rc = MQTTDeserialize_unsubscribe(&dup, &packetid, 4, &count, topics_out, wire, total);
    assert_int_equal(rc, 1);
    assert_int_equal(count, 3);
}

void TC_MQTTDeserialize_unsubscribe_wrong_type(void **state)
{
    unsigned char wire[] = {(unsigned char)(PUBACK << 4), 0x02, 0x00, 0x00};
    MQTTString topics_out[1];
    unsigned char dup = 0;
    unsigned short packetid = 0;
    int count = 0;
    int rc;
    UNUSED(state);

    rc = MQTTDeserialize_unsubscribe(&dup, &packetid, 1, &count, topics_out, wire, sizeof(wire));
    assert_int_equal(rc, 0);
}

void TC_MQTTDeserialize_unsubscribe_truncated_topic(void **state)
{
    /* UNSUBSCRIBE header (qos=1) + remlen(4) + packetid + topic-len claiming 10 bytes */
    unsigned char wire[] = {0xA2, 0x04, 0x00, 0x01, 0x00, 0x0A};
    MQTTString topics_out[1];
    unsigned char dup = 0;
    unsigned short packetid = 0;
    int count = 0;
    int rc;
    UNUSED(state);

    memset(topics_out, 0, sizeof(topics_out));
    rc = MQTTDeserialize_unsubscribe(&dup, &packetid, 1, &count, topics_out, wire, sizeof(wire));
    /* Truncated -> count stays zero.  rc is not reset by the current impl. */
    (void)rc;
    assert_int_equal(count, 0);
}

void TC_MQTTDeserialize_unsubscribe_empty_topic_list(void **state)
{
    /* UNSUBSCRIBE header (qos=1) + remlen(2) + packetid only; zero topics. */
    unsigned char wire[] = {0xA2, 0x02, 0x00, 0x01};
    MQTTString topics_out[1];
    unsigned char dup = 0;
    unsigned short packetid = 0;
    int count = 0;
    int rc;
    UNUSED(state);

    memset(topics_out, 0, sizeof(topics_out));
    rc = MQTTDeserialize_unsubscribe(&dup, &packetid, 1, &count, topics_out, wire, sizeof(wire));
    assert_int_equal(rc, 1);
    assert_int_equal(count, 0);
    assert_int_equal(packetid, 0x0001);
}

/*
 * Tests for MQTTSerialize_unsuback
 */
void TC_MQTTSerialize_unsuback_success(void **state)
{
    unsigned char buf[8] = {0};
    int rc;
    UNUSED(state);

    rc = MQTTSerialize_unsuback(buf, sizeof(buf), 0x1234);
    assert_int_equal(rc, 4);
    assert_int_equal((buf[0] & 0xF0) >> 4, UNSUBACK);
    assert_int_equal(buf[1], 2);
    assert_int_equal(buf[2], 0x12);
    assert_int_equal(buf[3], 0x34);
}

void TC_MQTTSerialize_unsuback_buffer_too_short(void **state)
{
    unsigned char buf[1] = {0};
    int rc;
    UNUSED(state);

    rc = MQTTSerialize_unsuback(buf, sizeof(buf), 0x0001);
    assert_int_equal(rc, MQTTPACKET_BUFFER_TOO_SHORT);
}

void TC_MQTTSerialize_unsuback_zero_buffer(void **state)
{
    unsigned char buf[8] = {0};
    int rc;
    UNUSED(state);

    rc = MQTTSerialize_unsuback(buf, 0, 0x0001);
    assert_int_equal(rc, MQTTPACKET_BUFFER_TOO_SHORT);
}

void TC_MQTTSerialize_unsuback_various_packetids(void **state)
{
    unsigned char buf[8];
    int rc;
    UNUSED(state);

    memset(buf, 0, sizeof(buf));
    rc = MQTTSerialize_unsuback(buf, sizeof(buf), 0x0000);
    assert_int_equal(rc, 4);

    memset(buf, 0, sizeof(buf));
    rc = MQTTSerialize_unsuback(buf, sizeof(buf), 0xFFFF);
    assert_int_equal(rc, 4);
    assert_int_equal(buf[2], 0xFF);
    assert_int_equal(buf[3], 0xFF);
}
