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

/* Not declared in the public header but defined in iot_mqtt_packet.c */
extern int getLenStringLen(char *ptr);

#define UNUSED(x) (void)(x)

/*
 * Helper getfn/getnb for MQTTPacket_read / MQTTPacket_readnb tests.
 */
typedef struct {
    const unsigned char *buf;
    int len;
    int pos;
    int fail_at;
    int fail_with;
    int yield_at;
} _mqtt_source_t;

static _mqtt_source_t *g_source;

static int _mqtt_src_get(unsigned char *c, int count)
{
    int remaining;

    if (g_source == NULL) {
        return -1;
    }
    if (g_source->fail_at >= 0 && g_source->pos >= g_source->fail_at) {
        return g_source->fail_with;
    }
    remaining = g_source->len - g_source->pos;
    if (remaining <= 0) {
        return 0;
    }
    if (count > remaining) {
        count = remaining;
    }
    memcpy(c, g_source->buf + g_source->pos, count);
    g_source->pos += count;
    return count;
}

static int _mqtt_src_getnb(void *sck, unsigned char *c, int count)
{
    UNUSED(sck);
    return _mqtt_src_get(c, count);
}

static void _mqtt_src_reset(_mqtt_source_t *src, const unsigned char *data, int len)
{
    src->buf = data;
    src->len = len;
    src->pos = 0;
    src->fail_at = -1;
    src->fail_with = -1;
    src->yield_at = -1;
    g_source = src;
}

/*
 * Tests for MQTTPacket_encode
 */
void TC_MQTTPacket_encode_single_byte_length(void **state)
{
    unsigned char buf[4] = {0};
    int rc;
    UNUSED(state);

    // When: length fits in a single byte (<128)
    rc = MQTTPacket_encode(buf, 10);
    // Then
    assert_int_equal(rc, 1);
    assert_int_equal(buf[0], 10);
}

void TC_MQTTPacket_encode_zero_length(void **state)
{
    unsigned char buf[4] = {0};
    int rc;
    UNUSED(state);

    // When
    rc = MQTTPacket_encode(buf, 0);
    // Then: at least one byte must be emitted (the 0 terminator for the varlen)
    assert_int_equal(rc, 1);
    assert_int_equal(buf[0], 0);
}

void TC_MQTTPacket_encode_two_byte_length(void **state)
{
    unsigned char buf[4] = {0};
    int rc;
    UNUSED(state);

    // When: length needs two bytes
    rc = MQTTPacket_encode(buf, 300);
    // Then
    assert_int_equal(rc, 2);
    assert_int_equal(buf[0] & 0x80, 0x80);
}

void TC_MQTTPacket_encode_three_byte_length(void **state)
{
    unsigned char buf[4] = {0};
    int rc;
    UNUSED(state);

    // When
    rc = MQTTPacket_encode(buf, 32768);
    // Then
    assert_int_equal(rc, 3);
}

void TC_MQTTPacket_encode_four_byte_length(void **state)
{
    unsigned char buf[8] = {0};
    int rc;
    UNUSED(state);

    // When: length requires four bytes (maximum MQTT remaining length)
    rc = MQTTPacket_encode(buf, 268435455);
    // Then
    assert_int_equal(rc, 4);
}

/*
 * Tests for MQTTPacket_decode / MQTTPacket_decodeBuf
 */
void TC_MQTTPacket_decodeBuf_single_byte_success(void **state)
{
    unsigned char buf[] = {0x0A};
    int value = 0;
    int len;
    UNUSED(state);

    // When
    len = MQTTPacket_decodeBuf(buf, &value);
    // Then
    assert_int_equal(len, 1);
    assert_int_equal(value, 10);
}

void TC_MQTTPacket_decodeBuf_multi_byte_success(void **state)
{
    unsigned char buf[] = {0xC1, 0x02}; /* 321 */
    int value = 0;
    int len;
    UNUSED(state);

    // When
    len = MQTTPacket_decodeBuf(buf, &value);
    // Then
    assert_int_equal(len, 2);
    assert_int_equal(value, 321);
}

static int _always_fail_getchar(unsigned char *c, int count)
{
    UNUSED(c);
    UNUSED(count);
    return -1;
}

void TC_MQTTPacket_decode_getfn_failure(void **state)
{
    int value = 99;
    int len;
    UNUSED(state);

    // When: getchar function returns an error
    len = MQTTPacket_decode(_always_fail_getchar, &value);
    // Then: returns that it has started reading once
    assert_int_equal(len, 1);
}

void TC_MQTTPacket_decode_too_many_bytes(void **state)
{
    /* 5 bytes all with continuation bit set would exceed MAX_NUM_OF_REMAINING_LENGTH_BYTES */
    unsigned char buf[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    int value = 0;
    int len;
    UNUSED(state);

    // When
    len = MQTTPacket_decodeBuf(buf, &value);
    // Then
    assert_int_equal(len, MAX_NUM_OF_REMAINING_LENGTH_BYTES + 1);
}

/*
 * Tests for MQTTPacket_len
 */
void TC_MQTTPacket_len_small(void **state)
{
    UNUSED(state);
    /* header 1 + remlen 1 + payload */
    assert_int_equal(MQTTPacket_len(10), 12);
}

void TC_MQTTPacket_len_boundary_127(void **state)
{
    UNUSED(state);
    /* rem_len after adding header = 128, still 1-byte encoding applies only when <128 */
    assert_int_equal(MQTTPacket_len(126), 128); /* 126 + 1 + 1 */
}

void TC_MQTTPacket_len_two_byte_range(void **state)
{
    UNUSED(state);
    /* rem_len=200 -> +1 header = 201 -> falls in [128, 16384) -> +2 */
    assert_int_equal(MQTTPacket_len(200), 203);
}

void TC_MQTTPacket_len_three_byte_range(void **state)
{
    UNUSED(state);
    /* rem_len=20000 -> +1 header = 20001 -> falls in [16384, 2097151) -> +3 */
    assert_int_equal(MQTTPacket_len(20000), 20004);
}

void TC_MQTTPacket_len_four_byte_range(void **state)
{
    UNUSED(state);
    assert_int_equal(MQTTPacket_len(3000000), 3000005);
}

/*
 * Tests for readInt / readChar / writeInt / writeChar / writeCString
 */
void TC_mqtt_packet_readInt_success(void **state)
{
    unsigned char buf[] = {0x01, 0x02};
    unsigned char *ptr = buf;
    int val;
    UNUSED(state);

    // When
    val = readInt(&ptr);
    // Then
    assert_int_equal(val, 0x0102);
    assert_ptr_equal(ptr, buf + 2);
}

void TC_mqtt_packet_readChar_success(void **state)
{
    unsigned char buf[] = {'A'};
    unsigned char *ptr = buf;
    char c;
    UNUSED(state);

    // When
    c = readChar(&ptr);
    // Then
    assert_int_equal(c, 'A');
    assert_ptr_equal(ptr, buf + 1);
}

void TC_mqtt_packet_writeChar_success(void **state)
{
    unsigned char buf[2] = {0};
    unsigned char *ptr = buf;
    UNUSED(state);

    // When
    writeChar(&ptr, 'Z');
    // Then
    assert_int_equal(buf[0], 'Z');
    assert_ptr_equal(ptr, buf + 1);
}

void TC_mqtt_packet_writeInt_success(void **state)
{
    unsigned char buf[4] = {0};
    unsigned char *ptr = buf;
    UNUSED(state);

    // When
    writeInt(&ptr, 258);
    // Then
    assert_int_equal(buf[0], 1);
    assert_int_equal(buf[1], 2);
    assert_ptr_equal(ptr, buf + 2);
}

void TC_mqtt_packet_writeCString_success(void **state)
{
    unsigned char buf[16] = {0};
    unsigned char *ptr = buf;
    UNUSED(state);

    // When
    writeCString(&ptr, "abc");
    // Then
    assert_int_equal(buf[0], 0);
    assert_int_equal(buf[1], 3);
    assert_memory_equal(&buf[2], "abc", 3);
}

/*
 * Tests for MQTTstrlen / MQTTPacket_equals / writeMQTTString / readMQTTLenString /
 * getLenStringLen
 */
void TC_MQTTstrlen_cstring(void **state)
{
    MQTTString s = MQTTString_initializer;
    UNUSED(state);

    s.cstring = "hello";
    assert_int_equal(MQTTstrlen(s), 5);
}

void TC_MQTTstrlen_lenstring(void **state)
{
    MQTTString s = MQTTString_initializer;
    UNUSED(state);

    s.lenstring.len = 4;
    s.lenstring.data = "test";
    assert_int_equal(MQTTstrlen(s), 4);
}

void TC_MQTTstrlen_empty(void **state)
{
    MQTTString s = MQTTString_initializer;
    UNUSED(state);
    assert_int_equal(MQTTstrlen(s), 0);
}

void TC_MQTTPacket_equals_cstring_equal(void **state)
{
    MQTTString s = MQTTString_initializer;
    UNUSED(state);

    s.cstring = "hello";
    assert_true(MQTTPacket_equals(&s, "hello"));
}

void TC_MQTTPacket_equals_cstring_not_equal(void **state)
{
    MQTTString s = MQTTString_initializer;
    UNUSED(state);

    s.cstring = "hello";
    assert_false(MQTTPacket_equals(&s, "world"));
}

void TC_MQTTPacket_equals_lenstring_equal(void **state)
{
    MQTTString s = MQTTString_initializer;
    UNUSED(state);

    s.lenstring.data = "abcd";
    s.lenstring.len = 4;
    assert_true(MQTTPacket_equals(&s, "abcd"));
}

void TC_MQTTPacket_equals_length_mismatch(void **state)
{
    MQTTString s = MQTTString_initializer;
    UNUSED(state);

    s.lenstring.data = "abcd";
    s.lenstring.len = 3;
    assert_false(MQTTPacket_equals(&s, "abcd"));
}

void TC_writeMQTTString_lenstring(void **state)
{
    MQTTString s = MQTTString_initializer;
    unsigned char buf[16] = {0};
    unsigned char *ptr = buf;
    UNUSED(state);

    s.lenstring.data = "abc";
    s.lenstring.len = 3;
    writeMQTTString(&ptr, s);
    assert_int_equal(buf[0], 0);
    assert_int_equal(buf[1], 3);
    assert_memory_equal(&buf[2], "abc", 3);
}

void TC_writeMQTTString_cstring(void **state)
{
    MQTTString s = MQTTString_initializer;
    unsigned char buf[16] = {0};
    unsigned char *ptr = buf;
    UNUSED(state);

    s.cstring = "xyz";
    writeMQTTString(&ptr, s);
    assert_int_equal(buf[0], 0);
    assert_int_equal(buf[1], 3);
    assert_memory_equal(&buf[2], "xyz", 3);
}

void TC_writeMQTTString_empty(void **state)
{
    MQTTString s = MQTTString_initializer;
    unsigned char buf[4] = {0xff, 0xff, 0xff, 0xff};
    unsigned char *ptr = buf;
    UNUSED(state);

    writeMQTTString(&ptr, s);
    assert_int_equal(buf[0], 0);
    assert_int_equal(buf[1], 0);
}

void TC_readMQTTLenString_success(void **state)
{
    unsigned char buf[] = {0x00, 0x03, 'a', 'b', 'c'};
    unsigned char *ptr = buf;
    unsigned char *end = buf + sizeof(buf);
    MQTTString s;
    int rc;
    UNUSED(state);

    rc = readMQTTLenString(&s, &ptr, end);
    assert_int_equal(rc, 1);
    assert_int_equal(s.lenstring.len, 3);
    assert_memory_equal(s.lenstring.data, "abc", 3);
}

void TC_readMQTTLenString_too_short_for_length(void **state)
{
    unsigned char buf[] = {0x00};
    unsigned char *ptr = buf;
    unsigned char *end = buf + sizeof(buf);
    MQTTString s = MQTTString_initializer;
    int rc;
    UNUSED(state);

    rc = readMQTTLenString(&s, &ptr, end);
    assert_int_equal(rc, 0);
}

void TC_readMQTTLenString_data_exceeds_end(void **state)
{
    unsigned char buf[] = {0x00, 0x05, 'a', 'b'};
    unsigned char *ptr = buf;
    unsigned char *end = buf + sizeof(buf);
    MQTTString s = MQTTString_initializer;
    int rc;
    UNUSED(state);

    rc = readMQTTLenString(&s, &ptr, end);
    assert_int_equal(rc, 0);
}

void TC_getLenStringLen_success(void **state)
{
    char buf[] = {0x01, 0x23};
    UNUSED(state);
    assert_int_equal(getLenStringLen(buf), 0x0123);
}

void TC_getLenStringLen_zero(void **state)
{
    char buf[] = {0x00, 0x00};
    UNUSED(state);
    assert_int_equal(getLenStringLen(buf), 0);
}

/*
 * Tests for MQTTPacket_msgTypesToString
 */
void TC_MQTTPacket_msgTypesToString_connect(void **state)
{
    UNUSED(state);
    assert_string_equal(MQTTPacket_msgTypesToString(CONNECT), "CONNECT");
}

void TC_MQTTPacket_msgTypesToString_publish(void **state)
{
    UNUSED(state);
    assert_string_equal(MQTTPacket_msgTypesToString(PUBLISH), "PUBLISH");
}

void TC_MQTTPacket_msgTypesToString_all_known(void **state)
{
    UNUSED(state);
    assert_string_equal(MQTTPacket_msgTypesToString(CONNACK), "CONNACK");
    assert_string_equal(MQTTPacket_msgTypesToString(PUBACK), "PUBACK");
    assert_string_equal(MQTTPacket_msgTypesToString(PUBREC), "PUBREC");
    assert_string_equal(MQTTPacket_msgTypesToString(PUBREL), "PUBREL");
    assert_string_equal(MQTTPacket_msgTypesToString(PUBCOMP), "PUBCOMP");
    assert_string_equal(MQTTPacket_msgTypesToString(SUBSCRIBE), "SUBSCRIBE");
    assert_string_equal(MQTTPacket_msgTypesToString(SUBACK), "SUBACK");
    assert_string_equal(MQTTPacket_msgTypesToString(UNSUBSCRIBE), "UNSUBSCRIBE");
    assert_string_equal(MQTTPacket_msgTypesToString(UNSUBACK), "UNSUBACK");
    assert_string_equal(MQTTPacket_msgTypesToString(PINGREQ), "PINGREQ");
    assert_string_equal(MQTTPacket_msgTypesToString(PINGRESP), "PINGRESP");
    assert_string_equal(MQTTPacket_msgTypesToString(DISCONNECT), "DISCONNECT");
}

void TC_MQTTPacket_msgTypesToString_invalid(void **state)
{
    UNUSED(state);
    assert_null(MQTTPacket_msgTypesToString(0));
    assert_null(MQTTPacket_msgTypesToString(99));
}

/*
 * Tests for MQTTPacket_getPacketId
 */
void TC_MQTTPacket_getPacketId_puback(void **state)
{
    /* PUBACK with rem_len=2 and packet id=0x1234 */
    unsigned char buf[] = {(unsigned char)(PUBACK << 4), 0x02, 0x12, 0x34};
    unsigned int id;
    UNUSED(state);

    id = MQTTPacket_getPacketId(buf);
    assert_int_equal(id, 0x1234);
}

void TC_MQTTPacket_getPacketId_publish_qos0(void **state)
{
    /* PUBLISH QoS 0 has no packet id */
    unsigned char buf[] = {(unsigned char)(PUBLISH << 4), 0x02, 0x00, 0x00};
    unsigned int id;
    UNUSED(state);

    id = MQTTPacket_getPacketId(buf);
    assert_int_equal(id, 0);
}

void TC_MQTTPacket_getPacketId_publish_qos1(void **state)
{
    /* PUBLISH QoS 1 with topic "ab" and packet id 0x0042
     * header byte layout: type=PUBLISH qos=1 -> (3<<4)|(1<<1) = 0x32 */
    unsigned char buf[] = {0x32, 0x06, 0x00, 0x02, 'a', 'b', 0x00, 0x42};
    unsigned int id;
    UNUSED(state);

    id = MQTTPacket_getPacketId(buf);
    assert_int_equal(id, 0x42);
}

void TC_MQTTPacket_getPacketId_unknown_type(void **state)
{
    unsigned char buf[] = {0xF0, 0x02, 0x00, 0x01};
    unsigned int id;
    UNUSED(state);

    id = MQTTPacket_getPacketId(buf);
    assert_int_equal(id, 0);
}

/*
 * Tests for MQTTPacket_read
 */
void TC_MQTTPacket_read_success(void **state)
{
    unsigned char in[] = {(unsigned char)(PUBACK << 4), 0x02, 0x12, 0x34};
    unsigned char out[16] = {0};
    _mqtt_source_t src;
    int rc;
    UNUSED(state);

    _mqtt_src_reset(&src, in, sizeof(in));
    rc = MQTTPacket_read(out, sizeof(out), _mqtt_src_get);
    assert_int_equal(rc, PUBACK);
}

void TC_MQTTPacket_read_header_getfn_failure(void **state)
{
    unsigned char out[16] = {0};
    _mqtt_source_t src;
    int rc;
    UNUSED(state);

    _mqtt_src_reset(&src, NULL, 0);
    src.fail_at = 0;
    rc = MQTTPacket_read(out, sizeof(out), _mqtt_src_get);
    assert_int_equal(rc, -1);
}

void TC_MQTTPacket_read_buffer_too_small(void **state)
{
    unsigned char in[] = {(unsigned char)(PUBACK << 4), 0x02, 0x12, 0x34};
    unsigned char out[2] = {0};
    _mqtt_source_t src;
    int rc;
    UNUSED(state);

    _mqtt_src_reset(&src, in, sizeof(in));
    rc = MQTTPacket_read(out, sizeof(out), _mqtt_src_get);
    assert_int_equal(rc, -1);
}

void TC_MQTTPacket_read_body_short(void **state)
{
    /* Claims rem_len=4 but only provides 2 bytes */
    unsigned char in[] = {(unsigned char)(PUBACK << 4), 0x04, 0x12, 0x34};
    unsigned char out[16] = {0};
    _mqtt_source_t src;
    int rc;
    UNUSED(state);

    _mqtt_src_reset(&src, in, sizeof(in));
    rc = MQTTPacket_read(out, sizeof(out), _mqtt_src_get);
    assert_int_equal(rc, -1);
}

/*
 * Tests for MQTTPacket_readnb
 */
void TC_MQTTPacket_readnb_success(void **state)
{
    unsigned char in[] = {(unsigned char)(PUBACK << 4), 0x02, 0x12, 0x34};
    unsigned char out[16] = {0};
    _mqtt_source_t src;
    MQTTTransport trp = {0};
    int rc;
    UNUSED(state);

    _mqtt_src_reset(&src, in, sizeof(in));
    trp.getfn = _mqtt_src_getnb;
    trp.sck = NULL;
    rc = MQTTPacket_readnb(out, sizeof(out), &trp);
    assert_int_equal(rc, PUBACK);
}

void TC_MQTTPacket_readnb_header_getfn_failure(void **state)
{
    unsigned char out[16] = {0};
    _mqtt_source_t src;
    MQTTTransport trp = {0};
    int rc;
    UNUSED(state);

    _mqtt_src_reset(&src, NULL, 0);
    src.fail_at = 0;
    trp.getfn = _mqtt_src_getnb;
    rc = MQTTPacket_readnb(out, sizeof(out), &trp);
    assert_int_equal(rc, -1);
}

void TC_MQTTPacket_readnb_call_again_on_header(void **state)
{
    unsigned char out[16] = {0};
    _mqtt_source_t src;
    MQTTTransport trp = {0};
    int rc;
    UNUSED(state);

    /* empty source + fail_at -1 means 0 remaining bytes, returns 0 for "call again" */
    _mqtt_src_reset(&src, NULL, 0);
    trp.getfn = _mqtt_src_getnb;
    rc = MQTTPacket_readnb(out, sizeof(out), &trp);
    assert_int_equal(rc, 0);
}

void TC_MQTTPacket_readnb_buffer_too_small(void **state)
{
    unsigned char in[] = {(unsigned char)(PUBACK << 4), 0x04, 0x12, 0x34};
    unsigned char out[2] = {0};
    _mqtt_source_t src;
    MQTTTransport trp = {0};
    int rc;
    UNUSED(state);

    _mqtt_src_reset(&src, in, sizeof(in));
    trp.getfn = _mqtt_src_getnb;
    rc = MQTTPacket_readnb(out, sizeof(out), &trp);
    assert_int_equal(rc, -1);
}
