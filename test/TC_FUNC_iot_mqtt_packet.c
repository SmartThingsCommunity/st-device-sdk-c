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

TEST_SUITE("iot_mqtt_packet.c");

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
TEST(TC_MQTTPacket_encode_single_byte_length_neg)
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

TEST(TC_MQTTPacket_encode_zero_length_neg)
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

TEST(TC_MQTTPacket_encode_two_byte_length_neg)
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

TEST(TC_MQTTPacket_encode_three_byte_length_neg)
{
    unsigned char buf[4] = {0};
    int rc;
    UNUSED(state);

    // When
    rc = MQTTPacket_encode(buf, 32768);
    // Then
    assert_int_equal(rc, 3);
}

TEST(TC_MQTTPacket_encode_four_byte_length_neg)
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
TEST(TC_MQTTPacket_decodeBuf_single_byte_success_pos)
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

TEST(TC_MQTTPacket_decodeBuf_multi_byte_success_pos)
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

TEST(TC_MQTTPacket_decode_getfn_failure_neg)
{
    int value = 99;
    int len;
    UNUSED(state);

    // When: getchar function returns an error
    len = MQTTPacket_decode(_always_fail_getchar, &value);
    // Then: returns that it has started reading once
    assert_int_equal(len, 1);
}

TEST(TC_MQTTPacket_decode_too_many_bytes_neg)
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
TEST(TC_MQTTPacket_len_small_neg)
{
    UNUSED(state);
    /* header 1 + remlen 1 + payload */
    assert_int_equal(MQTTPacket_len(10), 12);
}

TEST(TC_MQTTPacket_len_boundary_127_neg)
{
    UNUSED(state);
    /* rem_len after adding header = 128, still 1-byte encoding applies only when <128 */
    assert_int_equal(MQTTPacket_len(126), 128); /* 126 + 1 + 1 */
}

TEST(TC_MQTTPacket_len_two_byte_range_neg)
{
    UNUSED(state);
    /* rem_len=200 -> +1 header = 201 -> falls in [128, 16384) -> +2 */
    assert_int_equal(MQTTPacket_len(200), 203);
}

TEST(TC_MQTTPacket_len_three_byte_range_neg)
{
    UNUSED(state);
    /* rem_len=20000 -> +1 header = 20001 -> falls in [16384, 2097151) -> +3 */
    assert_int_equal(MQTTPacket_len(20000), 20004);
}

TEST(TC_MQTTPacket_len_four_byte_range_neg)
{
    UNUSED(state);
    assert_int_equal(MQTTPacket_len(3000000), 3000005);
}

/*
 * Tests for readInt / readChar / writeInt / writeChar / writeCString
 */
TEST(TC_mqtt_packet_readInt_success_pos)
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

TEST(TC_mqtt_packet_readChar_success_pos)
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

TEST(TC_mqtt_packet_writeChar_success_pos)
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

TEST(TC_mqtt_packet_writeInt_success_pos)
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

TEST(TC_mqtt_packet_writeCString_success_pos)
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
TEST(TC_MQTTstrlen_cstring_neg)
{
    MQTTString s = MQTTString_initializer;
    UNUSED(state);

    s.cstring = "hello";
    assert_int_equal(MQTTstrlen(s), 5);
}

TEST(TC_MQTTstrlen_lenstring_neg)
{
    MQTTString s = MQTTString_initializer;
    UNUSED(state);

    s.lenstring.len = 4;
    s.lenstring.data = "test";
    assert_int_equal(MQTTstrlen(s), 4);
}

TEST(TC_MQTTstrlen_empty_neg)
{
    MQTTString s = MQTTString_initializer;
    UNUSED(state);
    assert_int_equal(MQTTstrlen(s), 0);
}

TEST(TC_MQTTPacket_equals_cstring_equal_neg)
{
    MQTTString s = MQTTString_initializer;
    UNUSED(state);

    s.cstring = "hello";
    assert_true(MQTTPacket_equals(&s, "hello"));
}

TEST(TC_MQTTPacket_equals_cstring_not_equal_neg)
{
    MQTTString s = MQTTString_initializer;
    UNUSED(state);

    s.cstring = "hello";
    assert_false(MQTTPacket_equals(&s, "world"));
}

TEST(TC_MQTTPacket_equals_lenstring_equal_neg)
{
    MQTTString s = MQTTString_initializer;
    UNUSED(state);

    s.lenstring.data = "abcd";
    s.lenstring.len = 4;
    assert_true(MQTTPacket_equals(&s, "abcd"));
}

TEST(TC_MQTTPacket_equals_length_mismatch_neg)
{
    MQTTString s = MQTTString_initializer;
    UNUSED(state);

    s.lenstring.data = "abcd";
    s.lenstring.len = 3;
    assert_false(MQTTPacket_equals(&s, "abcd"));
}

TEST(TC_writeMQTTString_lenstring_neg)
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

TEST(TC_writeMQTTString_cstring_neg)
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

TEST(TC_writeMQTTString_empty_neg)
{
    MQTTString s = MQTTString_initializer;
    unsigned char buf[4] = {0xff, 0xff, 0xff, 0xff};
    unsigned char *ptr = buf;
    UNUSED(state);

    writeMQTTString(&ptr, s);
    assert_int_equal(buf[0], 0);
    assert_int_equal(buf[1], 0);
}

TEST(TC_readMQTTLenString_success_pos)
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

TEST(TC_readMQTTLenString_too_short_for_length_neg)
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

TEST(TC_readMQTTLenString_data_exceeds_end_neg)
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

TEST(TC_getLenStringLen_success_pos)
{
    char buf[] = {0x01, 0x23};
    UNUSED(state);
    assert_int_equal(getLenStringLen(buf), 0x0123);
}

TEST(TC_getLenStringLen_zero_neg)
{
    char buf[] = {0x00, 0x00};
    UNUSED(state);
    assert_int_equal(getLenStringLen(buf), 0);
}

/*
 * Tests for MQTTPacket_msgTypesToString
 */
TEST(TC_MQTTPacket_msgTypesToString_connect_pos)
{
    UNUSED(state);
    assert_string_equal(MQTTPacket_msgTypesToString(CONNECT), "CONNECT");
}

TEST(TC_MQTTPacket_msgTypesToString_publish_neg)
{
    UNUSED(state);
    assert_string_equal(MQTTPacket_msgTypesToString(PUBLISH), "PUBLISH");
}

TEST(TC_MQTTPacket_msgTypesToString_all_known_neg)
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

TEST(TC_MQTTPacket_msgTypesToString_invalid_neg)
{
    UNUSED(state);
    assert_null(MQTTPacket_msgTypesToString(0));
    assert_null(MQTTPacket_msgTypesToString(99));
}

/*
 * Tests for MQTTPacket_getPacketId
 */
TEST(TC_MQTTPacket_getPacketId_puback_neg)
{
    /* PUBACK with rem_len=2 and packet id=0x1234 */
    unsigned char buf[] = {(unsigned char)(PUBACK << 4), 0x02, 0x12, 0x34};
    unsigned int id;
    UNUSED(state);

    id = MQTTPacket_getPacketId(buf);
    assert_int_equal(id, 0x1234);
}

TEST(TC_MQTTPacket_getPacketId_publish_qos0_neg)
{
    /* PUBLISH QoS 0 has no packet id */
    unsigned char buf[] = {(unsigned char)(PUBLISH << 4), 0x02, 0x00, 0x00};
    unsigned int id;
    UNUSED(state);

    id = MQTTPacket_getPacketId(buf);
    assert_int_equal(id, 0);
}

TEST(TC_MQTTPacket_getPacketId_publish_qos1_neg)
{
    /* PUBLISH QoS 1 with topic "ab" and packet id 0x0042
     * header byte layout: type=PUBLISH qos=1 -> (3<<4)|(1<<1) = 0x32 */
    unsigned char buf[] = {0x32, 0x06, 0x00, 0x02, 'a', 'b', 0x00, 0x42};
    unsigned int id;
    UNUSED(state);

    id = MQTTPacket_getPacketId(buf);
    assert_int_equal(id, 0x42);
}

TEST(TC_MQTTPacket_getPacketId_unknown_type_neg)
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
TEST(TC_MQTTPacket_read_success_pos)
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

TEST(TC_MQTTPacket_read_header_getfn_failure_neg)
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

TEST(TC_MQTTPacket_read_buffer_too_small_neg)
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

TEST(TC_MQTTPacket_read_body_short_neg)
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
TEST(TC_MQTTPacket_readnb_success_pos)
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

TEST(TC_MQTTPacket_readnb_header_getfn_failure_neg)
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

TEST(TC_MQTTPacket_readnb_call_again_on_header_neg)
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

TEST(TC_MQTTPacket_readnb_buffer_too_small_neg)
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

/*
 * Additional negative tests for iot_mqtt_packet.c
 */
TEST(TC_MQTTPacket_encode_boundary_127_neg)
{
    unsigned char buf[4] = {0};
    UNUSED(state);

    // When: the length is the largest value that fits in one byte
    assert_int_equal(MQTTPacket_encode(buf, 127), 1);
    assert_int_equal(buf[0], 127);
}

TEST(TC_MQTTPacket_encode_boundary_128_neg)
{
    unsigned char buf[4] = {0};
    UNUSED(state);

    // When: the length is one past the single byte range
    assert_int_equal(MQTTPacket_encode(buf, 128), 2);
    assert_int_equal(buf[0], 0x80);
    assert_int_equal(buf[1], 0x01);
}

TEST(TC_MQTTPacket_encode_negative_length_neg)
{
    unsigned char buf[8] = {0};
    int rc;
    UNUSED(state);

    // When: a negative remaining length is encoded
    rc = MQTTPacket_encode(buf, -1);
    // Then: the loop stops after the first digit instead of rejecting the input
    assert_int_equal(rc, 1);
    assert_int_equal(buf[0], 0xFF);
}

TEST(TC_MQTTPacket_decodeBuf_four_byte_length_neg)
{
    unsigned char buf[] = {0xFF, 0xFF, 0xFF, 0x7F};
    int value = 0;
    UNUSED(state);

    // When: the maximum four byte remaining length is decoded
    assert_int_equal(MQTTPacket_decodeBuf(buf, &value), 4);
    assert_int_equal(value, 268435455);
}

TEST(TC_MQTTPacket_decodeBuf_five_byte_length_neg)
{
    unsigned char buf[] = {0xFF, 0xFF, 0xFF, 0xFF, 0x7F};
    int value = 0;
    UNUSED(state);

    // When: a fifth continuation byte is present, which the spec forbids
    // Then: the bad-data exit still returns the byte count, so callers must
    // check for a value above MAX_NUM_OF_REMAINING_LENGTH_BYTES themselves
    assert_int_equal(MQTTPacket_decodeBuf(buf, &value), MAX_NUM_OF_REMAINING_LENGTH_BYTES + 1);
}

TEST(TC_MQTTPacket_decodeBuf_zero_length_neg)
{
    unsigned char buf[] = {0x00};
    int value = 0xdead;
    UNUSED(state);

    assert_int_equal(MQTTPacket_decodeBuf(buf, &value), 1);
    assert_int_equal(value, 0);
}

TEST(TC_MQTTPacket_len_zero_neg)
{
    UNUSED(state);
    // A zero remaining length still needs the fixed header and the length byte
    assert_int_equal(MQTTPacket_len(0), 2);
}

TEST(TC_MQTTPacket_len_negative_neg)
{
    UNUSED(state);
    // A negative remaining length is not rejected; it silently under counts the
    // packet size by the header byte it is supposed to add
    assert_int_equal(MQTTPacket_len(-1), 1);
}

TEST(TC_MQTTstrlen_lenstring_negative_len_neg)
{
    MQTTString s = MQTTString_initializer;
    UNUSED(state);

    // Given: a negative length in the lenstring form
    s.lenstring.data = "abc";
    s.lenstring.len = -1;
    // Then: the negative length is returned unchanged instead of being rejected
    assert_int_equal(MQTTstrlen(s), -1);
}

TEST(TC_MQTTstrlen_cstring_wins_over_lenstring_neg)
{
    MQTTString s = MQTTString_initializer;
    UNUSED(state);

    // Given: both forms populated with different lengths
    s.cstring = "ab";
    s.lenstring.data = "abcdef";
    s.lenstring.len = 6;
    // Then: the c string form takes precedence
    assert_int_equal(MQTTstrlen(s), 2);
}

TEST(TC_MQTTPacket_equals_empty_both_neg)
{
    MQTTString s = MQTTString_initializer;
    UNUSED(state);

    // When: an empty MQTTString is compared against an empty c string
    assert_int_equal(MQTTPacket_equals(&s, ""), 1);
}

TEST(TC_MQTTPacket_equals_lenstring_prefix_neg)
{
    MQTTString s = MQTTString_initializer;
    UNUSED(state);

    // Given: a lenstring that is a prefix of the compared c string
    s.lenstring.data = "abc";
    s.lenstring.len = 3;
    // Then: the length mismatch makes them unequal
    assert_int_equal(MQTTPacket_equals(&s, "abcd"), 0);
}

TEST(TC_MQTTPacket_equals_cstring_case_mismatch_neg)
{
    MQTTString s = MQTTString_initializer;
    UNUSED(state);

    s.cstring = "Topic";
    // Then: the comparison is case sensitive
    assert_int_equal(MQTTPacket_equals(&s, "topic"), 0);
}

TEST(TC_writeMQTTString_lenstring_zero_len_neg)
{
    unsigned char buf[8] = {0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA};
    unsigned char *ptr = buf;
    MQTTString s = MQTTString_initializer;
    UNUSED(state);

    // Given: a lenstring pointer with a zero length
    s.lenstring.data = "abc";
    s.lenstring.len = 0;
    writeMQTTString(&ptr, s);
    // Then: only the two zero length bytes are written
    assert_int_equal(ptr - buf, 2);
    assert_int_equal(buf[0], 0);
    assert_int_equal(buf[1], 0);
    assert_int_equal(buf[2], 0xAA);
}

TEST(TC_writeMQTTString_lenstring_wins_over_cstring_neg)
{
    unsigned char buf[16] = {0};
    unsigned char *ptr = buf;
    MQTTString s = MQTTString_initializer;
    UNUSED(state);

    // Given: both forms populated
    s.cstring = "ab";
    s.lenstring.data = "zzzzzz";
    s.lenstring.len = 6;
    writeMQTTString(&ptr, s);
    // Then: the lenstring form wins here, the opposite of MQTTstrlen, so the
    // computed length and the serialized bytes can disagree
    assert_int_equal(ptr - buf, 8);
    assert_int_equal(buf[1], 6);
    assert_memory_equal(&buf[2], "zzzzzz", 6);
    assert_int_equal(MQTTstrlen(s), 2);
}

TEST(TC_readMQTTLenString_zero_length_neg)
{
    unsigned char buf[] = {0x00, 0x00};
    unsigned char *curdata = buf;
    MQTTString s = MQTTString_initializer;
    UNUSED(state);

    // When: a zero length string is read
    assert_int_equal(readMQTTLenString(&s, &curdata, buf + sizeof(buf)), 1);
    assert_int_equal(s.lenstring.len, 0);
    assert_int_equal(curdata - buf, 2);
}

TEST(TC_readMQTTLenString_exactly_one_byte_available_neg)
{
    unsigned char buf[] = {0x00};
    unsigned char *curdata = buf;
    MQTTString s = MQTTString_initializer;
    UNUSED(state);

    // When: only one of the two length bytes is available
    assert_int_equal(readMQTTLenString(&s, &curdata, buf + 1), 0);
    assert_int_equal(s.lenstring.len, 0);
}

TEST(TC_readMQTTLenString_length_one_byte_over_neg)
{
    unsigned char buf[] = {0x00, 0x03, 'a', 'b'};
    unsigned char *curdata = buf;
    MQTTString s = MQTTString_initializer;
    UNUSED(state);

    // When: the declared length runs one byte past the end of the buffer
    assert_int_equal(readMQTTLenString(&s, &curdata, buf + sizeof(buf)), 0);
    // Then: the rejected length is still written into the caller's struct
    assert_int_equal(s.lenstring.len, 3);
    assert_null(s.lenstring.data);
}

TEST(TC_getLenStringLen_two_byte_length_neg)
{
    char buf[] = {0x01, 0x02};
    UNUSED(state);

    // The length field is big endian, so 0x0102 must be reported
    assert_int_equal(getLenStringLen(buf), 0x0102);
}

TEST(TC_MQTTPacket_msgTypesToString_out_of_range_neg)
{
    UNUSED(state);

    // When: a message type beyond DISCONNECT is asked for
    // Then: a null pointer is returned, callers must not print it directly
    assert_null(MQTTPacket_msgTypesToString(15));
    assert_null(MQTTPacket_msgTypesToString(255));
}

TEST(TC_MQTTPacket_getPacketId_publish_qos2_neg)
{
    /* PUBLISH QoS 2 with topic "t" and packet id 0x1234 */
    unsigned char buf[] = {(unsigned char)(PUBLISH << 4) | 0x04, 0x07, 0x00, 0x01, 't', 0x12, 0x34, 'p'};
    UNUSED(state);

    // When: a qos 2 publish is inspected
    assert_int_equal(MQTTPacket_getPacketId(buf), 0x1234);
}

TEST(TC_MQTTPacket_readnb_remaining_length_too_long_neg)
{
    /* five continuation bytes for the remaining length */
    unsigned char in[] = {(unsigned char)(PUBACK << 4), 0xFF, 0xFF, 0xFF, 0xFF, 0x7F};
    unsigned char out[32] = {0};
    _mqtt_source_t src;
    MQTTTransport trp = {0};
    UNUSED(state);

    _mqtt_src_reset(&src, in, sizeof(in));
    trp.getfn = _mqtt_src_getnb;
    // Then: the transport aborts and resets its state machine
    assert_int_equal(MQTTPacket_readnb(out, sizeof(out), &trp), -1);
    assert_int_equal(trp.state, 0);
}

TEST(TC_MQTTPacket_readnb_call_again_on_length_neg)
{
    unsigned char in[] = {(unsigned char)(PUBACK << 4)};
    unsigned char out[32] = {0};
    _mqtt_source_t src;
    MQTTTransport trp = {0};
    UNUSED(state);

    // Given: only the fixed header byte is available
    _mqtt_src_reset(&src, in, sizeof(in));
    trp.getfn = _mqtt_src_getnb;
    // Then: the transport asks to be called again with the state preserved
    assert_int_equal(MQTTPacket_readnb(out, sizeof(out), &trp), 0);
    assert_int_equal(trp.state, 1);
}

TEST(TC_MQTTPacket_readnb_call_again_on_body_neg)
{
    unsigned char in[] = {(unsigned char)(PUBACK << 4), 0x02};
    unsigned char out[32] = {0};
    _mqtt_source_t src;
    MQTTTransport trp = {0};
    UNUSED(state);

    // Given: the header and length arrive but the body does not
    _mqtt_src_reset(&src, in, sizeof(in));
    trp.getfn = _mqtt_src_getnb;
    // Then: the transport asks to be called again from the body state
    assert_int_equal(MQTTPacket_readnb(out, sizeof(out), &trp), 0);
    assert_int_equal(trp.state, 2);
}

TEST(TC_MQTTPacket_readnb_body_getfn_failure_neg)
{
    unsigned char in[] = {(unsigned char)(PUBACK << 4), 0x02, 0x12, 0x34};
    unsigned char out[32] = {0};
    _mqtt_source_t src;
    MQTTTransport trp = {0};
    UNUSED(state);

    // Given: the transport fails once the body read starts
    _mqtt_src_reset(&src, in, sizeof(in));
    src.fail_at = 2;
    trp.getfn = _mqtt_src_getnb;
    assert_int_equal(MQTTPacket_readnb(out, sizeof(out), &trp), -1);
    assert_int_equal(trp.state, 0);
}

TEST(TC_MQTTPacket_readnb_invalid_state_reset_neg)
{
    unsigned char in[] = {(unsigned char)(PUBACK << 4), 0x02, 0x12, 0x34};
    unsigned char out[32] = {0};
    _mqtt_source_t src;
    MQTTTransport trp = {0};
    UNUSED(state);

    // Given: a transport carrying an out of range state value
    _mqtt_src_reset(&src, in, sizeof(in));
    trp.getfn = _mqtt_src_getnb;
    trp.state = 99;
    // Then: the state machine restarts from the header instead of misbehaving
    assert_int_equal(MQTTPacket_readnb(out, sizeof(out), &trp), PUBACK);
}
