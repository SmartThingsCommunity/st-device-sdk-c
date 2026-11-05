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
#include <string.h>
// clang-format on

#include "TC_REGISTRY.h"
#include "cmocka_custom.h"

/* Not declared in the public header but defined in iot_mqtt_connect_server.c */
extern int MQTTPacket_checkVersion(MQTTString *protocol, int version);

#define UNUSED(x) (void)(x)

/*
 * Tests for MQTTPacket_checkVersion
 */
TEST_SUITE("iot_mqtt_connect_server.c");

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTPacket_checkVersion_v3_success_pos)
{
    MQTTString proto = MQTTString_initializer;
    UNUSED(state);

    proto.lenstring.data = "MQIsdp";
    proto.lenstring.len = 6;
    assert_int_equal(MQTTPacket_checkVersion(&proto, 3), 1);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTPacket_checkVersion_v4_success_pos)
{
    MQTTString proto = MQTTString_initializer;
    UNUSED(state);

    proto.lenstring.data = "MQTT";
    proto.lenstring.len = 4;
    assert_int_equal(MQTTPacket_checkVersion(&proto, 4), 1);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTPacket_checkVersion_v3_wrong_name_neg)
{
    MQTTString proto = MQTTString_initializer;
    UNUSED(state);

    proto.lenstring.data = "MQTT";
    proto.lenstring.len = 4;
    assert_int_equal(MQTTPacket_checkVersion(&proto, 3), 0);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTPacket_checkVersion_v4_wrong_name_neg)
{
    MQTTString proto = MQTTString_initializer;
    UNUSED(state);

    proto.lenstring.data = "MQIsdp";
    proto.lenstring.len = 6;
    assert_int_equal(MQTTPacket_checkVersion(&proto, 4), 0);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTPacket_checkVersion_unsupported_version_neg)
{
    MQTTString proto = MQTTString_initializer;
    UNUSED(state);

    proto.lenstring.data = "MQTT";
    proto.lenstring.len = 4;
    assert_int_equal(MQTTPacket_checkVersion(&proto, 5), 0);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTPacket_checkVersion_zero_length_neg)
{
    MQTTString proto = MQTTString_initializer;
    char empty[1] = {0};
    UNUSED(state);

    proto.lenstring.data = empty;
    proto.lenstring.len = 0;
    /* min(4, 0) = 0, memcmp with length 0 returns 0 -> match */
    assert_int_equal(MQTTPacket_checkVersion(&proto, 4), 1);
}

/*
 * Tests for MQTTSerialize_connack
 */
TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_connack_success_pos)
{
    unsigned char buf[8] = {0};
    int rc;
    UNUSED(state);

    rc = MQTTSerialize_connack(buf, sizeof(buf), 0, 0);
    assert_int_equal(rc, 4);
    assert_int_equal((buf[0] & 0xF0) >> 4, CONNACK);
    assert_int_equal(buf[1], 2);
    assert_int_equal(buf[2], 0);
    assert_int_equal(buf[3], 0);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_connack_session_present_neg)
{
    unsigned char buf[8] = {0};
    int rc;
    UNUSED(state);

    rc = MQTTSerialize_connack(buf, sizeof(buf), 0, 1);
    assert_int_equal(rc, 4);
    assert_int_equal(buf[2] & 0x01, 1);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_connack_with_rc_neg)
{
    unsigned char buf[8] = {0};
    int rc;
    UNUSED(state);

    rc = MQTTSerialize_connack(buf, sizeof(buf), 0x05, 0);
    assert_int_equal(rc, 4);
    assert_int_equal(buf[3], 0x05);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_connack_buffer_too_short_neg)
{
    unsigned char buf[1] = {0};
    int rc;
    UNUSED(state);

    rc = MQTTSerialize_connack(buf, sizeof(buf), 0, 0);
    assert_int_equal(rc, MQTTPACKET_BUFFER_TOO_SHORT);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_connack_zero_buffer_neg)
{
    unsigned char buf[4] = {0};
    int rc;
    UNUSED(state);

    rc = MQTTSerialize_connack(buf, 0, 0, 0);
    assert_int_equal(rc, MQTTPACKET_BUFFER_TOO_SHORT);
}

/*
 * Tests for MQTTDeserialize_connect
 */
static int _build_connect_frame(unsigned char *buf, int cap, MQTTPacket_connectData *opts)
{
    return MQTTSerialize_connect(buf, cap, opts);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTDeserialize_connect_success_pos)
{
    unsigned char buf[128] = {0};
    MQTTPacket_connectData options = MQTTPacket_connectData_initializer;
    MQTTPacket_connectData out = MQTTPacket_connectData_initializer;
    int total;
    int rc;
    UNUSED(state);

    options.MQTTVersion = 4;
    options.clientID.cstring = "cli";
    options.keepAliveInterval = 30;
    options.cleansession = 1;

    total = _build_connect_frame(buf, sizeof(buf), &options);
    assert_true(total > 0);

    rc = MQTTDeserialize_connect(&out, buf, total);
    assert_int_equal(rc, 1);
    assert_int_equal(out.MQTTVersion, 4);
    assert_int_equal(out.cleansession, 1);
    assert_int_equal(out.keepAliveInterval, 30);
    assert_int_equal(out.clientID.lenstring.len, 3);
    assert_memory_equal(out.clientID.lenstring.data, "cli", 3);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTDeserialize_connect_with_will_pos)
{
    unsigned char buf[256] = {0};
    MQTTPacket_connectData options = MQTTPacket_connectData_initializer;
    MQTTPacket_connectData out = MQTTPacket_connectData_initializer;
    int total;
    int rc;
    UNUSED(state);

    options.MQTTVersion = 4;
    options.clientID.cstring = "c";
    options.willFlag = 1;
    options.will.qos = 1;
    options.will.retained = 1;
    options.will.topicName.cstring = "w/t";
    options.will.message.cstring = "msg";

    total = _build_connect_frame(buf, sizeof(buf), &options);
    assert_true(total > 0);

    rc = MQTTDeserialize_connect(&out, buf, total);
    assert_int_equal(rc, 1);
    assert_int_equal(out.willFlag, 1);
    assert_int_equal(out.will.qos, 1);
    assert_int_equal(out.will.retained, 1);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTDeserialize_connect_with_username_password_pos)
{
    unsigned char buf[256] = {0};
    MQTTPacket_connectData options = MQTTPacket_connectData_initializer;
    MQTTPacket_connectData out = MQTTPacket_connectData_initializer;
    int total;
    int rc;
    UNUSED(state);

    options.MQTTVersion = 4;
    options.clientID.cstring = "c";
    options.username.cstring = "user";
    options.password.cstring = "pass";

    total = _build_connect_frame(buf, sizeof(buf), &options);
    assert_true(total > 0);

    rc = MQTTDeserialize_connect(&out, buf, total);
    assert_int_equal(rc, 1);
    assert_memory_equal(out.username.lenstring.data, "user", 4);
    assert_memory_equal(out.password.lenstring.data, "pass", 4);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTDeserialize_connect_wrong_type_neg)
{
    unsigned char buf[] = {(unsigned char)(PUBACK << 4), 0x02, 0x00, 0x00};
    MQTTPacket_connectData out = MQTTPacket_connectData_initializer;
    int rc;
    UNUSED(state);

    rc = MQTTDeserialize_connect(&out, buf, sizeof(buf));
    assert_int_equal(rc, 0);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTDeserialize_connect_truncated_neg)
{
    /* header + remlen but no protocol data */
    unsigned char buf[] = {(unsigned char)(CONNECT << 4), 0x00};
    MQTTPacket_connectData out = MQTTPacket_connectData_initializer;
    int rc;
    UNUSED(state);

    rc = MQTTDeserialize_connect(&out, buf, sizeof(buf));
    assert_int_equal(rc, 0);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTDeserialize_connect_unknown_protocol_version_neg)
{
    /* Minimal CONNECT where the protocol version is bogus (99) so the
     * parser must refuse to continue. */
    unsigned char buf[] = {
        (unsigned char)(CONNECT << 4),
        10,
        0x00,
        0x04,
        'M',
        'Q',
        'T',
        'T',
        99,   /* protocol version */
        0x00, /* connect flags */
        0x00,
        0x1E, /* keep alive = 30 */
    };
    MQTTPacket_connectData out = MQTTPacket_connectData_initializer;
    int rc;
    UNUSED(state);

    rc = MQTTDeserialize_connect(&out, buf, sizeof(buf));
    assert_int_equal(rc, 0);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTDeserialize_connect_password_without_username_neg)
{
    /* Construct a CONNECT with password flag but no username flag. */
    unsigned char buf[] = {
        (unsigned char)(CONNECT << 4),
        14,
        0x00,
        0x04,
        'M',
        'Q',
        'T',
        'T',
        0x04, /* protocol version 4 */
        0x40, /* password flag set, username flag clear */
        0x00,
        0x1E, /* keep alive = 30 */
        0x00,
        0x00, /* client id len = 0 */
    };
    MQTTPacket_connectData out = MQTTPacket_connectData_initializer;
    int rc;
    UNUSED(state);

    rc = MQTTDeserialize_connect(&out, buf, sizeof(buf));
    assert_int_equal(rc, 0);
}

/*
 * Additional negative tests for iot_mqtt_connect_server.c
 */
TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTPacket_checkVersion_v3_with_v4_name_neg)
{
    MQTTString protocol = MQTTString_initializer;
    UNUSED(state);

    // Given: the v4 protocol name declared as version 3
    protocol.lenstring.data = "MQTT";
    protocol.lenstring.len = 4;
    // Then: rejected
    assert_int_equal(MQTTPacket_checkVersion(&protocol, 3), 0);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTPacket_checkVersion_v4_with_v3_name_neg)
{
    MQTTString protocol = MQTTString_initializer;
    UNUSED(state);

    // Given: the v3 protocol name declared as version 4
    protocol.lenstring.data = "MQIsdp";
    protocol.lenstring.len = 6;
    // Then: rejected
    assert_int_equal(MQTTPacket_checkVersion(&protocol, 4), 0);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTPacket_checkVersion_negative_version_neg)
{
    MQTTString protocol = MQTTString_initializer;
    UNUSED(state);

    protocol.lenstring.data = "MQTT";
    protocol.lenstring.len = 4;
    // When: the version number is negative
    assert_int_equal(MQTTPacket_checkVersion(&protocol, -1), 0);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTPacket_checkVersion_version_five_neg)
{
    MQTTString protocol = MQTTString_initializer;
    UNUSED(state);

    protocol.lenstring.data = "MQTT";
    protocol.lenstring.len = 4;
    // When: an MQTT version this parser does not implement is declared
    assert_int_equal(MQTTPacket_checkVersion(&protocol, 5), 0);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTPacket_checkVersion_v4_truncated_name_neg)
{
    MQTTString protocol = MQTTString_initializer;
    UNUSED(state);

    // Given: only the first two characters of the v4 name are present
    protocol.lenstring.data = "MQ";
    protocol.lenstring.len = 2;
    // Then: the prefix compare accepts the truncated name, the length is not checked
    assert_int_equal(MQTTPacket_checkVersion(&protocol, 4), 1);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_connack_negative_buflen_neg)
{
    unsigned char buf[8] = {0};
    UNUSED(state);

    // When: a negative buffer length is passed
    assert_int_equal(MQTTSerialize_connack(buf, -1, 0, 0), MQTTPACKET_BUFFER_TOO_SHORT);
    assert_int_equal(buf[0], 0);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_connack_undersized_buffer_not_detected_neg)
{
    unsigned char buf[8] = {0};
    UNUSED(state);

    // When: the declared buffer length is below the minimum the guard checks
    assert_int_equal(MQTTSerialize_connack(buf, 1, 0, 0), MQTTPACKET_BUFFER_TOO_SHORT);
    assert_int_equal(buf[0], 0);
    // When: the declared length is 3, one byte short of the 4 bytes actually written
    // Then: the guard only checks for 2 bytes, so the undersized buffer is not detected
    assert_int_equal(MQTTSerialize_connack(buf, 3, 0, 0), 4);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_connack_out_of_range_rc_neg)
{
    unsigned char buf[8] = {0};
    int rc;
    UNUSED(state);

    // When: a connack return code outside the specified range is requested
    rc = MQTTSerialize_connack(buf, sizeof(buf), 0xFF, 0);
    // Then: it is written to the wire as-is instead of being rejected
    assert_int_equal(rc, 4);
    assert_int_equal(buf[3], 0xFF);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTDeserialize_connect_reserved_type_neg)
{
    unsigned char buf[] = {0x00, 0x02, 0x00, 0x00};
    MQTTPacket_connectData out = MQTTPacket_connectData_initializer;
    UNUSED(state);

    // When: the reserved packet type 0 is deserialized as CONNECT
    assert_int_equal(MQTTDeserialize_connect(&out, buf, sizeof(buf)), 0);
    assert_int_equal(out.keepAliveInterval, 60);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTDeserialize_connect_connack_type_neg)
{
    unsigned char buf[] = {(unsigned char)(CONNACK << 4), 0x02, 0x00, 0x00};
    MQTTPacket_connectData out = MQTTPacket_connectData_initializer;
    UNUSED(state);

    assert_int_equal(MQTTDeserialize_connect(&out, buf, sizeof(buf)), 0);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTDeserialize_connect_protocol_name_overruns_neg)
{
    /* protocol name length claims 10 bytes but only 4 are present */
    unsigned char buf[] = {(unsigned char)(CONNECT << 4), 0x06, 0x00, 0x0A, 'M', 'Q', 'T', 'T'};
    MQTTPacket_connectData out = MQTTPacket_connectData_initializer;
    UNUSED(state);

    assert_int_equal(MQTTDeserialize_connect(&out, buf, sizeof(buf)), 0);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTDeserialize_connect_missing_client_id_neg)
{
    /* valid v4 header and flags, but the client id length field is cut off */
    unsigned char buf[] = {
        (unsigned char)(CONNECT << 4), 10, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x02, 0x00, 0x1E,
    };
    MQTTPacket_connectData out = MQTTPacket_connectData_initializer;
    UNUSED(state);

    assert_int_equal(MQTTDeserialize_connect(&out, buf, sizeof(buf)), 0);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTDeserialize_connect_will_flag_without_will_neg)
{
    /* will flag set but neither will topic nor will message follows */
    unsigned char buf[] = {
        (unsigned char)(CONNECT << 4), 12, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x04, 0x00, 0x1E, 0x00, 0x00,
    };
    MQTTPacket_connectData out = MQTTPacket_connectData_initializer;
    UNUSED(state);

    assert_int_equal(MQTTDeserialize_connect(&out, buf, sizeof(buf)), 0);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTDeserialize_connect_will_topic_without_message_neg)
{
    /* will flag set, will topic present, will message missing */
    unsigned char buf[] = {
        (unsigned char)(CONNECT << 4),
        17,
        0x00,
        0x04,
        'M',
        'Q',
        'T',
        'T',
        0x04,
        0x04,
        0x00,
        0x1E,
        0x00,
        0x00,
        0x00,
        0x03,
        'w',
        '/',
        't',
    };
    MQTTPacket_connectData out = MQTTPacket_connectData_initializer;
    UNUSED(state);

    assert_int_equal(MQTTDeserialize_connect(&out, buf, sizeof(buf)), 0);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTDeserialize_connect_username_flag_without_username_neg)
{
    /* username flag set but no username follows the client id */
    unsigned char buf[] = {
        (unsigned char)(CONNECT << 4), 12, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x80, 0x00, 0x1E, 0x00, 0x00,
    };
    MQTTPacket_connectData out = MQTTPacket_connectData_initializer;
    UNUSED(state);

    assert_int_equal(MQTTDeserialize_connect(&out, buf, sizeof(buf)), 0);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTDeserialize_connect_password_flag_without_password_neg)
{
    /* username and password flags set, username present, password missing */
    unsigned char buf[] = {
        (unsigned char)(CONNECT << 4),
        18,
        0x00,
        0x04,
        'M',
        'Q',
        'T',
        'T',
        0x04,
        0xC0,
        0x00,
        0x1E,
        0x00,
        0x00,
        0x00,
        0x04,
        'u',
        's',
        'e',
        'r',
    };
    MQTTPacket_connectData out = MQTTPacket_connectData_initializer;
    UNUSED(state);

    assert_int_equal(MQTTDeserialize_connect(&out, buf, sizeof(buf)), 0);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTDeserialize_connect_zero_length_buffer_neg)
{
    unsigned char buf[] = {(unsigned char)(CONNECT << 4)};
    MQTTPacket_connectData out = MQTTPacket_connectData_initializer;
    UNUSED(state);

    // When: nothing follows the fixed header byte
    assert_int_equal(MQTTDeserialize_connect(&out, buf, 1), 0);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTDeserialize_connect_v3_name_with_v4_version_neg)
{
    /* MQIsdp protocol name declared as version 4 */
    unsigned char buf[] = {
        (unsigned char)(CONNECT << 4), 14, 0x00, 0x06, 'M', 'Q', 'I', 's', 'd', 'p', 0x04, 0x02, 0x00, 0x1E, 0x00, 0x00,
    };
    MQTTPacket_connectData out = MQTTPacket_connectData_initializer;
    UNUSED(state);

    assert_int_equal(MQTTDeserialize_connect(&out, buf, sizeof(buf)), 0);
}
