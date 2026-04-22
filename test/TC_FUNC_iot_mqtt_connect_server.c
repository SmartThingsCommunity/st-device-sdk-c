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
#include <iot_mqtt_connect.h>
#include <string.h>

#include "cmocka_custom.h"

/* Not declared in the public header but defined in iot_mqtt_connect_server.c */
extern int MQTTPacket_checkVersion(MQTTString *protocol, int version);

#define UNUSED(x) (void)(x)

/*
 * Tests for MQTTPacket_checkVersion
 */
void TC_MQTTPacket_checkVersion_v3_success(void **state)
{
    MQTTString proto = MQTTString_initializer;
    UNUSED(state);

    proto.lenstring.data = "MQIsdp";
    proto.lenstring.len = 6;
    assert_int_equal(MQTTPacket_checkVersion(&proto, 3), 1);
}

void TC_MQTTPacket_checkVersion_v4_success(void **state)
{
    MQTTString proto = MQTTString_initializer;
    UNUSED(state);

    proto.lenstring.data = "MQTT";
    proto.lenstring.len = 4;
    assert_int_equal(MQTTPacket_checkVersion(&proto, 4), 1);
}

void TC_MQTTPacket_checkVersion_v3_wrong_name(void **state)
{
    MQTTString proto = MQTTString_initializer;
    UNUSED(state);

    proto.lenstring.data = "MQTT";
    proto.lenstring.len = 4;
    assert_int_equal(MQTTPacket_checkVersion(&proto, 3), 0);
}

void TC_MQTTPacket_checkVersion_v4_wrong_name(void **state)
{
    MQTTString proto = MQTTString_initializer;
    UNUSED(state);

    proto.lenstring.data = "MQIsdp";
    proto.lenstring.len = 6;
    assert_int_equal(MQTTPacket_checkVersion(&proto, 4), 0);
}

void TC_MQTTPacket_checkVersion_unsupported_version(void **state)
{
    MQTTString proto = MQTTString_initializer;
    UNUSED(state);

    proto.lenstring.data = "MQTT";
    proto.lenstring.len = 4;
    assert_int_equal(MQTTPacket_checkVersion(&proto, 5), 0);
}

void TC_MQTTPacket_checkVersion_zero_length(void **state)
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
void TC_MQTTSerialize_connack_success(void **state)
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

void TC_MQTTSerialize_connack_session_present(void **state)
{
    unsigned char buf[8] = {0};
    int rc;
    UNUSED(state);

    rc = MQTTSerialize_connack(buf, sizeof(buf), 0, 1);
    assert_int_equal(rc, 4);
    assert_int_equal(buf[2] & 0x01, 1);
}

void TC_MQTTSerialize_connack_with_rc(void **state)
{
    unsigned char buf[8] = {0};
    int rc;
    UNUSED(state);

    rc = MQTTSerialize_connack(buf, sizeof(buf), 0x05, 0);
    assert_int_equal(rc, 4);
    assert_int_equal(buf[3], 0x05);
}

void TC_MQTTSerialize_connack_buffer_too_short(void **state)
{
    unsigned char buf[1] = {0};
    int rc;
    UNUSED(state);

    rc = MQTTSerialize_connack(buf, sizeof(buf), 0, 0);
    assert_int_equal(rc, MQTTPACKET_BUFFER_TOO_SHORT);
}

void TC_MQTTSerialize_connack_zero_buffer(void **state)
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

void TC_MQTTDeserialize_connect_success(void **state)
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

void TC_MQTTDeserialize_connect_with_will(void **state)
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

void TC_MQTTDeserialize_connect_with_username_password(void **state)
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

void TC_MQTTDeserialize_connect_wrong_type(void **state)
{
    unsigned char buf[] = {(unsigned char)(PUBACK << 4), 0x02, 0x00, 0x00};
    MQTTPacket_connectData out = MQTTPacket_connectData_initializer;
    int rc;
    UNUSED(state);

    rc = MQTTDeserialize_connect(&out, buf, sizeof(buf));
    assert_int_equal(rc, 0);
}

void TC_MQTTDeserialize_connect_truncated(void **state)
{
    /* header + remlen but no protocol data */
    unsigned char buf[] = {(unsigned char)(CONNECT << 4), 0x00};
    MQTTPacket_connectData out = MQTTPacket_connectData_initializer;
    int rc;
    UNUSED(state);

    rc = MQTTDeserialize_connect(&out, buf, sizeof(buf));
    assert_int_equal(rc, 0);
}

void TC_MQTTDeserialize_connect_unknown_protocol_version(void **state)
{
    /* Minimal CONNECT where the protocol version is bogus (99) so the
     * parser must refuse to continue. */
    unsigned char buf[] = {
        (unsigned char)(CONNECT << 4), 10,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        99,    /* protocol version */
        0x00,  /* connect flags */
        0x00, 0x1E, /* keep alive = 30 */
    };
    MQTTPacket_connectData out = MQTTPacket_connectData_initializer;
    int rc;
    UNUSED(state);

    rc = MQTTDeserialize_connect(&out, buf, sizeof(buf));
    assert_int_equal(rc, 0);
}

void TC_MQTTDeserialize_connect_password_without_username(void **state)
{
    /* Construct a CONNECT with password flag but no username flag. */
    unsigned char buf[] = {
        (unsigned char)(CONNECT << 4), 14,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04,  /* protocol version 4 */
        0x40,  /* password flag set, username flag clear */
        0x00, 0x1E, /* keep alive = 30 */
        0x00, 0x00, /* client id len = 0 */
    };
    MQTTPacket_connectData out = MQTTPacket_connectData_initializer;
    int rc;
    UNUSED(state);

    rc = MQTTDeserialize_connect(&out, buf, sizeof(buf));
    assert_int_equal(rc, 0);
}
