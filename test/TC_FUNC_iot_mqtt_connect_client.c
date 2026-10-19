#define _GNU_SOURCE
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

/* Not declared in the public header but defined in iot_mqtt_connect_client.c */
extern int MQTTSerialize_connectLength(MQTTPacket_connectData *options);
extern int MQTTSerialize_zero(unsigned char *buf, int buflen, unsigned char packettype);

#define UNUSED(x) (void)(x)

/*
 * Tests for MQTTSerialize_connectLength
 */
TEST_SUITE("iot_mqtt_connect_client.c");

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_connectLength_v4_only_pos)
{
    MQTTPacket_connectData opts = MQTTPacket_connectData_initializer;
    int len;
    UNUSED(state);

    opts.MQTTVersion = 4;
    opts.clientID.cstring = "id";
    len = MQTTSerialize_connectLength(&opts);
    /* 10 (v4) + 2 (len) + 2 (id) = 14 */
    assert_int_equal(len, 14);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_connectLength_v3_pos)
{
    MQTTPacket_connectData opts = MQTTPacket_connectData_initializer;
    int len;
    UNUSED(state);

    opts.MQTTVersion = 3;
    opts.clientID.cstring = "id";
    len = MQTTSerialize_connectLength(&opts);
    /* 12 (v3) + 2 (len) + 2 (id) = 16 */
    assert_int_equal(len, 16);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_connectLength_with_will_pos)
{
    MQTTPacket_connectData opts = MQTTPacket_connectData_initializer;
    int len;
    UNUSED(state);

    opts.MQTTVersion = 4;
    opts.clientID.cstring = "id";
    opts.willFlag = 1;
    opts.will.topicName.cstring = "wt";
    opts.will.message.cstring = "wm";
    len = MQTTSerialize_connectLength(&opts);
    /* 14 + 2+2 (topic) + 2+2 (msg) = 22 */
    assert_int_equal(len, 22);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_connectLength_with_credentials_pos)
{
    MQTTPacket_connectData opts = MQTTPacket_connectData_initializer;
    int len;
    UNUSED(state);

    opts.MQTTVersion = 4;
    opts.clientID.cstring = "id";
    opts.username.cstring = "usr";
    opts.password.cstring = "pw";
    len = MQTTSerialize_connectLength(&opts);
    /* 14 + 2+3 (user) + 2+2 (pass) = 23 */
    assert_int_equal(len, 23);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_connectLength_unknown_version_neg)
{
    MQTTPacket_connectData opts = MQTTPacket_connectData_initializer;
    int len;
    UNUSED(state);

    opts.MQTTVersion = 99;
    opts.clientID.cstring = "id";
    len = MQTTSerialize_connectLength(&opts);
    /* Unknown version contributes no fixed header bytes */
    assert_int_equal(len, 4);
}

/*
 * Tests for MQTTSerialize_connect
 */
TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_connect_v4_success_pos)
{
    unsigned char buf[32] = {0};
    MQTTPacket_connectData opts = MQTTPacket_connectData_initializer;
    int rc;
    UNUSED(state);

    opts.MQTTVersion = 4;
    opts.clientID.cstring = "id";
    rc = MQTTSerialize_connect(buf, sizeof(buf), &opts);
    assert_true(rc > 0);
    assert_int_equal((buf[0] & 0xF0) >> 4, CONNECT);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_connect_v3_success_pos)
{
    unsigned char buf[32] = {0};
    MQTTPacket_connectData opts = MQTTPacket_connectData_initializer;
    int rc;
    UNUSED(state);

    opts.MQTTVersion = 3;
    opts.clientID.cstring = "id";
    rc = MQTTSerialize_connect(buf, sizeof(buf), &opts);
    assert_true(rc > 0);
    /* MQIsdp protocol string should appear in the packet payload */
    assert_non_null(memmem(buf, rc, "MQIsdp", 6));
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_connect_will_flags_pos)
{
    unsigned char buf[64] = {0};
    MQTTPacket_connectData opts = MQTTPacket_connectData_initializer;
    int rc;
    UNUSED(state);

    opts.MQTTVersion = 4;
    opts.clientID.cstring = "id";
    opts.willFlag = 1;
    opts.will.qos = 2;
    opts.will.retained = 1;
    opts.will.topicName.cstring = "wt";
    opts.will.message.cstring = "wm";
    rc = MQTTSerialize_connect(buf, sizeof(buf), &opts);
    assert_true(rc > 0);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_connect_buffer_too_short_neg)
{
    unsigned char buf[4] = {0};
    MQTTPacket_connectData opts = MQTTPacket_connectData_initializer;
    int rc;
    UNUSED(state);

    opts.MQTTVersion = 4;
    opts.clientID.cstring = "idstring";
    rc = MQTTSerialize_connect(buf, sizeof(buf), &opts);
    assert_int_equal(rc, MQTTPACKET_BUFFER_TOO_SHORT);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_connect_zero_buffer_neg)
{
    unsigned char buf[32] = {0};
    MQTTPacket_connectData opts = MQTTPacket_connectData_initializer;
    int rc;
    UNUSED(state);

    opts.MQTTVersion = 4;
    opts.clientID.cstring = "id";
    rc = MQTTSerialize_connect(buf, 0, &opts);
    assert_int_equal(rc, MQTTPACKET_BUFFER_TOO_SHORT);
}

/*
 * Tests for MQTTDeserialize_connack
 */
TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTDeserialize_connack_success_pos)
{
    unsigned char buf[] = {(unsigned char)(CONNACK << 4), 0x02, 0x01, 0x00};
    unsigned char session_present = 0, rc_code = 0xFF;
    int rc;
    UNUSED(state);

    rc = MQTTDeserialize_connack(&session_present, &rc_code, buf, sizeof(buf));
    assert_int_equal(rc, 1);
    assert_int_equal(session_present, 1);
    assert_int_equal(rc_code, 0);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTDeserialize_connack_wrong_type_neg)
{
    unsigned char buf[] = {(unsigned char)(PUBACK << 4), 0x02, 0x00, 0x00};
    unsigned char session_present = 0, rc_code = 0;
    int rc;
    UNUSED(state);

    rc = MQTTDeserialize_connack(&session_present, &rc_code, buf, sizeof(buf));
    assert_int_equal(rc, 0);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTDeserialize_connack_short_remlen_neg)
{
    unsigned char buf[] = {(unsigned char)(CONNACK << 4), 0x01, 0x00};
    unsigned char session_present = 0xFF, rc_code = 0xFF;
    int rc;
    UNUSED(state);

    rc = MQTTDeserialize_connack(&session_present, &rc_code, buf, sizeof(buf));
    /* remlen is only 1; the current implementation does not reset rc
     * before the early exit but the output parameters must remain
     * unchanged. */
    (void)rc;
    assert_int_equal(session_present, 0xFF);
    assert_int_equal(rc_code, 0xFF);
}

/*
 * Tests for MQTTSerialize_zero / _disconnect / _pingreq
 */
TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_zero_neg)
{
    unsigned char buf[4] = {0};
    int rc;
    UNUSED(state);

    rc = MQTTSerialize_zero(buf, sizeof(buf), DISCONNECT);
    assert_int_equal(rc, 2);
    assert_int_equal((buf[0] & 0xF0) >> 4, DISCONNECT);
    assert_int_equal(buf[1], 0);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_zero_buffer_too_short_neg)
{
    unsigned char buf[1] = {0};
    int rc;
    UNUSED(state);

    rc = MQTTSerialize_zero(buf, sizeof(buf), DISCONNECT);
    assert_int_equal(rc, MQTTPACKET_BUFFER_TOO_SHORT);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_zero_zero_buffer_neg)
{
    unsigned char buf[4] = {0};
    int rc;
    UNUSED(state);

    rc = MQTTSerialize_zero(buf, 0, DISCONNECT);
    assert_int_equal(rc, MQTTPACKET_BUFFER_TOO_SHORT);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_disconnect_neg)
{
    unsigned char buf[4] = {0};
    int rc;
    UNUSED(state);

    rc = MQTTSerialize_disconnect(buf, sizeof(buf));
    assert_int_equal(rc, 2);
    assert_int_equal((buf[0] & 0xF0) >> 4, DISCONNECT);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_disconnect_buffer_too_short_neg)
{
    unsigned char buf[1] = {0};
    int rc;
    UNUSED(state);

    rc = MQTTSerialize_disconnect(buf, sizeof(buf));
    assert_int_equal(rc, MQTTPACKET_BUFFER_TOO_SHORT);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_pingreq_success_pos)
{
    unsigned char buf[4] = {0};
    int rc;
    UNUSED(state);

    rc = MQTTSerialize_pingreq(buf, sizeof(buf));
    assert_int_equal(rc, 2);
    assert_int_equal((buf[0] & 0xF0) >> 4, PINGREQ);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_pingreq_buffer_too_short_neg)
{
    unsigned char buf[1] = {0};
    int rc;
    UNUSED(state);

    rc = MQTTSerialize_pingreq(buf, sizeof(buf));
    assert_int_equal(rc, MQTTPACKET_BUFFER_TOO_SHORT);
}

/*
 * Additional negative tests for iot_mqtt_connect_client.c
 */
TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_connectLength_version_zero_neg)
{
    MQTTPacket_connectData opts = MQTTPacket_connectData_initializer;
    UNUSED(state);

    // When: no protocol version is set at all
    opts.MQTTVersion = 0;
    opts.clientID.cstring = "id";
    // Then: no fixed header bytes are reserved, so the length is too small to be valid
    assert_int_equal(MQTTSerialize_connectLength(&opts), 4);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_connectLength_version_five_neg)
{
    MQTTPacket_connectData opts = MQTTPacket_connectData_initializer;
    UNUSED(state);

    opts.MQTTVersion = 5;
    opts.clientID.cstring = "id";
    assert_int_equal(MQTTSerialize_connectLength(&opts), 4);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_connectLength_negative_version_neg)
{
    MQTTPacket_connectData opts = MQTTPacket_connectData_initializer;
    UNUSED(state);

    opts.MQTTVersion = -1;
    opts.clientID.cstring = "id";
    assert_int_equal(MQTTSerialize_connectLength(&opts), 4);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_connectLength_empty_client_id_neg)
{
    MQTTPacket_connectData opts = MQTTPacket_connectData_initializer;
    UNUSED(state);

    // Given: no client id
    opts.MQTTVersion = 4;
    // Then: only the two length bytes of the empty client id are added
    assert_int_equal(MQTTSerialize_connectLength(&opts), 12);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_connectLength_will_flag_without_will_neg)
{
    MQTTPacket_connectData opts = MQTTPacket_connectData_initializer;
    UNUSED(state);

    // Given: the will flag is set but no will topic or message is supplied
    opts.MQTTVersion = 4;
    opts.clientID.cstring = "id";
    opts.willFlag = 1;
    // Then: four bytes are still reserved for the two empty strings
    assert_int_equal(MQTTSerialize_connectLength(&opts), 18);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_connectLength_password_without_username_neg)
{
    MQTTPacket_connectData opts = MQTTPacket_connectData_initializer;
    UNUSED(state);

    // Given: a password but no user name, which is invalid per the spec
    opts.MQTTVersion = 4;
    opts.clientID.cstring = "id";
    opts.password.cstring = "pw";
    // Then: the length is computed anyway
    assert_int_equal(MQTTSerialize_connectLength(&opts), 18);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_connectLength_zero_length_lenstring_username_neg)
{
    MQTTPacket_connectData opts = MQTTPacket_connectData_initializer;
    UNUSED(state);

    // Given: a user name pointer with a zero length
    opts.MQTTVersion = 4;
    opts.clientID.cstring = "id";
    opts.username.lenstring.data = "usr";
    opts.username.lenstring.len = 0;
    // Then: the two length bytes are still reserved for the empty user name
    assert_int_equal(MQTTSerialize_connectLength(&opts), 16);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_connectLength_cstring_wins_over_lenstring_neg)
{
    MQTTPacket_connectData opts = MQTTPacket_connectData_initializer;
    UNUSED(state);

    // Given: both string forms are populated with different lengths
    opts.MQTTVersion = 4;
    opts.clientID.cstring = "id";
    opts.clientID.lenstring.data = "longer";
    opts.clientID.lenstring.len = 6;
    // Then: the c string form takes precedence, the lenstring is silently ignored
    assert_int_equal(MQTTSerialize_connectLength(&opts), 14);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_connect_size_unknown_version_neg)
{
    MQTTPacket_connectData opts = MQTTPacket_connectData_initializer;
    UNUSED(state);

    opts.MQTTVersion = 99;
    opts.clientID.cstring = "id";
    // Then: header(1) + remlen(1) + 4 = 6
    assert_int_equal(MQTTSerialize_connect_size(&opts), 6);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_connect_size_two_byte_remlen_neg)
{
    MQTTPacket_connectData opts = MQTTPacket_connectData_initializer;
    char long_id[200];
    UNUSED(state);

    memset(long_id, 'a', sizeof(long_id) - 1);
    long_id[sizeof(long_id) - 1] = '\0';
    opts.MQTTVersion = 4;
    opts.clientID.cstring = long_id;
    // Then: header(1) + remlen(2) + 10 + 2 + 199 = 214
    assert_int_equal(MQTTSerialize_connect_size(&opts), 214);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_connect_negative_buflen_neg)
{
    unsigned char buf[32] = {0};
    MQTTPacket_connectData opts = MQTTPacket_connectData_initializer;
    UNUSED(state);

    opts.MQTTVersion = 4;
    opts.clientID.cstring = "id";
    // When: a negative buffer length is passed
    assert_int_equal(MQTTSerialize_connect(buf, -1, &opts), MQTTPACKET_BUFFER_TOO_SHORT);
    assert_int_equal(buf[0], 0);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_connect_one_byte_short_neg)
{
    unsigned char buf[64] = {0};
    MQTTPacket_connectData opts = MQTTPacket_connectData_initializer;
    int required;
    UNUSED(state);

    opts.MQTTVersion = 4;
    opts.clientID.cstring = "clientid";
    required = MQTTSerialize_connect_size(&opts);

    // When: the buffer is one byte smaller than required
    assert_int_equal(MQTTSerialize_connect(buf, required - 1, &opts), MQTTPACKET_BUFFER_TOO_SHORT);
    assert_int_equal(buf[0], 0);
    // When: the buffer is exactly the required size
    assert_int_equal(MQTTSerialize_connect(buf, required, &opts), required);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_connect_unknown_version_falls_back_to_v3_neg)
{
    unsigned char buf[64] = {0};
    MQTTPacket_connectData opts = MQTTPacket_connectData_initializer;
    int rc;
    UNUSED(state);

    // Given: a protocol version this serializer does not know
    opts.MQTTVersion = 99;
    opts.clientID.cstring = "id";
    // When: the buffer is large enough for the v3 form despite the short length estimate
    rc = MQTTSerialize_connect(buf, sizeof(buf), &opts);
    // Then: it silently emits the v3 protocol name and version instead of rejecting
    assert_true(rc > 0);
    assert_non_null(memmem(buf, rc, "MQIsdp", 6));
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_connect_reserved_will_qos_neg)
{
    unsigned char buf[64] = {0};
    MQTTPacket_connectData opts = MQTTPacket_connectData_initializer;
    int rc;
    UNUSED(state);

    opts.MQTTVersion = 4;
    opts.clientID.cstring = "id";
    opts.willFlag = 1;
    opts.will.qos = 3;
    opts.will.topicName.cstring = "wt";
    opts.will.message.cstring = "wm";
    // When: the reserved will qos value is requested
    rc = MQTTSerialize_connect(buf, sizeof(buf), &opts);
    // Then: it is written to the connect flags as-is
    assert_true(rc > 0);
    assert_int_equal((buf[9] >> 3) & 0x03, 3);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_connect_will_qos_ignored_without_will_flag_neg)
{
    unsigned char buf[64] = {0};
    MQTTPacket_connectData opts = MQTTPacket_connectData_initializer;
    int rc;
    UNUSED(state);

    // Given: a will qos and retain without the will flag
    opts.MQTTVersion = 4;
    opts.clientID.cstring = "id";
    opts.will.qos = 2;
    opts.will.retained = 1;
    // When
    rc = MQTTSerialize_connect(buf, sizeof(buf), &opts);
    // Then: the will bits must stay clear
    assert_true(rc > 0);
    assert_int_equal(buf[9] & 0x3C, 0);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_connect_password_without_username_flag_neg)
{
    unsigned char buf[64] = {0};
    MQTTPacket_connectData opts = MQTTPacket_connectData_initializer;
    int rc;
    UNUSED(state);

    // Given: a password but no user name
    opts.MQTTVersion = 4;
    opts.clientID.cstring = "id";
    opts.password.cstring = "pw";
    // When
    rc = MQTTSerialize_connect(buf, sizeof(buf), &opts);
    // Then: the password flag is set without the user name flag, which no broker accepts
    assert_true(rc > 0);
    assert_int_equal((buf[9] >> 6) & 0x01, 1);
    assert_int_equal((buf[9] >> 7) & 0x01, 0);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_connect_empty_client_id_neg)
{
    unsigned char buf[64] = {0};
    MQTTPacket_connectData opts = MQTTPacket_connectData_initializer;
    int rc;
    UNUSED(state);

    // Given: no client id and no clean session
    opts.MQTTVersion = 4;
    // When
    rc = MQTTSerialize_connect(buf, sizeof(buf), &opts);
    // Then: an empty client id is emitted instead of being rejected
    assert_true(rc > 0);
    assert_int_equal(buf[rc - 2], 0);
    assert_int_equal(buf[rc - 1], 0);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_connect_zero_keepalive_neg)
{
    unsigned char buf[64] = {0};
    MQTTPacket_connectData opts = MQTTPacket_connectData_initializer;
    int rc;
    UNUSED(state);

    opts.MQTTVersion = 4;
    opts.clientID.cstring = "id";
    opts.keepAliveInterval = 0;
    rc = MQTTSerialize_connect(buf, sizeof(buf), &opts);
    // Then: a zero keep alive disables the mechanism entirely
    assert_true(rc > 0);
    assert_int_equal(buf[10], 0);
    assert_int_equal(buf[11], 0);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_connect_max_keepalive_neg)
{
    unsigned char buf[64] = {0};
    MQTTPacket_connectData opts = MQTTPacket_connectData_initializer;
    int rc;
    UNUSED(state);

    opts.MQTTVersion = 4;
    opts.clientID.cstring = "id";
    opts.keepAliveInterval = 0xFFFF;
    rc = MQTTSerialize_connect(buf, sizeof(buf), &opts);
    assert_true(rc > 0);
    assert_int_equal(buf[10], 0xFF);
    assert_int_equal(buf[11], 0xFF);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_connect_lenstring_client_id_neg)
{
    unsigned char buf[64] = {0};
    MQTTPacket_connectData opts = MQTTPacket_connectData_initializer;
    int rc;
    UNUSED(state);

    // Given: the client id is given in length prefixed form
    opts.MQTTVersion = 4;
    opts.clientID.lenstring.data = "abcd";
    opts.clientID.lenstring.len = 4;
    rc = MQTTSerialize_connect(buf, sizeof(buf), &opts);
    assert_true(rc > 0);
    assert_non_null(memmem(buf, rc, "abcd", 4));
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_connect_v3_buffer_too_short_neg)
{
    unsigned char buf[8] = {0};
    MQTTPacket_connectData opts = MQTTPacket_connectData_initializer;
    UNUSED(state);

    // Given: the v3 form needs two more bytes than v4
    opts.MQTTVersion = 3;
    opts.clientID.cstring = "id";
    assert_int_equal(MQTTSerialize_connect(buf, sizeof(buf), &opts), MQTTPACKET_BUFFER_TOO_SHORT);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTDeserialize_connack_reserved_type_neg)
{
    unsigned char buf[] = {0x00, 0x02, 0x00, 0x00};
    unsigned char session_present = 0xFF, rc_code = 0xFF;
    UNUSED(state);

    // When: the reserved packet type 0 is deserialized as CONNACK
    assert_int_equal(MQTTDeserialize_connack(&session_present, &rc_code, buf, sizeof(buf)), 0);
    assert_int_equal(session_present, 0xFF);
    assert_int_equal(rc_code, 0xFF);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTDeserialize_connack_connect_type_neg)
{
    unsigned char buf[] = {(unsigned char)(CONNECT << 4), 0x02, 0x00, 0x00};
    unsigned char session_present = 0xFF, rc_code = 0xFF;
    UNUSED(state);

    assert_int_equal(MQTTDeserialize_connack(&session_present, &rc_code, buf, sizeof(buf)), 0);
    assert_int_equal(rc_code, 0xFF);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTDeserialize_connack_zero_remlen_neg)
{
    unsigned char buf[] = {(unsigned char)(CONNACK << 4), 0x00};
    unsigned char session_present = 0xFF, rc_code = 0xFF;
    UNUSED(state);

    // When: the remaining length says there is no payload
    (void)MQTTDeserialize_connack(&session_present, &rc_code, buf, sizeof(buf));
    // Then: the outputs must remain untouched
    assert_int_equal(session_present, 0xFF);
    assert_int_equal(rc_code, 0xFF);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTDeserialize_connack_refused_rc_neg)
{
    unsigned char buf[] = {(unsigned char)(CONNACK << 4), 0x02, 0x00, 0x05};
    unsigned char session_present = 0xFF, rc_code = 0;
    UNUSED(state);

    // Given: the broker refused the connection with "not authorized"
    assert_int_equal(MQTTDeserialize_connack(&session_present, &rc_code, buf, sizeof(buf)), 1);
    // Then: the refusal code is reported to the caller
    assert_int_equal(rc_code, 5);
    assert_int_equal(session_present, 0);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTDeserialize_connack_unknown_rc_neg)
{
    unsigned char buf[] = {(unsigned char)(CONNACK << 4), 0x02, 0x00, 0xFF};
    unsigned char session_present = 0, rc_code = 0;
    UNUSED(state);

    // When: a return code outside the specified range arrives
    assert_int_equal(MQTTDeserialize_connack(&session_present, &rc_code, buf, sizeof(buf)), 1);
    // Then: it is passed through unchanged instead of being rejected
    assert_int_equal(rc_code, 0xFF);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTDeserialize_connack_reserved_flag_bits_neg)
{
    unsigned char buf[] = {(unsigned char)(CONNACK << 4), 0x02, 0xFE, 0x00};
    unsigned char session_present = 0xFF, rc_code = 0xFF;
    UNUSED(state);

    // Given: the reserved bits of the connack flags byte are all set
    assert_int_equal(MQTTDeserialize_connack(&session_present, &rc_code, buf, sizeof(buf)), 1);
    // Then: only the session present bit is extracted
    assert_int_equal(session_present, 0);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTDeserialize_connack_extra_trailing_bytes_neg)
{
    unsigned char buf[] = {(unsigned char)(CONNACK << 4), 0x02, 0x00, 0x00, 0xAA, 0xBB};
    unsigned char session_present = 0xFF, rc_code = 0xFF;
    UNUSED(state);

    // Given: bytes beyond the declared remaining length
    assert_int_equal(MQTTDeserialize_connack(&session_present, &rc_code, buf, sizeof(buf)), 1);
    // Then: the trailing bytes are ignored rather than rejected
    assert_int_equal(session_present, 0);
    assert_int_equal(rc_code, 0);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTDeserialize_connack_oversized_remlen_neg)
{
    /* remlen claims 100 bytes but only 2 follow */
    unsigned char buf[] = {(unsigned char)(CONNACK << 4), 0x64, 0x00, 0x00};
    unsigned char session_present = 0xFF, rc_code = 0xFF;
    UNUSED(state);

    // Then: the length is trusted, the overrun is not detected
    assert_int_equal(MQTTDeserialize_connack(&session_present, &rc_code, buf, sizeof(buf)), 1);
    assert_int_equal(session_present, 0);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_zero_negative_buflen_neg)
{
    unsigned char buf[4] = {0};
    UNUSED(state);

    assert_int_equal(MQTTSerialize_zero(buf, -1, DISCONNECT), MQTTPACKET_BUFFER_TOO_SHORT);
    assert_int_equal(buf[0], 0);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_zero_reserved_type_neg)
{
    unsigned char buf[4] = {0};
    int rc;
    UNUSED(state);

    // When: the reserved packet type 0 is serialized
    rc = MQTTSerialize_zero(buf, sizeof(buf), 0);
    // Then: it is emitted as-is instead of being rejected
    assert_int_equal(rc, 2);
    assert_int_equal(buf[0], 0);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_zero_out_of_range_type_neg)
{
    unsigned char buf[4] = {0};
    int rc;
    UNUSED(state);

    // When: a packet type that does not fit the 4 bit field is requested
    rc = MQTTSerialize_zero(buf, sizeof(buf), 0xFF);
    // Then: the type is silently truncated to the low nibble
    assert_int_equal(rc, 2);
    assert_int_equal((buf[0] & MQTT_FIXED_HEADER_PACKET_TYPE_MASK) >> MQTT_FIXED_HEADER_PACKET_TYPE_OFFSET, 0x0F);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_zero_publish_type_neg)
{
    unsigned char buf[4] = {0};
    int rc;
    UNUSED(state);

    // When: a packet type that requires a payload is serialized as a zero length packet
    rc = MQTTSerialize_zero(buf, sizeof(buf), PUBLISH);
    // Then: an invalid empty PUBLISH is produced instead of an error
    assert_int_equal(rc, 2);
    assert_int_equal((buf[0] & MQTT_FIXED_HEADER_PACKET_TYPE_MASK) >> MQTT_FIXED_HEADER_PACKET_TYPE_OFFSET, PUBLISH);
    assert_int_equal(buf[1], 0);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_st_mqtt_disconnect_negative_buflen_neg)
{
    unsigned char buf[4] = {0};
    UNUSED(state);

    assert_int_equal(MQTTSerialize_disconnect(buf, -1), MQTTPACKET_BUFFER_TOO_SHORT);
    assert_int_equal(buf[0], 0);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_disconnect_zero_buffer_neg)
{
    unsigned char buf[4] = {0};
    UNUSED(state);

    assert_int_equal(MQTTSerialize_disconnect(buf, 0), MQTTPACKET_BUFFER_TOO_SHORT);
    assert_int_equal(buf[0], 0);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_disconnect_exact_buffer_neg)
{
    unsigned char buf[2] = {0};
    UNUSED(state);

    // When: the buffer is exactly the minimum size
    assert_int_equal(MQTTSerialize_disconnect(buf, sizeof(buf)), MQTT_DISCONNECT_PACKET_SIZE);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_pingreq_negative_buflen_neg)
{
    unsigned char buf[4] = {0};
    UNUSED(state);

    assert_int_equal(MQTTSerialize_pingreq(buf, -1), MQTTPACKET_BUFFER_TOO_SHORT);
    assert_int_equal(buf[0], 0);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_pingreq_zero_buffer_neg)
{
    unsigned char buf[4] = {0};
    UNUSED(state);

    assert_int_equal(MQTTSerialize_pingreq(buf, 0), MQTTPACKET_BUFFER_TOO_SHORT);
    assert_int_equal(buf[0], 0);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_pingreq_exact_buffer_neg)
{
    unsigned char buf[2] = {0};
    UNUSED(state);

    assert_int_equal(MQTTSerialize_pingreq(buf, sizeof(buf)), MQTT_PINGREQ_PACKET_SIZE);
    assert_int_equal((buf[0] & MQTT_FIXED_HEADER_PACKET_TYPE_MASK) >> MQTT_FIXED_HEADER_PACKET_TYPE_OFFSET, PINGREQ);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_connect_will_retain_bit_neg)
{
    unsigned char buf[64] = {0};
    MQTTPacket_connectData opts = MQTTPacket_connectData_initializer;
    int rc;
    UNUSED(state);

    opts.MQTTVersion = 4;
    opts.clientID.cstring = "id";
    opts.willFlag = 1;
    opts.will.retained = 1;
    opts.will.topicName.cstring = "wt";
    opts.will.message.cstring = "wm";
    rc = MQTTSerialize_connect(buf, sizeof(buf), &opts);
    assert_true(rc > 0);
    assert_int_equal((buf[9] >> 5) & 0x01, 1);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_connect_clean_session_bit_neg)
{
    unsigned char buf[64] = {0};
    MQTTPacket_connectData opts = MQTTPacket_connectData_initializer;
    int rc;
    UNUSED(state);

    // Given: clean session is explicitly disabled while the client id is empty,
    // a combination the spec forbids
    opts.MQTTVersion = 4;
    opts.cleansession = 0;
    rc = MQTTSerialize_connect(buf, sizeof(buf), &opts);
    // Then: it is serialized anyway
    assert_true(rc > 0);
    assert_int_equal((buf[9] >> 1) & 0x01, 0);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_connect_username_flag_from_lenstring_neg)
{
    unsigned char buf[64] = {0};
    MQTTPacket_connectData opts = MQTTPacket_connectData_initializer;
    int rc;
    UNUSED(state);

    // Given: a user name supplied only in length prefixed form
    opts.MQTTVersion = 4;
    opts.clientID.cstring = "id";
    opts.username.lenstring.data = "usr";
    opts.username.lenstring.len = 3;
    rc = MQTTSerialize_connect(buf, sizeof(buf), &opts);
    // Then: the user name flag is derived from the lenstring pointer as well
    assert_true(rc > 0);
    assert_int_equal((buf[9] >> 7) & 0x01, 1);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_connect_zero_length_username_still_flagged_neg)
{
    unsigned char buf[64] = {0};
    MQTTPacket_connectData opts = MQTTPacket_connectData_initializer;
    int rc;
    UNUSED(state);

    // Given: a user name pointer with a zero length
    opts.MQTTVersion = 4;
    opts.clientID.cstring = "id";
    opts.username.lenstring.data = "usr";
    opts.username.lenstring.len = 0;
    rc = MQTTSerialize_connect(buf, sizeof(buf), &opts);
    // Then: the flag is set even though no user name is carried
    assert_true(rc > 0);
    assert_int_equal((buf[9] >> 7) & 0x01, 1);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_connect_roundtrip_unknown_version_downgraded_neg)
{
    unsigned char buf[64] = {0};
    MQTTPacket_connectData opts = MQTTPacket_connectData_initializer;
    MQTTPacket_connectData out = MQTTPacket_connectData_initializer;
    int total;
    UNUSED(state);

    // Given: a connect packet serialized with an unknown version
    opts.MQTTVersion = 99;
    opts.clientID.cstring = "id";
    total = MQTTSerialize_connect(buf, sizeof(buf), &opts);
    assert_true(total > 0);
    // When: the server side parses it back
    // Then: the caller's version 99 was silently replaced by v3 on the wire, so the
    // peer accepts a packet the caller never asked for
    assert_int_equal(MQTTDeserialize_connect(&out, buf, total), 1);
    assert_non_null(memmem(buf, total, "MQIsdp", 6));
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_connect_will_topic_only_neg)
{
    unsigned char buf[64] = {0};
    MQTTPacket_connectData opts = MQTTPacket_connectData_initializer;
    int rc;
    UNUSED(state);

    // Given: a will topic without a will message
    opts.MQTTVersion = 4;
    opts.clientID.cstring = "id";
    opts.willFlag = 1;
    opts.will.topicName.cstring = "wt";
    rc = MQTTSerialize_connect(buf, sizeof(buf), &opts);
    // Then: an empty will message is emitted instead of an error
    assert_true(rc > 0);
    assert_int_equal(buf[rc - 2], 0);
    assert_int_equal(buf[rc - 1], 0);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_MQTTSerialize_connect_all_flags_neg)
{
    unsigned char buf[96] = {0};
    MQTTPacket_connectData opts = MQTTPacket_connectData_initializer;
    int rc;
    UNUSED(state);

    opts.MQTTVersion = 4;
    opts.clientID.cstring = "id";
    opts.cleansession = 1;
    opts.willFlag = 1;
    opts.will.qos = 2;
    opts.will.retained = 1;
    opts.will.topicName.cstring = "wt";
    opts.will.message.cstring = "wm";
    opts.username.cstring = "usr";
    opts.password.cstring = "pw";
    rc = MQTTSerialize_connect(buf, sizeof(buf), &opts);
    assert_true(rc > 0);
    // Then: reserved bit 0 stays clear, clean session / will / will retain /
    // password / user name are set and will qos 2 occupies bits 3-4 as 0b10
    assert_int_equal(buf[9], 0xF6);
}
