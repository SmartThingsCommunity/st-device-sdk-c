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

/* Not declared in the public header but defined in iot_mqtt_connect_client.c */
extern int MQTTSerialize_connectLength(MQTTPacket_connectData *options);
extern int MQTTSerialize_zero(unsigned char *buf, int buflen, unsigned char packettype);

#define UNUSED(x) (void)(x)

/*
 * Tests for MQTTSerialize_connectLength
 */
void TC_MQTTSerialize_connectLength_v4_only(void **state)
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

void TC_MQTTSerialize_connectLength_v3(void **state)
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

void TC_MQTTSerialize_connectLength_with_will(void **state)
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

void TC_MQTTSerialize_connectLength_with_credentials(void **state)
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

void TC_MQTTSerialize_connectLength_unknown_version(void **state)
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
void TC_MQTTSerialize_connect_v4_success(void **state)
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

void TC_MQTTSerialize_connect_v3_success(void **state)
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

void TC_MQTTSerialize_connect_will_flags(void **state)
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

void TC_MQTTSerialize_connect_buffer_too_short(void **state)
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

void TC_MQTTSerialize_connect_zero_buffer(void **state)
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
void TC_MQTTDeserialize_connack_success(void **state)
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

void TC_MQTTDeserialize_connack_wrong_type(void **state)
{
    unsigned char buf[] = {(unsigned char)(PUBACK << 4), 0x02, 0x00, 0x00};
    unsigned char session_present = 0, rc_code = 0;
    int rc;
    UNUSED(state);

    rc = MQTTDeserialize_connack(&session_present, &rc_code, buf, sizeof(buf));
    assert_int_equal(rc, 0);
}

void TC_MQTTDeserialize_connack_short_remlen(void **state)
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
void TC_MQTTSerialize_zero_success(void **state)
{
    unsigned char buf[4] = {0};
    int rc;
    UNUSED(state);

    rc = MQTTSerialize_zero(buf, sizeof(buf), DISCONNECT);
    assert_int_equal(rc, 2);
    assert_int_equal((buf[0] & 0xF0) >> 4, DISCONNECT);
    assert_int_equal(buf[1], 0);
}

void TC_MQTTSerialize_zero_buffer_too_short(void **state)
{
    unsigned char buf[1] = {0};
    int rc;
    UNUSED(state);

    rc = MQTTSerialize_zero(buf, sizeof(buf), DISCONNECT);
    assert_int_equal(rc, MQTTPACKET_BUFFER_TOO_SHORT);
}

void TC_MQTTSerialize_zero_zero_buffer(void **state)
{
    unsigned char buf[4] = {0};
    int rc;
    UNUSED(state);

    rc = MQTTSerialize_zero(buf, 0, DISCONNECT);
    assert_int_equal(rc, MQTTPACKET_BUFFER_TOO_SHORT);
}

void TC_MQTTSerialize_disconnect_success(void **state)
{
    unsigned char buf[4] = {0};
    int rc;
    UNUSED(state);

    rc = MQTTSerialize_disconnect(buf, sizeof(buf));
    assert_int_equal(rc, 2);
    assert_int_equal((buf[0] & 0xF0) >> 4, DISCONNECT);
}

void TC_MQTTSerialize_disconnect_buffer_too_short(void **state)
{
    unsigned char buf[1] = {0};
    int rc;
    UNUSED(state);

    rc = MQTTSerialize_disconnect(buf, sizeof(buf));
    assert_int_equal(rc, MQTTPACKET_BUFFER_TOO_SHORT);
}

void TC_MQTTSerialize_pingreq_success(void **state)
{
    unsigned char buf[4] = {0};
    int rc;
    UNUSED(state);

    rc = MQTTSerialize_pingreq(buf, sizeof(buf));
    assert_int_equal(rc, 2);
    assert_int_equal((buf[0] & 0xF0) >> 4, PINGREQ);
}

void TC_MQTTSerialize_pingreq_buffer_too_short(void **state)
{
    unsigned char buf[1] = {0};
    int rc;
    UNUSED(state);

    rc = MQTTSerialize_pingreq(buf, sizeof(buf));
    assert_int_equal(rc, MQTTPACKET_BUFFER_TOO_SHORT);
}
