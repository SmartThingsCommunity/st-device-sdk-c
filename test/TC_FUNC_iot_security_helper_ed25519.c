/* ***************************************************************************
 *
 * Copyright (c) 2020 Samsung Electronics All Rights Reserved.
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

#include <iot_error.h>
#include <iot_security_common.h>
#include <iot_security_util.h>
#include <string.h>

#include "TC_REGISTRY.h"
#include "cmocka_custom.h"

unsigned char sample_seckey_ed25519[] = {
    0xc9, 0x03, 0x2b, 0x14, 0xf9, 0x19, 0xd7, 0x02, 0x3a, 0xd8, 0xad, 0x5c, 0x12, 0xe8, 0x52, 0x2f,
    0x6d, 0xf0, 0x05, 0x1f, 0xe7, 0x2e, 0xbe, 0xec, 0xdd, 0x85, 0x19, 0x9f, 0xe5, 0xc0, 0xc1, 0xbf,
};

unsigned char sample_seckey_curve25519[] = {
    0xb8, 0x58, 0x17, 0x44, 0x8b, 0xbc, 0xeb, 0x00, 0x62, 0x8d, 0xac, 0x78, 0x80, 0xc5, 0xeb, 0x42,
    0xcd, 0xa3, 0x48, 0x53, 0x90, 0x2f, 0x3d, 0x60, 0x01, 0x93, 0x3e, 0x4f, 0xfb, 0xa7, 0xdf, 0x66,
};

extern iot_error_t _iot_security_ed25519_convert_seckey(unsigned char *ed25519_key, unsigned char *curve25519_key);

TEST_SUITE("iot_security_helper_ed25519.c");

TEST(TC_iot_security_ed25519_convert_seckey_null_parameters_neg)
{
    iot_error_t err;
    unsigned char *ed25519_key = sample_seckey_ed25519;
    unsigned char curve25519_key[IOT_SECURITY_ED25519_LEN];

    // When: all null
    err = _iot_security_ed25519_convert_seckey(NULL, NULL);
    // Then
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);

    // When: ed key null
    err = _iot_security_ed25519_convert_seckey(NULL, curve25519_key);
    // Then
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);

    // When: curve key null
    err = _iot_security_ed25519_convert_seckey(ed25519_key, NULL);
    // Then
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);
}

TEST(TC_iot_security_ed25519_convert_seckey_success_pos)
{
    iot_error_t err;
    unsigned char *ed25519_key;
    unsigned char curve25519_key[IOT_SECURITY_ED25519_LEN];

    // Given
    ed25519_key = sample_seckey_ed25519;
    // When
    err = _iot_security_ed25519_convert_seckey(ed25519_key, curve25519_key);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_memory_equal(curve25519_key, sample_seckey_curve25519, sizeof(sample_seckey_curve25519));
}

TEST(TC_iot_security_ed25519_convert_seckey_null_output_untouched_neg)
{
    iot_error_t err;
    unsigned char curve25519_key[IOT_SECURITY_ED25519_LEN];

    // Given: a canary in the output buffer
    memset(curve25519_key, 0xA5, sizeof(curve25519_key));
    // When: the ed25519 key is null
    err = _iot_security_ed25519_convert_seckey(NULL, curve25519_key);
    // Then: rejected without touching the output
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);
    for (size_t i = 0; i < sizeof(curve25519_key); i++) {
        assert_int_equal(curve25519_key[i], 0xA5);
    }
}

TEST(TC_iot_security_ed25519_convert_seckey_unclamped_bits_neg)
{
    iot_error_t err;
    unsigned char ed25519_key[IOT_SECURITY_ED25519_LEN];
    unsigned char curve25519_key[IOT_SECURITY_ED25519_LEN];

    // Given: a key made of all ones, which would give unclamped curve25519 bits
    memset(ed25519_key, 0xFF, sizeof(ed25519_key));
    // When
    err = _iot_security_ed25519_convert_seckey(ed25519_key, curve25519_key);
    // Then: the non canonical scalar bits must have been masked out
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_int_equal(curve25519_key[0] & 0x07, 0);
    assert_int_equal(curve25519_key[31] & 0x80, 0);
    assert_int_equal(curve25519_key[31] & 0x40, 0x40);
}

TEST(TC_iot_security_ed25519_convert_seckey_not_passthrough_neg)
{
    iot_error_t err;
    unsigned char curve25519_key[IOT_SECURITY_ED25519_LEN];

    // When
    err = _iot_security_ed25519_convert_seckey(sample_seckey_ed25519, curve25519_key);
    // Then: the converted key must not be a copy of the ed25519 key
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_memory_not_equal(curve25519_key, sample_seckey_ed25519, sizeof(curve25519_key));
}

TEST(TC_iot_security_ed25519_convert_seckey_distinct_keys_neg)
{
    iot_error_t err;
    unsigned char ed25519_key[IOT_SECURITY_ED25519_LEN];
    unsigned char curve_a[IOT_SECURITY_ED25519_LEN];
    unsigned char curve_b[IOT_SECURITY_ED25519_LEN];

    // Given: two keys differing in a single byte
    memcpy(ed25519_key, sample_seckey_ed25519, sizeof(ed25519_key));
    err = _iot_security_ed25519_convert_seckey(ed25519_key, curve_a);
    assert_int_equal(err, IOT_ERROR_NONE);
    ed25519_key[0] ^= 0x01;
    // When
    err = _iot_security_ed25519_convert_seckey(ed25519_key, curve_b);
    // Then: they must not collide onto the same curve25519 key
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_memory_not_equal(curve_a, curve_b, sizeof(curve_a));
}

TEST(TC_iot_security_ed25519_convert_seckey_zero_key_neg)
{
    iot_error_t err;
    unsigned char ed25519_key[IOT_SECURITY_ED25519_LEN] = {0};
    unsigned char curve25519_key[IOT_SECURITY_ED25519_LEN] = {0};
    unsigned char zero[IOT_SECURITY_ED25519_LEN] = {0};

    // Given: an all zero ed25519 key
    // When
    err = _iot_security_ed25519_convert_seckey(ed25519_key, curve25519_key);
    // Then: the hash based derivation must not leak the all zero key through
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_memory_not_equal(curve25519_key, zero, sizeof(zero));
}
