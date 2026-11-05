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
#include <iot_nv_data.h>
#include <iot_security_util.h>
#include <string.h>

#include "TC_MOCK_functions.h"
#include "TC_REGISTRY.h"
#include "cmocka_custom.h"

TEST_SUITE("iot_security_helper.c");

static const size_t b64_encode_len_input[] = {2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16,
                                              17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};

static const size_t b64_encode_len_required[] = {4,  4,  8,  8,  8,  12, 12, 12, 16, 16, 16, 20, 20, 20, 24,
                                                 24, 24, 28, 28, 28, 32, 32, 32, 36, 36, 36, 40, 40, 40, 44};

static const size_t b64_decode_len_input[] = {2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16,
                                              17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};

static const size_t b64_decode_len_required[] = {3,  3,  3,  6,  6,  6,  6,  9,  9,  9,  9,  12, 12, 12, 12,
                                                 15, 15, 15, 15, 18, 18, 18, 18, 21, 21, 21, 21, 24, 24, 24};

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_iot_security_base64_buffer_size_neg)
{
    const size_t *input;
    const size_t *expected;
    size_t required_len;
    int test_len;
    int i;

    // Given
    test_len = sizeof(b64_encode_len_input) / sizeof(b64_encode_len_input[0]);
    input = b64_encode_len_input;
    expected = b64_encode_len_required;
    for (i = 0; i < test_len; i++) {
        // When
        required_len = IOT_SECURITY_B64_ENCODE_LEN(input[i]);
        // Then
        assert_int_equal(required_len, expected[i] + 1);
    }

    // Given
    test_len = sizeof(b64_decode_len_input) / sizeof(b64_decode_len_input[0]);
    input = b64_decode_len_input;
    expected = b64_decode_len_required;
    for (i = 0; i < test_len; i++) {
        // When
        required_len = IOT_SECURITY_B64_DECODE_LEN(input[i]);
        // Then
        assert_int_equal(required_len, expected[i] + 1);
    }
}

static const unsigned char *sample = "ab~c123!?$*&()'-=@~abc";
static const unsigned char *sample_b64 = "YWJ+YzEyMyE/JComKCknLT1AfmFiYw==";
static const unsigned char *sample_b64url = "YWJ-YzEyMyE_JComKCknLT1AfmFiYw==";

typedef iot_error_t (*iot_security_base64_func)(const unsigned char *, size_t, unsigned char *, size_t, size_t *);

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_iot_security_base64_invalid_parameter_neg)
{
    iot_error_t err;
    unsigned char *src;
    unsigned char dst[256];
    size_t src_len;
    size_t dst_len;
    size_t out_len;
    int i;
    iot_security_base64_func base64_func_target;
    iot_security_base64_func base64_funcs[] = {
        iot_security_base64_encode,
        iot_security_base64_decode,
        iot_security_base64_encode_urlsafe,
        iot_security_base64_decode_urlsafe,
    };

    for (i = 0; i < (sizeof(base64_funcs) / sizeof(base64_funcs[0])); i++) {
        base64_func_target = base64_funcs[i];
        assert_non_null(base64_func_target);

        // Given
        src = (unsigned char *)sample;
        src_len = strlen(src);
        dst_len = IOT_SECURITY_B64_ENCODE_LEN(src_len);
        // When: src is null
        err = base64_func_target(NULL, src_len, dst, dst_len, &out_len);
        // Then
        assert_int_not_equal(err, IOT_ERROR_NONE);

        // When: dst is null
        err = base64_func_target(src, src_len, NULL, dst_len, &out_len);
        // Then
        assert_int_not_equal(err, IOT_ERROR_NONE);

        // When: out_len is null
        err = base64_func_target(src, src_len, dst, dst_len, NULL);
        // Then
        assert_int_not_equal(err, IOT_ERROR_NONE);
    }

    // Given
    src = (unsigned char *)sample;
    src_len = strlen(src);
    // When: small output buffer
    dst_len = IOT_SECURITY_B64_ENCODE_LEN(src_len) - 1;
    err = iot_security_base64_encode(src, src_len, dst, dst_len, &out_len);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_BASE64_ENCODE);

    // Given
    src = (unsigned char *)sample_b64;
    src_len = strlen(src);
    // When: small output buffer
    dst_len = 8;
    err = iot_security_base64_decode(src, src_len, dst, dst_len, &out_len);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_BASE64_DECODE);

    // Given
    src = (unsigned char *)sample;
    src_len = strlen(src);
    // When: small output buffer
    dst_len = IOT_SECURITY_B64_ENCODE_LEN(src_len) - 1;
    err = iot_security_base64_encode_urlsafe(src, src_len, dst, dst_len, &out_len);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_BASE64_URL_ENCODE);

    // Given: small output buffer
    src = (unsigned char *)sample_b64url;
    src_len = strlen(src);
    // When
    dst_len = 8;
    err = iot_security_base64_decode_urlsafe(src, src_len, dst, dst_len, &out_len);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_BASE64_URL_DECODE);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_iot_security_base64_encode_success_pos)
{
    iot_error_t err;
    unsigned char *src;
    unsigned char *dst;
    unsigned char *expected;
    size_t src_len;
    size_t dst_len;
    size_t out_len;

    // Given
    src = (unsigned char *)sample;
    src_len = strlen(src);
    expected = (unsigned char *)sample_b64;
    dst_len = IOT_SECURITY_B64_ENCODE_LEN(src_len);
    dst = (unsigned char *)iot_os_malloc(dst_len);
    assert_non_null(dst);
    // When
    err = iot_security_base64_encode(src, src_len, dst, dst_len, &out_len);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_memory_equal(dst, expected, out_len);

    // Local teardown
    free(dst);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_iot_security_base64_decode_failure_neg)
{
    iot_error_t err;
    unsigned char *src;
    unsigned char dst[256];
    unsigned char tmp[256] = {0x90, 0x13, 0x14, '='};
    size_t src_len;
    size_t dst_len;
    size_t out_len;

    // Given: invalid data
    src = (unsigned char *)tmp;
    src_len = 4;
    dst_len = IOT_SECURITY_B64_ENCODE_LEN(src_len);
    // When
    err = iot_security_base64_decode(src, src_len, dst, dst_len, &out_len);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_iot_security_base64_decode_success_pos)
{
    iot_error_t err;
    unsigned char *src;
    unsigned char *dst;
    unsigned char *expected;
    size_t src_len;
    size_t dst_len;
    size_t out_len;

    // Given
    src = (unsigned char *)sample_b64;
    src_len = strlen(src);
    expected = (unsigned char *)sample;
    dst_len = src_len;
    dst = (unsigned char *)iot_os_malloc(dst_len);
    assert_non_null(dst);
    // When
    err = iot_security_base64_decode(src, src_len, dst, dst_len, &out_len);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_memory_equal(dst, expected, out_len);

    // Local teardown
    free(dst);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_iot_security_base64_encode_urlsafe_success_pos)
{
    iot_error_t err;
    unsigned char *src;
    unsigned char *dst;
    unsigned char *expected;
    size_t src_len;
    size_t dst_len;
    size_t out_len;

    // Given
    src = (unsigned char *)sample;
    src_len = strlen(src);
    expected = (unsigned char *)sample_b64url;
    dst_len = IOT_SECURITY_B64_ENCODE_LEN(src_len);
    dst = (unsigned char *)iot_os_malloc(dst_len);
    assert_non_null(dst);
    // When
    err = iot_security_base64_encode_urlsafe(src, src_len, dst, dst_len, &out_len);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_memory_equal(dst, expected, out_len);

    // Local teardown
    free(dst);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_iot_security_base64_decode_urlsafe_alloc_failure_neg)
{
    iot_error_t err;
    unsigned char *src;
    unsigned char *dst;
    size_t src_len;
    size_t dst_len;
    size_t out_len;

    do_not_use_mock_iot_os_malloc_failure();

    // Setup
    src = (unsigned char *)sample_b64url;
    src_len = strlen(src);
    dst_len = src_len;
    dst = (unsigned char *)iot_os_malloc(dst_len);
    assert_non_null(dst);

    // Given: malloc failed
    set_mock_iot_os_malloc_failure_with_index(0);
    // When
    err = iot_security_base64_decode_urlsafe(src, src_len, dst, dst_len, &out_len);
    // Then
    assert_int_equal(err, IOT_ERROR_MEM_ALLOC);

    // Local teardown
    free(dst);

    do_not_use_mock_iot_os_malloc_failure();
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_iot_security_base64_decode_urlsafe_failure_neg)
{
    iot_error_t err;
    unsigned char *src;
    unsigned char dst[256];
    unsigned char tmp[256] = {0x90, 0x13, 0x14, '='};
    size_t src_len;
    size_t dst_len;
    size_t out_len;

    // Given: invalid data
    src = (unsigned char *)tmp;
    src_len = 4;
    dst_len = IOT_SECURITY_B64_ENCODE_LEN(src_len);
    // When
    err = iot_security_base64_decode_urlsafe(src, src_len, dst, dst_len, &out_len);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_iot_security_base64_decode_urlsafe_success_pos)
{
    iot_error_t err;
    unsigned char *src;
    unsigned char *dst;
    unsigned char *expected;
    size_t src_len;
    size_t dst_len;
    size_t out_len;

    // Given
    src = (unsigned char *)sample_b64url;
    src_len = strlen(src);
    expected = (unsigned char *)sample;
    dst_len = src_len;
    dst = (unsigned char *)iot_os_malloc(dst_len);
    assert_non_null(dst);
    // When
    err = iot_security_base64_decode_urlsafe(src, src_len, dst, dst_len, &out_len);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_memory_equal(dst, expected, out_len);

    // Local teardown
    free(dst);
}

const static unsigned char sample_input[] = {
    0xd0, 0xdf, 0x40, 0xee, 0x8c, 0x54, 0x25, 0xba, 0x46, 0x74, 0xf3, 0x4a, 0x33, 0x95, 0xde, 0xc6,
    0xec, 0xe9, 0xe1, 0xd6, 0x60, 0x50, 0x1e, 0xd5, 0x16, 0xbe, 0xaf, 0xce, 0x1c, 0x24, 0x49, 0x4c,
    0x6c, 0x61, 0xcc, 0x93, 0x50, 0xbf, 0x87, 0xe1, 0x3c, 0x0d, 0xc8, 0x60, 0xbd, 0xfd, 0xfc, 0x58,
    0xab, 0xc7, 0x9f, 0xe7, 0x0f, 0x35, 0x3a, 0x33, 0xd3, 0x11, 0xc4, 0x36, 0x1b, 0x32, 0x53, 0xe8,
};

const static unsigned char sample_hash[] = {
    0x17, 0x39, 0x33, 0x94, 0xcc, 0x66, 0x1f, 0x55, 0xdf, 0x8f, 0xc6, 0x0a, 0x63, 0x54, 0x3c, 0xf2,
    0x21, 0x27, 0x83, 0x89, 0xfb, 0x8d, 0x05, 0x75, 0xe2, 0x17, 0xce, 0xfc, 0x62, 0x3b, 0x35, 0xd9,
};

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_iot_security_sha256_failure_neg)
{
    iot_error_t err;
    const unsigned char *input;
    size_t input_len;
    unsigned char hash[IOT_SECURITY_SHA256_LEN] = {0};
    size_t hash_len = sizeof(hash);

    input = sample_input;
    input_len = sizeof(sample_input);

    // When: all null
    err = iot_security_sha256(NULL, 0, NULL, 0);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // When: input null
    err = iot_security_sha256(NULL, input_len, hash, hash_len);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // When: input size zero
    err = iot_security_sha256(input, 0, hash, hash_len);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // When: output null
    err = iot_security_sha256(input, input_len, NULL, hash_len);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // When: output size zero
    err = iot_security_sha256(input, input_len, hash, 0);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // When: insufficient output size
    err = iot_security_sha256(input, input_len, hash, IOT_SECURITY_SHA256_LEN - 1);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_iot_security_sha256_success_pos)
{
    iot_error_t err;
    const unsigned char *input;
    size_t input_len;
    unsigned char hash[IOT_SECURITY_SHA256_LEN] = {0};
    size_t hash_len = sizeof(hash);

    input = sample_input;
    input_len = sizeof(sample_input);

    err = iot_security_sha256(input, input_len, hash, hash_len);
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_memory_equal(hash, sample_hash, sizeof(sample_hash));
}

/* _base64_encode is not exposed through the public header but is not static. */
extern int _base64_encode(unsigned char *dst, size_t dlen, size_t *olen, const unsigned char *src, size_t slen);

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_iot_security_base64_decode_trailing_spaces_neg)
{
    iot_error_t err;
    unsigned char dst[16] = {0};
    size_t out_len = 0;

    // Given: base64 text padded with trailing spaces
    const unsigned char *src = (const unsigned char *)"YWJj   ";
    // When
    err = iot_security_base64_decode(src, strlen((const char *)src), dst, sizeof(dst), &out_len);
    // Then: trailing spaces must not corrupt the decoded output
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_int_equal(out_len, 3);
    assert_memory_equal(dst, "abc", 3);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_iot_security_base64_decode_embedded_crlf_neg)
{
    iot_error_t err;
    unsigned char dst[16] = {0};
    size_t out_len = 0;

    // Given: base64 text broken over two CRLF separated lines
    const unsigned char *src = (const unsigned char *)"YWJj\r\nYWJj";
    // When
    err = iot_security_base64_decode(src, strlen((const char *)src), dst, sizeof(dst), &out_len);
    // Then: the line break must not appear in the decoded output
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_int_equal(out_len, 6);
    assert_memory_equal(dst, "abcabc", 6);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_iot_security_base64_decode_embedded_lf_neg)
{
    iot_error_t err;
    unsigned char dst[16] = {0};
    size_t out_len = 0;

    // Given: base64 text broken over two LF separated lines
    const unsigned char *src = (const unsigned char *)"YWJj\nYWJj";
    // When
    err = iot_security_base64_decode(src, strlen((const char *)src), dst, sizeof(dst), &out_len);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_int_equal(out_len, 6);
    assert_memory_equal(dst, "abcabc", 6);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_iot_security_base64_decode_space_inside_line_neg)
{
    iot_error_t err;
    unsigned char dst[16] = {0};
    size_t out_len = 0;

    // Given: a space in the middle of a line
    const unsigned char *src = (const unsigned char *)"YWJ j";
    // When
    err = iot_security_base64_decode(src, strlen((const char *)src), dst, sizeof(dst), &out_len);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_BASE64_DECODE);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_iot_security_base64_decode_too_many_padding_neg)
{
    iot_error_t err;
    unsigned char dst[16] = {0};
    size_t out_len = 0;

    // Given: more than two padding characters
    const unsigned char *src = (const unsigned char *)"YWJj====";
    // When
    err = iot_security_base64_decode(src, strlen((const char *)src), dst, sizeof(dst), &out_len);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_BASE64_DECODE);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_iot_security_base64_decode_data_after_padding_neg)
{
    iot_error_t err;
    unsigned char dst[16] = {0};
    size_t out_len = 0;

    // Given: a base64 character following the padding
    const unsigned char *src = (const unsigned char *)"YW=j";
    // When
    err = iot_security_base64_decode(src, strlen((const char *)src), dst, sizeof(dst), &out_len);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_BASE64_DECODE);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_iot_security_base64_decode_only_newlines_neg)
{
    iot_error_t err;
    unsigned char dst[16];
    size_t out_len = 0xdead;

    // Given: input that carries no base64 payload at all
    const unsigned char *src = (const unsigned char *)"\n\n\n\n";
    memset(dst, 0xA5, sizeof(dst));
    // When
    err = iot_security_base64_decode(src, strlen((const char *)src), dst, sizeof(dst), &out_len);
    // Then: nothing is decoded and the output length is reported as zero
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_int_equal(out_len, 0);
    assert_int_equal(dst[0], 0xA5);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_iot_security_base64_decode_non_base64_char_neg)
{
    iot_error_t err;
    unsigned char dst[16] = {0};
    size_t out_len = 0;

    // Given: a character that is not in the base64 alphabet
    const unsigned char *src = (const unsigned char *)"YWJ#";
    // When
    err = iot_security_base64_decode(src, strlen((const char *)src), dst, sizeof(dst), &out_len);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_BASE64_DECODE);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_iot_security_base64_decode_high_bit_char_neg)
{
    iot_error_t err;
    unsigned char src[] = {'Y', 'W', 'J', 0xFF};
    unsigned char dst[16] = {0};
    size_t out_len = 0;

    // Given: a byte outside the ascii range
    // When
    err = iot_security_base64_decode(src, sizeof(src), dst, sizeof(dst), &out_len);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_BASE64_DECODE);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_iot_security_base64_decode_urlsafe_rejects_standard_alphabet_neg)
{
    iot_error_t err;
    unsigned char dst[64] = {0};
    size_t out_len = 0;

    // Given: url safe text handed to the standard decoder
    // When
    err = iot_security_base64_decode(sample_b64url, strlen((const char *)sample_b64url), dst, sizeof(dst), &out_len);
    // Then: '-' and '_' are not part of the standard alphabet
    assert_int_equal(err, IOT_ERROR_SECURITY_BASE64_DECODE);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_iot_security_base64_encode_zero_source_len_neg)
{
    unsigned char dst[16];
    size_t out_len = 0xdead;
    int ret;

    memset(dst, 0xA5, sizeof(dst));
    // When: the low level encoder is asked to encode nothing
    ret = _base64_encode(dst, sizeof(dst), &out_len, (const unsigned char *)"abc", 0);
    // Then: it reports an empty result without touching the destination
    assert_int_equal(ret, 0);
    assert_int_equal(out_len, 0);
    assert_int_equal(dst[0], 0xA5);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_iot_security_base64_encode_source_len_overflow_neg)
{
    unsigned char dst[16];
    size_t out_len = 0;
    int ret;

    memset(dst, 0xA5, sizeof(dst));
    // When: the encoded length would overflow size_t
    ret = _base64_encode(dst, sizeof(dst), &out_len, (const unsigned char *)"abc", (size_t)-1);
    // Then: rejected without touching the destination
    assert_int_equal(ret, -1);
    assert_int_equal(out_len, (size_t)-1);
    assert_int_equal(dst[0], 0xA5);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_iot_security_base64_encode_null_destination_neg)
{
    size_t out_len = 0;
    int ret;

    // When: no destination is provided
    ret = _base64_encode(NULL, 1024, &out_len, (const unsigned char *)"abc", 3);
    // Then: the required length is reported back with a failure
    assert_int_equal(ret, -1);
    assert_int_equal(out_len, 5);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_iot_security_base64_encode_urlsafe_has_no_standard_chars_neg)
{
    iot_error_t err;
    unsigned char dst[64] = {0};
    size_t out_len = 0;
    size_t i;

    // When
    err = iot_security_base64_encode_urlsafe(sample, strlen((const char *)sample), dst, sizeof(dst), &out_len);
    // Then: no standard-only alphabet character may leak into url safe output
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_true(out_len > 0);
    for (i = 0; i < out_len; i++) {
        assert_true(dst[i] != '+');
        assert_true(dst[i] != '/');
    }
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_iot_security_sha512_null_input_neg)
{
    unsigned char hash[IOT_SECURITY_SHA512_LEN] = {0};

    // When
    iot_error_t err = iot_security_sha512(NULL, sizeof(sample_input), hash, sizeof(hash));
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_INVALID_ARGS);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_iot_security_sha512_zero_input_len_neg)
{
    unsigned char hash[IOT_SECURITY_SHA512_LEN] = {0};

    // When
    iot_error_t err = iot_security_sha512(sample_input, 0, hash, sizeof(hash));
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_INVALID_ARGS);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_iot_security_sha512_null_output_neg)
{
    // When
    iot_error_t err = iot_security_sha512(sample_input, sizeof(sample_input), NULL, IOT_SECURITY_SHA512_LEN);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_INVALID_ARGS);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_iot_security_sha512_short_output_neg)
{
    unsigned char hash[IOT_SECURITY_SHA512_LEN] = {0};

    // When: the output buffer cannot hold a full sha512 digest
    iot_error_t err = iot_security_sha512(sample_input, sizeof(sample_input), hash, IOT_SECURITY_SHA512_LEN - 1);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_INVALID_ARGS);
    // and the buffer must be left untouched
    for (size_t i = 0; i < sizeof(hash); i++) {
        assert_int_equal(hash[i], 0);
    }
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_iot_security_sha256_single_bit_change_neg)
{
    iot_error_t err;
    unsigned char input[sizeof(sample_input)];
    unsigned char hash[IOT_SECURITY_SHA256_LEN] = {0};

    // Given: the sample input with a single bit flipped
    memcpy(input, sample_input, sizeof(input));
    input[0] ^= 0x01;
    // When
    err = iot_security_sha256(input, sizeof(input), hash, sizeof(hash));
    // Then: the digest must not match the digest of the original input
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_memory_not_equal(hash, sample_hash, sizeof(sample_hash));
}
