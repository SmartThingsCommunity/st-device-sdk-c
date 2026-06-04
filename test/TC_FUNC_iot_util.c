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
#include <iot_util.h>
#include <iot_uuid.h>
#include <string.h>

#include "cmocka_custom.h"

#define UNUSED(x) (void **)(x)

void TC_iot_util_dump_mem(void **state)
{
    uint8_t test_buffer[] = {0x01, 0x02, 0x03, 0x04, 0x05};
    FILE *original_stdout;
    UNUSED(state);

    // Redirect stdout to suppress output
    original_stdout = stdout;
    stdout = fopen("/dev/null", "w");

    // Test with "raw" tag
    iot_util_dump_mem("raw", test_buffer, sizeof(test_buffer));

    // Test with "dump" tag
    iot_util_dump_mem("dump", test_buffer, sizeof(test_buffer));

    // Test with custom tag
    iot_util_dump_mem("custom", test_buffer, sizeof(test_buffer));

    // Test with empty buffer
    iot_util_dump_mem("raw", NULL, 0);

    // Restore stdout
    fclose(stdout);
    stdout = original_stdout;
}

void TC_iot_util_validate_uuid_format_null_str(void **state)
{
    iot_error_t err;
    UNUSED(state);

    // When: NULL string
    err = validate_uuid_format(NULL, 36);

    // Then: should return error
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);
}

void TC_iot_util_validate_uuid_format_invalid_clock_seq(void **state)
{
    iot_error_t err;
    const char *invalid_clock_seq_uuid = "c236f527-5d8d-4d0b-86f6-0add22717f0z";  // Invalid char in clock seq
    UNUSED(state);

    // When: invalid clock sequence
    err = validate_uuid_format(invalid_clock_seq_uuid, strlen(invalid_clock_seq_uuid));

    // Then: should return error
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);
}

void TC_iot_util_convert_str_uuid_success(void **state)
{
    iot_error_t err;
    const char *uuid_random_type_lower = "c236f527-5d8d-4d0b-86f6-0add22717f0e";
    const char *uuid_random_type_upper = "C236F527-5d8D-4D0B-86F6-0ADD22717F0E";
    const char *uuid_timebased = "292aa580-7872-11ea-90f5-e81132336bba";
    struct iot_uuid random_type_uuid = {
        .id[0] = 0xc2,
        .id[1] = 0x36,
        .id[2] = 0xf5,
        .id[3] = 0x27,
        .id[4] = 0x5d,
        .id[5] = 0x8d,
        .id[6] = 0x4d,
        .id[7] = 0x0b,
        .id[8] = 0x86,
        .id[9] = 0xf6,
        .id[10] = 0x0a,
        .id[11] = 0xdd,
        .id[12] = 0x22,
        .id[13] = 0x71,
        .id[14] = 0x7f,
        .id[15] = 0x0e,
    };
    struct iot_uuid timebased_uuid = {
        .id[0] = 0x29,
        .id[1] = 0x2a,
        .id[2] = 0xa5,
        .id[3] = 0x80,
        .id[4] = 0x78,
        .id[5] = 0x72,
        .id[6] = 0x11,
        .id[7] = 0xea,
        .id[8] = 0x90,
        .id[9] = 0xf5,
        .id[10] = 0xe8,
        .id[11] = 0x11,
        .id[12] = 0x32,
        .id[13] = 0x33,
        .id[14] = 0x6b,
        .id[15] = 0xba,
    };
    struct iot_uuid uuid;
    UNUSED(state);

    // Given: random type lower case uuid string
    memset(&uuid, '\0', sizeof(struct iot_uuid));
    // When
    err = iot_util_convert_str_uuid(uuid_random_type_lower, &uuid);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_memory_equal(&uuid, &random_type_uuid, sizeof(struct iot_uuid));

    // Given: random type upper case uuid string
    memset(&uuid, '\0', sizeof(struct iot_uuid));
    // When
    err = iot_util_convert_str_uuid(uuid_random_type_upper, &uuid);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_memory_equal(&uuid, &random_type_uuid, sizeof(struct iot_uuid));

    // Given: time based uuid string
    memset(&uuid, '\0', sizeof(struct iot_uuid));
    // When
    err = iot_util_convert_str_uuid(uuid_timebased, &uuid);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_memory_equal(&uuid, &timebased_uuid, sizeof(struct iot_uuid));
}

void TC_iot_util_convert_str_uuid_null_parameters(void **state)
{
    iot_error_t err;
    const char *valid_uuid_str = "c236f527-5d8d-4d0b-86f6-0add22717f0e";
    struct iot_uuid uuid;
    UNUSED(state);

    // When: all parameters null
    err = iot_util_convert_str_uuid(NULL, NULL);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // When: str is null
    err = iot_util_convert_str_uuid(NULL, &uuid);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // When: uuid is null
    err = iot_util_convert_str_uuid(valid_uuid_str, NULL);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_util_convert_str_uuid_invalid_length(void **state)
{
    iot_error_t err;
    struct iot_uuid uuid;
    char invalid_uuid[2][40] = {
        "c236f527-5d8d-4d0b-86f6-0add2271",       // short length
        "c236f527-5d8d-4d0b-86f6-0add22717f0e8",  // long length
    };
    UNUSED(state);

    for (int i = 0; i < 2; i++) {
        // When: invalid uuid length
        err = iot_util_convert_str_uuid(invalid_uuid[i], &uuid);
        // Then
        assert_int_not_equal(err, IOT_ERROR_NONE);
    }
}

void TC_iot_util_convert_str_uuid_invalid_delimiters(void **state)
{
    iot_error_t err;
    struct iot_uuid uuid;
    char invalid_uuid[4][40] = {
        "c236f527_5d8d-4d0b-86f6-0add22717f0e",  // invalid 1st delimiter '_'
        "c236f527-5d8d_4d0b-86f6-0add22717f0e",  // invalid 2nd delimiter '_'
        "c236f527-5d8d-4d0b_86f6-0add22717f0e",  // invalid 3rd delimiter '_'
        "c236f527-5d8d-4d0b-86f6_0add22717f0e",  // invalid 4th delimiter '_'
    };
    UNUSED(state);

    for (int i = 0; i < 4; i++) {
        // When: invalid uuid delimiters
        err = iot_util_convert_str_uuid(invalid_uuid[i], &uuid);
        // Then
        assert_int_not_equal(err, IOT_ERROR_NONE);
    }
}

void TC_iot_util_convert_str_uuid_invalid_characters(void **state)
{
    iot_error_t err;
    struct iot_uuid uuid;
    char invalid_uuid[3][40] = {
        "c236f527-5d8d-4d0b-86f6-0add22717f e",   // space at middle
        "c236f527-5d8d-4d0b-86f6-0add22717f0z",   // invalid character 'z'
        "c236f527-5d8d-4d0b-86f6-0add22717f0e ",  // space at last
    };
    UNUSED(state);

    for (int i = 0; i < 3; i++) {
        // When: invalid uuid characters
        err = iot_util_convert_str_uuid(invalid_uuid[i], &uuid);
        // Then
        assert_int_not_equal(err, IOT_ERROR_NONE);
    }
}

void TC_iot_util_convert_str_uuid_invalid_format(void **state)
{
    iot_error_t err;
    struct iot_uuid uuid;
    char invalid_uuid[4][40] = {
        " c236f527-5d8d-4d0b-86f6-0add22717f0e",  // space at first
        "c236f52-75d8d-4d0b-86f6-0add22717f0e",   // 7-5-4-4-12 format
        "c236f527-5d8-d4d0b-86f6-0add22717f0e",   // 8-3-5-4-12 format
        "c236f527-5d8d-4d0-b86f6-0add22717f0e",   // 8-4-3-5-12 format
    };
    UNUSED(state);

    for (int i = 0; i < 4; i++) {
        // When: invalid uuid format
        err = iot_util_convert_str_uuid(invalid_uuid[i], &uuid);
        // Then
        assert_int_not_equal(err, IOT_ERROR_NONE);
    }
}

void TC_iot_util_convert_str_uuid_invalid_version(void **state)
{
    iot_error_t err;
    struct iot_uuid uuid;
    char invalid_uuid[2][40] = {
        "292aa580-7872-01ea-90f5-e81132336bba",  // invalid version 0
        "292aa580-7872-61ea-90f5-e81132336bba",  // invalid version 6
    };
    UNUSED(state);

    for (int i = 0; i < 2; i++) {
        // When: invalid uuid version
        err = iot_util_convert_str_uuid(invalid_uuid[i], &uuid);
        // Then
        assert_int_not_equal(err, IOT_ERROR_NONE);
    }
}

void TC_iot_util_convert_uuid_str_null_uuid(void **state)
{
    iot_error_t err;
    struct iot_uuid uuid = {
        {0xc2, 0x36, 0xf5, 0x27, 0x5d, 0x8d, 0x4d, 0x0b, 0x86, 0xf6, 0x0a, 0xdd, 0x22, 0x71, 0x7f, 0x0e}};
    char buffer[64];
    UNUSED(state);

    // When: NULL uuid
    err = iot_util_convert_uuid_str(NULL, buffer, sizeof(buffer));
    // Then: should return error
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);
}

void TC_iot_util_convert_uuid_str_null_buffer(void **state)
{
    iot_error_t err;
    struct iot_uuid uuid = {
        {0xc2, 0x36, 0xf5, 0x27, 0x5d, 0x8d, 0x4d, 0x0b, 0x86, 0xf6, 0x0a, 0xdd, 0x22, 0x71, 0x7f, 0x0e}};
    char buffer[64];
    UNUSED(state);

    // When: NULL buffer
    err = iot_util_convert_uuid_str(&uuid, NULL, sizeof(buffer));
    // Then: should return error
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);
}

void TC_iot_util_convert_uuid_str_insufficient_buffer(void **state)
{
    iot_error_t err;
    struct iot_uuid uuid = {
        {0xc2, 0x36, 0xf5, 0x27, 0x5d, 0x8d, 0x4d, 0x0b, 0x86, 0xf6, 0x0a, 0xdd, 0x22, 0x71, 0x7f, 0x0e}};
    char short_buffer[10];
    UNUSED(state);

    // When: buffer too small
    err = iot_util_convert_uuid_str(&uuid, short_buffer, sizeof(short_buffer));
    // Then: should return error
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);
}

void TC_iot_util_convert_str_mac_success(void **state)
{
    iot_error_t err;
    char mac_addr_str[] = "a2:b3:fe:c9:8e:7d";
    struct iot_mac mac;
    struct iot_mac mac_empty;
    UNUSED(state);

    // Given
    memset(&mac, '\0', sizeof(struct iot_mac));
    memset(&mac_empty, '\0', sizeof(struct iot_mac));
    assert_memory_equal(&mac, &mac_empty, sizeof(struct iot_mac));
    // When
    err = iot_util_convert_str_mac(mac_addr_str, &mac);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_memory_not_equal(&mac, &mac_empty, sizeof(struct iot_mac));
}

void TC_iot_util_convert_str_mac_null_parameters(void **state)
{
    iot_error_t err;
    struct iot_mac mac;
    UNUSED(state);

    // When: null parameters
    err = iot_util_convert_str_mac(NULL, NULL);
    // Then: should return error
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);

    // When: null string
    err = iot_util_convert_str_mac(NULL, &mac);
    // Then: should return error
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);

    // When: null mac
    err = iot_util_convert_str_mac("a2:b3:fe:c9:8e:7d", NULL);
    // Then: should return error
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);
}

void TC_iot_util_convert_str_mac_invalid_length(void **state)
{
    iot_error_t err;
    struct iot_mac mac;
    char invalid_mac[2][20] = {
        "a2:b3:fe:c9:8e:d",    // short length
        "a2:b3:fe:c9:8e:7d1",  // long length
    };
    UNUSED(state);

    for (int i = 0; i < 2; i++) {
        // When: invalid mac length
        err = iot_util_convert_str_mac(invalid_mac[i], &mac);
        // Then
        assert_int_not_equal(err, IOT_ERROR_NONE);
    }
}

void TC_iot_util_convert_str_mac_invalid_format(void **state)
{
    iot_error_t err;
    struct iot_mac mac;
    char invalid_mac[4][20] = {
        " a2:b3:fe:c9:8e:7d",  // start with space
        "a2:b3:fe:c9:8e:7d ",  // end with space
        "a2:b3:fe c9:8e:7d ",  // space in the middle
        "a2:b3:fe:c9:8e;7d",   // invalid delimiter ';'
    };
    UNUSED(state);

    for (int i = 0; i < 4; i++) {
        // When: invalid mac format
        err = iot_util_convert_str_mac(invalid_mac[i], &mac);
        // Then
        assert_int_not_equal(err, IOT_ERROR_NONE);
    }
}

void TC_iot_util_convert_str_mac_invalid_characters(void **state)
{
    iot_error_t err;
    struct iot_mac mac;
    char invalid_mac[2][20] = {
        "a2:b3:fg:c9:8e:7d",  // non hex char 'g'
        "a2:b3:fe:c9:8e:7x",  // non hex char 'x'
    };
    UNUSED(state);

    for (int i = 0; i < 2; i++) {
        // When: invalid mac characters
        err = iot_util_convert_str_mac(invalid_mac[i], &mac);
        // Then
        assert_int_not_equal(err, IOT_ERROR_NONE);
    }
}

void TC_iot_util_convert_str_mac_invalid_segment_format(void **state)
{
    iot_error_t err;
    struct iot_mac mac;
    char invalid_mac[3][20] = {
        "a2b:3:fe:c9:8e:7d",  // 3-1-2-2-2-2
        "a2:b3f:e:c9:8e:7d",  // 2-3-1-2-2-2
        "a2:b3:fec:9:8e:7d",  // 2-2-3-1-2-2
    };
    UNUSED(state);

    for (int i = 0; i < 3; i++) {
        // When: invalid mac segment format
        err = iot_util_convert_str_mac(invalid_mac[i], &mac);
        // Then
        assert_int_not_equal(err, IOT_ERROR_NONE);
    }
}

void TC_iot_util_convert_mac_str_null_mac(void **state)
{
    iot_error_t err;
    char out_buffer[32];
    UNUSED(state);

    // Given: null mac
    // When
    err = iot_util_convert_mac_str(NULL, out_buffer, sizeof(out_buffer));
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_util_convert_mac_str_null_buffer(void **state)
{
    iot_error_t err;
    struct iot_mac *mac;
    char out_buffer[32];
    UNUSED(state);

    // Given: null mac, str
    mac = NULL;
    // When
    err = iot_util_convert_mac_str(mac, NULL, 16);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Given: null mac
    mac = NULL;
    // When
    err = iot_util_convert_mac_str(mac, out_buffer, sizeof(out_buffer));
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_util_convert_mac_str_null_output_buffer(void **state)
{
    iot_error_t err;
    struct iot_mac *mac;
    UNUSED(state);

    // Given: null str
    mac = (struct iot_mac *)calloc(1, sizeof(struct iot_mac));
    mac->addr[0] = 0x0a;
    mac->addr[1] = 0x0b;
    mac->addr[2] = 0x11;
    mac->addr[3] = 0x22;
    mac->addr[4] = 0x33;
    mac->addr[5] = 0x44;
    // When
    err = iot_util_convert_mac_str(mac, NULL, 16);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    // Teardown
    free(mac);
}

void TC_iot_util_convert_mac_str_insufficient_buffer(void **state)
{
    iot_error_t err;
    struct iot_mac *mac;
    char out_buffer[32];
    UNUSED(state);

    // Given: short buffer length
    mac = (struct iot_mac *)calloc(1, sizeof(struct iot_mac));
    mac->addr[0] = 0x0a;
    mac->addr[1] = 0x0b;
    mac->addr[2] = 0x11;
    mac->addr[3] = 0x22;
    mac->addr[4] = 0x33;
    mac->addr[5] = 0x44;
    // When
    err = iot_util_convert_mac_str(mac, out_buffer, 5);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    // Teardown
    free(mac);
}

void TC_iot_util_convert_mac_str_success(void **state)
{
    iot_error_t err;
    struct iot_mac *mac;
    char out_buffer[32];
    UNUSED(state);

    // Given
    mac = (struct iot_mac *)calloc(1, sizeof(struct iot_mac));
    mac->addr[0] = 0x0a;
    mac->addr[1] = 0x0b;
    mac->addr[2] = 0x11;
    mac->addr[3] = 0x22;
    mac->addr[4] = 0x33;
    mac->addr[5] = 0x44;
    // When
    err = iot_util_convert_mac_str(mac, out_buffer, sizeof(out_buffer));
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_string_equal("0a:0b:11:22:33:44", out_buffer);
    // Teardown
    free(mac);
}

void TC_iot_util_convert_channel_freq_success(void **state)
{
    UNUSED(state);

    // Given
    struct {
        uint8_t ch;
        uint16_t freq;
    } channel_map[] = {{1, 2412},  {2, 2417},  {3, 2422},  {4, 2427},  {5, 2432},   {6, 2437},   {7, 2442},
                       {8, 2447},  {9, 2452},  {10, 2457}, {11, 2462}, {12, 2467},  {13, 2472},  {14, 2484},
                       {32, 5160}, {34, 5170}, {36, 5180}, {42, 5210}, {120, 5600}, {165, 5825}, {174, 0},
                       {31, 0},    {183, 0},   {196, 0},   {0xff, 0},  {0, 0}

    };
    // When, Then
    for (int i = 0; i < (sizeof(channel_map) / sizeof(channel_map[0])); i++) {
        assert_int_equal(iot_util_convert_channel_freq(channel_map[i].ch), channel_map[i].freq);
    }
}

void TC_iot_util_convert_freq_channel_success(void **state)
{
    uint8_t channel;
    UNUSED(state);

    // Test valid frequency conversions
    channel = iot_util_convert_freq_channel(2412);  // Channel 1
    assert_int_equal(channel, 1);

    channel = iot_util_convert_freq_channel(2437);  // Channel 6
    assert_int_equal(channel, 6);

    channel = iot_util_convert_freq_channel(2472);  // Channel 13
    assert_int_equal(channel, 13);

    channel = iot_util_convert_freq_channel(2484);  // Channel 14
    assert_int_equal(channel, 14);

    channel = iot_util_convert_freq_channel(5160);  // Channel 32
    assert_int_equal(channel, 32);

    channel = iot_util_convert_freq_channel(5865);  // Channel 173
    assert_int_equal(channel, 173);
}

void TC_iot_util_url_parse_success(void **state)
{
    iot_error_t err;
    url_parse_t output;
    UNUSED(state);

    // Test successful case to verify memory allocation paths
    err = iot_util_url_parse("https://example.com:443", &output);
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(output.protocol);
    assert_non_null(output.domain);
    assert_int_equal(output.port, 443);

    // Cleanup
    if (output.protocol)
        free(output.protocol);
    if (output.domain)
        free(output.domain);
}

void TC_iot_util_url_parse_negative_cases(void **state)
{
    iot_error_t err;
    url_parse_t output;
    char url_buffer[256];
    UNUSED(state);

    // When: NULL url
    err = iot_util_url_parse(NULL, &output);
    // Then: should return error
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);

    // When: NULL output
    err = iot_util_url_parse("https://example.com:443", NULL);
    // Then: should return error
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);

    // When: URL without protocol
    err = iot_util_url_parse("example.com:443", &output);
    // Then: should return error
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);

    // When: URL without port
    err = iot_util_url_parse("https://example.com", &output);
    // Then: should return error
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);
}

void TC_iot_util_queue_create_negative_cases(void **state)
{
    iot_util_queue_t *queue;
    UNUSED(state);

    // When: item size is 0
    queue = iot_util_queue_create(0);
    // Then: should return NULL
    assert_null(queue);
}

void TC_iot_util_queue_delete_edge_cases(void **state)
{
    UNUSED(state);

    // When: NULL queue (should not crash)
    iot_util_queue_delete(NULL);
}

void TC_iot_util_queue_send_negative_cases(void **state)
{
    iot_error_t err;
    iot_util_queue_t *queue;
    int test_data = 42;
    UNUSED(state);

    // When: NULL queue
    err = iot_util_queue_send(NULL, &test_data);
    // Then: should return error
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);

    // When: NULL data
    queue = iot_util_queue_create(sizeof(int));
    err = iot_util_queue_send(queue, NULL);
    // Then: should return error
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);

    // Cleanup
    iot_util_queue_delete(queue);
}

void TC_iot_util_queue_receive_negative_cases(void **state)
{
    iot_error_t err;
    iot_util_queue_t *queue;
    int received_data;
    UNUSED(state);

    // When: NULL queue
    err = iot_util_queue_receive(NULL, &received_data);
    // Then: should return error
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);

    // When: NULL data
    queue = iot_util_queue_create(sizeof(int));
    err = iot_util_queue_receive(queue, NULL);
    // Then: should return error
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);

    // When: empty queue
    err = iot_util_queue_receive(queue, &received_data);
    // Then: should return error
    assert_int_equal(err, IOT_ERROR_BAD_REQ);

    // Cleanup
    iot_util_queue_delete(queue);
}

void TC_iot_util_generator_backoff(void **state)
{
    unsigned int backoff;
    UNUSED(state);

    // Test various try counts and maximum backoffs
    backoff = iot_util_generator_backoff(0, 10);
    // Should be between 1000 and 1999 (1 * 1000 + random[0-999])
    assert_true(backoff >= 1000 && backoff < 2000);

    backoff = iot_util_generator_backoff(1, 10);
    // Should be between 2000 and 2999 (2 * 1000 + random[0-999])
    assert_true(backoff >= 2000 && backoff < 3000);

    backoff = iot_util_generator_backoff(2, 10);
    // Should be between 4000 and 4999 (4 * 1000 + random[0-999])
    assert_true(backoff >= 4000 && backoff < 5000);

    // Test when backoff exceeds maximum
    backoff = iot_util_generator_backoff(10, 5);
    // Should be exactly 5000 (capped at maximum)
    assert_int_equal(backoff, 5000);

    backoff = iot_util_generator_backoff(20, 2);
    // Should be exactly 2000 (capped at maximum)
    assert_int_equal(backoff, 2000);
}

void TC_iot_util_print_ssid_secure_positive(void **state)
{
    char test_ssid[] = "TestWiFiNetwork";
    char empty_ssid[] = "";
    FILE *original_stdout;
    UNUSED(state);

    // Redirect stdout to suppress output
    original_stdout = stdout;
    stdout = fopen("/dev/null", "w");

    // Test with normal SSID
    iot_util_print_ssid_secure(__func__, __LINE__, "SSID:", test_ssid);

    // Test with empty SSID
    iot_util_print_ssid_secure(__func__, __LINE__, "SSID:", empty_ssid);

    // Restore stdout
    fclose(stdout);
    stdout = original_stdout;
}

void TC_iot_util_print_mac_secure_positive(void **state)
{
    uint8_t test_mac[] = {0x0a, 0x0b, 0x11, 0x22, 0x33, 0x44};
    FILE *original_stdout;
    UNUSED(state);

    // Redirect stdout to suppress output
    original_stdout = stdout;
    stdout = fopen("/dev/null", "w");

    // Test with normal MAC address
    iot_util_print_mac_secure(__func__, __LINE__, "MAC:", test_mac);

    // Restore stdout
    fclose(stdout);
    stdout = original_stdout;
}
