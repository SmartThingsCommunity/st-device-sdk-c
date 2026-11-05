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
#include <iot_debug.h>
#include <iot_dump_log.h>
#include <iot_internal.h>
#include <iot_log_file.h>
#include <security/iot_security_util.h>
#include <string.h>

#include "TC_MOCK_functions.h"
#include "TC_REGISTRY.h"
#include "cmocka_custom.h"

TEST_SUITE("iot_dump_log.c");

static int _tc_dump_log_setup(void **state);
static int _tc_dump_log_teardown(void **state);

TEST_FIXTURE(tc_dump_log, _tc_dump_log_setup, _tc_dump_log_teardown);

static char sample_device_info[] = {
    "{\n"
    "\t\"deviceInfo\": {\n"
    "\t\t\"firmwareVersion\": \"TEST_FIRMWARE_VERSION\",\n"
    "\t\t\"privateKey\": \"TEST_DEVICE_SECRET_B64_KEY\",\n"
    "\t\t\"publicKey\": \"TEST_DEVICE_PUBLIC_B64_KEY\",\n"
    "\t\t\"serialNumber\": \"TEST_DEVICE_SERIAL_NUMBER\",\n"
    "\t\t\"modelNumber\": \"TEST_MODEL_NUMBER\",\n"
    "\t\t\"manufacturerName\": \"TEST_MANUFACTURER_NAME\"\n"
    "\t}\n"
    "}"};

static void write_log_lines(int number_of_lines)
{
    static int count = 0;

    while (number_of_lines > 0) {
        iot_dump_log(0xf, 0xffffffff, 0, 0);
        number_of_lines--;
        count++;
    }
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_iot_dump_create_dump_state_failure_neg)
{
    struct iot_context *context = NULL;
    char *buf = NULL;
    size_t allocated_size = 0;
    size_t max_log_dump_size = 0;
    int mode = 0;
    iot_error_t err;
#ifdef CONFIG_STDK_IOT_CORE_LOG_FILE
    int malloc_test_count = 4;
#else
    int malloc_test_count = 3;
#endif

    // Given :  max_log_dump_size is smaller than minimum
    max_log_dump_size = 1;
    // when
    err = st_create_log_dump((IOT_CTX *)context, &buf, max_log_dump_size, &allocated_size, mode);
    // then : failure
    assert_int_not_equal(err, IOT_ERROR_NONE);

    mode = IOT_DUMP_MODE_NEED_BASE64 | IOT_DUMP_MODE_NEED_DUMP_STATE;
    max_log_dump_size = 500;
    for (int i = 0; i < malloc_test_count; i++) {
        // Given: malloc failure
        do_not_use_mock_iot_os_malloc_failure();
        set_mock_iot_os_malloc_failure_with_index(i);
        // when
        err = st_create_log_dump((IOT_CTX *)context, &buf, max_log_dump_size, &allocated_size, mode);
        // then : failure
        assert_int_not_equal(err, IOT_ERROR_NONE);
    }
    do_not_use_mock_iot_os_malloc_failure();
}

static void create_dump_test()
{
    struct iot_context *context = NULL;
    char *buf = NULL;
    size_t allocated_size = 0;
    int mode = 0;
    iot_error_t err;

    struct iot_device_info *device_info;

    // given: context is null, no base64, no dumpstate
    // when:
    err = st_create_log_dump((IOT_CTX *)context, &buf, 500, &allocated_size, mode);
    // then: success
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(buf);
    assert_true(allocated_size > 0);
    free(buf);

    // given: context has device info, base64, dumpstate
    context = (struct iot_context *)malloc((sizeof(struct iot_context)));
    memset(context, 0, sizeof(struct iot_context));
    device_info = &context->device_info;
    err = iot_api_device_info_load(sample_device_info, sizeof(sample_device_info), device_info);
    assert_int_equal(err, IOT_ERROR_NONE);
    mode = IOT_DUMP_MODE_NEED_BASE64 | IOT_DUMP_MODE_NEED_DUMP_STATE;

    // when:
    err = st_create_log_dump((IOT_CTX *)context, &buf, 2048, &allocated_size, mode);
    // then: success
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(buf);
    assert_true(allocated_size > 0);
    free(buf);

    iot_api_device_info_mem_free(device_info);
    free(context);
}

TEST_F(tc_dump_log, TC_iot_dump_create_dump_state_neg)
{
    iot_error_t iot_err;
    int log_file_type;

    // test with no log file condition
    create_dump_test();

#ifdef CONFIG_STDK_IOT_CORE_LOG_FILE
#if defined(CONFIG_STDK_IOT_CORE_LOG_FILE_RAM_ONLY)
    log_file_type = RAM_ONLY;
#elif defined(CONFIG_STDK_IOT_CORE_LOG_FILE_FLASH_WITH_RAM)
    log_file_type = FLASH_WITH_RAM;
#else
#error "Need to choice STDK_IOT_CORE_LOG_FILE_TYPE first"
#endif

    iot_log_file_init(log_file_type);
    // test with different log message size condition
    for (int i = 0; i < 10; i++) {
        write_log_lines(1 << i);
        create_dump_test();
        iot_log_file_remove(log_file_type);
    }
    iot_log_file_exit();
#endif  // CONFIG_STDK_IOT_CORE_LOG_FILE

    assert_true(true);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_iot_dump_log_neg)
{
    iot_dump_log(IOT_DEBUG_LEVEL_ERROR, 0xffffffff, 0, 0);
    iot_dump_log(IOT_DEBUG_LEVEL_WARN, 0xffffffff, 0, 0);
    iot_dump_log(IOT_DEBUG_LEVEL_INFO, 0xffffffff, 0, 0);
    iot_dump_log(IOT_DEBUG_LEVEL_DEBUG, 0xffffffff, 0, 0);

    assert_true(true);
}

/* The dump path needs an initialized log file when CONFIG_STDK_IOT_CORE_LOG_FILE is on. */
static void _tc_dump_log_file_init(void)
{
#ifdef CONFIG_STDK_IOT_CORE_LOG_FILE
#if defined(CONFIG_STDK_IOT_CORE_LOG_FILE_RAM_ONLY)
    assert_int_equal(iot_log_file_init(RAM_ONLY), IOT_ERROR_NONE);
#else
    assert_int_equal(iot_log_file_init(FLASH_WITH_RAM), IOT_ERROR_NONE);
#endif
#endif
}

static void _tc_dump_log_file_exit(void)
{
#ifdef CONFIG_STDK_IOT_CORE_LOG_FILE
    iot_log_file_exit();
#endif
}

static int _tc_dump_log_setup(void **state)
{
    _tc_dump_log_file_init();
    return 0;
}

static int _tc_dump_log_teardown(void **state)
{
    _tc_dump_log_file_exit();
    return 0;
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_iot_dump_create_log_dump_base64_min_size_neg)
{
    char *buf = (char *)0x1;
    size_t allocated_size = 0xdeadbeef;
    size_t min_log_dump_size;
    int mode = IOT_DUMP_MODE_NEED_BASE64 | IOT_DUMP_MODE_NEED_DUMP_STATE;
    iot_error_t err;

    // Given: one byte less than the minimum base64 encoded header + dump state
    min_log_dump_size = IOT_SECURITY_B64_ENCODE_LEN(sizeof(struct iot_dump_header) + sizeof(struct iot_dump_state));
    // When
    err = st_create_log_dump(NULL, &buf, min_log_dump_size - 1, &allocated_size, mode);
    // Then
    assert_int_equal(err, IOT_ERROR_BAD_REQ);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_iot_dump_create_log_dump_raw_min_size_neg)
{
    char *buf = (char *)0x1;
    size_t allocated_size = 0xdeadbeef;
    size_t min_log_dump_size;
    int mode = IOT_DUMP_MODE_NEED_DUMP_STATE;
    iot_error_t err;

    // Given: one byte less than the raw header + dump state size
    min_log_dump_size = sizeof(struct iot_dump_header) + sizeof(struct iot_dump_state);
    // When
    err = st_create_log_dump(NULL, &buf, min_log_dump_size - 1, &allocated_size, mode);
    // Then
    assert_int_equal(err, IOT_ERROR_BAD_REQ);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_iot_dump_create_log_dump_output_cleared_on_failure_neg)
{
    char *buf = (char *)0x1;
    size_t allocated_size = 0xdeadbeef;
    int mode = IOT_DUMP_MODE_NEED_BASE64 | IOT_DUMP_MODE_NEED_DUMP_STATE;
    iot_error_t err;

    _tc_dump_log_file_init();

    // Given: the malloc for the dump output buffer fails (index 0 is the log file handle)
    do_not_use_mock_iot_os_malloc_failure();
    set_mock_iot_os_malloc_failure_with_index(1);
    // When
    err = st_create_log_dump(NULL, &buf, 2048, &allocated_size, mode);
    do_not_use_mock_iot_os_malloc_failure();
    _tc_dump_log_file_exit();

    // Then: caller visible outputs must be reset, not left dangling
    assert_int_equal(err, IOT_ERROR_MEM_ALLOC);
    assert_null(buf);
    assert_int_equal(allocated_size, 0);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_iot_dump_create_log_dump_dip_not_dropped_neg)
{
    struct iot_context *context;
    struct iot_dip_data dip;
    char *dump_with_dip = NULL;
    char *dump_without_dip = NULL;
    size_t size_with_dip = 0;
    size_t size_without_dip = 0;
    int mode = IOT_DUMP_MODE_NEED_DUMP_STATE;
    iot_error_t err;

    _tc_dump_log_file_init();

    context = (struct iot_context *)malloc(sizeof(struct iot_context));
    assert_non_null(context);
    memset(context, 0, sizeof(struct iot_context));
    memset(&dip, 0, sizeof(dip));
    memset(dip.dip_id.id, 0x5a, sizeof(dip.dip_id.id));
    dip.dip_major_version = 0x1234;
    dip.dip_minor_version = 0x5678;

    // Given: a context without dip information
    err = st_create_log_dump((IOT_CTX *)context, &dump_without_dip, 2048, &size_without_dip, mode);
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(dump_without_dip);

    // Given: the same context carrying dip information
    context->devconf.dip = &dip;
    // When
    err = st_create_log_dump((IOT_CTX *)context, &dump_with_dip, 2048, &size_with_dip, mode);

    free(context);
    _tc_dump_log_file_exit();

    // Then: the dip must not be silently dropped from the dump state
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(dump_with_dip);
    assert_int_equal(size_with_dip, size_without_dip);
    assert_memory_not_equal(dump_with_dip, dump_without_dip, size_with_dip);

    free(dump_with_dip);
    free(dump_without_dip);
}
