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
#include <iot_error.h>
#include <string.h>

#if defined(CONFIG_STDK_IOT_CORE_LOG_FILE)
#include <iot_log_file.h>
#endif

#include "TC_MOCK_functions.h"
#include "TC_REGISTRY.h"
#include "cmocka_custom.h"

#define UNUSED(x) (void **)(x)

#if defined(CONFIG_STDK_IOT_CORE_LOG_FILE)

#define TC_LOG_FILE_INVALID_TYPE_neg ((iot_log_file_type_t)0xFE)
#define TC_LOG_FILE_SAMPLE_LINE_neg "iot_log_file_test_sample_log_line\n"

/* Defined in iot_log_file.c but not exposed through the public header. */
extern iot_error_t _iot_log_read_bytes(iot_log_file_handle_t *file_handle, void *buffer, unsigned int size);

TEST_SUITE("iot_log_file.c");

static int _tc_log_file_init(void)
{
#if defined(CONFIG_STDK_IOT_CORE_LOG_FILE_RAM_ONLY)
    return (int)iot_log_file_init(RAM_ONLY);
#elif defined(CONFIG_STDK_IOT_CORE_LOG_FILE_FLASH_WITH_RAM)
    return (int)iot_log_file_init(FLASH_WITH_RAM);
#else
    return (int)IOT_ERROR_INVALID_ARGS;
#endif
}

static iot_log_file_type_t _tc_log_file_type(void)
{
#if defined(CONFIG_STDK_IOT_CORE_LOG_FILE_RAM_ONLY)
    return RAM_ONLY;
#elif defined(CONFIG_STDK_IOT_CORE_LOG_FILE_FLASH_WITH_RAM)
    return FLASH_WITH_RAM;
#else
    return TC_LOG_FILE_INVALID_TYPE_neg;
#endif
}

/*
 * iot_log_file_init tests
 */
TEST(TC_iot_log_file_init_success_pos)
{
    iot_error_t err;
    UNUSED(state);

    // When
    err = (iot_error_t)_tc_log_file_init();
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);

    // Local teardown
    iot_log_file_exit();
}

TEST(TC_iot_log_file_init_invalid_type_neg)
{
    iot_error_t err;
    UNUSED(state);

    // When: pass an unsupported type
    err = iot_log_file_init(TC_LOG_FILE_INVALID_TYPE_neg);
    // Then
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);
}

TEST(TC_iot_log_file_init_ctx_alloc_failure_neg)
{
    iot_error_t err;
    UNUSED(state);

    // Given: simulate allocation failure for log_ctx
    do_not_use_mock_iot_os_malloc_failure();
    set_mock_iot_os_malloc_failure_with_index(0);
    // When
    err = (iot_error_t)_tc_log_file_init();
    // Then
    assert_int_equal(err, IOT_ERROR_MEM_ALLOC);

    do_not_use_mock_iot_os_malloc_failure();
}

TEST(TC_iot_log_file_init_double_init_neg)
{
    iot_error_t err;
    UNUSED(state);

    // Given: first init succeeds
    err = (iot_error_t)_tc_log_file_init();
    assert_int_equal(err, IOT_ERROR_NONE);

    // When: init is called again, the old context is leaked but call should not crash
    // and should still return a valid status.
    err = (iot_error_t)_tc_log_file_init();
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);

    iot_log_file_exit();
}

/*
 * iot_log_file_exit tests
 */
TEST(TC_iot_log_file_exit_success_pos)
{
    iot_error_t err;
    UNUSED(state);

    // Given
    err = (iot_error_t)_tc_log_file_init();
    assert_int_equal(err, IOT_ERROR_NONE);

    // When
    iot_log_file_exit();

    // Then: calling exit again on NULL context should be a no-op
    iot_log_file_exit();
}

TEST(TC_iot_log_file_exit_without_init_neg)
{
    UNUSED(state);

    // When: exit is called without prior init
    iot_log_file_exit();
    // Then: no crash; subsequent exits are still safe
    iot_log_file_exit();

    assert_true(true);
}

/*
 * iot_log_file_store tests
 */
TEST(TC_iot_log_file_store_success_pos)
{
    iot_error_t err;
    const char *msg = TC_LOG_FILE_SAMPLE_LINE_neg;
    int written;
    UNUSED(state);

    // Given
    err = (iot_error_t)_tc_log_file_init();
    assert_int_equal(err, IOT_ERROR_NONE);

    // When
    written = iot_log_file_store(msg, strlen(msg));
    // Then
    assert_int_equal(written, (int)strlen(msg));

    iot_log_file_exit();
}

TEST(TC_iot_log_file_store_without_init_neg)
{
    int written;
    const char *msg = TC_LOG_FILE_SAMPLE_LINE_neg;
    UNUSED(state);

    // When: no init was called; global log_ctx should be NULL
    written = iot_log_file_store(msg, strlen(msg));
    // Then
    assert_int_equal(written, -1);
}

TEST(TC_iot_log_file_store_zero_size_neg)
{
    iot_error_t err;
    int written;
    UNUSED(state);

    // Given
    err = (iot_error_t)_tc_log_file_init();
    assert_int_equal(err, IOT_ERROR_NONE);

    // When: zero size is a no-op, but should not fail
    written = iot_log_file_store("ignored", 0);
    // Then
    assert_int_equal(written, 0);

    iot_log_file_exit();
}

TEST(TC_iot_log_file_store_oversize_neg)
{
    iot_error_t err;
    int written;
    char big_buf[IOT_LOG_FILE_MAX_STRING_SIZE + 16];
    UNUSED(state);

    // Given
    memset(big_buf, 'A', sizeof(big_buf));
    err = (iot_error_t)_tc_log_file_init();
    assert_int_equal(err, IOT_ERROR_NONE);

    // When: log size is at/over the max threshold
    written = iot_log_file_store(big_buf, sizeof(big_buf));
    // Then
    assert_int_equal(written, -1);

    iot_log_file_exit();
}

TEST(TC_iot_log_file_store_disabled_buffer_neg)
{
    iot_error_t err;
    int written;
    iot_log_file_handle_t *handle = NULL;
    size_t filesize = 0;
    UNUSED(state);

    // Given: open() in RAM_ONLY disables the buffer
    err = (iot_error_t)_tc_log_file_init();
    assert_int_equal(err, IOT_ERROR_NONE);

    handle = iot_log_file_open(&filesize, _tc_log_file_type());
    assert_non_null(handle);

    // When: storing while buffer is disabled
    written = iot_log_file_store("x", 1);
    // Then
    assert_int_equal(written, -1);

    iot_log_file_close(handle);
    iot_log_file_exit();
}

/*
 * iot_log_file_sync tests (only FLASH_WITH_RAM has event group; for RAM_ONLY
 * sync just exercises the "events == NULL" branch).
 */
TEST(TC_iot_log_file_sync_without_events_neg)
{
    iot_error_t err;
    UNUSED(state);

    err = (iot_error_t)_tc_log_file_init();
    assert_int_equal(err, IOT_ERROR_NONE);

    // When
    iot_log_file_sync();
    // Then: call returns normally for RAM_ONLY which does not create events
    iot_log_file_exit();
}

/*
 * iot_log_file_open tests
 */
TEST(TC_iot_log_file_open_success_pos)
{
    iot_error_t err;
    iot_log_file_handle_t *handle;
    size_t filesize = 0;
    UNUSED(state);

    // Given
    err = (iot_error_t)_tc_log_file_init();
    assert_int_equal(err, IOT_ERROR_NONE);

    // When
    handle = iot_log_file_open(&filesize, _tc_log_file_type());
    // Then
    assert_non_null(handle);
    assert_int_equal(handle->file_type, _tc_log_file_type());

    iot_log_file_close(handle);
    iot_log_file_exit();
}

TEST(TC_iot_log_file_open_without_init_neg)
{
    iot_log_file_handle_t *handle;
    size_t filesize = 0;
    UNUSED(state);

    // When: log_ctx is NULL because init was not called
    handle = iot_log_file_open(&filesize, _tc_log_file_type());
    // Then
    assert_null(handle);
}

TEST(TC_iot_log_file_open_invalid_type_neg)
{
    iot_error_t err;
    iot_log_file_handle_t *handle;
    size_t filesize = 0;
    UNUSED(state);

    err = (iot_error_t)_tc_log_file_init();
    assert_int_equal(err, IOT_ERROR_NONE);

    // When: unsupported file_type triggers default branch
    handle = iot_log_file_open(&filesize, TC_LOG_FILE_INVALID_TYPE_neg);
    // Then
    assert_null(handle);

    iot_log_file_exit();
}

TEST(TC_iot_log_file_open_alloc_failure_neg)
{
    iot_error_t err;
    iot_log_file_handle_t *handle;
    size_t filesize = 0;
    UNUSED(state);

    err = (iot_error_t)_tc_log_file_init();
    assert_int_equal(err, IOT_ERROR_NONE);

    // When: file handle allocation fails
    do_not_use_mock_iot_os_malloc_failure();
    set_mock_iot_os_malloc_failure_with_index(0);
    handle = iot_log_file_open(&filesize, _tc_log_file_type());
    do_not_use_mock_iot_os_malloc_failure();
    // Then
    assert_null(handle);

    iot_log_file_exit();
}

TEST(TC_iot_log_file_open_after_overridden_neg)
{
#if defined(CONFIG_STDK_IOT_CORE_LOG_FILE_RAM_ONLY)
    iot_error_t err;
    iot_log_file_handle_t *handle;
    size_t filesize = 0;
    size_t i;
    size_t chunk_len = IOT_LOG_FILE_MAX_STRING_SIZE - 1;
    char *chunk;
    UNUSED(state);

    chunk = malloc(chunk_len);
    assert_non_null(chunk);
    memset(chunk, 'L', chunk_len);

    err = (iot_error_t)_tc_log_file_init();
    assert_int_equal(err, IOT_ERROR_NONE);

    // Given: fill the buffer past its capacity to force the overridden flag
    for (i = 0; i < (IOT_LOG_FILE_RAM_BUF_SIZE / chunk_len) + 2; i++) {
        (void)iot_log_file_store(chunk, chunk_len);
    }

    // When
    handle = iot_log_file_open(&filesize, RAM_ONLY);
    // Then
    assert_non_null(handle);
    assert_int_equal(filesize, IOT_LOG_FILE_RAM_BUF_SIZE);
    assert_int_equal(handle->cur_addr, handle->tail_addr);

    iot_log_file_close(handle);
    iot_log_file_exit();
    free(chunk);
#else
    UNUSED(state);
#endif
}

/*
 * iot_log_file_close tests
 */
TEST(TC_iot_log_file_close_success_pos)
{
    iot_error_t err;
    iot_log_file_handle_t *handle;
    size_t filesize = 0;
    UNUSED(state);

    err = (iot_error_t)_tc_log_file_init();
    assert_int_equal(err, IOT_ERROR_NONE);

    handle = iot_log_file_open(&filesize, _tc_log_file_type());
    assert_non_null(handle);

    // When
    err = iot_log_file_close(handle);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);

    iot_log_file_exit();
}

TEST(TC_iot_log_file_close_null_handle_neg)
{
    iot_error_t err;
    UNUSED(state);

    // When
    err = iot_log_file_close(NULL);
    // Then
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);
}

/*
 * iot_log_file_seek tests
 */
TEST(TC_iot_log_file_seek_success_pos)
{
    iot_error_t err;
    iot_log_file_handle_t *handle;
    size_t filesize = 0;
    const char *msg = TC_LOG_FILE_SAMPLE_LINE_neg;
    UNUSED(state);

    err = (iot_error_t)_tc_log_file_init();
    assert_int_equal(err, IOT_ERROR_NONE);
    (void)iot_log_file_store(msg, strlen(msg));

    handle = iot_log_file_open(&filesize, _tc_log_file_type());
    assert_non_null(handle);

    // When: positive offset
    err = iot_log_file_seek(handle, 1, handle->cur_addr);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);

    iot_log_file_close(handle);
    iot_log_file_exit();
}

TEST(TC_iot_log_file_seek_empty_log_neg)
{
    iot_error_t err;
    iot_log_file_handle_t *handle;
    size_t filesize = 0;
    UNUSED(state);

    err = (iot_error_t)_tc_log_file_init();
    assert_int_equal(err, IOT_ERROR_NONE);

    handle = iot_log_file_open(&filesize, _tc_log_file_type());
    assert_non_null(handle);
    // Given
    handle->log_size = 0;

    // When: seek on empty log should fail
    err = iot_log_file_seek(handle, 0, 0);
    // Then
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);

    iot_log_file_close(handle);
    iot_log_file_exit();
}

TEST(TC_iot_log_file_seek_negative_offset_neg)
{
    iot_error_t err;
    iot_log_file_handle_t *handle;
    size_t filesize = 0;
    const char *msg = TC_LOG_FILE_SAMPLE_LINE_neg;
    unsigned int prev_addr;
    UNUSED(state);

    err = (iot_error_t)_tc_log_file_init();
    assert_int_equal(err, IOT_ERROR_NONE);
    (void)iot_log_file_store(msg, strlen(msg));

    handle = iot_log_file_open(&filesize, _tc_log_file_type());
    assert_non_null(handle);
    prev_addr = handle->cur_addr;

    // When: negative offset wraps around
    err = iot_log_file_seek(handle, -1, handle->start_addr);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_true(handle->cur_addr != prev_addr);

    iot_log_file_close(handle);
    iot_log_file_exit();
}

TEST(TC_iot_log_file_seek_invalid_type_neg)
{
    iot_error_t err;
    iot_log_file_handle_t *handle;
    size_t filesize = 0;
    const char *msg = TC_LOG_FILE_SAMPLE_LINE_neg;
    UNUSED(state);

    err = (iot_error_t)_tc_log_file_init();
    assert_int_equal(err, IOT_ERROR_NONE);
    (void)iot_log_file_store(msg, strlen(msg));

    handle = iot_log_file_open(&filesize, _tc_log_file_type());
    assert_non_null(handle);
    // Given: corrupt file_type to hit default branch
    handle->file_type = TC_LOG_FILE_INVALID_TYPE_neg;

    // When
    err = iot_log_file_seek(handle, 0, handle->start_addr);
    // Then
    assert_int_equal(err, IOT_ERROR_BAD_REQ);

    // Restore type so close works normally
    handle->file_type = _tc_log_file_type();
    iot_log_file_close(handle);
    iot_log_file_exit();
}

/*
 * iot_log_file_read tests
 */
TEST(TC_iot_log_file_read_success_pos)
{
    iot_error_t err;
    iot_log_file_handle_t *handle;
    size_t filesize = 0;
    size_t read_size = 0;
    const char *msg = TC_LOG_FILE_SAMPLE_LINE_neg;
    char out[64] = {0};
    UNUSED(state);

    err = (iot_error_t)_tc_log_file_init();
    assert_int_equal(err, IOT_ERROR_NONE);
    (void)iot_log_file_store(msg, strlen(msg));

    handle = iot_log_file_open(&filesize, _tc_log_file_type());
    assert_non_null(handle);

    // When: read within range
    err = iot_log_file_read(handle, out, strlen(msg), &read_size);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_int_equal(read_size, strlen(msg));
    assert_memory_equal(out, msg, strlen(msg));

    iot_log_file_close(handle);
    iot_log_file_exit();
}

TEST(TC_iot_log_file_read_null_handle_neg)
{
    iot_error_t err;
    char out[16];
    size_t read_size = 0;
    UNUSED(state);

    // When
    err = iot_log_file_read(NULL, out, sizeof(out), &read_size);
    // Then
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);
}

TEST(TC_iot_log_file_read_null_buffer_neg)
{
    iot_error_t err;
    iot_log_file_handle_t *handle;
    size_t filesize = 0;
    size_t read_size = 0;
    const char *msg = TC_LOG_FILE_SAMPLE_LINE_neg;
    UNUSED(state);

    err = (iot_error_t)_tc_log_file_init();
    assert_int_equal(err, IOT_ERROR_NONE);
    (void)iot_log_file_store(msg, strlen(msg));

    handle = iot_log_file_open(&filesize, _tc_log_file_type());
    assert_non_null(handle);

    // When
    err = iot_log_file_read(handle, NULL, 4, &read_size);
    // Then
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);

    iot_log_file_close(handle);
    iot_log_file_exit();
}

TEST(TC_iot_log_file_read_no_read_size_out_neg)
{
    iot_error_t err;
    iot_log_file_handle_t *handle;
    size_t filesize = 0;
    const char *msg = TC_LOG_FILE_SAMPLE_LINE_neg;
    char out[64] = {0};
    UNUSED(state);

    err = (iot_error_t)_tc_log_file_init();
    assert_int_equal(err, IOT_ERROR_NONE);
    (void)iot_log_file_store(msg, strlen(msg));

    handle = iot_log_file_open(&filesize, _tc_log_file_type());
    assert_non_null(handle);

    // When: omitting the optional out parameter is legal
    err = iot_log_file_read(handle, out, strlen(msg), NULL);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);

    iot_log_file_close(handle);
    iot_log_file_exit();
}

TEST(TC_iot_log_file_read_wrap_around_neg)
{
#if defined(CONFIG_STDK_IOT_CORE_LOG_FILE_RAM_ONLY)
    iot_error_t err;
    iot_log_file_handle_t *handle;
    size_t filesize = 0;
    size_t read_size = 0;
    const char *msg = TC_LOG_FILE_SAMPLE_LINE_neg;
    char out[64] = {0};
    UNUSED(state);

    err = (iot_error_t)_tc_log_file_init();
    assert_int_equal(err, IOT_ERROR_NONE);
    (void)iot_log_file_store(msg, strlen(msg));

    handle = iot_log_file_open(&filesize, RAM_ONLY);
    assert_non_null(handle);
    // Given: force cur_addr to force a wrap-around path
    handle->cur_addr = handle->start_addr + handle->log_size - 4;

    // When: read more than the remaining range
    err = iot_log_file_read(handle, out, 16, &read_size);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);

    iot_log_file_close(handle);
    iot_log_file_exit();
#else
    UNUSED(state);
#endif
}

TEST(TC_iot_log_file_read_invalid_type_neg)
{
    iot_error_t err;
    iot_log_file_handle_t *handle;
    size_t filesize = 0;
    size_t read_size = 0;
    const char *msg = TC_LOG_FILE_SAMPLE_LINE_neg;
    char out[8];
    UNUSED(state);

    err = (iot_error_t)_tc_log_file_init();
    assert_int_equal(err, IOT_ERROR_NONE);
    (void)iot_log_file_store(msg, strlen(msg));

    handle = iot_log_file_open(&filesize, _tc_log_file_type());
    assert_non_null(handle);
    // Given
    handle->file_type = TC_LOG_FILE_INVALID_TYPE_neg;

    // When
    err = iot_log_file_read(handle, out, sizeof(out), &read_size);
    // Then
    assert_int_equal(err, IOT_ERROR_BAD_REQ);

    handle->file_type = _tc_log_file_type();
    iot_log_file_close(handle);
    iot_log_file_exit();
}

/*
 * iot_log_file_remove tests
 */
TEST(TC_iot_log_file_remove_success_pos)
{
    iot_error_t err;
    UNUSED(state);

    err = (iot_error_t)_tc_log_file_init();
    assert_int_equal(err, IOT_ERROR_NONE);

    // When
    err = iot_log_file_remove(_tc_log_file_type());
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);

    iot_log_file_exit();
}

TEST(TC_iot_log_file_remove_invalid_type_neg)
{
    iot_error_t err;
    UNUSED(state);

    err = (iot_error_t)_tc_log_file_init();
    assert_int_equal(err, IOT_ERROR_NONE);

    // When
    err = iot_log_file_remove(TC_LOG_FILE_INVALID_TYPE_neg);
    // Then
    assert_int_equal(err, IOT_ERROR_BAD_REQ);

    iot_log_file_exit();
}

#else /* CONFIG_STDK_IOT_CORE_LOG_FILE */

/*
 * Log file feature is disabled.  Provide no-op placeholders so tests compile
 * cleanly when the feature is off.  Each will simply report success.
 */
#define _TC_LOG_FILE_NOOP(name) \
    void name(void **state)     \
    {                           \
        UNUSED(state);          \
    }

_TC_LOG_FILE_NOOP(TC_iot_log_file_init_success_pos)
_TC_LOG_FILE_NOOP(TC_iot_log_file_init_invalid_type_neg)
_TC_LOG_FILE_NOOP(TC_iot_log_file_init_ctx_alloc_failure_neg)
_TC_LOG_FILE_NOOP(TC_iot_log_file_init_double_init_neg)
_TC_LOG_FILE_NOOP(TC_iot_log_file_exit_success_pos)
_TC_LOG_FILE_NOOP(TC_iot_log_file_exit_without_init_neg)
_TC_LOG_FILE_NOOP(TC_iot_log_file_store_success_pos)
_TC_LOG_FILE_NOOP(TC_iot_log_file_store_without_init_neg)
_TC_LOG_FILE_NOOP(TC_iot_log_file_store_zero_size_neg)
_TC_LOG_FILE_NOOP(TC_iot_log_file_store_oversize_neg)
_TC_LOG_FILE_NOOP(TC_iot_log_file_store_disabled_buffer_neg)
_TC_LOG_FILE_NOOP(TC_iot_log_file_sync_without_events_neg)
_TC_LOG_FILE_NOOP(TC_iot_log_file_open_success_pos)
_TC_LOG_FILE_NOOP(TC_iot_log_file_open_without_init_neg)
_TC_LOG_FILE_NOOP(TC_iot_log_file_open_invalid_type_neg)
_TC_LOG_FILE_NOOP(TC_iot_log_file_open_alloc_failure_neg)
_TC_LOG_FILE_NOOP(TC_iot_log_file_open_after_overridden_neg)
_TC_LOG_FILE_NOOP(TC_iot_log_file_close_success_pos)
_TC_LOG_FILE_NOOP(TC_iot_log_file_close_null_handle_neg)
_TC_LOG_FILE_NOOP(TC_iot_log_file_seek_success_pos)
_TC_LOG_FILE_NOOP(TC_iot_log_file_seek_empty_log_neg)
_TC_LOG_FILE_NOOP(TC_iot_log_file_seek_negative_offset_neg)
_TC_LOG_FILE_NOOP(TC_iot_log_file_seek_invalid_type_neg)
_TC_LOG_FILE_NOOP(TC_iot_log_file_read_success_pos)
_TC_LOG_FILE_NOOP(TC_iot_log_file_read_null_handle_neg)
_TC_LOG_FILE_NOOP(TC_iot_log_file_read_null_buffer_neg)
_TC_LOG_FILE_NOOP(TC_iot_log_file_read_no_read_size_out_neg)
_TC_LOG_FILE_NOOP(TC_iot_log_file_read_wrap_around_neg)
_TC_LOG_FILE_NOOP(TC_iot_log_file_read_invalid_type_neg)
_TC_LOG_FILE_NOOP(TC_iot_log_file_remove_success_pos)
_TC_LOG_FILE_NOOP(TC_iot_log_file_remove_invalid_type_neg)

#endif /* CONFIG_STDK_IOT_CORE_LOG_FILE */

#if defined(CONFIG_STDK_IOT_CORE_LOG_FILE)

/*
 * Additional negative tests for iot_log_file.c
 */
TEST(TC_iot_log_file_close_flash_type_handle_neg)
{
    iot_log_file_handle_t *handle;
    UNUSED(state);

    assert_int_equal(_tc_log_file_init(), IOT_ERROR_NONE);

    // Given: a handle claiming the flash backed type while the build is ram only
    handle = (iot_log_file_handle_t *)malloc(sizeof(iot_log_file_handle_t));
    assert_non_null(handle);
    memset(handle, 0, sizeof(*handle));
    handle->file_type = FLASH_WITH_RAM;
    // When: it is closed
    // Then: the open state is cleared instead of re-enabling the ram buffer
    assert_int_equal(iot_log_file_close(handle), IOT_ERROR_NONE);

    iot_log_file_exit();
}

TEST(TC_iot_log_file_close_without_init_neg)
{
    iot_log_file_handle_t *handle;
    UNUSED(state);

    // Given: no log context exists
    iot_log_file_exit();
    handle = (iot_log_file_handle_t *)malloc(sizeof(iot_log_file_handle_t));
    assert_non_null(handle);
    memset(handle, 0, sizeof(*handle));
    handle->file_type = RAM_ONLY;
    // When: a handle is closed anyway
    // Then: the missing context is tolerated instead of crashing
    assert_int_equal(iot_log_file_close(handle), IOT_ERROR_NONE);
}

TEST(TC_iot_log_file_read_wrap_first_read_failure_neg)
{
    iot_log_file_handle_t handle;
    char buffer[16] = {0};
    size_t read_size = 0xdead;
    UNUSED(state);

    assert_int_equal(_tc_log_file_init(), IOT_ERROR_NONE);

    // Given: a handle with an unsupported type and a read that has to wrap
    memset(&handle, 0, sizeof(handle));
    handle.file_type = TC_LOG_FILE_INVALID_TYPE_neg;
    handle.start_addr = 0;
    handle.cur_addr = 8;
    handle.log_size = 16;
    handle.max_log_size = 16;
    // When
    assert_int_equal(iot_log_file_read(&handle, buffer, sizeof(buffer), &read_size), IOT_ERROR_BAD_REQ);
    // Then: nothing is reported as read
    assert_int_equal(read_size, 0);

    iot_log_file_exit();
}

TEST(TC_iot_log_file_read_remain_size_capped_neg)
{
    iot_log_file_handle_t handle;
    char buffer[64] = {0};
    size_t read_size = 0;
    UNUSED(state);

    assert_int_equal(_tc_log_file_init(), IOT_ERROR_NONE);
    assert_true(iot_log_file_store(TC_LOG_FILE_SAMPLE_LINE_neg, strlen(TC_LOG_FILE_SAMPLE_LINE_neg)) > 0);

    // Given: a wrapping read whose tail is larger than the bytes before cur_addr
    memset(&handle, 0, sizeof(handle));
    handle.file_type = _tc_log_file_type();
    handle.start_addr = 0;
    handle.cur_addr = 2;
    handle.log_size = 16;
    handle.max_log_size = 16;
    // When: more bytes are requested than the buffer can wrap around to
    assert_int_equal(iot_log_file_read(&handle, buffer, 32, &read_size), IOT_ERROR_NONE);
    // Then: the tail read is capped at the bytes available before cur_addr
    assert_int_equal(read_size, 16);

    iot_log_file_exit();
}

TEST(TC_iot_log_read_bytes_invalid_type_neg)
{
    iot_log_file_handle_t handle;
    char buffer[8] = {0};
    UNUSED(state);

    memset(&handle, 0, sizeof(handle));
    handle.file_type = TC_LOG_FILE_INVALID_TYPE_neg;
    // When: the low level reader is asked for an unsupported backing store
    assert_int_equal(_iot_log_read_bytes(&handle, buffer, sizeof(buffer)), IOT_ERROR_BAD_REQ);
}

TEST(TC_iot_log_file_seek_zero_log_size_neg)
{
    iot_log_file_handle_t handle;
    UNUSED(state);

    memset(&handle, 0, sizeof(handle));
    handle.file_type = _tc_log_file_type();
    handle.log_size = 0;
    // When: the log is empty
    assert_int_equal(iot_log_file_seek(&handle, 0, 0), IOT_ERROR_INVALID_ARGS);
    assert_int_equal(handle.cur_addr, 0);
}

TEST(TC_iot_log_file_seek_offset_beyond_log_size_neg)
{
    iot_log_file_handle_t handle;
    UNUSED(state);

    memset(&handle, 0, sizeof(handle));
    handle.file_type = _tc_log_file_type();
    handle.start_addr = 0;
    handle.log_size = 16;
    // When: an offset far beyond the log size is requested
    assert_int_equal(iot_log_file_seek(&handle, 100, 0), IOT_ERROR_NONE);
    // Then: it silently wraps instead of being rejected
    assert_int_equal(handle.cur_addr, 100 % 16);
}

TEST(TC_iot_log_file_read_zero_size_neg)
{
    iot_log_file_handle_t handle;
    char buffer[8] = {0};
    size_t read_size = 0xdead;
    UNUSED(state);

    assert_int_equal(_tc_log_file_init(), IOT_ERROR_NONE);

    memset(&handle, 0, sizeof(handle));
    handle.file_type = _tc_log_file_type();
    handle.log_size = 16;
    handle.max_log_size = 16;
    // When: nothing is requested
    assert_int_equal(iot_log_file_read(&handle, buffer, 0, &read_size), IOT_ERROR_NONE);
    assert_int_equal(read_size, 0);

    iot_log_file_exit();
}

TEST(TC_iot_log_file_store_max_string_size_neg)
{
    UNUSED(state);

    assert_int_equal(_tc_log_file_init(), IOT_ERROR_NONE);
    // When: exactly the maximum string size is stored, which the guard rejects
    assert_int_equal(iot_log_file_store(TC_LOG_FILE_SAMPLE_LINE_neg, IOT_LOG_FILE_MAX_STRING_SIZE), -1);
    iot_log_file_exit();
}

TEST(TC_iot_log_file_store_after_exit_neg)
{
    UNUSED(state);

    assert_int_equal(_tc_log_file_init(), IOT_ERROR_NONE);
    iot_log_file_exit();
    // When: a log line is stored after the context was torn down
    assert_int_equal(iot_log_file_store(TC_LOG_FILE_SAMPLE_LINE_neg, strlen(TC_LOG_FILE_SAMPLE_LINE_neg)), -1);
}

TEST(TC_iot_log_file_remove_without_init_neg)
{
    UNUSED(state);

    // Given: no log context exists
    iot_log_file_exit();
    // When: the log is removed anyway
    // Then: the missing context is tolerated instead of crashing
    assert_int_equal(iot_log_file_remove(_tc_log_file_type()), IOT_ERROR_NONE);
}

TEST(TC_iot_log_file_remove_unsupported_type_neg)
{
    UNUSED(state);

    assert_int_equal(_tc_log_file_init(), IOT_ERROR_NONE);
    // When: a type this build does not support is removed
    assert_int_equal(iot_log_file_remove(TC_LOG_FILE_INVALID_TYPE_neg), IOT_ERROR_BAD_REQ);
    iot_log_file_exit();
}

TEST(TC_iot_log_file_exit_twice_neg)
{
    UNUSED(state);

    assert_int_equal(_tc_log_file_init(), IOT_ERROR_NONE);
    iot_log_file_exit();
    // When: the context is torn down a second time
    // Then: it must not double free
    iot_log_file_exit();
    assert_int_equal(iot_log_file_store(TC_LOG_FILE_SAMPLE_LINE_neg, 1), -1);
}

TEST(TC_iot_log_file_open_after_exit_neg)
{
    size_t filesize = 0xdead;
    UNUSED(state);

    assert_int_equal(_tc_log_file_init(), IOT_ERROR_NONE);
    iot_log_file_exit();
    // When: the log file is opened after the context was torn down
    assert_null(iot_log_file_open(&filesize, _tc_log_file_type()));
}

TEST(TC_iot_log_file_open_unsupported_type_after_init_neg)
{
    size_t filesize = 0;
    UNUSED(state);

    assert_int_equal(_tc_log_file_init(), IOT_ERROR_NONE);
    // When: a type this build does not support is opened
    assert_null(iot_log_file_open(&filesize, TC_LOG_FILE_INVALID_TYPE_neg));
    iot_log_file_exit();
}

TEST(TC_iot_log_file_read_null_read_size_invalid_type_neg)
{
    iot_log_file_handle_t handle;
    char buffer[8] = {0};
    UNUSED(state);

    assert_int_equal(_tc_log_file_init(), IOT_ERROR_NONE);

    // Given: an unsupported type and no place to report the read size
    memset(&handle, 0, sizeof(handle));
    handle.file_type = TC_LOG_FILE_INVALID_TYPE_neg;
    handle.log_size = 16;
    handle.max_log_size = 16;
    // When
    assert_int_equal(iot_log_file_read(&handle, buffer, sizeof(buffer), NULL), IOT_ERROR_BAD_REQ);

    iot_log_file_exit();
}

TEST(TC_iot_log_file_seek_null_after_close_neg)
{
    iot_log_file_handle_t handle;
    UNUSED(state);

    // Given: a handle whose type this build does not support
    memset(&handle, 0, sizeof(handle));
    handle.file_type = TC_LOG_FILE_INVALID_TYPE_neg;
    handle.log_size = 16;
    // When: a seek is attempted
    assert_int_equal(iot_log_file_seek(&handle, 0, 0), IOT_ERROR_BAD_REQ);
}

#else /* CONFIG_STDK_IOT_CORE_LOG_FILE */

_TC_LOG_FILE_NOOP(TC_iot_log_file_close_flash_type_handle_neg)
_TC_LOG_FILE_NOOP(TC_iot_log_file_close_without_init_neg)
_TC_LOG_FILE_NOOP(TC_iot_log_file_read_wrap_first_read_failure_neg)
_TC_LOG_FILE_NOOP(TC_iot_log_file_read_remain_size_capped_neg)
_TC_LOG_FILE_NOOP(TC_iot_log_read_bytes_invalid_type_neg)
_TC_LOG_FILE_NOOP(TC_iot_log_file_seek_zero_log_size_neg)
_TC_LOG_FILE_NOOP(TC_iot_log_file_seek_offset_beyond_log_size_neg)
_TC_LOG_FILE_NOOP(TC_iot_log_file_read_zero_size_neg)
_TC_LOG_FILE_NOOP(TC_iot_log_file_store_max_string_size_neg)
_TC_LOG_FILE_NOOP(TC_iot_log_file_store_after_exit_neg)
_TC_LOG_FILE_NOOP(TC_iot_log_file_remove_without_init_neg)
_TC_LOG_FILE_NOOP(TC_iot_log_file_remove_unsupported_type_neg)
_TC_LOG_FILE_NOOP(TC_iot_log_file_exit_twice_neg)
_TC_LOG_FILE_NOOP(TC_iot_log_file_open_after_exit_neg)
_TC_LOG_FILE_NOOP(TC_iot_log_file_open_unsupported_type_after_init_neg)
_TC_LOG_FILE_NOOP(TC_iot_log_file_read_null_read_size_invalid_type_neg)
_TC_LOG_FILE_NOOP(TC_iot_log_file_seek_null_after_close_neg)

#endif /* CONFIG_STDK_IOT_CORE_LOG_FILE */
