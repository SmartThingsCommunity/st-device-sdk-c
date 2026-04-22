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
#include "cmocka_custom.h"

#define UNUSED(x) (void **)(x)

#if defined(CONFIG_STDK_IOT_CORE_LOG_FILE)

#define TC_LOG_FILE_INVALID_TYPE ((iot_log_file_type_t)0xFE)
#define TC_LOG_FILE_SAMPLE_LINE "iot_log_file_test_sample_log_line\n"

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
    return TC_LOG_FILE_INVALID_TYPE;
#endif
}

/*
 * iot_log_file_init tests
 */
void TC_iot_log_file_init_success(void **state)
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

void TC_iot_log_file_init_invalid_type(void **state)
{
    iot_error_t err;
    UNUSED(state);

    // When: pass an unsupported type
    err = iot_log_file_init(TC_LOG_FILE_INVALID_TYPE);
    // Then
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);
}

void TC_iot_log_file_init_ctx_alloc_failure(void **state)
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

void TC_iot_log_file_init_double_init(void **state)
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
void TC_iot_log_file_exit_success(void **state)
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

void TC_iot_log_file_exit_without_init(void **state)
{
    UNUSED(state);

    // When: exit is called without prior init
    iot_log_file_exit();
    // Then: no crash; subsequent exits are still safe
    iot_log_file_exit();
}

/*
 * iot_log_file_store tests
 */
void TC_iot_log_file_store_success(void **state)
{
    iot_error_t err;
    const char *msg = TC_LOG_FILE_SAMPLE_LINE;
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

void TC_iot_log_file_store_without_init(void **state)
{
    int written;
    const char *msg = TC_LOG_FILE_SAMPLE_LINE;
    UNUSED(state);

    // When: no init was called; global log_ctx should be NULL
    written = iot_log_file_store(msg, strlen(msg));
    // Then
    assert_int_equal(written, -1);
}

void TC_iot_log_file_store_zero_size(void **state)
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

void TC_iot_log_file_store_oversize(void **state)
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

void TC_iot_log_file_store_disabled_buffer(void **state)
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
void TC_iot_log_file_sync_without_events(void **state)
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
void TC_iot_log_file_open_success(void **state)
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

void TC_iot_log_file_open_without_init(void **state)
{
    iot_log_file_handle_t *handle;
    size_t filesize = 0;
    UNUSED(state);

    // When: log_ctx is NULL because init was not called
    handle = iot_log_file_open(&filesize, _tc_log_file_type());
    // Then
    assert_null(handle);
}

void TC_iot_log_file_open_invalid_type(void **state)
{
    iot_error_t err;
    iot_log_file_handle_t *handle;
    size_t filesize = 0;
    UNUSED(state);

    err = (iot_error_t)_tc_log_file_init();
    assert_int_equal(err, IOT_ERROR_NONE);

    // When: unsupported file_type triggers default branch
    handle = iot_log_file_open(&filesize, TC_LOG_FILE_INVALID_TYPE);
    // Then
    assert_null(handle);

    iot_log_file_exit();
}

void TC_iot_log_file_open_alloc_failure(void **state)
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

void TC_iot_log_file_open_after_overridden(void **state)
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
void TC_iot_log_file_close_success(void **state)
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

void TC_iot_log_file_close_null_handle(void **state)
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
void TC_iot_log_file_seek_success(void **state)
{
    iot_error_t err;
    iot_log_file_handle_t *handle;
    size_t filesize = 0;
    const char *msg = TC_LOG_FILE_SAMPLE_LINE;
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

void TC_iot_log_file_seek_empty_log(void **state)
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

void TC_iot_log_file_seek_negative_offset(void **state)
{
    iot_error_t err;
    iot_log_file_handle_t *handle;
    size_t filesize = 0;
    const char *msg = TC_LOG_FILE_SAMPLE_LINE;
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

void TC_iot_log_file_seek_invalid_type(void **state)
{
    iot_error_t err;
    iot_log_file_handle_t *handle;
    size_t filesize = 0;
    const char *msg = TC_LOG_FILE_SAMPLE_LINE;
    UNUSED(state);

    err = (iot_error_t)_tc_log_file_init();
    assert_int_equal(err, IOT_ERROR_NONE);
    (void)iot_log_file_store(msg, strlen(msg));

    handle = iot_log_file_open(&filesize, _tc_log_file_type());
    assert_non_null(handle);
    // Given: corrupt file_type to hit default branch
    handle->file_type = TC_LOG_FILE_INVALID_TYPE;

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
void TC_iot_log_file_read_success(void **state)
{
    iot_error_t err;
    iot_log_file_handle_t *handle;
    size_t filesize = 0;
    size_t read_size = 0;
    const char *msg = TC_LOG_FILE_SAMPLE_LINE;
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

void TC_iot_log_file_read_null_handle(void **state)
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

void TC_iot_log_file_read_null_buffer(void **state)
{
    iot_error_t err;
    iot_log_file_handle_t *handle;
    size_t filesize = 0;
    size_t read_size = 0;
    const char *msg = TC_LOG_FILE_SAMPLE_LINE;
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

void TC_iot_log_file_read_no_read_size_out(void **state)
{
    iot_error_t err;
    iot_log_file_handle_t *handle;
    size_t filesize = 0;
    const char *msg = TC_LOG_FILE_SAMPLE_LINE;
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

void TC_iot_log_file_read_wrap_around(void **state)
{
#if defined(CONFIG_STDK_IOT_CORE_LOG_FILE_RAM_ONLY)
    iot_error_t err;
    iot_log_file_handle_t *handle;
    size_t filesize = 0;
    size_t read_size = 0;
    const char *msg = TC_LOG_FILE_SAMPLE_LINE;
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

void TC_iot_log_file_read_invalid_type(void **state)
{
    iot_error_t err;
    iot_log_file_handle_t *handle;
    size_t filesize = 0;
    size_t read_size = 0;
    const char *msg = TC_LOG_FILE_SAMPLE_LINE;
    char out[8];
    UNUSED(state);

    err = (iot_error_t)_tc_log_file_init();
    assert_int_equal(err, IOT_ERROR_NONE);
    (void)iot_log_file_store(msg, strlen(msg));

    handle = iot_log_file_open(&filesize, _tc_log_file_type());
    assert_non_null(handle);
    // Given
    handle->file_type = TC_LOG_FILE_INVALID_TYPE;

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
void TC_iot_log_file_remove_success(void **state)
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

void TC_iot_log_file_remove_invalid_type(void **state)
{
    iot_error_t err;
    UNUSED(state);

    err = (iot_error_t)_tc_log_file_init();
    assert_int_equal(err, IOT_ERROR_NONE);

    // When
    err = iot_log_file_remove(TC_LOG_FILE_INVALID_TYPE);
    // Then
    assert_int_equal(err, IOT_ERROR_BAD_REQ);

    iot_log_file_exit();
}

#else  /* CONFIG_STDK_IOT_CORE_LOG_FILE */

/*
 * Log file feature is disabled.  Provide no-op placeholders so tests compile
 * cleanly when the feature is off.  Each will simply report success.
 */
#define _TC_LOG_FILE_NOOP(name)           \
    void name(void **state)               \
    {                                     \
        UNUSED(state);                    \
    }

_TC_LOG_FILE_NOOP(TC_iot_log_file_init_success)
_TC_LOG_FILE_NOOP(TC_iot_log_file_init_invalid_type)
_TC_LOG_FILE_NOOP(TC_iot_log_file_init_ctx_alloc_failure)
_TC_LOG_FILE_NOOP(TC_iot_log_file_init_double_init)
_TC_LOG_FILE_NOOP(TC_iot_log_file_exit_success)
_TC_LOG_FILE_NOOP(TC_iot_log_file_exit_without_init)
_TC_LOG_FILE_NOOP(TC_iot_log_file_store_success)
_TC_LOG_FILE_NOOP(TC_iot_log_file_store_without_init)
_TC_LOG_FILE_NOOP(TC_iot_log_file_store_zero_size)
_TC_LOG_FILE_NOOP(TC_iot_log_file_store_oversize)
_TC_LOG_FILE_NOOP(TC_iot_log_file_store_disabled_buffer)
_TC_LOG_FILE_NOOP(TC_iot_log_file_sync_without_events)
_TC_LOG_FILE_NOOP(TC_iot_log_file_open_success)
_TC_LOG_FILE_NOOP(TC_iot_log_file_open_without_init)
_TC_LOG_FILE_NOOP(TC_iot_log_file_open_invalid_type)
_TC_LOG_FILE_NOOP(TC_iot_log_file_open_alloc_failure)
_TC_LOG_FILE_NOOP(TC_iot_log_file_open_after_overridden)
_TC_LOG_FILE_NOOP(TC_iot_log_file_close_success)
_TC_LOG_FILE_NOOP(TC_iot_log_file_close_null_handle)
_TC_LOG_FILE_NOOP(TC_iot_log_file_seek_success)
_TC_LOG_FILE_NOOP(TC_iot_log_file_seek_empty_log)
_TC_LOG_FILE_NOOP(TC_iot_log_file_seek_negative_offset)
_TC_LOG_FILE_NOOP(TC_iot_log_file_seek_invalid_type)
_TC_LOG_FILE_NOOP(TC_iot_log_file_read_success)
_TC_LOG_FILE_NOOP(TC_iot_log_file_read_null_handle)
_TC_LOG_FILE_NOOP(TC_iot_log_file_read_null_buffer)
_TC_LOG_FILE_NOOP(TC_iot_log_file_read_no_read_size_out)
_TC_LOG_FILE_NOOP(TC_iot_log_file_read_wrap_around)
_TC_LOG_FILE_NOOP(TC_iot_log_file_read_invalid_type)
_TC_LOG_FILE_NOOP(TC_iot_log_file_remove_success)
_TC_LOG_FILE_NOOP(TC_iot_log_file_remove_invalid_type)

#endif /* CONFIG_STDK_IOT_CORE_LOG_FILE */
