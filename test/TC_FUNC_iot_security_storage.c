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
#include <security/backend/iot_security_be.h>
#include <security/iot_security_storage.h>
#include <string.h>

#include "TC_MOCK_functions.h"
#include "TC_REGISTRY.h"
#include "cmocka_custom.h"

#define TEST_SECURITY_STORAGE_PRIVATE_KEY "y04i7Pme6rJTkLBPngQoZfEI5KEAyE70A9xOhoX8uTI="
#define TEST_SECURITY_STORAGE_PUBLIC_KEY "Sh4cBHRnPuEFyinaVuEd+mE5IQTkwPHmbOrgD3fwPsw="

extern iot_error_t _iot_security_storage_set_storage_id(iot_security_context_t *context,
                                                        iot_security_storage_id_t storage_id);

TEST_SUITE("iot_security_storage.c");

static int TC_iot_security_storage_init_setup(void **state);
static int TC_iot_security_storage_init_teardown(void **state);
static int TC_iot_security_storage_setup(void **state);
static int TC_iot_security_storage_teardown(void **state);

TEST_FIXTURE(iot_security_storage, TC_iot_security_storage_setup, TC_iot_security_storage_teardown);
TEST_FIXTURE(iot_security_storage_init, TC_iot_security_storage_init_setup, TC_iot_security_storage_init_teardown);

static int TC_iot_security_storage_init_setup(void **state);
static int TC_iot_security_storage_init_teardown(void **state);
static int TC_iot_security_storage_setup(void **state);
static int TC_iot_security_storage_teardown(void **state);

static int TC_iot_security_storage_init_setup(void **state);
static int TC_iot_security_storage_init_teardown(void **state);
static int TC_iot_security_storage_setup(void **state);
static int TC_iot_security_storage_teardown(void **state);

static const char *sample_id = "a3b94a19-4363-4b60-b01e-f3d505898407";

static char sample_device_info[] = {
    "{\n"
    "\t\"deviceInfo\": {\n"
    "\t\t\"firmwareVersion\": \"testFirmwareVersion\",\n"
    "\t\t\"privateKey\": \"" TEST_SECURITY_STORAGE_PRIVATE_KEY
    "\",\n"
    "\t\t\"publicKey\": \"" TEST_SECURITY_STORAGE_PUBLIC_KEY
    "\",\n"
    "\t\t\"serialNumber\": \"STDKtestc77078cc\"\n"
    "\t}\n"
    "}"};

static int TC_iot_security_storage_init_setup(void **state)
{
    iot_error_t err;
    iot_security_context_t *context;

    context = iot_security_init();
    assert_non_null(context);

    *state = context;

    return 0;
}

static int TC_iot_security_storage_init_teardown(void **state)
{
    iot_error_t err;
    iot_security_context_t *context;

    context = (iot_security_context_t *)*state;
    assert_non_null(context);

    err = iot_security_deinit(context);
    assert_int_equal(err, IOT_ERROR_NONE);

    return 0;
}

static int TC_iot_security_storage_setup(void **state)
{
    iot_error_t err;
    iot_security_context_t *context;

    set_mock_detect_memory_leak(true);

#if !defined(CONFIG_STDK_IOT_CORE_SUPPORT_STNV_PARTITION)
    err = iot_nv_init((unsigned char *)sample_device_info, strlen(sample_device_info));
#else
    err = iot_nv_init(NULL, 0);
#endif
    assert_int_equal(err, IOT_ERROR_NONE);

    context = iot_security_init();
    assert_non_null(context);

    err = iot_security_storage_init(context);
    assert_int_equal(err, IOT_ERROR_NONE);

    *state = context;

    return 0;
}

static int TC_iot_security_storage_teardown(void **state)
{
    iot_error_t err;
    iot_security_context_t *context;

    context = (iot_security_context_t *)*state;
    assert_non_null(context);

    err = iot_security_storage_deinit(context);
    assert_int_equal(err, IOT_ERROR_NONE);

    err = iot_security_deinit(context);
    assert_int_equal(err, IOT_ERROR_NONE);

    err = iot_nv_deinit();
    assert_int_equal(err, IOT_ERROR_NONE);

    set_mock_detect_memory_leak(false);

    return 0;
}

TEST_F(iot_security_storage_init, TC_iot_security_storage_init_malloc_failure_neg)
{
    iot_error_t err;
    iot_security_context_t *context;

    context = (iot_security_context_t *)*state;
    assert_non_null(context);

    // Given: malloc failure
    do_not_use_mock_iot_os_malloc_failure();
    set_mock_iot_os_malloc_failure_with_index(0);
    // When
    err = iot_security_storage_init(context);
    // Then
    assert_int_equal(err, IOT_ERROR_MEM_ALLOC);
    // Teardown
    do_not_use_mock_iot_os_malloc_failure();
}

TEST_F(iot_security_storage_init, TC_iot_security_storage_init_null_parameters_neg)
{
    iot_error_t err;

    // When
    err = iot_security_storage_init(NULL);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_CONTEXT_NULL);
}

TEST_F(iot_security_storage_init, TC_iot_security_storage_init_success_pos)
{
    iot_error_t err;
    iot_security_context_t *context;

    context = (iot_security_context_t *)*state;
    assert_non_null(context);

    // When
    err = iot_security_storage_init(context);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    // Teardown
    err = iot_security_storage_deinit(context);
    assert_int_equal(err, IOT_ERROR_NONE);
}

TEST_F(iot_security_storage_init, TC_iot_security_storage_deinit_null_parameters_neg)
{
    iot_error_t err;

    // When
    err = iot_security_storage_deinit(NULL);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_CONTEXT_NULL);
}

TEST_F(iot_security_storage_init, TC_iot_security_storage_deinit_success_pos)
{
    iot_error_t err;
    iot_security_context_t *context;

    context = (iot_security_context_t *)*state;
    assert_non_null(context);

    // Given
    err = iot_security_storage_init(context);
    assert_int_equal(err, IOT_ERROR_NONE);
    // When
    err = iot_security_storage_deinit(context);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
}

typedef iot_error_t (*storage_rw_func)(iot_security_context_t *, iot_security_storage_id_t storage_id,
                                       iot_security_buffer_t *);

static void TC_iot_security_storage_do_null_parameters_neg(iot_security_context_t *context, storage_rw_func rw_func)
{
    iot_error_t err;
    iot_security_storage_id_t storage_id = IOT_NVD_DEVICE_ID;
    iot_security_buffer_t buf = {0};

    assert_non_null(context);
    assert_non_null(rw_func);

    // When: context, buf null
    err = rw_func(NULL, storage_id, NULL);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // When: context null
    err = rw_func(NULL, storage_id, &buf);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // When: buf null
    err = rw_func(context, storage_id, NULL);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

static void TC_iot_security_storage_do_invalid_parameters_neg(iot_security_context_t *context, storage_rw_func rw_func,
                                                              char rw)
{
    iot_error_t err;
    iot_security_storage_id_t storage_id = IOT_NVD_DEVICE_ID;
    iot_security_buffer_t buf = {0};
    const char *sample = "1c83f234-9a53-11ea-b2e2-8f936ceb1180";

    assert_non_null(context);
    assert_non_null(rw_func);

    if (rw == 'W') {
        // When: buffer doesn't have data
        err = rw_func(context, storage_id, &buf);
        // Then
        assert_int_not_equal(err, IOT_ERROR_NONE);

        // Given: buffer len is zero
        buf.p = (unsigned char *)sample_id;
        buf.len = 0;
        // When
        err = rw_func(context, storage_id, &buf);
        // Then
        assert_int_not_equal(err, IOT_ERROR_NONE);

        // Given: buffer pointer is null
        buf.p = NULL;
        buf.len = strlen((char *)sample_id);
        // When
        err = rw_func(context, storage_id, &buf);
        // Then
        assert_int_not_equal(err, IOT_ERROR_NONE);
    }

    // Given: storage id invalid
    storage_id = IOT_NVD_UNKNOWN;
    buf.p = (unsigned char *)sample;
    buf.len = strlen(sample);
    // When
    err = rw_func(context, storage_id, &buf);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

TEST_F(iot_security_storage, TC_iot_security_storage_read_malloc_failure_neg)
{
    iot_error_t err;
    iot_security_context_t *context;
    iot_security_storage_id_t storage_id = IOT_NVD_DEVICE_ID;
    iot_security_buffer_t buf = {0};
    iot_security_buffer_t sample_buf = {0};
    const char *sample = "1c83f234-9a53-11ea-b2e2-8f936ceb1180";

    context = (iot_security_context_t *)*state;
    assert_non_null(context);

    // Given: prepare sample file
    sample_buf.p = (unsigned char *)sample;
    sample_buf.len = strlen(sample);
    err = iot_security_storage_write(context, storage_id, &sample_buf);
    assert_int_equal(err, IOT_ERROR_NONE);

    for (int i = 0; i < 1; i++) {
        // Given: i-th malloc failure
        do_not_use_mock_iot_os_malloc_failure();
        set_mock_iot_os_malloc_failure_with_index(i);
        // When: valid input
        err = iot_security_storage_read(context, storage_id, &buf);
        // Then
        assert_int_equal(err, IOT_ERROR_MEM_ALLOC);
    }

    // Teardown
    do_not_use_mock_iot_os_malloc_failure();
}

TEST_F(iot_security_storage, TC_iot_security_storage_read_null_parameters_neg)
{
    iot_security_context_t *context;

    context = (iot_security_context_t *)*state;
    assert_non_null(context);

    TC_iot_security_storage_do_null_parameters_neg(context, iot_security_storage_read);
}

TEST_F(iot_security_storage, TC_iot_security_storage_read_invalid_parameters_neg)
{
    iot_security_context_t *context;

    context = (iot_security_context_t *)*state;
    assert_non_null(context);

    TC_iot_security_storage_do_invalid_parameters_neg(context, iot_security_storage_read, 'R');
}

TEST_F(iot_security_storage_init, TC_iot_security_storage_read_failure_neg)
{
    iot_error_t err;
    iot_security_context_t *context;
    iot_security_storage_id_t storage_id = IOT_NVD_DEVICE_ID;
    iot_security_buffer_t buf = {0};

    context = (iot_security_context_t *)*state;
    assert_non_null(context);

    // When: read without storage_init
    err = iot_security_storage_read(context, storage_id, &buf);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

TEST_F(iot_security_storage, TC_iot_security_storage_read_success_pos)
{
    iot_error_t err;
    iot_security_context_t *context;
    iot_security_storage_id_t storage_id = IOT_NVD_DEVICE_ID;
    iot_security_buffer_t buf = {0};
    iot_security_buffer_t sample_buf = {0};
    const char *sample = "1c83f234-9a53-11ea-b2e2-8f936ceb1180";

    context = (iot_security_context_t *)*state;
    assert_non_null(context);

    // Given: cleanup sample file
    iot_security_storage_remove(context, storage_id);

    // Given: prepare sample file
    sample_buf.p = (unsigned char *)sample;
    sample_buf.len = strlen(sample);
    err = iot_security_storage_write(context, storage_id, &sample_buf);
    assert_int_equal(err, IOT_ERROR_NONE);
    // When
    err = iot_security_storage_read(context, storage_id, &buf);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(buf.p);
    assert_int_equal(buf.len, sample_buf.len);
    assert_memory_equal(buf.p, sample_buf.p, sample_buf.len);
    // Teardown
    iot_os_free(buf.p);

    // Given: id of factory nv
    storage_id = IOT_NVD_PUBLIC_KEY;
    sample_buf.p = (unsigned char *)TEST_SECURITY_STORAGE_PUBLIC_KEY;
    sample_buf.len = strlen(sample_buf.p);
    // When
    err = iot_security_storage_read(context, storage_id, &buf);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(buf.p);
    assert_int_equal(buf.len, sample_buf.len);
    assert_memory_equal(buf.p, sample_buf.p, sample_buf.len);
    // Teardown
    iot_os_free(buf.p);
}

TEST_F(iot_security_storage, TC_iot_security_storage_write_null_parameters_neg)
{
    iot_security_context_t *context;

    context = (iot_security_context_t *)*state;
    assert_non_null(context);

    TC_iot_security_storage_do_null_parameters_neg(context, iot_security_storage_write);
}

TEST_F(iot_security_storage, TC_iot_security_storage_write_invalid_parameters_neg)
{
    iot_security_context_t *context;

    context = (iot_security_context_t *)*state;
    assert_non_null(context);

    TC_iot_security_storage_do_invalid_parameters_neg(context, iot_security_storage_write, 'W');
}

TEST_F(iot_security_storage, TC_iot_security_storage_write_failure_neg)
{
    iot_error_t err;
    iot_security_context_t *context;
    iot_security_storage_id_t storage_id = IOT_NVD_DEVICE_ID;
    iot_security_buffer_t sample_buf = {0};
    const char *sample = "1c83f234-9a53-11ea-b2e2-8f936ceb1180";

    context = (iot_security_context_t *)*state;
    assert_non_null(context);

    // Given: prepare data
    sample_buf.p = (unsigned char *)sample;
    sample_buf.len = strlen(sample);

    // Given: factory file
    storage_id = IOT_NVD_PUBLIC_KEY;
    // When
    err = iot_security_storage_write(context, storage_id, &sample_buf);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_FS_INVALID_TARGET);

    // Given: write without storage_init
    context = iot_security_init();
    assert_non_null(context);
    // When
    err = iot_security_storage_write(context, storage_id, &sample_buf);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    // Teardown
    iot_security_deinit(context);
}

TEST_F(iot_security_storage, TC_iot_security_storage_write_success_pos)
{
    iot_error_t err;
    iot_security_context_t *context;
    iot_security_storage_id_t storage_id = IOT_NVD_DEVICE_ID;
    iot_security_buffer_t sample_buf = {0};
    const char *sample = "1c83f234-9a53-11ea-b2e2-8f936ceb1180";

    context = (iot_security_context_t *)*state;
    assert_non_null(context);

    // Given: prepare data
    sample_buf.p = (unsigned char *)sample;
    sample_buf.len = strlen(sample);
    // When
    err = iot_security_storage_write(context, storage_id, &sample_buf);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
}

TEST_F(iot_security_storage, TC_iot_security_storage_remove_null_parameters_neg)
{
    iot_error_t err;
    iot_security_context_t *context;
    iot_security_storage_id_t storage_id = IOT_NVD_DEVICE_ID;

    context = (iot_security_context_t *)*state;
    assert_non_null(context);

    // When: context is null
    err = iot_security_storage_remove(NULL, storage_id);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

TEST_F(iot_security_storage, TC_iot_security_storage_remove_invalid_parameters_neg)
{
    iot_error_t err;
    iot_security_context_t *context;
    iot_security_storage_id_t storage_id;

    context = (iot_security_context_t *)*state;
    assert_non_null(context);

    // Given: storage id invalid
    storage_id = IOT_NVD_UNKNOWN;
    // When
    err = iot_security_storage_remove(context, storage_id);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

TEST_F(iot_security_storage, TC_iot_security_storage_remove_failure_neg)
{
    iot_error_t err;
    iot_security_context_t *context;
    iot_security_storage_id_t storage_id = IOT_NVD_DEVICE_ID;

    context = (iot_security_context_t *)*state;
    assert_non_null(context);

    // Given: factory file
    storage_id = IOT_NVD_PUBLIC_KEY;
    // When
    err = iot_security_storage_remove(context, storage_id);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_FS_INVALID_TARGET);

    // Given: remove without storage_init
    context = iot_security_init();
    assert_non_null(context);
    // When
    err = iot_security_storage_remove(context, storage_id);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    // Teardown
    iot_security_deinit(context);
}

TEST_F(iot_security_storage, TC_iot_security_storage_remove_success_pos)
{
    iot_error_t err;
    iot_security_context_t *context;
    iot_security_storage_id_t storage_id = IOT_NVD_DEVICE_ID;
    iot_security_buffer_t sample_buf = {0};
    const char *sample = "1c83f234-9a53-11ea-b2e2-8f936ceb1180";

    context = (iot_security_context_t *)*state;
    assert_non_null(context);

    // Given: prepare sample file
    sample_buf.p = (unsigned char *)sample;
    sample_buf.len = strlen(sample);
    err = iot_security_storage_write(context, storage_id, &sample_buf);
    assert_int_equal(err, IOT_ERROR_NONE);
    // When
    err = iot_security_storage_remove(context, storage_id);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
}

/*
 * A backend function table can be partially populated (or its calls can fail).
 * The helpers below build such a backend so the guard paths of
 * iot_security_storage.c can be reached without a real backend.
 */

static iot_error_t _tc_storage_be_fail(iot_security_context_t *context)
{
    return IOT_ERROR_SECURITY_FS_OPEN;
}

typedef struct {
    iot_security_context_t context;
    iot_security_be_context_t be_context;
    iot_security_be_funcs_t fn;
    iot_security_storage_params_t storage_params;
} tc_storage_fake_be_t;

static void _tc_storage_fake_be_init(tc_storage_fake_be_t *fake)
{
    memset(fake, 0, sizeof(*fake));
    fake->be_context.fn = &fake->fn;
    fake->context.be_context = &fake->be_context;
    fake->context.storage_params = &fake->storage_params;
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_iot_security_storage_set_storage_id_context_null_neg)
{
    // When
    iot_error_t err = _iot_security_storage_set_storage_id(NULL, IOT_NVD_DEVICE_ID);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_CONTEXT_NULL);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_iot_security_storage_set_storage_id_params_null_neg)
{
    iot_security_context_t context = {0};

    // When: the storage params were never allocated
    iot_error_t err = _iot_security_storage_set_storage_id(&context, IOT_NVD_DEVICE_ID);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_STORAGE_PARAMS_NULL);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_iot_security_storage_set_storage_id_below_range_neg)
{
    tc_storage_fake_be_t fake;

    _tc_storage_fake_be_init(&fake);
    // When: the id is at or below the lower bound
    iot_error_t err = _iot_security_storage_set_storage_id(&fake.context, IOT_NVD_UNKNOWN);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_STORAGE_INVALID_ID);
    assert_int_equal(fake.storage_params.storage_id, 0);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_iot_security_storage_set_storage_id_above_range_neg)
{
    tc_storage_fake_be_t fake;

    _tc_storage_fake_be_init(&fake);
    // When: the id is at or above the upper bound
    iot_error_t err = _iot_security_storage_set_storage_id(&fake.context, IOT_NVD_MAX);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_STORAGE_INVALID_ID);
    assert_int_equal(fake.storage_params.storage_id, 0);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_iot_security_storage_init_be_failure_neg)
{
    tc_storage_fake_be_t fake;
    iot_error_t err;

    // Given: a backend whose storage_init fails
    _tc_storage_fake_be_init(&fake);
    fake.context.storage_params = NULL;
    fake.fn.storage_init = _tc_storage_be_fail;
    // When
    err = iot_security_storage_init(&fake.context);
    // Then: the params allocated by init must be rolled back
    assert_int_equal(err, IOT_ERROR_SECURITY_FS_OPEN);
    assert_null(fake.context.storage_params);
    assert_int_equal(fake.context.sub_system & IOT_SECURITY_SUB_STORAGE, 0);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_iot_security_storage_deinit_be_failure_neg)
{
    tc_storage_fake_be_t fake;
    iot_error_t err;

    // Given: a backend whose storage_deinit fails
    _tc_storage_fake_be_init(&fake);
    fake.context.sub_system = IOT_SECURITY_SUB_STORAGE;
    fake.fn.storage_deinit = _tc_storage_be_fail;
    // When
    err = iot_security_storage_deinit(&fake.context);
    // Then: the params must be kept so the caller can retry
    assert_int_equal(err, IOT_ERROR_SECURITY_FS_OPEN);
    assert_non_null(fake.context.storage_params);
    assert_int_equal(fake.context.sub_system, IOT_SECURITY_SUB_STORAGE);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_iot_security_storage_read_be_func_null_neg)
{
    tc_storage_fake_be_t fake;
    iot_security_buffer_t buf;
    iot_error_t err;

    // Given: a function table without storage_read
    _tc_storage_fake_be_init(&fake);
    memset(&buf, 0xA5, sizeof(buf));
    // When
    err = iot_security_storage_read(&fake.context, IOT_NVD_DEVICE_ID, &buf);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_BE_FUNC_NULL);
    assert_null(buf.p);
    assert_int_equal(buf.len, 0);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_iot_security_storage_write_be_func_null_neg)
{
    tc_storage_fake_be_t fake;
    unsigned char data[] = "payload";
    iot_security_buffer_t buf = {.p = data, .len = sizeof(data) - 1};
    iot_error_t err;

    // Given: a function table without storage_write
    _tc_storage_fake_be_init(&fake);
    // When
    err = iot_security_storage_write(&fake.context, IOT_NVD_DEVICE_ID, &buf);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_BE_FUNC_NULL);
}

TEST_F(TC_REGISTRY_NO_FIXTURE, TC_iot_security_storage_remove_be_func_null_neg)
{
    tc_storage_fake_be_t fake;
    iot_error_t err;

    // Given: a function table without storage_remove
    _tc_storage_fake_be_init(&fake);
    // When
    err = iot_security_storage_remove(&fake.context, IOT_NVD_DEVICE_ID);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_BE_FUNC_NULL);
}

TEST_F(iot_security_storage, TC_iot_security_storage_read_removed_id_neg)
{
    iot_error_t err;
    iot_security_context_t *context;
    iot_security_storage_id_t storage_id = IOT_NVD_DEVICE_ID;
    iot_security_buffer_t buf = {0};
    iot_security_buffer_t sample_buf = {0};
    const char *sample = "1c83f234-9a53-11ea-b2e2-8f936ceb1180";

    context = (iot_security_context_t *)*state;
    assert_non_null(context);

    // Given: the entry exists and is then removed
    sample_buf.p = (unsigned char *)sample;
    sample_buf.len = strlen(sample);
    err = iot_security_storage_write(context, storage_id, &sample_buf);
    assert_int_equal(err, IOT_ERROR_NONE);
    err = iot_security_storage_remove(context, storage_id);
    assert_int_equal(err, IOT_ERROR_NONE);
    // When
    err = iot_security_storage_read(context, storage_id, &buf);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_FS_NOT_FOUND);
    assert_null(buf.p);
}
