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
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <iot_debug.h>
#include <iot_dump_log.h>
#include <iot_internal.h>

#include "TC_MOCK_functions.h"

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
        "}"
};

void TC_iot_dump_create_dump_state_failure(void **state)
{
    struct iot_context *context = NULL;
    char *buf = NULL;
    size_t size = 0;
    int mode = 0;
    iot_error_t err;

    err = iot_dump_create_all_log_dump(context, &buf, 1, &size, mode);
    assert_int_not_equal(err, IOT_ERROR_NONE);

    mode = IOT_DUMP_MODE_NEED_BASE64 | IOT_DUMP_MODE_NEED_DUMP_STATE;
    for (int i = 0; i < 3; i++) {
        do_not_use_mock_iot_os_malloc_failure();
        set_mock_iot_os_malloc_failure_with_index(i);

        err = iot_dump_create_all_log_dump(context, &buf, 500, &size, mode);
        assert_int_not_equal(err, IOT_ERROR_NONE);
    }
    do_not_use_mock_iot_os_malloc_failure();
}

void TC_iot_dump_create_dump_state_success(void **state)
{
    struct iot_context *context = NULL;
    char *buf = NULL;
    size_t size = 0;
    int mode = 0;
    iot_error_t err;

    struct iot_device_info *device_info;

    err = iot_dump_create_all_log_dump(context, &buf, 500, &size, mode);
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(buf);
    assert_true(size > 0);
    free(buf);

    context = (struct iot_context *) malloc((sizeof(struct iot_context)));
    memset(context, 0, sizeof(struct iot_context));
    device_info = &context->device_info;
    err = iot_api_device_info_load(sample_device_info, sizeof(sample_device_info), device_info);
    assert_int_equal(err, IOT_ERROR_NONE);

    mode = IOT_DUMP_MODE_NEED_BASE64 | IOT_DUMP_MODE_NEED_DUMP_STATE;
    err = iot_dump_create_all_log_dump(context, &buf, 2048, &size, mode);
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(buf);
    assert_true(size > 0);
    free(buf);

    iot_api_device_info_mem_free(device_info);
    free(context);
}
void TC_iot_dump_log(void **state)
{
    iot_dump_log(IOT_DEBUG_LEVEL_ERROR, 0xffffffff, 0, 0);
    iot_dump_log(IOT_DEBUG_LEVEL_WARN, 0xffffffff, 0, 0);
    iot_dump_log(IOT_DEBUG_LEVEL_INFO, 0xffffffff, 0, 0);
    iot_dump_log(IOT_DEBUG_LEVEL_DEBUG, 0xffffffff, 0, 0);
}
