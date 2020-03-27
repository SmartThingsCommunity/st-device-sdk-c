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
#include <iot_error.h>
#include <iot_mqtt.h>
#include <iot_internal.h>
#include <mqtt/iot_mqtt_client.h>
#include "TC_MOCK_functions.h"
#define UNUSED(x) (void**)(x)

void TC_st_mqtt_create_success(void** state)
{
    int err;
    st_mqtt_client client;
    MQTTClient *internal_client;
    UNUSED(state);

    // Given
    set_mock_detect_memory_leak(true);
    // When
    err = st_mqtt_create(&client, 150);
    // Then
    assert_return_code(err, 0);
    internal_client = (MQTTClient*) client;
    assert_int_equal(internal_client->command_timeout_ms, 150);
    // Teardown
    st_mqtt_destroy(client);
    set_mock_detect_memory_leak(false);
}