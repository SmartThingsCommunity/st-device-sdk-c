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
#include <iot_error.h>
#include <stdio.h>
#include <iot_easysetup.h>
#include "../src/easysetup/http/easysetup_http.h"

#define UNUSED(x) (void**)(x)

static char *gen_get_method_payload(char* uri)
{
    char buffer[2048] = {0, };
    char *client_http_header_set = "User-Agent: Mozilla/5.0\r\n"
                                   "Accept-Language: en-US,en;q=0.5\r\n"
                                   "Connection: keep-alive\r\n"
                                   "Cache-Control: max-age=0\r\n";
    int len = 0;

    len = snprintf(buffer, sizeof(buffer), "GET %s HTTP/1.1\r\n", uri);
    assert_true(len > 0);
    strncat(buffer, client_http_header_set, sizeof(buffer) - len);
    return strdup(buffer);
}

struct cgi_method_test_map {
    char *method;
    int command;
    int type;
};

void TC_es_msg_parser_VALID_GET_METHOD(void **state)
{
    iot_error_t err;
    int command = -1;
    int type = -1;
    size_t contents_len = 0;
    struct cgi_method_test_map map[] = {
            {IOT_ES_URI_GET_DEVICEINFO, IOT_EASYSETUP_STEP_DEVICEINFO, D2D_GET},
            {IOT_ES_URI_GET_WIFISCANINFO, IOT_EASYSETUP_STEP_WIFISCANINFO, D2D_GET},
            {IOT_ES_URI_GET_LOGS_SYSTEMINFO, IOT_EASYSETUP_STEP_LOG_SYSTEMINFO, D2D_GET},
            {IOT_ES_URI_GET_LOGS_DUMP, IOT_EASYSETUP_STEP_LOG_GET_DUMP, D2D_GET},
    };
    UNUSED(state);

    for (int i = 0; i < sizeof(map)/sizeof(struct cgi_method_test_map); i++) {
        // Given
        char *test_payload = gen_get_method_payload(map[i].method);
        // When
        err = es_msg_parser(test_payload, strlen(test_payload), NULL, &command, &type, &contents_len);
        // Then
        assert_int_equal(err, IOT_ERROR_NONE);
        assert_int_equal(command, map[i].command);
        assert_int_equal(type, map[i].type);
        // Teardown
        free(test_payload);
    }
}

void TC_es_msg_parser_INVALID_GET_METHOD(void **state)
{
    iot_error_t err;
    int command = -1;
    int type = -1;
    size_t contents_len = 0;
    UNUSED(state);

    // Given: unknown url
    char unknown_url[] = "GET /nowhere HTTP/1.1\r\n"
                        "User-Agent: Mozilla/5.0\r\n"
                        "Accept-Language: en-US,en;q=0.5\r\n"
                        "Connection: keep-alive\r\n"
                        "Cache-Control: max-age=0\r\n";
    // When
    err = es_msg_parser(unknown_url, strlen(unknown_url), NULL, &command, &type, &contents_len);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_int_equal(command, IOT_EASYSETUP_INVALID_STEP);

    // Given: invalid method
    char invalid_method[] = "GOT /deviceinfo HTTP/1.1\r\n"
                           "User-Agent: Mozilla/5.0\r\n"
                           "Accept-Language: en-US,en;q=0.5\r\n"
                           "Connection: keep-alive\r\n"
                           "Cache-Control: max-age=0\r\n";
    // When
    err = es_msg_parser(invalid_method, strlen(invalid_method), NULL, &command, &type, &contents_len);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_int_equal(command, IOT_EASYSETUP_INVALID_STEP);
}