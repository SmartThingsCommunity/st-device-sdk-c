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
    char *client_http_header_set = "User-Agent: Android/Oneapp StdkD2DHttpClient\r\n"
                                   "Host: 192.168.4.1:8888\r\n"
                                   "Connection: Keep-Alive\r\n"
                                   "Accept-Encoding: gzip\r\n\r\n";
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
    char post_body[64];
};

void TC_es_msg_parser_VALID_GET_METHOD(void **state)
{
    iot_error_t err;
    int command = -1;
    int type = -1;
    size_t contents_len = 0;
    struct cgi_method_test_map map[] = {
            {IOT_ES_URI_GET_DEVICEINFO, IOT_EASYSETUP_STEP_DEVICEINFO, D2D_GET, ""},
            {IOT_ES_URI_GET_WIFISCANINFO, IOT_EASYSETUP_STEP_WIFISCANINFO, D2D_GET, ""},
            {IOT_ES_URI_GET_LOGS_SYSTEMINFO, IOT_EASYSETUP_STEP_LOG_SYSTEMINFO, D2D_GET, ""},
            {IOT_ES_URI_GET_LOGS_DUMP, IOT_EASYSETUP_STEP_LOG_GET_DUMP, D2D_GET, ""},
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
                         "User-Agent: Android/Oneapp StdkD2DHttpClient\r\n"
                         "Host: 192.168.4.1:8888\r\n"
                         "Connection: Keep-Alive\r\n"
                         "Accept-Encoding: gzip\r\n\r\n";
    // When
    err = es_msg_parser(unknown_url, strlen(unknown_url), NULL, &command, &type, &contents_len);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_int_equal(command, IOT_EASYSETUP_INVALID_STEP);

    // Given: invalid method
    char invalid_method[] = "GOT /deviceinfo HTTP/1.1\r\n"
                            "User-Agent: Android/Oneapp StdkD2DHttpClient\r\n"
                            "Host: 192.168.4.1:8888\r\n"
                            "Connection: Keep-Alive\r\n"
                            "Accept-Encoding: gzip\r\n\r\n";
    // When
    err = es_msg_parser(invalid_method, strlen(invalid_method), NULL, &command, &type, &contents_len);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_int_equal(command, IOT_EASYSETUP_INVALID_STEP);
}

#define TC_POST_CONTENT "test content"

static char *gen_post_method_payload(char* uri, char* body)
{
    char buffer[2048] = {0, };
    char *client_http_header_1 = "User-Agent: Android/Oneapp SDKClient\r\n"
                                 "Content-Type: application/json; charset=UTF-8\r\n";
    char *client_http_header_2 = "Host: 192.168.4.1:8888\r\n"
                                 "Connection: Keep-Alive\r\n"
                                 "Accept-Encoding: gzip\r\n";
    int len = 0;

    len = snprintf(buffer, sizeof(buffer), "POST %s HTTP/1.1\r\n%sContent-Length: %zu\r\n%s\r\n%s",
                   uri, client_http_header_1, strlen(body), client_http_header_2, body);
    assert_true(len > 0);

    return strdup(buffer);
}

void TC_es_msg_parser_VALID_POST_METHOD(void** state)
{
    iot_error_t err;
    int command;
    int type;
    size_t contents_len;
    char *parsed_content;
    struct cgi_method_test_map map[] = {
            {IOT_ES_URI_POST_KEYINFO, IOT_EASYSETUP_STEP_KEYINFO, D2D_POST, "Key Info Body"},
            {IOT_ES_URI_POST_CONFIRMINFO, IOT_EASYSETUP_STEP_CONFIRMINFO, D2D_POST, "Confirm Info Body"},
            {IOT_ES_URI_POST_CONFIRM, IOT_EASYSETUP_STEP_CONFIRM, D2D_POST, "Confirm Body"},
            {IOT_ES_URI_POST_WIFIPROVISIONINGINFO, IOT_EASYSETUP_STEP_WIFIPROVIONINGINFO, D2D_POST, "WiFiProvisioning Body"},
            {IOT_ES_URI_POST_SETUPCOMPLETE, IOT_EASYSETUP_STEP_SETUPCOMPLETE, D2D_POST, ""},
            {IOT_ES_URI_POST_LOGS, IOT_EASYSETUP_STEP_LOG_CREATE_DUMP, D2D_POST, "Log body"}
    };
    UNUSED(state);

    for (int i = 0; i < sizeof(map)/sizeof(struct cgi_method_test_map); i++) {
        // Given
        char *in_payload = gen_post_method_payload(map[i].method, map[i].post_body);
        parsed_content = NULL;
        contents_len = 0;
        command = -1;
        type = -1;
        // When
        err = es_msg_parser(in_payload, strlen(in_payload), &parsed_content, &command, &type, &contents_len);
        // Then
        assert_int_equal(err, IOT_ERROR_NONE);
        assert_int_equal(command, map[i].command);
        if (parsed_content != NULL) {
            assert_string_equal(parsed_content, map[i].post_body);
        }
        assert_int_equal(type, map[i].type);
        assert_int_equal(contents_len, strlen(map[i].post_body));
        // Teardown
        free(in_payload);
    }
}

void TC_es_msg_parser_INVALID_POST_METHOD(void **state)
{
    iot_error_t err;
    int command;
    int type;
    size_t contents_len;
    char *parsed_content;
    UNUSED(state);

    // Given: unknown url
    char unknown_url[] = "POST /nowhere HTTP/1.1\r\n"
                         "User-Agent: Android/Oneapp SDKClient\r\n"
                         "Content-Length: 12\r\n"
                         "Host: 192.168.4.1:8888\r\n"
                         "Connection: Keep-Alive\r\n"
                         "Accept-Encoding: gzip\r\n"
                         "\r\n"
                         "test content";
    parsed_content = NULL;
    contents_len = 0;
    command = -1;
    type = -1;
    // When
    err = es_msg_parser(unknown_url, strlen(unknown_url), &parsed_content, &command, &type, &contents_len);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_int_equal(command, IOT_EASYSETUP_INVALID_STEP);


    // Given: no body part
    char no_body_message[] = "POST /confirminfo HTTP/1.1\r\n"
                             "User-Agent: Android/Oneapp SDKClient\r\n"
                             "Content-Length: 12\r\n"
                             "Host: 192.168.4.1:8888\r\n"
                             "Connection: Keep-Alive\r\n"
                             "Accept-Encoding: gzip\r\n"
                             "\r\n";
    parsed_content = NULL;
    contents_len = 0;
    command = -1;
    type = -1;
    // When
    err = es_msg_parser(no_body_message, strlen(no_body_message), &parsed_content, &command, &type, &contents_len);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Given: no-header
    char no_header_single_body[] = "POST /confirm HTTP/1.1\r\n"
                                   "\r\n"
                                   "test_content";
    parsed_content = NULL;
    contents_len = 0;
    command = -1;
    type = -1;
    // When
    err = es_msg_parser(no_header_single_body, strlen(no_header_single_body), &parsed_content, &command, &type, &contents_len);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Given: incomplete header - no value
    char incomplete_header_msg[] = "POST /confirm HTTP/1.1\r\n"
                                   "Content-Length: \r\n"
                                   "\r\n"
                                   "test_content";
    parsed_content = NULL;
    contents_len = 0;
    command = -1;
    type = -1;
    // When
    err = es_msg_parser(incomplete_header_msg, strlen(incomplete_header_msg), &parsed_content, &command, &type, &contents_len);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Given: missing content length header
    char missing_content_length_header[] = "POST /confirminfo HTTP/1.1\r\n"
                                           "User-Agent: Mozilla/5.0\r\n"
                                           "Accept-Language: en-US,en;q=0.5\r\n"
                                           "Connection: keep-alive\r\n"
                                           "Cache-Control: max-age=0\r\n"
                                           "\r\n"
                                           "test content";
    parsed_content = NULL;
    contents_len = 0;
    command = -1;
    type = -1;
    // When
    err = es_msg_parser(missing_content_length_header, strlen(missing_content_length_header),
                        &parsed_content, &command, &type, &contents_len);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}