/* ***************************************************************************
 *
 * Copyright (c) 2020-2022 Samsung Electronics All Rights Reserved.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iot_main.h>
#include <external/JSON.h>
#include <security/iot_security_crypto.h>
#include <security/iot_security_helper.h>
#include <iot_easysetup.h>
#include <iot_internal.h>
#include <security/iot_security_common.h>
#include "TC_UTIL_easysetup_common.h"
#include "../src/easysetup/http/easysetup_http.h"

int TC_iot_easysetup_httpd_setup(void **state)
{
    struct iot_context *context;
    iot_error_t err;
    int ret;

    ret = TC_iot_easysetup_common_setup((void **)&context);
    if (ret != 0)
        return ret;

    context->iot_events = iot_os_eventgroup_create();
    assert_non_null(context->iot_events);
    context->cmd_queue = iot_os_queue_create(IOT_QUEUE_LENGTH, sizeof(struct iot_command));
    assert_non_null(context->cmd_queue);
    context->easysetup_req_queue = iot_os_queue_create(1, sizeof(struct iot_easysetup_payload));
    assert_non_null(context->easysetup_req_queue);
    context->easysetup_resp_queue = iot_os_queue_create(1, sizeof(struct iot_easysetup_payload));
    assert_non_null(context->easysetup_resp_queue);
    context->easysetup_security_context = iot_security_init();
    assert_non_null(context->easysetup_security_context);
    err = iot_security_cipher_init(context->easysetup_security_context);
    assert_int_equal(err, IOT_ERROR_NONE);

    err = iot_easysetup_init(context);
    assert_int_equal(err, IOT_ERROR_NONE);
    usleep(100);

    *state = context;

    return 0;
}

int TC_iot_easysetup_httpd_teardown(void **state)
{
    struct iot_context *context = (struct iot_context *)*state;

    iot_easysetup_deinit(context);

    iot_os_queue_delete(context->easysetup_resp_queue);
    iot_os_queue_delete(context->easysetup_req_queue);
    iot_os_queue_delete(context->cmd_queue);
    iot_os_eventgroup_delete(context->iot_events);
    iot_security_cipher_deinit(context->easysetup_security_context);
    iot_security_deinit(context->easysetup_security_context);

    return TC_iot_easysetup_common_teardown((void**) &context);
}

static int _connect_to_server(char *server_addr)
{
    struct sockaddr_in server;
    int rc;
    int sock;
    unsigned int connect_retry = 0;
    struct timeval timeout;
    assert_non_null(server_addr);

    sock = socket(AF_INET, SOCK_STREAM, 0);
    assert_int_not_equal(sock, -1);

    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
    rc = setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    assert_return_code(rc, errno);

    server.sin_addr.s_addr = inet_addr(server_addr);
    server.sin_family = AF_INET;
    server.sin_port = htons(8888);
    memset(&(server.sin_zero), 0, 8);

    do {
        rc = connect(sock, (struct sockaddr *)&server, sizeof(server));
        if (rc < 0) {
            if (++connect_retry > 5) {
                assert_return_code(rc, errno);
            }
            sleep(1);
        }
    } while (rc < 0);

    return sock;
}

typedef struct { char *name, *value; } header_t;

static void _parse_http_resonse(char* rx_buffer, int *out_res_code, char **body_ptr)
{
    char *protocol;
    char *res_code;
    char *body;
    static header_t reqhdr[17] = {{"\0", "\0"}};

    protocol = strtok(rx_buffer, " \t\r\n");
    res_code = strtok(NULL, " \t");

    header_t *h = reqhdr;
    char *t = NULL;

    while (h < reqhdr + 16) {
        char *k, *v;

        k = strtok(NULL, "\r\n: \t");
        if (!k)
            break;

        v = strtok(NULL, "\r\n");
        while (*v && *v == ' ')
            v++;

        h->name = k;
        h->value = v;
        h++;

        t = v + 1 + strlen(v);

        if (t[1] == '\r' && t[2] == '\n')
            break;
    }

    t++;
    *body_ptr = t;
    char* endptr = NULL;
    *out_res_code = (int) strtol(res_code, &endptr, 10);
    assert_non_null(endptr);
}

void assert_error_response(char *buffer, int expected_error_code, int expected_http_code)
{
    JSON_H *root;
    JSON_H *err_item;
    JSON_H *code_item;
    int code;
    char *body;

    assert_non_null(buffer);
    _parse_http_resonse(buffer, &code, &body);
    assert_int_equal(expected_http_code, code);
    root = JSON_PARSE(body);
    assert_non_null(root);
    err_item = JSON_GET_OBJECT_ITEM(root, "error");
    assert_non_null(err_item);
    code_item = JSON_GET_OBJECT_ITEM(err_item, "code");
    assert_non_null(code_item);
    assert_int_equal(expected_error_code, code_item->valueint);
    JSON_DELETE(root);
}

enum {
    REQ_GET_INVALID_URI,
    REQ_POST_INVALID_URI,
    REQ_INVALID_METHOD,
    REQ_MAX,
};

void TC_iot_easysetup_httpd_invalid_request(void **state)
{
    int sock;
    ssize_t len;
    char *request_message[REQ_MAX];
    char recv_buffer[1024] = {0, };
    char *get_request_message = "GET /invaliduri HTTP/1.1\r\nContent-Length: 0\r\n\r\n";
    char *post_request_message = "POST /invaliduri HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 18 \r\n\r\n{\"message\":\"invalid\"}";
    char *invalid_method_message = "INVAL /deviceinfo HTTP/1.1\r\nContent-Length: 0\r\n\r\n";

    // Given
    request_message[REQ_GET_INVALID_URI] = get_request_message;
    request_message[REQ_POST_INVALID_URI] = post_request_message;
    request_message[REQ_INVALID_METHOD] = invalid_method_message;

    for (int i = 0; i < REQ_MAX; i++) {
        // Given
        memset(recv_buffer, '\0', sizeof(recv_buffer));
        sock = _connect_to_server("127.0.0.1");

        // When: send GET message to invalid URI
        len = send(sock, request_message[i], strlen(request_message[i]), 0);
        // Then
        assert_int_equal(len, strlen(request_message[i]));

        // When: recv response
        len = recv(sock, recv_buffer, sizeof(recv_buffer), 0);
        // Then
        assert_true(len > 0);
        assert_error_response(recv_buffer, 401, 400);

        close(sock);
    }
}

void assert_device_info_response(char* buffer)
{
    JSON_H *root;
    JSON_H *item;
    int code;
    char *body;

    assert_non_null(buffer);
    _parse_http_resonse(buffer, &code, &body);
    assert_int_equal(code, 200);
    root = JSON_PARSE(body);
    assert_non_null(root);
    item = JSON_GET_OBJECT_ITEM(root, "protocolVersion");
    assert_non_null(item);
    assert_true(JSON_IS_STRING(item));
    item = JSON_GET_OBJECT_ITEM(root, "wifiSupportFrequency");
    assert_non_null(item);
    assert_true(JSON_IS_NUMBER(item));
    item = JSON_GET_OBJECT_ITEM(root, "iv");
    assert_non_null(item);
    assert_true(JSON_IS_STRING(item));
    JSON_DELETE(root);
}

void TC_iot_easysetup_httpd_deviceinfo_success(void **state)
{
    int sock;
    ssize_t len;
    struct iot_context *context = (struct iot_context *)*state;
    iot_error_t err;
    struct iot_easysetup_payload easysetup_req;
    char recv_buffer[1024] = {0, };
    char *request_message = "GET /deviceinfo HTTP/1.1\r\nConnection: keep-alive\r\n\r\n";

    // Given
    memset(recv_buffer, '\0', sizeof(recv_buffer));
    sock = _connect_to_server("127.0.0.1");

    // When: send request
    len = send(sock, request_message, strlen(request_message), 0);
    // Then
    assert_int_equal(len, strlen(request_message));

    // Given
    iot_os_eventgroup_wait_bits(context->iot_events,
                                IOT_EVENT_BIT_EASYSETUP_REQ, true, IOT_OS_MAX_DELAY);
    easysetup_req.payload = NULL;
    easysetup_req.err = IOT_ERROR_NONE;
    if (iot_os_queue_receive(context->easysetup_req_queue, &easysetup_req, 0) == IOT_OS_FALSE) {
        assert_true(1);
    }
    err = iot_easysetup_request_handler(context, easysetup_req);
    assert_int_equal(err, IOT_ERROR_NONE);

    // When: recv response
    len = recv(sock, recv_buffer, sizeof(recv_buffer), 0);
    // Then
    assert_true(len > 0);
    assert_device_info_response(recv_buffer);

    close(sock);
}

void assert_keyinfo_http_response(char* buffer, iot_security_cipher_params_t *server_cipher, unsigned int expected_otm_support)
{
    int code;
    char *body;

    assert_non_null(buffer);
    _parse_http_resonse(buffer, &code, &body);
    assert_int_equal(code, 200);
    assert_keyinfo(body, server_cipher, expected_otm_support);
}

extern int ref_step;

void TC_iot_easysetup_httpd_keyinfo_single_transfer_success(void **state)
{
    int sock;
    ssize_t len;
    struct iot_context *context = (struct iot_context *)*state;
    iot_error_t err;
    struct iot_easysetup_payload easysetup_req;
    char recv_buffer[1024] = {0, };
    char *post_header = "POST /keyinfo HTTP/1.1\r\nConnection: keep-alive\r\nContent-Length: ";
    char *post_body;
    char *post_message;
    size_t post_message_len = 0;
    iot_security_cipher_params_t *device_cipher;
    iot_security_cipher_params_t *server_cipher;
    char *time_to_set;

    // Given
    device_cipher = _generate_device_cipher(NULL, 0);
    assert_non_null(device_cipher);
    err = iot_security_cipher_set_params(context->easysetup_security_context, device_cipher);
    assert_int_equal(err, IOT_ERROR_NONE);
    server_cipher = _generate_server_cipher(device_cipher->iv.p, device_cipher->iv.len);
    assert_non_null(server_cipher);
    time_to_set = calloc(sizeof(char), 11);
    assert_non_null(time_to_set);
    post_body = _generate_post_keyinfo_payload(2021, time_to_set, 11);
    assert_non_null(post_body);
    expect_string(__wrap_iot_bsp_system_set_time_in_sec, time_in_sec, time_to_set);
    post_message_len = strlen(post_header) + strlen(post_body) + strlen("4096\r\n\r\n") + 1;
    post_message = calloc(1, post_message_len);
    assert_non_null(post_message);
    snprintf(post_message, post_message_len, "%s%zu\r\n\r\n%s",
             post_header, strlen(post_body), post_body);
    ref_step = IOT_EASYSETUP_STEP_KEYINFO;
    memset(recv_buffer, '\0', sizeof(recv_buffer));
    sock = _connect_to_server("127.0.0.1");

    // When: send request
    len = send(sock, post_message, strlen(post_message), 0);
    // Then
    assert_int_equal(len, strlen(post_message));

    // Given
    iot_os_eventgroup_wait_bits(context->iot_events,
                                IOT_EVENT_BIT_EASYSETUP_REQ, true, IOT_OS_MAX_DELAY);
    easysetup_req.payload = NULL;
    easysetup_req.err = IOT_ERROR_NONE;
    if (iot_os_queue_receive(context->easysetup_req_queue, &easysetup_req, 0) == IOT_OS_FALSE) {
        assert_true(1);
    }
    err = iot_easysetup_request_handler(context, easysetup_req);
    assert_int_equal(err, IOT_ERROR_NONE);

    // When: recv response
    len = recv(sock, recv_buffer, sizeof(recv_buffer), 0);
    // Then
    assert_true(len > 0);
    assert_keyinfo_http_response(recv_buffer, server_cipher, IOT_OVF_TYPE_BUTTON);

    // Teardown
    free(time_to_set);
    free(post_message);
    free(post_body);
    _free_cipher(device_cipher);
    _free_cipher(server_cipher);
    close(sock);
}

void TC_iot_easysetup_httpd_keyinfo_separated_transfer_success(void **state)
{
    int sock;
    ssize_t len;
    struct iot_context *context = (struct iot_context *)*state;
    iot_error_t err;
    struct iot_easysetup_payload easysetup_req;
    char recv_buffer[1024] = {0, };
    char *post_header_prefix = "POST /keyinfo HTTP/1.1\r\nConnection: keep-alive\r\nContent-Length: ";
    char *post_body;
    char *post_header;
    size_t post_header_len = 0;
    iot_security_cipher_params_t *device_cipher;
    iot_security_cipher_params_t *server_cipher;
    char *time_to_set;

    // Given
    device_cipher = _generate_device_cipher(NULL, 0);
    assert_non_null(device_cipher);
    err = iot_security_cipher_set_params(context->easysetup_security_context, device_cipher);
    assert_int_equal(err, IOT_ERROR_NONE);
    server_cipher = _generate_server_cipher(device_cipher->iv.p, device_cipher->iv.len);
    assert_non_null(server_cipher);
    time_to_set = calloc(sizeof(char), 11);
    assert_non_null(time_to_set);
    post_body = _generate_post_keyinfo_payload(2022, time_to_set, 11);
    assert_non_null(post_body);
    expect_string(__wrap_iot_bsp_system_set_time_in_sec, time_in_sec, time_to_set);
    post_header_len = strlen(post_header_prefix) + strlen("4096\r\n\r\n") + 1;
    post_header = calloc(1, post_header_len);
    assert_non_null(post_header);
    snprintf(post_header, post_header_len, "%s%zu\r\n\r\n",
             post_header_prefix, strlen(post_body));
    ref_step = IOT_EASYSETUP_STEP_KEYINFO;
    memset(recv_buffer, '\0', sizeof(recv_buffer));
    sock = _connect_to_server("127.0.0.1");

    // When: send header only
    len = send(sock, post_header, strlen(post_header), 0);
    // Then
    assert_int_equal(len, strlen(post_header));
    usleep(100); // to make sure send separately.
    // When: send body only
    len = send(sock, post_body, strlen(post_body), 0);
    // Then
    assert_int_equal(len, strlen(post_body));

    // Given
    iot_os_eventgroup_wait_bits(context->iot_events,
                                IOT_EVENT_BIT_EASYSETUP_REQ, true, IOT_OS_MAX_DELAY);
    easysetup_req.payload = NULL;
    easysetup_req.err = IOT_ERROR_NONE;
    if (iot_os_queue_receive(context->easysetup_req_queue, &easysetup_req, 0) == IOT_OS_FALSE) {
        assert_true(1);
    }
    err = iot_easysetup_request_handler(context, easysetup_req);
    assert_int_equal(err, IOT_ERROR_NONE);

    // When: recv response
    len = recv(sock, recv_buffer, sizeof(recv_buffer), 0);
    // Then
    assert_true(len > 0);
    assert_keyinfo_http_response(recv_buffer, server_cipher, IOT_OVF_TYPE_BUTTON);

    // Teardown
    free(time_to_set);
    free(post_header);
    free(post_body);
    _free_cipher(device_cipher);
    _free_cipher(server_cipher);
    close(sock);
}
