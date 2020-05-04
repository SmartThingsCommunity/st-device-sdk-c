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
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <external/JSON.h>
#include <stdlib.h>
#include "../src/easysetup/http/es_tcp_httpd.h"

int TC_iot_easysetup_httpd_group_setup(void **state)
{
    es_tcp_init();
    usleep(100);
    return 0;
}

int TC_iot_easysetup_httpd_group_teardown(void **state)
{
    es_tcp_deinit();
    return 0;
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
    char *get_request_message = "GET /invaliduri HTTP/1.1\r\nContent-Length: 0\r\n";
    char *post_request_message = "POST /invaliduri HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 18 \r\n\r\n{\"message\":\"invalid\"}";
    char *invalid_method_message = "INVAL /deviceinfo HTTP/1.1\r\nContent-Length: 0\r\n";

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
        assert_error_response(recv_buffer, -401, 400);

        close(sock);
    }
}
