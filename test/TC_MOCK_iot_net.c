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
#include <stdbool.h>
#include <stdlib.h>
#include <iot_error.h>
#include "port_net.h"
#include <os/iot_os_util.h>
#define UNUSED(x) (void)(x)

static unsigned char *mock_read_stream;
static size_t mock_read_stream_size;
static size_t mock_read_stream_offset;
void port_net_mock_reset_read_stream(unsigned char *read_stream, size_t size)
{
    mock_read_stream = read_stream;
    mock_read_stream_size = size;
    mock_read_stream_offset = 0;
}

static int mock_socket_status; // 0 : initialized, 1 : connected, 2 : not-connected
void port_net_mock_reset_socket_status(int status)
{
    mock_socket_status = status;
}

int __wrap_port_net_read(PORT_NET_CONTEXT ctx, void *buf, size_t len)
{
    int ret;
    UNUSED(ctx);

    if (mock_read_stream == NULL || mock_read_stream_size <= mock_read_stream_offset)
        return 0;
    if (mock_read_stream_offset + len > mock_read_stream_size)
        ret = mock_read_stream_size - mock_read_stream_offset;
    else
        ret = len;
    memcpy(buf, mock_read_stream + mock_read_stream_offset, ret);
    mock_read_stream_offset += ret;
    return ret;
}

int __wrap_port_net_write(PORT_NET_CONTEXT ctx, void *buf, size_t len)
{
    UNUSED(ctx);
    check_expected_ptr(buf);
    check_expected(len);
    return len;
}

PORT_NET_CONTEXT __wrap_port_net_connect(char *address, char *port, port_net_tls_config *config)
{
    UNUSED(address);
	UNUSED(config);
    if (mock_socket_status == 1)
        return (PORT_NET_CONTEXT)1;
    return NULL;
}

void __wrap_port_net_close(PORT_NET_CONTEXT ctx)
{
    UNUSED(ctx);
    mock_socket_status = 2;
}

int __wrap_port_net_read_poll(PORT_NET_CONTEXT ctx, unsigned int wait_time_ms)
{
    UNUSED(ctx);
    UNUSED(wait_time_ms);
    if (mock_socket_status == 2)
        return -1;
    if (mock_read_stream == NULL || mock_read_stream_size <= mock_read_stream_offset)
        return 0;
    return 1;
}

void __wrap_port_net_free(PORT_NET_CONTEXT ctx)
{
    UNUSED(ctx);
    mock_socket_status = 2;
}
