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
#include <iot_net.h>
#include <os/iot_os_util.h>
#define UNUSED(x) (void)(x)

static iot_error_t _iot_net_mock_connect(iot_net_interface_t *net)
{
    UNUSED(net);
    return IOT_ERROR_NONE;
}

static void _iot_net_mock_disconnect(iot_net_interface_t *net)
{
    UNUSED(net);
}

static int _iot_net_mock_select(iot_net_interface_t *net, unsigned int timeout_ms)
{
    UNUSED(net);
    UNUSED(timeout_ms);

    return (int)mock();
}

struct mock_net_read_buffer_pointer {
    unsigned int offset;
    unsigned int count;
};
static unsigned int net_read_ptr_index;
#define NET_READ_PTR_INDEX_MAX 10
static struct mock_net_read_buffer_pointer net_read_ptr_value[NET_READ_PTR_INDEX_MAX];

void set_mock_net_read_buffer_pointer(unsigned int index, unsigned int offset, unsigned int count)
{
    net_read_ptr_value[index].offset = offset;
    net_read_ptr_value[index].count = count;
}

void reset_mock_net_read_buffer_pointer_index(void)
{
    net_read_ptr_index = 0;
}

static int _iot_net_mock_read(iot_net_interface_t *net, unsigned char *buf, size_t len, iot_os_timer timer)
{
    unsigned char *mock_buf = mock_ptr_type(unsigned char*);
    int ret;
    UNUSED(net);
    UNUSED(timer);

    assert_true(net_read_ptr_value[net_read_ptr_index].count <= len);
    assert_true(net_read_ptr_index < NET_READ_PTR_INDEX_MAX);
    memcpy(buf, &mock_buf[net_read_ptr_value[net_read_ptr_index].offset], net_read_ptr_value[net_read_ptr_index].count);

    ret = (int) net_read_ptr_value[net_read_ptr_index].count;
    net_read_ptr_index++;
    return ret;
}

static int _iot_net_mock_write(iot_net_interface_t *net, unsigned char *buf, int len, iot_os_timer timer)
{
    UNUSED(net);
    UNUSED(timer);
    check_expected_ptr(buf);
    check_expected(len);
    return len;
}

static void _iot_net_mock_show_status(iot_net_interface_t *net)
{
    UNUSED(net);
}

iot_error_t __wrap_iot_net_init(iot_net_interface_t *net)
{
    if (!net)
        return IOT_ERROR_NET_INVALID_INTERFACE;

    net->connect = _iot_net_mock_connect;
    net->disconnect = _iot_net_mock_disconnect;
    net->select = _iot_net_mock_select;
    net->read = _iot_net_mock_read;
    net->write = _iot_net_mock_write;
    net->show_status = _iot_net_mock_show_status;

    return IOT_ERROR_NONE;
}
