/* ***************************************************************************
 *
 * Copyright 2020-2021 Samsung Electronics All Rights Reserved.
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

#ifndef ST_DEVICE_SDK_C_IOT_EASYSETUP_HTTP_IMPL_H
#define ST_DEVICE_SDK_C_IOT_EASYSETUP_HTTP_IMPL_H

#include <sys/socket.h>
#include <errno.h>
#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#endif
#include "iot_debug.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	int listen_sock;
	int accept_sock;
} HTTP_CONN_H;

#define CONN_HANDLE_UNINITIALIZED	(-1)

#ifdef __cplusplus
}
#endif

#endif //ST_DEVICE_SDK_C_IOT_EASYSETUP_HTTP_IMPL_H
