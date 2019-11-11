/* ***************************************************************************
 *
 * Copyright 2019 Samsung Electronics All Rights Reserved.
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

#ifndef _IOT_NET_PLATFORM_H_
#define _IOT_NET_PLATFORM_H_

#include "iot_os_util.h"
#include "openssl/ssl.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Contains connection context
 */
typedef struct iot_net_platform_context {
	int socket;			/**< @brief socket handle */
	int read_count;			/**< @brief number of read data */
	SSL *ssl;			/**< @brief SSL Handle */
	SSL_CTX *ctx;			/**< @brief set SSL context */
	const SSL_METHOD *method;	/**< @brief set SSL method */
} iot_net_platform_context_t;

#ifdef __cplusplus
}
#endif

#endif /* _IOT_NET_PLATFORM_H_ */
