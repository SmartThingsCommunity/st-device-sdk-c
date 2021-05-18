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

#ifndef _IOT_NET_H_
#define _IOT_NET_H_

#include "iot_net_platform.h"
#include "iot_os_util.h"
#include "iot_error.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct iot_net_interface iot_net_interface_t;

/**
 * @brief Contains server related information
 *
 * This structure has address, port and certificate of server.
 */
typedef struct iot_net_connection {
	char *url;			/**< @brief server address */
	int port;			/**< @brief server port */
	const unsigned char *ca_cert;	/**< @brief a pointer to a CA certificate */
	unsigned int ca_cert_len;	/**< @brief a size of CA certificate */
	const unsigned char *cert;	/**< @brief a pointer to a device certificate */
	unsigned int cert_len;		/**< @brief a size of device certificate */
	const unsigned char *key;	/**< @brief a pointer to a private key */
	unsigned int key_len;		/**< @brief a size of private key */
} iot_net_connection_t;

/**
 * @brief Contains "network management structure" data
 */
typedef struct iot_net_interface {
	/**< @brief server connection informations */
	iot_net_connection_t connection;
	/**< @brief contains connection context that depend to net library */
	iot_net_platform_context_t context;

	/**< @brief connect to server */
	iot_error_t (*connect)(iot_net_interface_t *);
	/**< @brief enable tcp keep-alive */
	iot_error_t (*tcp_keepalive)(iot_net_interface_t *, unsigned int, unsigned int, unsigned int);
	/**< @brief disconnect the server connection */
	void (*disconnect)(iot_net_interface_t *);
	/**< @brief check network socket status */
	int (*select)(iot_net_interface_t *, unsigned int);
	/**< @brief read from network */
	int (*read)(iot_net_interface_t *, unsigned char *, size_t, iot_os_timer);
	/**< @brief write to network */
	int (*write)(iot_net_interface_t *, unsigned char *, int, iot_os_timer);
	/**< @brief show socket status on console */
	void (*show_status)(iot_net_interface_t *);
} iot_net_interface_t;

/**
 * @brief Initialize the network structure for SSL connection
 *
 * @param n - iot_net_interface structure
 *
 * @return iot_error_t
 * @retval IOT_ERROR_NONE		success
 * @retval IOT_ERROR_NET_INVALID_INTERFACE	error
 */
iot_error_t iot_net_init(iot_net_interface_t *net);

#ifdef __cplusplus
}
#endif

#endif /* _IOT_NET_H_ */
