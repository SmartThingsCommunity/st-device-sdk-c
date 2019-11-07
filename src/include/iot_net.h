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

#ifdef __cplusplus
extern "C" {
#endif

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

	/**< @brief read from network */
	int (*read)(struct iot_net_interface *, unsigned char *, int, iot_os_timer);
	/**< @brief write to network */
	int (*write)(struct iot_net_interface *, unsigned char *, int, iot_os_timer);
} iot_net_interface_t;

/**
 * @brief print network status
 *
 * @param n           - iot_net_interface struct
 *
 * @return void
 */
void iot_os_net_print_status(iot_net_interface_t *n);

/**
 * @brief check network socket  status
 *
 * @param n           - iot_net_interface struct
 * @param timeout_ms  - timeout in miliseconds
 *
 * @return
 *              > 0 : there is some data to read
 *              == 0 : there is no data
 *              < 0 : there is error in network
 */

int iot_os_net_select(iot_net_interface_t *n, unsigned int timeout_ms);

/**
 * @brief Initialize the network structure
 *
 * @param n - iot_net_interface struct
 *
 * @return void
 */
void iot_os_net_init(iot_net_interface_t *);

/**
 * @brief connect with server
 *
 * @param n           - iot_net_interface struct
 * @param addr        - server address
 * @param port        -  server port
 *
 * @return connect status
 */
int iot_os_net_connet(iot_net_interface_t *n, char *addr, int port);

/**
 * @brief disconnect with server
 *
 * @param n           - iot_net_interface struct
 *
 * @return void
 */
void iot_os_net_disconnect(iot_net_interface_t *n);

#ifdef CONFIG_STDK_MQTT_USE_SSL

/**
 * @brief Initialize the network structure for SSL connection
 *
 * @param n - iot_net_interface structure
 *
 * @return iot_error_t
 * @retval IOT_ERROR_NONE		success
 * @retval IOT_ERROR_NET_INVALID_INTERFACE	error
 */
iot_error_t iot_net_init(iot_net_interface_t *n);

/**
 * @brief Use SSL to connect with server
 *
 * @param n           - iot_net_interface struct
 * @param addr        - server address
 * @param port        - server port
 * @param ssl_cck     - client CA, certificate and private key
 * @param method      - SSL context client method
 * @param verify_mode - SSL verifying mode
 * @param frag_len    - SSL read buffer length
 *
 * @return connect status
 */
int iot_os_net_ssl_connect(iot_net_interface_t *n);

 /**
 * @brief disconnect with server SSL connection
 *
 * @param n           - iot_net_interface struct
 *
 * @return void
 */
void iot_os_net_ssl_disconnect(iot_net_interface_t *n);

#endif //CONFIG_STDK_MQTT_USE_SSL

#ifdef __cplusplus
}
#endif

#endif /* _IOT_NET_H_ */
