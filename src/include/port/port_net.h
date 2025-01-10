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

#ifndef _PORT_NET_H_
#define _PORT_NET_H_

#ifdef __cplusplus
extern "C" {
#endif

#define PORT_NET_WAIT_FOREVER	0xffffffff

typedef void *PORT_NET_CONTEXT;

typedef struct {
	char *ca_cert;		/**< @brief a pointer to a CA certificate chain */
	unsigned int ca_cert_len;			/**< @brief a size of CA certificate chain */
	char *device_cert;	/**< @brief a pointer to a device certificate chain */
	unsigned int device_cert_len;		/**< @brief a size of device certificate chain */
} port_net_tls_config;

void port_net_free(PORT_NET_CONTEXT ctx);

PORT_NET_CONTEXT port_net_connect(char *address, char *port, port_net_tls_config *config);

PORT_NET_CONTEXT port_net_listen(char *port, port_net_tls_config *config);

int port_net_read(PORT_NET_CONTEXT ctx, void *buf, size_t len);

int port_net_read_poll(PORT_NET_CONTEXT ctx, unsigned int wait_time_ms);

int port_net_write(PORT_NET_CONTEXT ctx, void *buf, size_t len);

void port_net_close(PORT_NET_CONTEXT ctx);

#ifdef __cplusplus
}
#endif

#endif /* _PORT_NET_H_ */
