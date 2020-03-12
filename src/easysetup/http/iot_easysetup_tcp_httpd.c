/******************************************************************
 *
 * MIT License
 *
 * Copyright (c) 2019 Aleksey Kurepin
 * Copyright (c) 2020 Samsung Electronics All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * http message parser has come from Pico HTTP Server (https://github.com/foxweb/pico)
 *
 ******************************************************************/

#include <string.h>
#include <sys/socket.h>
#include <errno.h>
#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
#include <netinet/in.h>
#include <unistd.h>
#endif
#include "es_tcp_httpd.h"
#include "iot_os_util.h"
#include "iot_debug.h"
#include "iot_easysetup.h"

#define PORT 8888
#define RX_BUFFER_MAX    1024

typedef struct { char *name, *value; } header_t;

static header_t reqhdr[17] = {{"\0", "\0"}};
static char *tx_buffer = NULL;

// Client request
char *method, // "GET" or "POST"
	*uri,     // "/index.html" things before '?'
	*qs,      // "a=1&b=2"     things after  '?'
	*prot;    // "HTTP/1.1"

static void es_tcp_task(void *pvParameters)
{
	char *payload = NULL;
	char rx_buffer[RX_BUFFER_MAX];
	int addr_family, ip_protocol, listen_sock, sock, err, len;
	struct sockaddr_in sourceAddr;
	uint addrLen;

	while (1) {
		struct sockaddr_in destAddr;
		destAddr.sin_addr.s_addr = htonl(INADDR_ANY);
		destAddr.sin_family = AF_INET;
		destAddr.sin_port = htons(PORT);
		addr_family = AF_INET;
		ip_protocol = IPPROTO_IP;

		listen_sock = socket(addr_family, SOCK_STREAM, ip_protocol);
		if (listen_sock < 0) {
			IOT_ERROR("Unable to create socket: errno %d", errno);
			break;
		}

		err = bind(listen_sock, (struct sockaddr *)&destAddr, sizeof(destAddr));
		if (err != 0) {
			IOT_ERROR("Socket unable to bind: errno %d", errno);
			break;
		}

		err = listen(listen_sock, 1);
		if (err != 0) {
			IOT_ERROR("Error occurred during listen: errno %d", errno);
			break;
		}

		while (1) {
			addrLen = sizeof(sourceAddr);

			sock = accept(listen_sock, (struct sockaddr *)&sourceAddr, &addrLen);
			if (sock < 0) {
				IOT_ERROR("Unable to accept connection: errno %d", errno);
				break;
			}

			memset(rx_buffer, '\0', sizeof(rx_buffer));

			len = recv(sock, rx_buffer, sizeof(rx_buffer) - 1, 0);
			IOT_DEBUG("rx_buffer : %s", rx_buffer);

			if (len < 0) {
				IOT_ERROR("recv failed: errno %d", errno);
				break;
			}
			else if (len == 0) {
				IOT_ERROR("Connection closed");
				break;
			}
			else {
				rx_buffer[len] = '\0';

				method = strtok(rx_buffer, " \t\r\n");
				uri = strtok(NULL, " \t");
				prot = strtok(NULL, " \t\r\n");

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
				payload = t;
				IOT_DEBUG("payload : %s", payload);

				if (!strcmp(method,  "GET"))
					http_packet_handle(uri, &tx_buffer, payload, GET);
				else if (!strcmp(method,  "POST"))
					http_packet_handle(uri, &tx_buffer, payload, POST);
				else {
					IOT_ERROR("not support type");
					http_packet_handle("ERROR", &tx_buffer, payload, ERROR);
				}

				if (!tx_buffer) {
					IOT_ERROR("tx_buffer is NULL");
					break;
				}

				len = strlen((char *)tx_buffer);
				tx_buffer[len] = 0;

				err = send(sock, tx_buffer, len, 0);
				if (err < 0) {
					IOT_ERROR("Error occured during sending: errno %d", err);
					break;
				}
				if (tx_buffer) {
					free(tx_buffer);
					tx_buffer = NULL;
				}
			}
		}

		if (sock != -1) {
			IOT_ERROR("Shutting down socket and restarting...");
			shutdown(sock, SHUT_RD);
			close(sock);
		}
	}
	iot_os_thread_delete(NULL);
}

static iot_os_thread es_tcp_task_handle = NULL;

void es_tcp_init(void)
{
	IOT_INFO("es_tcp_init!!");
	iot_os_thread_create(es_tcp_task, "es_tcp_task", 4096, NULL, 5, (iot_os_thread * const)(&es_tcp_task_handle));
}

void es_tcp_deinit(void)
{
	if (es_tcp_task_handle) {
		iot_os_thread_delete(es_tcp_task_handle);
		es_tcp_task_handle = NULL;
	}

	if (tx_buffer) {
		free(tx_buffer);
		tx_buffer = NULL;
	}

	IOT_INFO("es_tcp_deinit!!");
}

