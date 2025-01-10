/* ***************************************************************************
 *
 * Copyright 2020 Samsung Electronics All Rights Reserved.
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
 
#include <string.h>
#include <iot_nv_data.h>
#include <iot_util.h>

#include "../easysetup_http.h"
#include "iot_os_util.h"
#include "iot_debug.h"
#include "iot_easysetup.h"
#include "iot_main.h"
#include "port_net.h"

static iot_os_thread es_http_tls_task_handle = NULL;
static int close_connection = false;
static PORT_NET_CONTEXT net_ctx = NULL;
static char *tx_buffer = NULL;

static void es_http_tls_close_connection(void)
{
	close_connection = true;

	if (net_ctx) {
		port_net_free(net_ctx);
	}
	net_ctx = NULL;
}

static void es_http_tls_task(void *data)
{
	port_net_tls_config tls_config = {0,};
	char buf[2048];
	size_t content_len;
	int ret, len, type, cmd;
	iot_error_t err = IOT_ERROR_NONE;
	char *payload = NULL;

	ret = iot_nv_get_certificate(IOT_SECURITY_CERT_ID_DEVICE, &tls_config.device_cert, &tls_config.device_cert_len);
	if (ret) {
		IOT_ERROR("iot_nv_get_certificate = %d", ret);
		goto exit;
	}

	ret = iot_nv_get_certificate(IOT_SECURITY_CERT_ID_SUB_CA, &tls_config.ca_cert, &tls_config.ca_cert_len);
	if (ret) {
		IOT_ERROR("iot_nv_get_certificate = %d", ret);
		goto exit;
	}

	do
	{
		net_ctx = port_net_listen("8888", &tls_config);
		if (!net_ctx) {
			IOT_ERROR("Failed to listen http tls server");
			continue;
		}

		do
		{
			ret = port_net_read_poll(net_ctx);
			if (ret < 0) {
				IOT_ERROR("Read error");
				break;
			} else (ret == 0) {
				continue;
			}
			len = sizeof( buf ) - 1;
			memset(buf, 0, sizeof( buf ) );
			ret = port_net_read(net_ctx, buf, len);
			if (ret <= 0)
				continue;
			err = es_msg_parser(buf, sizeof(buf), &payload, &cmd, &type, &content_len);
		}
		while (1);

		if(err == IOT_ERROR_INVALID_ARGS)
			http_msg_handler(cmd, &tx_buffer, D2D_ERROR, payload);
		else
			http_msg_handler(cmd, &tx_buffer, type, payload);

		memset(buf, 0, sizeof(buf));
		len = sprintf(buf, tx_buffer);
		if (tx_buffer) {
			iot_os_free(tx_buffer);
			tx_buffer = NULL;
		}
		port_net_write(net_ctx, buf, len);
		port_net_free(net_ctx);
	}
	while (1);

exit:
	if (tls_config.ca_cert) {
		iot_os_free(tls_config.ca_cert);
	}

	if (tls_config.device_cert) {
		iot_os_free(tls_config.device_cert);
	}

	es_http_tls_task_handle = NULL;
	iot_os_thread_delete(es_http_tls_task_handle);
}

void es_http_init(void)
{
	IOT_INFO("http tls init!!");

	iot_os_thread_create(es_http_tls_task, "es_tls_task", (1024 * 8), NULL, 5, (iot_os_thread * const)(&es_http_tls_task_handle));
}

void es_http_deinit(void)
{
	es_http_tls_close_connection();

	if (es_http_tls_task_handle) {
		IOT_INFO("es_http_tls_deinit");
		iot_os_thread_delete(es_http_tls_task_handle);
		es_http_tls_task_handle = NULL;
		IOT_INFO("es_http_tls_deinit");
	}

	if (tx_buffer) {
		iot_os_free(tx_buffer);
		tx_buffer = NULL;
	}

	close_connection = false;

	IOT_INFO("http tls deinit!!");
}
