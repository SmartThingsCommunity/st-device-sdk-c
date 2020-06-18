/* ***************************************************************************
 *
 * Copyright (c) 2019-2020 Samsung Electronics All Rights Reserved.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/socket.h>

#include "iot_main.h"
#include "iot_debug.h"

#define IOT_MBEDTLS_READ_TIMEOUT_MS 30000

#ifdef CONFIG_MBEDTLS_DEBUG
static void _iot_net_mbedtls_debug(void *ctx, int level, const char *file, int line,
					const char *str)
{
	const char *filename;

	filename = strrchr(file, '/') ? strrchr(file, '/') + 1 : file;

	IOT_INFO("%s:%04d: |%d| %s", filename, line, level, str);
}
#endif

static iot_error_t _iot_net_check_interface(iot_net_interface_t *net)
{
	if (net == NULL) {
		IOT_ERROR("interface is null");
		return IOT_ERROR_NET_INVALID_INTERFACE;
	}

	return IOT_ERROR_NONE;
}

static void _iot_net_show_status(iot_net_interface_t *net)
{
	struct timeval tv;
	struct timeval timeout = {0};
	int socket;
	int sock_err = 0;
	socklen_t err_len = sizeof(sock_err);
	fd_set rfdset;
	fd_set wfdset;

	if (_iot_net_check_interface(net)) {
		return;
	}

	socket = net->context.server_fd.fd;

	FD_ZERO(&rfdset);
	FD_ZERO(&wfdset);
	FD_SET(socket, &rfdset);
	FD_SET(socket, &wfdset);

	select(socket + 1, &rfdset, &wfdset, NULL, &timeout);
	getsockopt(socket, SOL_SOCKET, SO_ERROR, &sock_err, &err_len);
	gettimeofday(&tv, NULL);

	IOT_INFO("[%ld] network socket status: readable %d writable %d sock_err %d errno %d",
				tv.tv_sec,
				FD_ISSET(socket, &rfdset),
				FD_ISSET(socket, &wfdset), sock_err, errno);
}

static int _iot_net_select(iot_net_interface_t *net, unsigned int timeout_ms)
{
	struct timeval timeout;
	fd_set fdset;
	int socket;
	int ret;

	if (_iot_net_check_interface(net)) {
		return 0;
	}

	socket = net->context.server_fd.fd;

	FD_ZERO(&fdset);
	FD_SET(socket, &fdset);

	timeout.tv_sec = timeout_ms / 1000;
	timeout.tv_usec = (timeout_ms % 1000) * 1000;

	ret = select(socket + 1, &fdset, NULL, NULL, &timeout);

	return ret;
}

static void _iot_net_cleanup_platform_context(iot_net_interface_t *net)
{
	if (_iot_net_check_interface(net)) {
		return;
	}

	mbedtls_net_free(&net->context.server_fd);

	mbedtls_x509_crt_free(&net->context.cacert);
	mbedtls_ssl_free(&net->context.ssl);
	mbedtls_ssl_config_free(&net->context.conf);
	mbedtls_ctr_drbg_free(&net->context.ctr_drbg);
	mbedtls_entropy_free(&net->context.entropy);
}

static iot_error_t _iot_net_tls_connect(iot_net_interface_t *net)
{
	iot_error_t err;
	const char *pers = "iot_net_mbedtls";
	char port[5] = {0};
	unsigned int flags;
	int ret;

	err = _iot_net_check_interface(net);
	if (err) {
		return err;
	}

	mbedtls_net_init(&net->context.server_fd);
	mbedtls_ssl_init(&net->context.ssl);
	mbedtls_ssl_config_init(&net->context.conf);
	mbedtls_x509_crt_init(&net->context.cacert);
	mbedtls_ctr_drbg_init(&net->context.ctr_drbg);

	mbedtls_entropy_init(&net->context.entropy);
	ret = mbedtls_ctr_drbg_seed(&net->context.ctr_drbg,
				mbedtls_entropy_func, &net->context.entropy,
				(const unsigned char *)pers, strlen((char *)pers));
	if (ret) {
		IOT_ERROR("mbedtls_ctr_drbg_seed = -0x%04X", -ret);
		goto exit;
	}

	if ((net->connection.ca_cert == NULL) ||
	    (net->connection.ca_cert_len == 0)) {
		IOT_ERROR("ca cert is invalid");
		ret = IOT_ERROR_INVALID_ARGS;
		goto exit;
	}

	IOT_INFO("Loading the CA root certificate %d@%p",
				net->connection.ca_cert_len + 1,
				net->connection.ca_cert);

	/* iot-core passed the certificate without NULL character */
	ret = mbedtls_x509_crt_parse(&net->context.cacert,
				(const unsigned char *)net->connection.ca_cert,
				net->connection.ca_cert_len + 1);
	if (ret) {
		IOT_ERROR("mbedtls_x509_crt_parse = -0x%04X", -ret);
		goto exit;
	}

	if ((net->connection.url == NULL) ||
	    (net->connection.port == 0)) {
		IOT_ERROR("server infomation is invalid");
		ret = IOT_ERROR_INVALID_ARGS;
		goto exit;
	}

	IOT_DEBUG("Connecting to %s:%d", net->connection.url, net->connection.port);

	snprintf(port, sizeof(port), "%d", net->connection.port);
	ret = mbedtls_net_connect(&net->context.server_fd,
				net->connection.url, port,
				MBEDTLS_NET_PROTO_TCP);
	if (ret) {
		IOT_ERROR("mbedtls_net_connect = -0x%04X", -ret);
		goto exit;
	}

	ret = mbedtls_ssl_config_defaults(&net->context.conf,
				MBEDTLS_SSL_IS_CLIENT,
				MBEDTLS_SSL_TRANSPORT_STREAM,
				MBEDTLS_SSL_PRESET_DEFAULT);
	if (ret) {
		IOT_ERROR("mbedtls_ssl_config_defaults = -0x%04X", -ret);
		goto exit;
	}

	mbedtls_ssl_conf_authmode(&net->context.conf, MBEDTLS_SSL_VERIFY_REQUIRED);
	mbedtls_ssl_conf_ca_chain(&net->context.conf, &net->context.cacert, NULL);
	mbedtls_ssl_conf_rng(&net->context.conf, mbedtls_ctr_drbg_random,
				&net->context.ctr_drbg);
	mbedtls_ssl_conf_read_timeout(&net->context.conf, IOT_MBEDTLS_READ_TIMEOUT_MS);

#ifdef CONFIG_MBEDTLS_DEBUG
	mbedtls_ssl_conf_dbg(&net->context.conf, _iot_net_mbedtls_debug, NULL);
	mbedtls_debug_set_threshold(CONFIG_MBEDTLS_DEBUG_LEVEL);
#endif

	ret = mbedtls_ssl_setup(&net->context.ssl, &net->context.conf);
	if (ret) {
		IOT_ERROR("mbedtls_ssl_setup = -0x%04X", -ret);
		goto exit;
	}

	ret = mbedtls_ssl_set_hostname(&net->context.ssl, net->connection.url);
	if (ret) {
		IOT_ERROR("mbedtls_ssl_set_hostname = -0x%04X", -ret);
		goto exit;
	}

	mbedtls_ssl_set_bio(&net->context.ssl,
				&net->context.server_fd,
				mbedtls_net_send, NULL, mbedtls_net_recv_timeout);

	IOT_DEBUG("Performing the SSL/TLS handshake");

	while ((ret = mbedtls_ssl_handshake(&net->context.ssl)) != 0) {
		if ((ret != MBEDTLS_ERR_SSL_WANT_READ) &&
		    (ret != MBEDTLS_ERR_SSL_WANT_WRITE)) {
			IOT_ERROR("mbedtls_ssl_handshake = -0x%x", -ret);
			if (ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) {
				IOT_ERROR("failed to verify the server's certificate");
			}
			goto exit;
		}
	}

	IOT_DEBUG("Protocol is %s", mbedtls_ssl_get_version(&net->context.ssl));
	IOT_DEBUG("Ciphersuite is %s", mbedtls_ssl_get_ciphersuite(&net->context.ssl));

	IOT_DEBUG("Verifying peer X.509 certificate");

	flags = mbedtls_ssl_get_verify_result(&net->context.ssl);
	if (flags) {
		IOT_ERROR("mbedtls_ssl_get_verify_result = 0x%x", flags);
		goto exit;
	}
#if defined(STDK_IOT_CORE_TLS_DEBUG)
	if (mbedtls_ssl_get_peer_cert(&net->context.ssl) != NULL) {
		unsigned char buf[2048];
		IOT_INFO("Peer certificate information");
		mbedtls_x509_crt_info((char *)buf, sizeof(buf) - 1,
				"!", mbedtls_ssl_get_peer_cert(&net->context.ssl));
		IOT_INFO("%s\n", buf);
	}
#endif
	return IOT_ERROR_NONE;

exit:
	_iot_net_cleanup_platform_context(net);

	return IOT_ERROR_NET_CONNECT;
}

static void _iot_net_tls_disconnect(iot_net_interface_t *net)
{
	_iot_net_cleanup_platform_context(net);
}

static int _iot_net_tls_read(iot_net_interface_t *net,
		unsigned char *buf, size_t len, iot_os_timer timer)
{
	int recvLen = 0, ret = 0;

	IOT_DEBUG("%d@%p", len, buf);

	if (_iot_net_check_interface(net)) {
		return 0;
	}

	mbedtls_ssl_conf_read_timeout(&net->context.conf, (uint32_t)iot_os_timer_left_ms(timer));

	do {
		ret = mbedtls_ssl_read(&net->context.ssl, buf, len);

		if(ret > 0) {
			recvLen += ret;
		} else {
			if ((ret != MBEDTLS_ERR_SSL_WANT_READ) &&
				(ret != MBEDTLS_ERR_SSL_WANT_WRITE) &&
				(ret != MBEDTLS_ERR_SSL_TIMEOUT)) {
				IOT_ERROR("mbedtls_ssl_read = -0x%04X", -ret);
				return ret;
			}
		}
	} while(recvLen < len && !iot_os_timer_isexpired(timer));

	return recvLen;
}

static int _iot_net_tls_write(iot_net_interface_t *net,
		unsigned char *buf, int len, iot_os_timer timer)
{
	int sentLen = 0, ret = 0;

	IOT_DEBUG("%d@%p", len, buf);

	if (_iot_net_check_interface(net)) {
		return 0;
	}

	do {
		ret = mbedtls_ssl_write(&net->context.ssl, buf + sentLen, (size_t)len - sentLen);

		if(ret > 0) {
			sentLen += ret;
		} else {
			if ((ret != MBEDTLS_ERR_SSL_WANT_READ) &&
				(ret != MBEDTLS_ERR_SSL_WANT_WRITE)) {
				IOT_ERROR("mbedtls_ssl_write = -0x%04X\n", -ret);
				return ret;
			}
		}
	} while (sentLen < len && !iot_os_timer_isexpired(timer));

	return sentLen;
}

iot_error_t iot_net_init(iot_net_interface_t *net)
{
	iot_error_t err;

	err = _iot_net_check_interface(net);
	if (err) {
		return err;
	}

	net->connect = _iot_net_tls_connect;
	net->disconnect = _iot_net_tls_disconnect;
	net->select = _iot_net_select;
	net->read = _iot_net_tls_read;
	net->write = _iot_net_tls_write;
	net->show_status = _iot_net_show_status;

	return IOT_ERROR_NONE;
}
