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

#include "iot_debug.h"
#include "port_net.h"

#include <sys/socket.h>
#include <errno.h>
#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
#include <netinet/in.h>
#include <unistd.h>
#include <netinet/tcp.h>
#endif

#include "mbedtls/version.h"
#include "mbedtls/platform.h"
#if MBEDTLS_VERSION_NUMBER > 0x03000000
#include "mbedtls/net_sockets.h"
#else
#include "mbedtls/net.h"
#endif
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#if MBEDTLS_VERSION_NUMBER < 0x03000000
#include "mbedtls/certs.h"
#endif
#include "mbedtls/x509.h"
#include "mbedtls/debug.h"

#define IOT_MBEDTLS_READ_TIMEOUT_MS 10000

typedef struct {
	bool is_tls_connection;

	mbedtls_net_context sock_fd;
	mbedtls_ssl_context ssl;
	mbedtls_ssl_config conf;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_x509_crt cacert;
	mbedtls_x509_crt own_cert;
} port_net_mbedtls_context_t;

static void _free_net_ctx(port_net_mbedtls_context_t *ctx)
{
	mbedtls_net_free(&ctx->sock_fd);
	mbedtls_x509_crt_free(&ctx->cacert);
	mbedtls_x509_crt_free(&ctx->own_cert);
	mbedtls_ssl_free(&ctx->ssl);
	mbedtls_ssl_config_free(&ctx->conf);
	mbedtls_ctr_drbg_free(&ctx->ctr_drbg);
	mbedtls_entropy_free(&ctx->entropy);
}

void port_net_free(PORT_NET_CONTEXT ctx)
{
	port_net_mbedtls_context_t *_ctx = (port_net_mbedtls_context_t *)ctx;

	if (_ctx == NULL) {
		return;
	}

	_free_net_ctx(_ctx);
	free(_ctx);
}

#ifdef CONFIG_MBEDTLS_DEBUG
static void _iot_net_mbedtls_debug(void *ctx, int level, const char *file, int line,
					const char *str)
{
	const char *filename;

	filename = strrchr(file, '/') ? strrchr(file, '/') + 1 : file;

	IOT_INFO("%s:%04d: |%d| %s", filename, line, level, str);
}
#endif

PORT_NET_CONTEXT port_net_connect(char *address, char *port, port_net_tls_config *config)
{
	port_net_mbedtls_context_t *new_net_context = NULL;

	new_net_context = (port_net_mbedtls_context_t *)malloc(sizeof(port_net_mbedtls_context_t));
	if (!new_net_context)
		return NULL;
	memset(new_net_context, 0, sizeof(port_net_mbedtls_context_t));

	if (config) {
		const char *pers = "iot_net_mbedtls";
		int ret;

		mbedtls_net_init(&new_net_context->sock_fd);
		mbedtls_ssl_init(&new_net_context->ssl);
		mbedtls_ssl_config_init(&new_net_context->conf);

		mbedtls_ctr_drbg_init(&new_net_context->ctr_drbg);
		mbedtls_entropy_init(&new_net_context->entropy);
		ret = mbedtls_ctr_drbg_seed(&new_net_context->ctr_drbg, mbedtls_entropy_func, &new_net_context->entropy,
					(const unsigned char *)pers, strlen((char *)pers));
		if (ret) {
			IOT_ERROR("mbedtls_ctr_drbg_seed = -0x%04X", -ret);
			goto exit;
		}

		IOT_INFO("Loading the CA root certificate %d@%p",
				config->ca_cert_len + 1,
				config->ca_cert);
		mbedtls_x509_crt_init(&new_net_context->cacert);
		/* iot-core passed the certificate without NULL character */
		ret = mbedtls_x509_crt_parse(&new_net_context->cacert,
					(const unsigned char *)config->ca_cert,
					config->ca_cert_len + 1);
		if (ret) {
			IOT_ERROR("mbedtls_x509_crt_parse = -0x%04X", -ret);
			goto exit;
		}

		IOT_DEBUG("Connecting to %s:%s", address, port);
		ret = mbedtls_net_connect(&new_net_context->sock_fd,
				address, port,
				MBEDTLS_NET_PROTO_TCP);
		if (ret) {
			IOT_ERROR("mbedtls_net_connect = -0x%04X", -ret);
			goto exit;
		}

		mbedtls_ssl_config_defaults(&new_net_context->conf,
					MBEDTLS_SSL_IS_CLIENT,
					MBEDTLS_SSL_TRANSPORT_STREAM,
					MBEDTLS_SSL_PRESET_DEFAULT);
		mbedtls_ssl_conf_authmode(&new_net_context->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
		mbedtls_ssl_conf_ca_chain(&new_net_context->conf, &new_net_context->cacert, NULL);
		mbedtls_ssl_conf_rng(&new_net_context->conf, mbedtls_ctr_drbg_random, &new_net_context->ctr_drbg);
		mbedtls_ssl_conf_read_timeout(&new_net_context->conf, IOT_MBEDTLS_READ_TIMEOUT_MS);

#ifdef CONFIG_MBEDTLS_DEBUG
		mbedtls_ssl_conf_dbg(&new_net_context->conf, _iot_net_mbedtls_debug, NULL);
		mbedtls_debug_set_threshold(CONFIG_MBEDTLS_DEBUG_LEVEL);
#endif

		ret = mbedtls_ssl_setup(&new_net_context->ssl, &new_net_context->conf);
		if (ret) {
			IOT_ERROR("mbedtls_ssl_setup = -0x%04X", -ret);
			goto exit;
		}

		ret = mbedtls_ssl_set_hostname(&new_net_context->ssl, address);
		if (ret) {
			IOT_ERROR("mbedtls_ssl_set_hostname = -0x%04X", -ret);
			goto exit;
		}

		mbedtls_ssl_set_bio(&new_net_context->ssl,
					&new_net_context->sock_fd,
					mbedtls_net_send, NULL, mbedtls_net_recv_timeout);

		IOT_DEBUG("Performing the SSL/TLS handshake");

		while ((ret = mbedtls_ssl_handshake(&new_net_context->ssl)) != 0) {
			if ((ret != MBEDTLS_ERR_SSL_WANT_READ) &&
			    (ret != MBEDTLS_ERR_SSL_WANT_WRITE)) {
				IOT_ERROR("mbedtls_ssl_handshake = -0x%x", -ret);
				if (ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) {
					IOT_ERROR("failed to verify the server's certificate");
				}
				goto exit;
			}
		}

		IOT_DEBUG("Protocol is %s", mbedtls_ssl_get_version(&new_net_context->ssl));
		IOT_DEBUG("Ciphersuite is %s", mbedtls_ssl_get_ciphersuite(&new_net_context->ssl));
		IOT_DEBUG("Verifying peer X.509 certificate");
		ret = mbedtls_ssl_get_verify_result(&new_net_context->ssl);
		if (ret) {
			IOT_ERROR("mbedtls_ssl_get_verify_result = 0x%x", ret);
			goto exit;
		}
#if defined(STDK_IOT_CORE_TLS_DEBUG)
		if (mbedtls_ssl_get_peer_cert(&new_net_context->ssl) != NULL) {
			unsigned char buf[2048];
			IOT_INFO("Peer certificate information");
			mbedtls_x509_crt_info((char *)buf, sizeof(buf) - 1,
					"!", mbedtls_ssl_get_peer_cert(&new_net_context->ssl));
			IOT_INFO("%s\n", buf);
		}
#endif
		new_net_context->is_tls_connection = true;
	} else {
		/* TODO : Implement no-tls connect part */
		goto exit;
	}

	return (PORT_NET_CONTEXT)new_net_context;
exit:
	if (new_net_context) {
		_free_net_ctx(new_net_context);
		free(new_net_context);
	}
	return NULL;
}

PORT_NET_CONTEXT port_net_listen(char *port, port_net_tls_config *config)
{
	int ret;
	mbedtls_net_context listen_fd = {0,};
	port_net_mbedtls_context_t *new_net_context = NULL;

	new_net_context = (port_net_mbedtls_context_t *)malloc(sizeof(port_net_mbedtls_context_t));
	if (!new_net_context)
		return NULL;
	memset(new_net_context, 0, sizeof(port_net_mbedtls_context_t));

	mbedtls_net_init(&listen_fd);

	if (config) {
		const char *pers = "easysetup";

		mbedtls_net_init(&new_net_context->sock_fd);
		mbedtls_ssl_init(&new_net_context->ssl);
		mbedtls_ssl_config_init(&new_net_context->conf);

		mbedtls_ctr_drbg_init(&new_net_context->ctr_drbg);
		mbedtls_entropy_init(&new_net_context->entropy);
		ret = mbedtls_ctr_drbg_seed(&new_net_context->ctr_drbg, mbedtls_entropy_func, &new_net_context->entropy,
					(const unsigned char *)pers, strlen((char *)pers));
		if (ret) {
			IOT_ERROR("mbedtls_ctr_drbg_seed = -0x%04X", -ret);
			goto exit;
		}

		IOT_INFO("Loading the CA root certificate %d@%p",
				config->ca_cert_len + 1,
				config->ca_cert);
		mbedtls_x509_crt_init(&new_net_context->cacert);
		/* iot-core passed the certificate without NULL character */
		ret = mbedtls_x509_crt_parse(&new_net_context->cacert,
					(const unsigned char *)config->ca_cert,
					config->ca_cert_len + 1);
		if (ret) {
			IOT_ERROR("mbedtls_x509_crt_parse = -0x%04X", -ret);
			goto exit;
		}

		IOT_INFO("Loading the device certificate %d@%p",
				config->device_cert_len + 1,
				config->device_cert);
		mbedtls_x509_crt_init(&new_net_context->own_cert);
		/* iot-core passed the certificate without NULL character */
		ret = mbedtls_x509_crt_parse(&new_net_context->own_cert,
					(const unsigned char *)config->device_cert,
					config->device_cert_len + 1);
		if (ret) {
			IOT_ERROR("mbedtls_x509_crt_parse = -0x%04X", -ret);
			goto exit;
		}

		mbedtls_ssl_config_defaults(&new_net_context->conf,
					MBEDTLS_SSL_IS_CLIENT,
					MBEDTLS_SSL_TRANSPORT_STREAM,
					MBEDTLS_SSL_PRESET_DEFAULT);
		mbedtls_ssl_conf_rng(&new_net_context->conf, mbedtls_ctr_drbg_random, &new_net_context->ctr_drbg);
		mbedtls_ssl_conf_ca_chain(&new_net_context->conf, &new_net_context->cacert, NULL);
		mbedtls_ssl_conf_own_cert(&new_net_context->conf, &new_net_context->own_cert, NULL);

#ifdef CONFIG_MBEDTLS_DEBUG
		mbedtls_ssl_conf_dbg(&new_net_context->conf, _iot_net_mbedtls_debug, NULL);
		mbedtls_debug_set_threshold(CONFIG_MBEDTLS_DEBUG_LEVEL);
#endif

		ret = mbedtls_ssl_setup(&new_net_context->ssl, &new_net_context->conf);
		if (ret) {
			IOT_ERROR("mbedtls_ssl_setup = -0x%04X", -ret);
			goto exit;
		}

		ret = mbedtls_net_bind(&listen_fd, NULL, port, MBEDTLS_NET_PROTO_TCP);
		if (ret)
		{
			IOT_ERROR("mbedtls_net_bind = -0x%04X", -ret);
			goto exit;
		}

		ret = mbedtls_net_accept(&listen_fd, &new_net_context->sock_fd, NULL, 0, NULL);
		if (ret)
		{
			IOT_ERROR("mbedtls_net_accept = -0x%04X", -ret);
			goto exit;
		}

		mbedtls_ssl_set_bio(&new_net_context->ssl,
					&new_net_context->sock_fd,
					mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout);

		IOT_DEBUG("Performing the SSL/TLS handshake");

		while ((ret = mbedtls_ssl_handshake(&new_net_context->ssl)) != 0) {
			if ((ret != MBEDTLS_ERR_SSL_WANT_READ) &&
			    (ret != MBEDTLS_ERR_SSL_WANT_WRITE)) {
				IOT_ERROR("mbedtls_ssl_handshake = -0x%x", -ret);
				if (ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) {
					IOT_ERROR("failed to verify the server's certificate");
				}
				goto exit;
			}
		}
		new_net_context->is_tls_connection = true;
	} else {
		mbedtls_net_init(&new_net_context->sock_fd);

		ret = mbedtls_net_bind(&listen_fd, NULL, port, MBEDTLS_NET_PROTO_TCP);
		if (ret)
		{
			IOT_ERROR("mbedtls_net_bind = -0x%04X", -ret);
			goto exit;
		}

		ret = mbedtls_net_accept(&listen_fd, &new_net_context->sock_fd, NULL, 0, NULL);
		if (ret)
		{
			IOT_ERROR("mbedtls_net_accept = -0x%04X", -ret);
			goto exit;
		}

		// set tcp keepalive related opts
		// if ST app WiFi disconnect coincidentally during easysetup,
		// we need short time tcp keepalive here.
		int keep_alive = 1;
		ret = setsockopt(new_net_context->sock_fd.fd, SOL_SOCKET, SO_KEEPALIVE, &keep_alive, sizeof(int));
		if (ret < 0) {
			IOT_INFO("socket set keep-alive failed %d", errno);
		}

		int idle = 10;
		ret = setsockopt(new_net_context->sock_fd.fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(int));
		if (ret < 0) {
			IOT_INFO("socket set keep-idle failed %d", errno);
		}

		int interval = 5;
		ret = setsockopt(new_net_context->sock_fd.fd, IPPROTO_TCP, TCP_KEEPINTVL, &interval, sizeof(int));
		if (ret < 0) {
			IOT_INFO("socket set keep-interval failed %d", errno);
		}

		int maxpkt = 3;
		ret = setsockopt(new_net_context->sock_fd.fd, IPPROTO_TCP, TCP_KEEPCNT, &maxpkt, sizeof(int));
		if (ret < 0) {
			IOT_INFO("socket set keep-count failed %d", errno);
		}

		// HTTP response as tcp payload is sent once, and mostly less than MTU.
		// There is no need for tcp packet coalesced.
		// To enhance throughput, disable TCP Nagle's algorithm here.
		int no_delay = 1;
		ret = setsockopt(new_net_context->sock_fd.fd, IPPROTO_TCP, TCP_NODELAY, &no_delay, sizeof(int));
		if (ret < 0) {
			IOT_INFO("socket set no-delay failed %d", errno);
		}
		new_net_context->is_tls_connection = false;
	}

	return (PORT_NET_CONTEXT)new_net_context;
exit:
	mbedtls_net_free(&listen_fd);

	if (new_net_context) {
		_free_net_ctx(new_net_context);
		free(new_net_context);
	}
	return NULL;
}

int port_net_read(PORT_NET_CONTEXT ctx, void *buf, size_t len)
{
	int recvLen = 0, ret = 0;
	port_net_mbedtls_context_t *_ctx = (port_net_mbedtls_context_t *)ctx;

	if (_ctx == NULL) {
		return -1;
	}

	IOT_DEBUG("%d@%p", len, buf);
	if (_ctx->is_tls_connection) {
		ret = mbedtls_ssl_read(&_ctx->ssl, buf, len);

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
	} else {
		recvLen = mbedtls_net_recv(&_ctx->sock_fd, buf, len);
	}

	return recvLen;
}

int port_net_read_poll(PORT_NET_CONTEXT ctx, unsigned int wait_time_ms)
{
	struct timeval timeout;
	fd_set fdset;
	int socket;
	int ret;
	port_net_mbedtls_context_t *_ctx = (port_net_mbedtls_context_t *)ctx;

	if (_ctx == NULL) {
		return -1;
	}

	socket = _ctx->sock_fd.fd;
	FD_ZERO(&fdset);
	FD_SET(socket, &fdset);
	if (wait_time_ms == PORT_NET_WAIT_FOREVER) {
		ret = select(socket + 1, &fdset, NULL, NULL, NULL);
	} else {
		timeout.tv_sec = wait_time_ms;
		timeout.tv_usec = 0;
		ret = select(socket + 1, &fdset, NULL, NULL, &timeout);
	}

	return ret;
}

int port_net_write(PORT_NET_CONTEXT ctx, void *buf, size_t len)
{
	int sentLen = 0, ret = 0;
	port_net_mbedtls_context_t *_ctx = (port_net_mbedtls_context_t *)ctx;

	if (_ctx == NULL) {
		return -1;
	}

	IOT_DEBUG("%d@%p", len, buf);
	if (_ctx->is_tls_connection) {
		ret = mbedtls_ssl_write(&_ctx->ssl, buf, len);

		if(ret > 0) {
			sentLen += ret;
		} else {
			if ((ret != MBEDTLS_ERR_SSL_WANT_READ) &&
				(ret != MBEDTLS_ERR_SSL_WANT_WRITE)) {
				IOT_ERROR("mbedtls_ssl_write = -0x%04X\n", -ret);
				return ret;
			}
		}
	} else {
		sentLen = mbedtls_net_send(&_ctx->sock_fd, buf, len);
	}

	return sentLen;
}

void port_net_close(PORT_NET_CONTEXT ctx)
{
	port_net_mbedtls_context_t *_ctx = (port_net_mbedtls_context_t *)ctx;

	if (_ctx == NULL || !_ctx->is_tls_connection) {
		return;
	}

	mbedtls_ssl_close_notify(&_ctx->ssl);
	mbedtls_net_free(&_ctx->sock_fd);
}
