/*******************************************************************************
 * Copyright (c) 2019 Samsung Electronics All Rights Reserved.
 * Copyright (c) 2014, 2017 IBM Corp.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 *
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *   http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * Contributors:
 *   Allan Stockdill-Mander/Ian Craggs - initial API and implementation and/or initial documentation
 *   Ian Craggs - fix for #96 - check rem_len in readPacket
 *   Ian Craggs - add ability to set message handler separately #6
 *******************************************************************************/
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <errno.h>
#include <unistd.h>

#include "iot_main.h"
#include "iot_debug.h"

void __SSL_library_init(void)
{
	return;
}

void SSL_library_init(void) __attribute__((weak, alias("__SSL_library_init")));

static void _iot_net_show_status(iot_net_interface_t *n)
{
	struct timeval tv, timeout = {0,};
	int sock_err = 0;
	socklen_t err_len = sizeof(sock_err);
	fd_set rfdset, wfdset;

	FD_ZERO(&rfdset);
	FD_ZERO(&wfdset);
	FD_SET(n->context.socket, &rfdset);
	FD_SET(n->context.socket, &wfdset);

	select(n->context.socket + 1, &rfdset, &wfdset, NULL, &timeout);
	getsockopt(n->context.socket, SOL_SOCKET, SO_ERROR, &sock_err, &err_len);
	gettimeofday(&tv, NULL);

	IOT_INFO("[%ld] Socket Network Status readable %d writable %d sock_err %d errno %d", tv.tv_sec,
			FD_ISSET(n->context.socket, &rfdset), FD_ISSET(n->context.socket, &wfdset), sock_err, errno);
}

static int _iot_net_select(iot_net_interface_t *n, unsigned int timeout_ms)
{
	int ret = 0;
	struct timeval timeout;
	fd_set fdset;

	FD_ZERO(&fdset);
	FD_SET(n->context.socket, &fdset);

	timeout.tv_sec = timeout_ms / 1000;
	timeout.tv_usec = (timeout_ms % 1000) * 1000;

	if ((n->context.ssl && SSL_pending(n->context.ssl) > 0) || select(n->context.socket + 1, &fdset, NULL, NULL, &timeout) > 0)
		ret = 1;

	return ret;
}

static int _iot_net_ssl_read(iot_net_interface_t *n, unsigned char *buffer, int len, iot_os_timer timer)
{
	int recvLen = 0, rc = 0;

	struct timeval timeout;
	fd_set fdset;

	FD_ZERO(&fdset);
	FD_SET(n->context.socket, &fdset);

	timeout.tv_sec =  iot_os_timer_left_ms(timer) / 1000;
	timeout.tv_usec = (iot_os_timer_left_ms(timer) % 1000) * 1000;

	if (SSL_pending(n->context.ssl) > 0 || select(n->context.socket + 1, &fdset, NULL, NULL, &timeout) > 0) {
		do {
			rc = SSL_read(n->context.ssl, buffer + recvLen, len - recvLen);

			if (rc > 0)
				recvLen += rc;
			else if (rc <= 0) {
				int error = 0;
				error = SSL_get_error(n->context.ssl, rc);
				IOT_WARN("recv error %d %d %d\n", rc, error, errno);
				switch (error) {
				case SSL_ERROR_WANT_READ:
					if (errno == ECONNABORTED) {
						recvLen = -1;
						goto exit;
					}
					iot_os_delay(1000);
					break;
				default:
					recvLen = -1;
					goto exit;
				}
			}
		} while (recvLen < len && !iot_os_timer_isexpired(timer));
	}

exit:
	return recvLen;
}

static int _iot_net_ssl_write(iot_net_interface_t *n, unsigned char *buffer, int len, iot_os_timer timer)
{
	int sentLen = 0, rc = 0, ret = 0;

	struct timeval timeout;
	fd_set fdset;

	FD_ZERO(&fdset);
	FD_SET(n->context.socket, &fdset);

	timeout.tv_sec =  iot_os_timer_left_ms(timer) / 1000;
	timeout.tv_usec = (iot_os_timer_left_ms(timer) % 1000) * 1000;

	errno = 0;
	ret = select(n->context.socket + 1, NULL, &fdset, NULL, &timeout);

	if (ret <= 0) {
		struct timeval tv;
		int error = 0;
		long expired = 0;
		socklen_t err_len = sizeof(error);
		expired = iot_os_timer_left_ms(timer);
		getsockopt(n->context.socket, SOL_SOCKET, SO_ERROR, &error, &err_len);
		gettimeofday(&tv, NULL);
		IOT_ERROR("[%ld] Socket Network Error write_sel_rc %d sock_err %d errno %d select expired=%ld",
			tv.tv_sec, ret, error, errno, expired);
		return ret;
	}

	if (FD_ISSET(n->context.socket, &fdset)) {
		do {
			rc = SSL_write(n->context.ssl, buffer + sentLen, len - sentLen);

			if (rc > 0) {
				sentLen += rc;
			}
			else if (rc <= 0){
				int error = 0;
				error = SSL_get_error(n->context.ssl, rc);
				IOT_WARN("write error %d %d %d\n", rc, error, errno);
				sentLen = -1;
				break;
			}
		} while (sentLen < len && !iot_os_timer_isexpired(timer));
	}

	return sentLen;
}

static void _iot_net_ssl_disconnect(iot_net_interface_t *n)
{
	close(n->context.socket);
	SSL_free(n->context.ssl);
	SSL_CTX_free(n->context.ctx);
	n->context.read_count = 0;
}

static iot_error_t _iot_net_ssl_connect(iot_net_interface_t *n)
{
	struct sockaddr_in sAddr;
	int retVal = -1;
	struct hostent *ipAddress;
#if defined(LWIP_SO_SNDRCVTIMEO_NONSTANDARD) && (LWIP_SO_SNDRCVTIMEO_NONSTANDARD == 0)
	struct timeval sock_timeout = {30, 0};
#else
	unsigned int sock_timeout = 30* 1000;
#endif

	SSL_library_init();

	if ((ipAddress = gethostbyname(n->connection.url)) == 0) {
		IOT_ERROR("gethostbyname failed");
		goto exit;
	}

	n->context.ctx = SSL_CTX_new(n->context.method);

	if (!n->context.ctx) {
		IOT_ERROR("SSL_CTX_new failed");
		goto exit;
	}
#if defined(CONFIG_STDK_IOT_CORE_OS_SUPPORT_FREERTOS) || defined(CONFIG_STDK_IOT_CORE_OS_SUPPORT_TIZENRT)
	if (n->connection.ca_cert) {
		retVal = SSL_CTX_load_verify_buffer(n->context.ctx, n->connection.ca_cert, n->connection.ca_cert_len);

		if (retVal != 1) {
			IOT_ERROR("SSL_CTX_load_verify_buffer failed retVal (%d)", retVal);
			goto exit1;
		}
	}
#endif
	if (n->connection.ca_cert && n->connection.key) {
		retVal = SSL_CTX_use_certificate_ASN1(n->context.ctx, n->connection.ca_cert_len, n->connection.ca_cert);

		if (!retVal) {
			IOT_ERROR("SSL_CTX_use_certificate_ASN1 failed retVal (%d)", retVal);
			goto exit1;
		}

		retVal = SSL_CTX_use_PrivateKey_ASN1(0, n->context.ctx, n->connection.key, n->connection.key_len);

		if (!retVal) {
			IOT_ERROR("SSL_CTX_use_PrivateKey_ASN1 failed retVal (%d)", retVal);
			goto exit1;
		}
	}

	if (n->connection.ca_cert) {
		SSL_CTX_set_verify(n->context.ctx, SSL_VERIFY_PEER, NULL);
	} else {
		SSL_CTX_set_verify(n->context.ctx, SSL_VERIFY_NONE, NULL);
	}

	sAddr.sin_family = AF_INET;
	sAddr.sin_addr.s_addr = ((struct in_addr *)(ipAddress->h_addr))->s_addr;
	sAddr.sin_port = htons(n->connection.port);

	if ((n->context.socket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		IOT_ERROR("socket create failed (%d) errno (%d)", n->context.socket, errno);
		goto exit1;
	}
	setsockopt(n->context.socket, SOL_SOCKET, SO_RCVTIMEO, &sock_timeout, sizeof(sock_timeout));
	setsockopt(n->context.socket, SOL_SOCKET, SO_SNDTIMEO, &sock_timeout, sizeof(sock_timeout));
	if ((retVal = connect(n->context.socket, (struct sockaddr *)&sAddr, sizeof(sAddr))) < 0) {
		IOT_ERROR("socket connect failed (socket:%d) retVal (%d) errno (%d)", n->context.socket, retVal, errno);
		goto exit2;
	}

	n->context.ssl = SSL_new(n->context.ctx);

	if (!n->context.ssl) {
		IOT_ERROR("SSL_new failed");
		goto exit2;
	}

	SSL_set_fd(n->context.ssl, n->context.socket);

	if ((retVal = SSL_connect(n->context.ssl)) <= 0) {
		IOT_ERROR("ssl connect failed retVal (%d)", retVal);
		goto exit3;
	} else {
		retVal = IOT_ERROR_NONE;
		goto exit;
	}

exit3:
	SSL_free(n->context.ssl);
exit2:
	close(n->context.socket);
exit1:
	SSL_CTX_free(n->context.ctx);
	retVal = IOT_ERROR_NET_CONNECT;
exit:
	return retVal;
}

iot_error_t iot_net_init(iot_net_interface_t *n)
{
	if (n == NULL) {
		IOT_ERROR("interface is null");
		return IOT_ERROR_NET_INVALID_INTERFACE;
	}

	memset(n, 0, sizeof(iot_net_interface_t));

	n->context.method = TLSv1_2_client_method();

	n->connect = _iot_net_ssl_connect;
	n->disconnect = _iot_net_ssl_disconnect;
	n->select = _iot_net_select;
	n->read = _iot_net_ssl_read;
	n->write = _iot_net_ssl_write;
	n->show_status = _iot_net_show_status;

	return IOT_ERROR_NONE;
}
