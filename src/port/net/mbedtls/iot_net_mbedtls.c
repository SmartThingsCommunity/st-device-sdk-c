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
#include <iot_util.h>
#if defined(CONFIG_STDK_IOT_CORE_OS_SUPPORT_POSIX)
#include <netinet/in.h>
#include <netinet/tcp.h>
#endif

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

	if (select(socket + 1, &rfdset, &wfdset, NULL, &timeout) < 0) {
		IOT_ERROR("failed to select :%d/%d", (socket + 1), errno);
	}
	if (getsockopt(socket, SOL_SOCKET, SO_ERROR, &sock_err, &err_len) < 0) {
		IOT_ERROR("failed to getsockopt :%d/%d", socket, errno);
	}
	if (gettimeofday(&tv, NULL) < 0) {
		IOT_ERROR("failed to gettimeofday :%d", errno);
	}

	IOT_INFO("[%ld] network socket status: sockfd %d readable %d writable %d sock_err %d errno %d",
				tv.tv_sec, socket,
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

#if defined(CONFIG_MBEDTLS_SSL_ASYNC_PRIVATE)
static void _iot_net_tls_asn1_write_int(unsigned char **p, unsigned char *raw, int base_ofs, size_t len)
{
	size_t length;

	// TAG : INTEGER
	*(*p)++ = MBEDTLS_ASN1_INTEGER;

	// LENGTH
	length = len;
	if (raw[base_ofs] & 0x80) {
		length += 1;
	}
	*(*p)++ = length;

	// VALUE
	if (raw[base_ofs] & 0x80) {
		*(*p)++ = 0x00;
	}

	memcpy(*p, raw + base_ofs, len);
	*p += len;
}

static iot_error_t _iot_net_tls_raw_to_der(iot_security_buffer_t *raw_buf, iot_security_buffer_t *der_buf)
{
	const int asn1_extra_len = 6;
	unsigned char *p;
	size_t mpi_r_len;
	size_t mpi_s_len;
	int len;

	if (!raw_buf || !der_buf) {
		IOT_ERROR("params is null");
		return IOT_ERROR_INVALID_ARGS;
	}

	if (raw_buf->len > 0x80) {
		IOT_ERROR("not supported length %d", raw_buf->len);
		return IOT_ERROR_INVALID_ARGS;
	}

	/*
	 * Get expected DER buffer size
	 */
	mpi_r_len = raw_buf->len / 2;
	mpi_s_len = raw_buf->len - mpi_r_len;

	der_buf->len = raw_buf->len + asn1_extra_len;
	if (raw_buf->p[0] & 0x80) {
		der_buf->len += 1;
	}
	if (raw_buf->p[mpi_r_len] & 0x80) {
		der_buf->len += 1;
	}

	der_buf->p = (unsigned char *)iot_os_malloc(der_buf->len);
	if (!der_buf->p) {
		IOT_ERROR("failed to malloc for der buf");
		return IOT_ERROR_MEM_ALLOC;
	}

	/*
	 * Fill DER buffer
	 */
	p = der_buf->p;

	// TAG : SEQUENCE
	*p++ = (MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);

	// LENGTH
	len = 4 + raw_buf->len;
	if (raw_buf->p[0] & 0x80) {
		len += 1;
	}
	if (raw_buf->p[mpi_r_len] & 0x80) {
		len += 1;
	}
	*p++ = len;

	_iot_net_tls_asn1_write_int(&p, raw_buf->p, 0, mpi_r_len);
	_iot_net_tls_asn1_write_int(&p, raw_buf->p, mpi_r_len, mpi_s_len);

	return IOT_ERROR_NONE;
}

static int _iot_net_tls_external_sign(mbedtls_ssl_context *ssl,
		mbedtls_x509_crt *cert, mbedtls_md_type_t md_alg,
		const unsigned char *hash, size_t hash_len)
{
	iot_security_context_t *security_context;
	iot_security_key_type_t key_type;
	iot_security_buffer_t hash_buf = { 0 };
	iot_security_buffer_t *sig_buf;
	iot_security_buffer_t *der_buf;
	int ret = 0;

	if (ssl == NULL || hash == NULL || hash_len == 0) {
		IOT_ERROR("invalid input parameter");
		return MBEDTLS_ERR_PK_INVALID_ALG;
	}

	if (md_alg != MBEDTLS_MD_SHA256) {
		IOT_ERROR("SHA256 only supported");
		return MBEDTLS_ERR_PK_INVALID_ALG;
	}

	sig_buf = (iot_security_buffer_t *)malloc(sizeof(iot_security_buffer_t));
	if (!sig_buf) {
		IOT_ERROR("failed to malloc for sig");
		return MBEDTLS_ERR_PK_ALLOC_FAILED;
	}

	security_context = iot_security_init();
	if (!security_context) {
		return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
	}

	if (iot_security_pk_init(security_context)) {
		iot_security_deinit(security_context);
		return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
	}

	if (iot_security_pk_get_key_type(security_context, &key_type)) {
		ret = MBEDTLS_ERR_PK_BAD_INPUT_DATA;
		goto cleanup;
	}

	switch (key_type) {
	case IOT_SECURITY_KEY_TYPE_ECCP256:
		hash_buf.p = (unsigned char *)hash;
		hash_buf.len = hash_len;
		if (iot_security_pk_sign(security_context, &hash_buf, sig_buf)) {
			ret = MBEDTLS_ERR_PK_KEY_INVALID_FORMAT;
			iot_os_free(sig_buf);
			break;
		}

		der_buf = (iot_security_buffer_t *)malloc(sizeof(iot_security_buffer_t));
		if (!der_buf) {
			IOT_ERROR("failed to malloc for der");
			return MBEDTLS_ERR_PK_ALLOC_FAILED;
		}

		if (_iot_net_tls_raw_to_der(sig_buf, der_buf)) {
			ret = MBEDTLS_ERR_PK_KEY_INVALID_FORMAT;
			iot_os_free(der_buf);
			memset(sig_buf->p, 0, sig_buf->len);
			iot_os_free(sig_buf->p);
			iot_os_free(sig_buf);
			break;
		}

		mbedtls_ssl_set_async_operation_data(ssl, der_buf);

		memset(sig_buf->p, 0, sig_buf->len);
		iot_os_free(sig_buf->p);
		iot_os_free(sig_buf);

		break;
	case IOT_SECURITY_KEY_TYPE_RSA2048:
		hash_buf.p = (unsigned char *)hash;
		hash_buf.len = hash_len;
		if (iot_security_pk_sign(security_context, &hash_buf, sig_buf)) {
			ret = MBEDTLS_ERR_PK_KEY_INVALID_FORMAT;
			break;
		}

		mbedtls_ssl_set_async_operation_data(ssl, sig_buf);
		break;
	default:
		IOT_ERROR("'%d' is not supported algorithm", key_type);
		ret = MBEDTLS_ERR_PK_UNKNOWN_PK_ALG;
		break;
	}

cleanup:
	(void)iot_security_pk_deinit(security_context);
	(void)iot_security_deinit(security_context);

	return ret;
}

static int _iot_net_tls_external_resume(mbedtls_ssl_context *ssl,
		unsigned char *output, size_t *output_len, size_t output_size)
{
	iot_security_buffer_t *sig_buf;

	if (ssl == NULL || output == NULL || output_len == NULL) {
		IOT_ERROR("invalid input parameter");
		return MBEDTLS_ERR_PK_INVALID_ALG;
	}

	sig_buf = (iot_security_buffer_t *)mbedtls_ssl_get_async_operation_data(ssl);
	if (!sig_buf) {
		IOT_ERROR("cannot retrieve signature buffer");
		return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
	}

	if (sig_buf->len > output_size) {
		IOT_ERROR("output buffer is too small %d > %d", sig_buf->len, output_size);
		return MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL;
	}

	memcpy(output, sig_buf->p, sig_buf->len);
	*output_len = sig_buf->len;

	memset(sig_buf->p, 0, sig_buf->len);
	iot_os_free(sig_buf->p);
	iot_os_free(sig_buf);

	return 0;
}

static void _iot_net_tls_external_cancel(mbedtls_ssl_context *ssl)
{
	iot_security_buffer_t *sig_buf;

	if (ssl == NULL) {
		IOT_ERROR("invalid input parameter");
		return;
	}

	sig_buf = (iot_security_buffer_t *)mbedtls_ssl_get_async_operation_data(ssl);
	if (sig_buf) {
		memset(sig_buf->p, 0, sig_buf->len);
		iot_os_free(sig_buf->p);
		iot_os_free(sig_buf);
	}
}

// TODO : will be implemented as static
void iot_net_tls_external_private(mbedtls_ssl_config *conf)
{
	mbedtls_ssl_conf_async_private_cb(conf,
			_iot_net_tls_external_sign,
			NULL,
			_iot_net_tls_external_resume,
			_iot_net_tls_external_cancel,
			NULL);
}
#else
void iot_net_tls_external_private(mbedtls_ssl_config *conf)
{
}
#endif /* CONFIG_MBEDTLS_SSL_ASYNC_PRIVATE */

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

static iot_error_t _iot_net_tcp_keepalive(iot_net_interface_t *net, unsigned int idle, unsigned int count, unsigned int intval)
{
	iot_error_t err;
	int socket;
	int keepAlive = 1;
	int ret;

	err = _iot_net_check_interface(net);
	if (err) {
		return err;
	}

	socket = net->context.server_fd.fd;
	ret = setsockopt(socket, SOL_SOCKET, SO_KEEPALIVE, &keepAlive, sizeof(keepAlive));
	if (ret)
	{
		IOT_WARN("fail to set KEEPALIVE error %d", ret);
		return IOT_ERROR_BAD_REQ;
	}
	ret = setsockopt(socket, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
	if (ret)
	{
		IOT_WARN("fail to set KEEPALIVEIDLE error %d", ret);
		return IOT_ERROR_BAD_REQ;
	}
	ret = setsockopt(socket, IPPROTO_TCP, TCP_KEEPCNT, &count, sizeof(count));
	if (ret)
	{
		IOT_WARN("fail to set KEEPALIVECOUNT error %d", ret);
		return IOT_ERROR_BAD_REQ;
	}
	ret = setsockopt(socket, IPPROTO_TCP, TCP_KEEPINTVL, &intval, sizeof(intval));
	if (ret)
	{
		IOT_WARN("fail to set KEEPALIVEINTERVAL error %d", ret);
		return IOT_ERROR_BAD_REQ;
	}

	return IOT_ERROR_NONE;
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

	if (buf == NULL || timer == NULL) {
		return -1;
	}

	if (len == 0) {
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
	net->tcp_keepalive = _iot_net_tcp_keepalive;
	net->disconnect = _iot_net_tls_disconnect;
	net->select = _iot_net_select;
	net->read = _iot_net_tls_read;
	net->write = _iot_net_tls_write;
	net->show_status = _iot_net_show_status;

	return IOT_ERROR_NONE;
}
