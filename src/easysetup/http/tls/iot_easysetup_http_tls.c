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
#include <sys/socket.h>
#include <errno.h>
#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
#include <netinet/in.h>
#include <unistd.h>
#endif
#include <iot_nv_data.h>
#include <iot_util.h>

#include "../easysetup_http.h"
#include "iot_os_util.h"
#include "iot_debug.h"
#include "iot_easysetup.h"
#include "iot_main.h"

#include "mbedtls/platform.h"
#include "mbedtls/net.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/debug.h"

// TODO : remove this after following is implemented as static
void iot_net_tls_external_private(mbedtls_ssl_config *conf);

static char *tx_buffer = NULL;

static mbedtls_net_context listen_fd, client_fd;
static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context ctr_drbg;
static mbedtls_ssl_context ssl;
static mbedtls_ssl_config conf;
static mbedtls_x509_crt srvcert;
static mbedtls_pk_context pkey;

static iot_os_thread es_mbedtls_task_handle = NULL;
static int close_connection = false;

#if defined(MBEDTLS_DEBUG_C)
static void es_mbedtls_debug(void *ctx, int level, const char *file, int line, 
					const char *str)
{
	char *pfile;

	pfile = rindex(file, '/');

	if(pfile) {
		file = pfile+1;
	}
	printf("%s:%04d: |%d| %s", file, line, level, str);
}
#endif

static void es_mbedtls_close_connection(void)
{
	close_connection = true;

	mbedtls_net_free(&client_fd);
	mbedtls_ssl_free(&ssl);

	mbedtls_x509_crt_free(&srvcert);
	mbedtls_pk_free(&pkey);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	mbedtls_ssl_config_free(&conf);
	mbedtls_net_free(&listen_fd);
}

static void es_mbedtls_task(void *data)
{
	char buf[2048];
	char *cert_buf = NULL;
	char *cert_chain_buf = NULL;
	char *payload = NULL;
	const char *pers = "easysetup";
	int ret, len, type, cmd;
	int handshake_done = 0;
	iot_error_t err = IOT_ERROR_NONE;
	size_t cert_len;
	size_t cert_chain_len;
	size_t content_len;

	mbedtls_net_init(&listen_fd);
	mbedtls_net_init(&client_fd);
	mbedtls_ssl_init(&ssl);
	mbedtls_ssl_config_init(&conf);
	mbedtls_x509_crt_init(&srvcert);
	mbedtls_pk_init(&pkey);
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);
#if defined(MBEDTLS_DEBUG_C)
	mbedtls_debug_set_threshold(4);
#endif

	/*
	 * 1. Load the certificate chain
	 */
	ret = iot_nv_get_certificate(IOT_SECURITY_CERT_ID_DEVICE, &cert_buf, &cert_len);
	if (ret) {
		IOT_ERROR("iot_nv_get_certificate = %d", ret);
		goto exit;
	}

	// for null-terminated string format, it should be removed from certificate chain
	if (cert_buf[cert_len - 1] == 0) {
		cert_len--;
	}

	cert_chain_buf = (char *)iot_os_malloc(cert_len);
	cert_chain_len = cert_len;
	memcpy(cert_chain_buf, cert_buf, cert_len);

	ret = iot_nv_get_certificate(IOT_SECURITY_CERT_ID_SUB_CA, &cert_buf, &cert_len);
	if (ret) {
		IOT_ERROR("iot_nv_get_certificate = %d", ret);
		goto exit;
	}

	cert_chain_buf = (char *)iot_os_realloc(cert_chain_buf, cert_chain_len + cert_len + 1);
	if (cert_chain_buf) {
		memcpy(cert_chain_buf + cert_chain_len, cert_buf, cert_len);
		cert_chain_len += cert_len + 1;
		cert_chain_buf[cert_chain_len - 1] = '\0';
	} else {
		IOT_ERROR("failed to realloc for cert chain");
		goto exit;
	}

	ret = mbedtls_x509_crt_parse(&srvcert, (const unsigned char *)cert_chain_buf, cert_chain_len);
	if (ret) {
		IOT_ERROR( "certification parse failed : 0x%x", -ret);
		goto exit;
	}

	iot_os_free(cert_buf);

	/*
	 * 2. Setup the listening TCP socket
	 */
	if ((ret = mbedtls_net_bind(&listen_fd, NULL, "8888", MBEDTLS_NET_PROTO_TCP)) != 0)
	{
		IOT_ERROR("to net bind failed : %d", ret);
		goto exit;
	}

	/*
	 * 3. Seed the RNG
	 */
	if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
							   (const unsigned char *) pers, strlen(pers))) != 0)
	{
		IOT_ERROR("to seed the random number generator : %d\n", ret);
		goto exit;
	}

	/*
	 * 4. Setup stuff
	 */
	if ((ret = mbedtls_ssl_config_defaults(&conf,
					MBEDTLS_SSL_IS_SERVER,
					MBEDTLS_SSL_TRANSPORT_STREAM,
					MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
	{
		IOT_ERROR("to set up the SSL default config failed : %d", ret);
		goto exit;
	}

	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
#if defined(MBEDTLS_DEBUG_C)
	mbedtls_ssl_conf_dbg(&conf, es_mbedtls_debug, NULL);
#endif

	mbedtls_ssl_conf_ca_chain(&conf, srvcert.next, NULL);
	if ((ret = mbedtls_ssl_conf_own_cert(&conf, &srvcert, &pkey)) != 0)
	{
		IOT_ERROR("to set up the SSL own certification config failed : %d", ret);
		goto exit;
	}

	iot_net_tls_external_private(&conf);

	if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0)
	{
		IOT_ERROR("to set up the SSL data failed : %d", ret);
		goto exit;
	}

	do
	{
		mbedtls_ssl_session_reset(&ssl);

		content_len = 0;

		if ((ret = mbedtls_net_accept(&listen_fd, &client_fd, NULL, 0, NULL)) != 0)
		{
			if (close_connection == true) {
				goto exit;
			} else {
				IOT_ERROR("to accept a client connection failed : %d", ret);
				continue;
			}
		}

		mbedtls_ssl_set_bio(&ssl, &client_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

		/*
		 * 5. Handshake
		 */
		if (!handshake_done) {
			while ((ret = mbedtls_ssl_handshake(&ssl)) != 0)
			{
				if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
				{
					IOT_ERROR(" the SSL/TLS handshake failed : %d", ret);
					continue;
				}
			}
			IOT_INFO("the SSL/TLS handshake success!!");
			handshake_done = 1;
		}

		/*
		 * 6. Read the HTTP Request
		 */
		do
		{
			len = sizeof( buf ) - 1;
			memset(buf, 0, sizeof(buf));
			ret = mbedtls_ssl_read(&ssl, (unsigned char *) buf, len);

			if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
				continue;

			if (ret <= 0)
			{
				switch (ret)
				{
					case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
						IOT_ERROR("connection was closed gracefully");

					case MBEDTLS_ERR_NET_CONN_RESET:
						IOT_ERROR("connection was reset by peer");

					default:
						IOT_ERROR("mbedtls_ssl_read returned -0x%x", -ret);
				}
				continue;
			} else {
				if (content_len > 0) {
					payload = buf;
				} else {
					err = es_msg_parser(buf, sizeof(buf), &payload, &cmd, &type, &content_len);
					if ((err == IOT_ERROR_NONE) && (type == D2D_POST)
										&&	payload && (content_len > strlen((char *)payload)))
						continue;
				}
				break;
			}
		}
		while (1);

		if(err == IOT_ERROR_INVALID_ARGS)
			http_msg_handler(cmd, &tx_buffer, D2D_ERROR, payload);
		else
			http_msg_handler(cmd, &tx_buffer, type, payload);

		/*
		 * 7. Send the Response
		 */
		memset(buf, 0, sizeof(buf));

		len = sprintf(buf, tx_buffer,
					   mbedtls_ssl_get_ciphersuite(&ssl));

		if (tx_buffer) {
			iot_os_free(tx_buffer);
			tx_buffer = NULL;
		}

		while ((ret = mbedtls_ssl_write(&ssl, (unsigned char *) buf, len)) <= 0)
		{
			if (ret == MBEDTLS_ERR_NET_CONN_RESET)
			{
				IOT_ERROR("peer closed the connection");
			}

			if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
			{
				IOT_ERROR(" ssl write failed : %d", ret);
				continue;
			}
		}

		shutdown( client_fd.fd, SHUT_RDWR );
		while (1) {
			memset(buf, 0, sizeof(buf));
			ret = mbedtls_ssl_read(&ssl, (unsigned char *) buf, len);
			if (ret > 0)
				continue;
			break;
		}
		close( client_fd.fd );
		client_fd.fd = -1;
	}
	while (1);

exit:
	es_mbedtls_task_handle = NULL;
	iot_os_thread_delete(es_mbedtls_task_handle);
}

void es_http_init(void)
{
	IOT_INFO("http tls init!!");

	iot_os_thread_create(es_mbedtls_task, "es_tls_task", (1024 * 8), NULL, 5, (iot_os_thread * const)(&es_mbedtls_task_handle));
}

void es_http_deinit(void)
{
	es_mbedtls_close_connection();

	if (es_mbedtls_task_handle) {
		IOT_INFO("es_http_tls_deinit");
		iot_os_thread_delete(es_mbedtls_task_handle);
		es_mbedtls_task_handle = NULL;
		IOT_INFO("es_http_tls_deinit");
	}

	if (tx_buffer) {
		iot_os_free(tx_buffer);
		tx_buffer = NULL;
	}

	close_connection = false;

	IOT_INFO("http tls deinit!!");
}

