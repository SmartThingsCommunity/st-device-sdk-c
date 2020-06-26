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

#define STDK_RSA_ROOTCA \
"-----BEGIN CERTIFICATE-----\r\n" \
"MIIDojCCAoqgAwIBAgIBATANBgkqhkiG9w0BAQsFADBzMQswCQYDVQQGEwJLUjEf\r\n" \
"MB0GA1UECgwWU21hcnRUaGluZ3MgRGV2aWNlIFNESzEVMBMGA1UECwwMTVFUVCBS\r\n" \
"b290IENBMSwwKgYDVQQDDCNTbWFydFRoaW5ncyBEZXZpY2UgU0RLIFJvb3QgQ0Eg\r\n" \
"VEVTVDAgFw0yMDAzMTgwNzAzMzhaGA8yMDUwMDMxMTA3MDMzOFowczELMAkGA1UE\r\n" \
"BhMCS1IxHzAdBgNVBAoMFlNtYXJ0VGhpbmdzIERldmljZSBTREsxFTATBgNVBAsM\r\n" \
"DE1RVFQgUm9vdCBDQTEsMCoGA1UEAwwjU21hcnRUaGluZ3MgRGV2aWNlIFNESyBS\r\n" \
"b290IENBIFRFU1QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC5Au2r\r\n" \
"+itMj8vbvHwwaWa7QDRvNFEz/Qkb90JCnEGytLJV4XGWkcDiCnYYRlumMX9a1lmp\r\n" \
"YRQHmCjArrY4iNO9S1EwM3fht9pXaJuNqZEC6leqwMPFIWImHOz6mezUqanMpe9R\r\n" \
"oo161hvugal0aGHm5w6RbzXSCHTUWaHO+EaLq1Qm0IRuVHVLX9kltG7iqZXJ4CgJ\r\n" \
"fZDjkBYzV8bj+pp6zcb1c+ZfpEQXtlxdTHtk4mRP6gnZwWsmPGzE6EEDlPUweiCz\r\n" \
"F+uG9Aup43aKL4L25Sar1jlU7qOADS6JEOfbEiG3AmeS2cUiMF3YrFf6WrMYvE7q\r\n" \
"YX43IyYlGNwg5qO5AgMBAAGjPzA9MA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYE\r\n" \
"FE18Fuly4MxVXZMBTfC2iEceRkRzMAsGA1UdDwQEAwIBxjANBgkqhkiG9w0BAQsF\r\n" \
"AAOCAQEAQnji/3IXoYP3Ep2+BidrVBplw7CPKxBDebTOHEW/j4yQXbivFHF2l985\r\n" \
"pTjCL4ToK4zRAxDSDsH+mpkaS2JjuiS/KAOGXFAxdV8H2fH5uO0aks4EDIx8SLLK\r\n" \
"b7W3qSOtU9BNmgtwt2k9pgTq/GyEsbsAurxRRI23XNfD5eldDz4i/NYQ9tQkk7tI\r\n" \
"yCuurSDuuF5ojdQ2BeWgF1BRJPyNfYpnD9NceJHvRuJAenL/2My6XC0q+9Cz8tyf\r\n" \
"X0GZldbecF05pPIx3WMUKbgWfJaDFDOUaAXkQWGLRmkKzkSRHhCcVMJmThrcG8Y7\r\n" \
"gjNv9hQqAgBQd8GZhfXR3NEhrxwNOA==\r\n" \
"-----END CERTIFICATE-----\r\n"

#define STDK_RSA_DEVICE \
"-----BEGIN CERTIFICATE-----\r\n" \
"MIID0jCCArqgAwIBAgIJAL9O6OLPK0ZsMA0GCSqGSIb3DQEBCwUAMHMxCzAJBgNV\r\n" \
"BAYTAktSMR8wHQYDVQQKDBZTbWFydFRoaW5ncyBEZXZpY2UgU0RLMRUwEwYDVQQL\r\n" \
"DAxNUVRUIFJvb3QgQ0ExLDAqBgNVBAMMI1NtYXJ0VGhpbmdzIERldmljZSBTREsg\r\n" \
"Um9vdCBDQSBURVNUMCAXDTIwMDMxODA4MjAzNVoYDzIwNjAwMzA4MDgyMDM1WjBh\r\n" \
"MQswCQYDVQQGEwJLUjEfMB0GA1UECgwWU21hcnRUaGluZ3MgRGV2aWNlIFNESzEU\r\n" \
"MBIGA1UECwwLTVFUVCBEZXZpY2UxGzAZBgNVBAMMElNtYXJ0VGhpbmdzIERldmlj\r\n" \
"ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL4jUwmm4QWhGc4WvbJh\r\n" \
"a8WDLcyVfCTqvtkMD9AqwaO8cC1n8C+IRqurD2gJSxyyRLQP2qIBjcX+iEs12d/Z\r\n" \
"l+ZGUOovcWKRCfEr+qexsu3f2BS1A1U638iTjuF7ByxjI89F/RvmvbdlwxHvD1N9\r\n" \
"6oJfF+MP4sFVqP/3QT14kbrQ7T7cEWokQx/l3ItvqSJzeEoccZBGPjAxf+3K2Fse\r\n" \
"/y1mlJEBnQ+gfX3h7u8HkLO7NhCP490I0qZosi95hIU7wB7VxuWpctCp0uOcbh4K\r\n" \
"Yo4bikYb2Hz+8NLl3R5eZsLDxZCrZmw/8xBgb0J+nwbUa1sljrelsjuKa7rRf+E3\r\n" \
"nP0CAwEAAaN5MHcwCQYDVR0TBAIwADAfBgNVHSMEGDAWgBRNfBbpcuDMVV2TAU3w\r\n" \
"tohHHkZEczAdBgNVHQ4EFgQUBVEurDL0dr9M2jI43P5eJYVjiN4wCwYDVR0PBAQD\r\n" \
"AgXgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjANBgkqhkiG9w0BAQsF\r\n" \
"AAOCAQEAbgaAyWqF4z4LG2bLGHRD4QSmDpDIkByY0bX8y92oyFVlNokbu0ggV5nE\r\n" \
"vmRh/dPB4KZ/uVt6ikfoZN6yCsrWkx8PWN7ivQsUhmcRqiPUQZZPdOk5XZEd8A1i\r\n" \
"YRfBLTooFvfhoiOT7BKhwsst+U5ilh1ObcBUlGhme6dSgEfXUNFYf4bt7lupSjU8\r\n" \
"2nHglmcClDXI0PhZJJbqci1yjXKwY+zJ9sgeBz4VqdTbdblQLRWpSYDLcfdCGO1r\r\n" \
"gxTlCwIvfpTc6Fdqu9XHMnl3B8j9hDbXUknsfqr8uJgn/E9oCO9EON3kkgqg6qBb\r\n" \
"uC555eYxbrmIgrHfx8Nf69vA4oxA9g==\r\n" \
"-----END CERTIFICATE-----\r\n"

const char mbedtls_stdk_cert[] = STDK_RSA_DEVICE;
const size_t mbedtls_stdk_cert_len = sizeof(mbedtls_stdk_cert);

#define STDK_RSA_PRIVATE_KEY \
"-----BEGIN RSA PRIVATE KEY-----\r\n" \
"MIIEpAIBAAKCAQEAviNTCabhBaEZzha9smFrxYMtzJV8JOq+2QwP0CrBo7xwLWfw\r\n" \
"L4hGq6sPaAlLHLJEtA/aogGNxf6ISzXZ39mX5kZQ6i9xYpEJ8Sv6p7Gy7d/YFLUD\r\n" \
"VTrfyJOO4XsHLGMjz0X9G+a9t2XDEe8PU33qgl8X4w/iwVWo//dBPXiRutDtPtwR\r\n" \
"aiRDH+Xci2+pInN4ShxxkEY+MDF/7crYWx7/LWaUkQGdD6B9feHu7weQs7s2EI/j\r\n" \
"3QjSpmiyL3mEhTvAHtXG5aly0KnS45xuHgpijhuKRhvYfP7w0uXdHl5mwsPFkKtm\r\n" \
"bD/zEGBvQn6fBtRrWyWOt6WyO4prutF/4Tec/QIDAQABAoIBAG524VhbLqJxnSdh\r\n" \
"iOYouU8vzhzswApGo4g//LPpE0UIRnfqyd0jpEM6B6Jeu9e5Ljcaet/iXTapkQ95\r\n" \
"AtKNfTWYpovX8lzcfNUzwtVIZPbUNJqbK4uJv9es+ra/HkTIeFaEh+98173EDlfN\r\n" \
"9q6AGg2SJ7OQWCIQnTXQtYN8F9ZbZ6hjPueO5V8oe0zfbP9tAMQWvWnm8Vg0+Zbs\r\n" \
"oN8Hk4pKLoso91kHTmKgyRsLKx2jLrSWPH32EzMW9wkm+O4752xO/Qhi3IWXkzJJ\r\n" \
"gbrPoLQ5GNp+c1pH1YHxW5p1WXaMU8gFVK4uOjrbmComCchRSZz2Vt+0kE5E2vRH\r\n" \
"AfMC+qECgYEA9OzBJvnX3RhmT3zw+FlrsJD+iUY3vrlyLTIWzyxknyKKEGd013c0\r\n" \
"noBU6ufHZ+WhgU9DjmugA80yx98Y+t4q97qqgZtMn8TnlGY7/t5YwvlU6TxMI7aa\r\n" \
"s46bBMBvJbBdyBlvVkhA249wdFjgmhJv0fnae1l/s9eOUrRcMY1PTzkCgYEAxrxb\r\n" \
"v8yRPd541MEg6vOvSjoeXHfh0W/HkwnDMTJh9NRJvC5JXViw4r/VgtYGh9Sj9C/S\r\n" \
"FdK/3R1i8u0TnN3/jXUvAbWXQLsyPy0uD7tKdcuPluG654osiuzvFAUK5TOgsP8J\r\n" \
"XNOEExepMbfXXzPo+uI0YnvWNjQ9VcdN0SDEt+UCgYB8mST56whB1fPWZD1CWltK\r\n" \
"i7ixpSMex8Cp9V1dL7xQqIWMKtVp956xM5//kMIEvPEYk3ZOsbnJtU4sF/bhSLyb\r\n" \
"Ij8ziAnHDaix+gBzfDGznpvvu1kQogi5Z8a8+BiTF9HdxfK59i/ogmQ3DC/WsaJp\r\n" \
"M65OKg2pM/OXZ2GvY7ABIQKBgQDEy4bLQgZdTq02eNxg7Nga17xy8p+iJl9pglRQ\r\n" \
"pkSMDZ/KgcdScV4P28jRG6Ex5mZIiwYtaBloGw594jf2sXq7GFxpA+n4Rqa2GsYu\r\n" \
"+9b7GI1i6rqLR69eDsucdnXYi6xHOPWLf0SdJ2P7AMJ72sqNjWw0Tc7MtCQ8ifTL\r\n" \
"7vf95QKBgQDs7pkpGwmTqkF5QpqLiJ1pVdo0ZKniia0k2Xzn6nIwhuWBq2WgIIhL\r\n" \
"y9VLNovTHTHl6E4Y0jXjFmbapF03TEnM4mFBZ6lAIJuzN6dPY3VaZk6aDfpaV9fr\r\n" \
"ay49ZXd3aQsYaker7WVrKPGxMNsZ7Ej5BETSeiT+xdOmZj7SuZvTlQ==\r\n" \
"-----END RSA PRIVATE KEY-----\r\n"

const char mbedtls_stdk_private_key[] = STDK_RSA_PRIVATE_KEY;
const size_t mbedtls_stdk_private_key_len = sizeof(mbedtls_stdk_private_key);

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
	char *payload = NULL;
	const char *pers = "easysetup";
	int ret, len, type, cmd;
	int handshake_done = 0;
	iot_error_t err = IOT_ERROR_NONE;
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
	 * 1. Load the certificates and private RSA key
	 */
	ret = mbedtls_x509_crt_parse(&srvcert, (const unsigned char *) mbedtls_stdk_cert,
						  mbedtls_stdk_cert_len);
	if (ret != 0)
	{
		IOT_ERROR( "certification parse failed : %d", ret );
		goto exit;
	}

	ret = mbedtls_pk_parse_key(&pkey, (const unsigned char *) mbedtls_stdk_private_key,
						 mbedtls_stdk_private_key_len, NULL, 0);
	if (ret != 0)
	{
		IOT_ERROR("private key parse failed : %d\n\n", ret);
		goto exit;
	}

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
			free(tx_buffer);
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
			if (ret)
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
		free(tx_buffer);
		tx_buffer = NULL;
	}

	close_connection = false;

	IOT_INFO("http tls deinit!!");
}

