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

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>

#include "iot_debug.h"
#include "port_net.h"
#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#endif

#include "mbedtls/platform.h"
#include "mbedtls/version.h"
#if MBEDTLS_VERSION_NUMBER > 0x03000000
#include "mbedtls/net_sockets.h"
#else
#include "mbedtls/net.h"
#endif
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ssl.h"
#if MBEDTLS_VERSION_NUMBER < 0x03000000
#include "mbedtls/certs.h"
#endif
#include "mbedtls/debug.h"
#include "mbedtls/x509.h"

#define IOT_MBEDTLS_READ_TIMEOUT_MS 10000

/* Allowed cipher suites for cloud client TLS connections.
 * mbedtls stores only the pointer (does not copy), so this must have static lifetime.
 * The list must be terminated with a 0 entry. */
static const int s_allowed_ciphersuites[] = {MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                                             MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                                             MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                                             MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                                             MBEDTLS_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                                             MBEDTLS_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                                             0};

typedef struct {
    bool is_tls_connection;

    mbedtls_net_context sock_fd;
    /* Self-pipe used to wake up a thread blocked in port_net_read_poll()
     * when port_net_close() is called from another thread. On POSIX,
     * close()-ing a socket does not wake up select() waiters.
     * [0]: read end (added to select set), [1]: write end (signaled on close).
     * Owned by port_net_init()/port_net_free(), survives connect retries. */
    int socket_termination_fd[2];
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

/* Put the context into the same state as right after port_net_init(),
 * so it is safe to free or to retry port_net_connect() on it.
 * Note mbedtls_net_init() sets fd to -1, which a bare memset does not. */
static void _init_net_ctx(port_net_mbedtls_context_t *ctx)
{
    memset(ctx, 0, sizeof(port_net_mbedtls_context_t));
    ctx->socket_termination_fd[0] = -1;
    ctx->socket_termination_fd[1] = -1;

    mbedtls_net_init(&ctx->sock_fd);
    mbedtls_ssl_init(&ctx->ssl);
    mbedtls_ssl_config_init(&ctx->conf);
    mbedtls_ctr_drbg_init(&ctx->ctr_drbg);
    mbedtls_entropy_init(&ctx->entropy);
    mbedtls_x509_crt_init(&ctx->cacert);
    mbedtls_x509_crt_init(&ctx->own_cert);
}

PORT_NET_CONTEXT port_net_init(void)
{
    port_net_mbedtls_context_t *new_net_context = NULL;

    new_net_context = (port_net_mbedtls_context_t *)malloc(sizeof(port_net_mbedtls_context_t));
    if (!new_net_context)
        return NULL;
    _init_net_ctx(new_net_context);

#if defined(CONFIG_STDK_IOT_CORE_OS_SUPPORT_POSIX)
    if (pipe(new_net_context->socket_termination_fd) != 0) {
        IOT_WARN("There is no socket termination fd allocated");
        new_net_context->socket_termination_fd[0] = -1;
        new_net_context->socket_termination_fd[1] = -1;
    }
#endif

    return (PORT_NET_CONTEXT)new_net_context;
}

void port_net_free(PORT_NET_CONTEXT ctx)
{
    port_net_mbedtls_context_t *_ctx = (port_net_mbedtls_context_t *)ctx;

    if (_ctx == NULL) {
        return;
    }

    _free_net_ctx(_ctx);
    if (_ctx->socket_termination_fd[0] != -1) {
        close(_ctx->socket_termination_fd[0]);
        close(_ctx->socket_termination_fd[1]);
        _ctx->socket_termination_fd[0] = -1;
        _ctx->socket_termination_fd[1] = -1;
    }
    free(_ctx);
}

#ifdef CONFIG_MBEDTLS_DEBUG
static void _iot_net_mbedtls_debug(void *ctx, int level, const char *file, int line, const char *str)
{
    const char *filename;

    filename = strrchr(file, '/') ? strrchr(file, '/') + 1 : file;

    IOT_INFO("%s:%04d: |%d| %s", filename, line, level, str);
}
#endif

#define IOT_NET_CONNECT_TIMEOUT_SEC 10

/* Helper function for connect with timeout */
static int _connect_with_timeout(int sockfd, const struct sockaddr *addr, socklen_t addrlen, int timeout_sec)
{
    int ret;
    int flags;
    fd_set writefds, exceptfds;
    struct timeval tv;
    int so_error;
    socklen_t len;

    /* Get socket flags */
    flags = fcntl(sockfd, F_GETFL, 0);
    if (flags < 0) {
        printf("fcntl F_GETFL failed, errno: %d\n", errno);
        return -1;
    }

    /* Set non-blocking mode */
    if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) < 0) {
        printf("fcntl F_SETFL O_NONBLOCK failed, errno: %d\n", errno);
        return -1;
    }

    /* Attempt connection */
    ret = connect(sockfd, addr, addrlen);

    if (ret < 0) {
        if (errno == EINPROGRESS || errno == EWOULDBLOCK) {
            /* Connection in progress, wait for completion with timeout */
            FD_ZERO(&writefds);
            FD_SET(sockfd, &writefds);
            FD_ZERO(&exceptfds);
            FD_SET(sockfd, &exceptfds);

            tv.tv_sec = timeout_sec;
            tv.tv_usec = 0;

            ret = select(sockfd + 1, NULL, &writefds, &exceptfds, &tv);

            if (ret > 0) {
                /* Check if connection succeeded or failed */
                len = sizeof(so_error);
                if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len) < 0) {
                    printf("getsockopt SO_ERROR failed, errno: %d\n", errno);
                    fcntl(sockfd, F_SETFL, flags); /* Restore flags */
                    return -1;
                }

                if (so_error == 0) {
                    /* Connection succeeded */
                    printf("Connection established successfully\n");
                    ret = 0;
                } else {
                    /* Connection failed */
                    printf("Connection failed, so_error: %d (%s)\n", so_error, strerror(so_error));
                    errno = so_error;
                    ret = -1;
                }
            } else if (ret == 0) {
                /* Timeout */
                printf("Connect timeout after %d seconds\n", timeout_sec);
                errno = ETIMEDOUT;
                ret = -1;
            } else {
                /* select error */
                printf("select failed, errno: %d\n", errno);
                ret = -1;
            }
        } else {
            /* Immediate connection error */
            printf("Connect failed immediately, errno: %d (%s)\n", errno, strerror(errno));
            ret = -1;
        }
    }

    /* Set back to blocking mode */
    fcntl(sockfd, F_SETFL, flags);

    return ret;
}

/*
 * Initiate a TCP connection with host:port and the given protocol
 */
static int _port_net_connect(mbedtls_net_context *ctx, const char *host, const char *port, int proto)
{
    int ret;
    struct addrinfo hints, *addr_list, *cur;

    /* Do name resolution with both IPv6 and IPv4 */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = proto == MBEDTLS_NET_PROTO_UDP ? SOCK_DGRAM : SOCK_STREAM;
    hints.ai_protocol = proto == MBEDTLS_NET_PROTO_UDP ? IPPROTO_UDP : IPPROTO_TCP;

    if (getaddrinfo(host, port, &hints, &addr_list) != 0)
        return (MBEDTLS_ERR_NET_UNKNOWN_HOST);

    /* Try the sockaddrs until a connection succeeds */
    ret = MBEDTLS_ERR_NET_UNKNOWN_HOST;
    for (cur = addr_list; cur != NULL; cur = cur->ai_next) {
        ctx->fd = (int)socket(cur->ai_family, cur->ai_socktype, cur->ai_protocol);
        if (ctx->fd < 0) {
            ret = MBEDTLS_ERR_NET_SOCKET_FAILED;
            continue;
        }

        if (_connect_with_timeout(ctx->fd, cur->ai_addr, cur->ai_addrlen, IOT_NET_CONNECT_TIMEOUT_SEC) == 0) {
            ret = 0;
            break;
        }

        close(ctx->fd);
        ret = MBEDTLS_ERR_NET_CONNECT_FAILED;
    }

    freeaddrinfo(addr_list);

    return (ret);
}

port_net_connect_result port_net_connect(PORT_NET_CONTEXT ctx, char *address, char *port, port_net_proto proto,
                                         port_net_tls_config *config)
{
    port_net_connect_result result = PORT_NET_CONNECT_SUCCESS;
    port_net_mbedtls_context_t *new_net_context = (port_net_mbedtls_context_t *)ctx;

    if (ctx == NULL) {
        return PORT_NET_CONNECT_INVALID_ARGS;
    }

    /* DTLS is not supported */
    if (config && proto == PORT_NET_PROTO_UDP) {
        return PORT_NET_CONNECT_INVALID_ARGS;
    }

    if (config) {
        const char *pers = "iot_net_mbedtls";
        int ret;

        ret = mbedtls_ctr_drbg_seed(&new_net_context->ctr_drbg, mbedtls_entropy_func, &new_net_context->entropy,
                                    (const unsigned char *)pers, strlen((char *)pers));
        if (ret) {
            IOT_ERROR("mbedtls_ctr_drbg_seed = -0x%04X", -ret);
            result = PORT_NET_CONNECT_OPERATION_FAIL;
            goto exit;
        }

        IOT_INFO("Loading the CA root certificate %d@%p", config->ca_cert_len + 1, config->ca_cert);
        /* iot-core passed the certificate without NULL character */
        ret = mbedtls_x509_crt_parse(&new_net_context->cacert, (const unsigned char *)config->ca_cert,
                                     config->ca_cert_len + 1);
        if (ret) {
            IOT_ERROR("mbedtls_x509_crt_parse = -0x%04X", -ret);
            result = PORT_NET_CONNECT_OPERATION_FAIL;
            goto exit;
        }

        IOT_DEBUG("Connecting to %s:%s", address, port);
        ret = _port_net_connect(&new_net_context->sock_fd, address, port, MBEDTLS_NET_PROTO_TCP);
        if (ret == MBEDTLS_ERR_NET_UNKNOWN_HOST) {
            IOT_ERROR("Failed to resolve host");
            result = PORT_NET_CONNECT_DNS_RESOLVE_FAIL;
            goto exit;
        } else if (ret == MBEDTLS_ERR_NET_CONNECT_FAILED) {
            IOT_ERROR("Failed to connect TCP");
            result = PORT_NET_CONNECT_TCP_CONNECTION_FAIL;
            goto exit;
        } else if (ret) {
            IOT_ERROR("_port_net_connect = -0x%04X", -ret);
            result = PORT_NET_CONNECT_OPERATION_FAIL;
            goto exit;
        }

        mbedtls_ssl_config_defaults(&new_net_context->conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT);
        mbedtls_ssl_conf_ciphersuites(&new_net_context->conf, s_allowed_ciphersuites);
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
            result = PORT_NET_CONNECT_OPERATION_FAIL;
            goto exit;
        }

        ret = mbedtls_ssl_set_hostname(&new_net_context->ssl, address);
        if (ret) {
            IOT_ERROR("mbedtls_ssl_set_hostname = -0x%04X", -ret);
            result = PORT_NET_CONNECT_OPERATION_FAIL;
            goto exit;
        }

        mbedtls_ssl_set_bio(&new_net_context->ssl, &new_net_context->sock_fd, mbedtls_net_send, NULL,
                            mbedtls_net_recv_timeout);

        IOT_DEBUG("Performing the SSL/TLS handshake");

        while ((ret = mbedtls_ssl_handshake(&new_net_context->ssl)) != 0) {
            if ((ret != MBEDTLS_ERR_SSL_WANT_READ) && (ret != MBEDTLS_ERR_SSL_WANT_WRITE)) {
                IOT_ERROR("mbedtls_ssl_handshake = -0x%x", -ret);
                if (ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) {
                    IOT_ERROR("failed to verify the server's certificate");
                }
                result = PORT_NET_CONNECT_TLS_HANDSHAKE_FAIL;
                goto exit;
            }
        }

        IOT_DEBUG("Protocol is %s", mbedtls_ssl_get_version(&new_net_context->ssl));
        IOT_DEBUG("Ciphersuite is %s", mbedtls_ssl_get_ciphersuite(&new_net_context->ssl));
        IOT_DEBUG("Verifying peer X.509 certificate");
        ret = mbedtls_ssl_get_verify_result(&new_net_context->ssl);
        if (ret) {
            IOT_ERROR("mbedtls_ssl_get_verify_result = 0x%x", ret);
            result = PORT_NET_CONNECT_TLS_HANDSHAKE_FAIL;
            goto exit;
        }
#if defined(STDK_IOT_CORE_TLS_DEBUG)
        if (mbedtls_ssl_get_peer_cert(&new_net_context->ssl) != NULL) {
            unsigned char buf[2048];
            IOT_INFO("Peer certificate information");
            mbedtls_x509_crt_info((char *)buf, sizeof(buf) - 1, "!", mbedtls_ssl_get_peer_cert(&new_net_context->ssl));
            IOT_INFO("%s\n", buf);
        }
#endif
        new_net_context->is_tls_connection = true;
    } else {
        int ret;

        IOT_DEBUG("Connecting to %s:%s (plain %s)", address, port, proto == PORT_NET_PROTO_UDP ? "UDP" : "TCP");
        ret = _port_net_connect(&new_net_context->sock_fd, address, port,
                                proto == PORT_NET_PROTO_UDP ? MBEDTLS_NET_PROTO_UDP : MBEDTLS_NET_PROTO_TCP);
        if (ret == MBEDTLS_ERR_NET_UNKNOWN_HOST) {
            IOT_ERROR("Failed to resolve host");
            result = PORT_NET_CONNECT_DNS_RESOLVE_FAIL;
            goto exit;
        } else if (ret == MBEDTLS_ERR_NET_CONNECT_FAILED) {
            IOT_ERROR("Failed to connect");
            result = PORT_NET_CONNECT_TCP_CONNECTION_FAIL;
            goto exit;
        } else if (ret) {
            IOT_ERROR("_port_net_connect = -0x%04X", -ret);
            result = PORT_NET_CONNECT_OPERATION_FAIL;
            goto exit;
        }

        new_net_context->is_tls_connection = false;
    }

exit:
    if (result != PORT_NET_CONNECT_SUCCESS) {
        int term_read_fd = new_net_context->socket_termination_fd[0];
        int term_write_fd = new_net_context->socket_termination_fd[1];

        /* Release everything acquired during this attempt and return the
         * context to its initial state, so the caller can retry
         * port_net_connect() on it without port_net_free()/port_net_init(). */
        _free_net_ctx(new_net_context);
        _init_net_ctx(new_net_context);
        new_net_context->socket_termination_fd[0] = term_read_fd;
        new_net_context->socket_termination_fd[1] = term_write_fd;
    }

    return result;
}

PORT_NET_CONTEXT port_net_listen(char *port, port_net_tls_config *config)
{
    int ret;
    mbedtls_net_context listen_fd = {
        0,
    };
    port_net_mbedtls_context_t *new_net_context = NULL;

    new_net_context = (port_net_mbedtls_context_t *)malloc(sizeof(port_net_mbedtls_context_t));
    if (!new_net_context)
        return NULL;
    memset(new_net_context, 0, sizeof(port_net_mbedtls_context_t));
    new_net_context->socket_termination_fd[0] = -1;
    new_net_context->socket_termination_fd[1] = -1;

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

        IOT_INFO("Loading the CA root certificate %d@%p", config->ca_cert_len + 1, config->ca_cert);
        mbedtls_x509_crt_init(&new_net_context->cacert);
        /* iot-core passed the certificate without NULL character */
        ret = mbedtls_x509_crt_parse(&new_net_context->cacert, (const unsigned char *)config->ca_cert,
                                     config->ca_cert_len + 1);
        if (ret) {
            IOT_ERROR("mbedtls_x509_crt_parse = -0x%04X", -ret);
            goto exit;
        }

        IOT_INFO("Loading the device certificate %d@%p", config->device_cert_len + 1, config->device_cert);
        mbedtls_x509_crt_init(&new_net_context->own_cert);
        /* iot-core passed the certificate without NULL character */
        ret = mbedtls_x509_crt_parse(&new_net_context->own_cert, (const unsigned char *)config->device_cert,
                                     config->device_cert_len + 1);
        if (ret) {
            IOT_ERROR("mbedtls_x509_crt_parse = -0x%04X", -ret);
            goto exit;
        }

        mbedtls_ssl_config_defaults(&new_net_context->conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
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
        if (ret) {
            IOT_ERROR("mbedtls_net_bind = -0x%04X", -ret);
            goto exit;
        }

        ret = mbedtls_net_accept(&listen_fd, &new_net_context->sock_fd, NULL, 0, NULL);
        if (ret) {
            IOT_ERROR("mbedtls_net_accept = -0x%04X", -ret);
            goto exit;
        }

        mbedtls_ssl_set_bio(&new_net_context->ssl, &new_net_context->sock_fd, mbedtls_net_send, mbedtls_net_recv,
                            mbedtls_net_recv_timeout);

        IOT_DEBUG("Performing the SSL/TLS handshake");

        while ((ret = mbedtls_ssl_handshake(&new_net_context->ssl)) != 0) {
            if ((ret != MBEDTLS_ERR_SSL_WANT_READ) && (ret != MBEDTLS_ERR_SSL_WANT_WRITE)) {
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
        if (ret) {
            IOT_ERROR("mbedtls_net_bind = -0x%04X", -ret);
            goto exit;
        }

        ret = mbedtls_net_accept(&listen_fd, &new_net_context->sock_fd, NULL, 0, NULL);
        if (ret) {
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
    mbedtls_net_free(&listen_fd);

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

    if (_ctx == NULL || buf == NULL) {
        return -1;
    }

    if (len == 0) {
        return 0;
    }

    IOT_DEBUG("%d@%p", len, buf);
    if (_ctx->is_tls_connection) {
        ret = mbedtls_ssl_read(&_ctx->ssl, buf, len);
    } else {
        ret = mbedtls_net_recv(&_ctx->sock_fd, buf, len);
    }

    if (ret > 0) {
        recvLen += ret;
    } else {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            IOT_ERROR("read(tls:%d) fail = -0x%04X", _ctx->is_tls_connection, -ret);
            return -1;
        }
    }

    return recvLen;
}

int port_net_read_poll(PORT_NET_CONTEXT ctx, unsigned int wait_time_ms)
{
    struct timeval timeout;
    fd_set fdset;
    int socket;
    int max_socket;
    int ret;
    port_net_mbedtls_context_t *_ctx = (port_net_mbedtls_context_t *)ctx;

    if (_ctx == NULL) {
        return -1;
    }

    socket = _ctx->sock_fd.fd;
    max_socket = socket;
    FD_ZERO(&fdset);
    FD_SET(socket, &fdset);
    if (_ctx->socket_termination_fd[0] != -1) {
        FD_SET(_ctx->socket_termination_fd[0], &fdset);
        if (max_socket < _ctx->socket_termination_fd[0]) {
            max_socket = _ctx->socket_termination_fd[0];
        }
    }
    if (wait_time_ms == PORT_NET_WAIT_FOREVER) {
        ret = select(max_socket + 1, &fdset, NULL, NULL, NULL);
    } else {
        timeout.tv_sec = wait_time_ms / 1000;
        timeout.tv_usec = (wait_time_ms % 1000) * 1000;
        ret = select(max_socket + 1, &fdset, NULL, NULL, &timeout);
    }

    if (ret > 0 && _ctx->socket_termination_fd[0] != -1 && FD_ISSET(_ctx->socket_termination_fd[0], &fdset)) {
        return -1;
    }

    return ret;
}

int port_net_write_poll(PORT_NET_CONTEXT ctx, unsigned int wait_time_ms)
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
        ret = select(socket + 1, NULL, &fdset, NULL, NULL);
    } else {
        timeout.tv_sec = wait_time_ms / 1000;
        timeout.tv_usec = (wait_time_ms % 1000) * 1000;
        ret = select(socket + 1, NULL, &fdset, NULL, &timeout);
    }

    return ret;
}

int port_net_write(PORT_NET_CONTEXT ctx, void *buf, size_t len)
{
    int sentLen = 0, ret = 0;
    port_net_mbedtls_context_t *_ctx = (port_net_mbedtls_context_t *)ctx;

    if (_ctx == NULL || buf == NULL) {
        return -1;
    }

    if (len == 0) {
        return 0;
    }

    IOT_DEBUG("%d@%p", len, buf);
    if (_ctx->is_tls_connection) {
        ret = mbedtls_ssl_write(&_ctx->ssl, buf, len);
    } else {
        ret = mbedtls_net_send(&_ctx->sock_fd, buf, len);
    }

    if (ret >= 0) {
        sentLen += ret;
    } else {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            IOT_ERROR("write(tls:%d) fail = -0x%04X", _ctx->is_tls_connection, -ret);
            return -1;
        }
    }

    return sentLen;
}

#define SOCKET_CLOSE_SIGNAL (1)
void port_net_close(PORT_NET_CONTEXT ctx)
{
    port_net_mbedtls_context_t *_ctx = (port_net_mbedtls_context_t *)ctx;

    if (_ctx == NULL || !_ctx->is_tls_connection) {
        return;
    }

    mbedtls_ssl_close_notify(&_ctx->ssl);
    mbedtls_net_free(&_ctx->sock_fd);

    if (_ctx->socket_termination_fd[1] != -1) {
        uint64_t close_sig = SOCKET_CLOSE_SIGNAL;
        int ret = write(_ctx->socket_termination_fd[1], &close_sig, sizeof(close_sig));
        if (ret < 0) {
            IOT_WARN("Send socket close signal %d", ret);
        }
    }
}
