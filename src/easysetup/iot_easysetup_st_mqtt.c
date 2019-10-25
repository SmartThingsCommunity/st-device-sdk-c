/* ***************************************************************************
 *
 * Copyright 2019 Samsung Electronics All Rights Reserved.
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

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include "iot_main.h"
#include "iot_internal.h"
#include "iot_util.h"
#include "iot_nv_data.h"
#include "iot_debug.h"
#include "iot_jwt.h"
#include "iot_crypto.h"
#include "iot_os_util.h"

#include "cJSON.h"

static iot_error_t _iot_es_st_mqtt_connect(struct iot_mqtt_ctx *target_cli,
		enum iot_connect_type conn_type)
{
	struct iot_cloud_prov_data *cloud_prov;
	struct iot_context *ctx = target_cli->iot_ctx;
	iot_crypto_pk_info_t pk_info = { 0, };
	char *root_cert = NULL;
	char *dev_sn = NULL;
	char *mqtt_uid;
	char *jwt_data = NULL;
	unsigned int root_cert_len, devsn_len;
	iot_error_t iot_ret;
	int connect_retry;
	ssl_ca_crt_key_t ssl_cck = {0};
	const SSL_METHOD *ssl_method = TLSv1_2_client_method();

	cloud_prov = &ctx->prov_data.cloud;
	if (!cloud_prov->broker_url) {
		IOT_ERROR("cloud_prov_data url does not exist!");
		iot_ret = IOT_ERROR_INVALID_ARGS;
		goto out;
	}

	iot_ret = iot_nv_get_root_certificate(&root_cert, &root_cert_len);
	if (iot_ret != IOT_ERROR_NONE) {
		IOT_ERROR("failed to get root cert");
		goto out;
	} else {
		ssl_cck.cacrt = (unsigned char *)root_cert;
		ssl_cck.cacrt_len = root_cert_len;
	}

	iot_ret = iot_nv_get_serial_number(&dev_sn, &devsn_len);
	if (iot_ret != IOT_ERROR_NONE) {
		IOT_ERROR("failed to get serial num");
		goto out;
	}

	switch (conn_type) {
		case IOT_CONNECT_TYPE_REGISTRATION:
			mqtt_uid = (char *)dev_sn;
			break;

		case IOT_CONNECT_TYPE_COMMUNICATION:
			/* Using for new MQTT PUB/SUB connection after registration */
			if (!ctx->iot_reg_data.updated) {
				IOT_ERROR("failed to get user id");
				goto out;
			}

			mqtt_uid = (char *)ctx->iot_reg_data.deviceId;
			break;

		default:
			IOT_ERROR("Unsupported connection type");
			iot_ret = IOT_ERROR_INVALID_ARGS;
			goto out;
	};

	IOT_INFO("url: %s, port: %d", cloud_prov->broker_url, cloud_prov->broker_port);

	iot_es_crypto_init_pk(&pk_info, ctx->devconf.pk_type);

	iot_ret = iot_es_crypto_load_pk(&pk_info);
	if (iot_ret != IOT_ERROR_NONE) {
		IOT_ERROR("failed to load pk");
		goto out;
	}

	iot_ret = iot_jwt_create(&jwt_data, dev_sn, &pk_info);
	if (iot_ret != IOT_ERROR_NONE) {
		IOT_ERROR("failed to make jwt-token");
		goto out;
	}

	iot_os_net_ssl_init(&target_cli->net);

	connect_retry = 3;
	do {
		if (iot_os_net_ssl_connet(&(target_cli->net),
				cloud_prov->broker_url, cloud_prov->broker_port,
				&ssl_cck, ssl_method, SSL_VERIFY_PEER, 0) != 0) {
			IOT_ERROR("iot_os_net_ssl_connet failed, retry (%d)", connect_retry);
			iot_ret = IOT_ERROR_MQTT_NETCONN_FAIL;
			connect_retry--;
			iot_os_delay(2000);
		} else {
			iot_ret = IOT_ERROR_NONE;
		}
	} while ((iot_ret != IOT_ERROR_NONE) && connect_retry);

	if (iot_ret != IOT_ERROR_NONE) {
		IOT_ERROR("MQTT net connection failed");
		goto out;
	}

	IOT_INFO("connect_type: %s, with ID: %s", conn_type == IOT_CONNECT_TYPE_REGISTRATION ? "registration" :
			(conn_type == IOT_CONNECT_TYPE_COMMUNICATION ? "pubsub" : "unknown"), mqtt_uid);

	iot_ret = iot_mqtt_connect(target_cli, (char *)mqtt_uid, jwt_data);
	if (iot_ret != IOT_ERROR_NONE) {
		IOT_ERROR("failed to connect");
		goto out;
	}

	switch (conn_type) {
	case IOT_CONNECT_TYPE_REGISTRATION:
		/* WARNING : this is Great-Gate's specific process
		 * And it can be trigger infinite waiting
		 */
		iot_ret = iot_mqtt_registration(target_cli);
		if (iot_ret != IOT_ERROR_NONE)
			IOT_ERROR("failed to register");
		break;

	case IOT_CONNECT_TYPE_COMMUNICATION:
		iot_ret = iot_mqtt_subscribe(target_cli);
		if (iot_ret != IOT_ERROR_NONE)
			IOT_ERROR("failed to subscribe");
		break;

	/* No need default case, conn_type was already checked */
	}

	if (iot_ret != IOT_ERROR_NONE)
		iot_mqtt_disconnect(target_cli);

out:
	iot_es_crypto_free_pk(&pk_info);

	if (root_cert)
		free((void *)root_cert);

	if (dev_sn)
		free((void *)dev_sn);

	if (jwt_data)
		free(jwt_data);

	return iot_ret;
}

static void _iot_es_st_mqtt_disconnect(struct iot_mqtt_ctx *mqtt_ctx)
{
	iot_error_t iot_ret;

	if (mqtt_ctx->cmd_filter || mqtt_ctx->noti_filter) {
		iot_ret = iot_mqtt_unsubscribe(mqtt_ctx);
		if (iot_ret != IOT_ERROR_NONE)
			IOT_ERROR("Failed to unsubscribe(%d)", iot_ret);
	}
#if defined(STDK_MQTT_TASK)
	MQTTEndTask(&mqtt_ctx->cli);
#endif
	iot_mqtt_disconnect(mqtt_ctx);
#ifdef CONFIG_STDK_MQTT_USE_SSL
	iot_os_net_ssl_disconnect(&mqtt_ctx->net);
#else
	iot_os_net_disconnect(&mqtt_ctx->net);
#endif
}

iot_error_t iot_es_connect(struct iot_context *ctx, int conn_type)
{
	struct iot_mqtt_ctx *client_ctx = NULL;
	iot_error_t iot_ret;

	if (!ctx) {
		IOT_ERROR("invalid args");
		return IOT_ERROR_INVALID_ARGS;
	}

	client_ctx = (struct iot_mqtt_ctx *)malloc(sizeof(struct iot_mqtt_ctx));
	if (!client_ctx) {
		IOT_ERROR("failed to malloc for mqtt_ctx");
		return IOT_ERROR_MEM_ALLOC;
	}

	/* For iot_mqtt msg cb handling */
	client_ctx->iot_ctx = ctx;

	/* For mqtt-lib. notification & command filter */
	client_ctx->cmd_filter = NULL;
	client_ctx->noti_filter = NULL;

	if (conn_type == IOT_CONNECT_TYPE_COMMUNICATION)
		ctx->reged_cli = client_ctx;
	else
		ctx->client_ctx = client_ctx;

	iot_ret = _iot_es_st_mqtt_connect(client_ctx, conn_type);
	if (iot_ret != IOT_ERROR_NONE) {
		IOT_ERROR("Failed es_st_mqtt connect(%d)", iot_ret);
		if (conn_type == IOT_CONNECT_TYPE_COMMUNICATION)
			ctx->reged_cli = NULL;
		else
			ctx->client_ctx = NULL;

		free(client_ctx);
	}

	return iot_ret;
}

iot_error_t iot_es_disconnect(struct iot_context *ctx, int conn_type)
{
	struct iot_mqtt_ctx *target_cli;

	if (!ctx) {
		IOT_ERROR("There is no ctx!!");
		return IOT_ERROR_INVALID_ARGS;
	}

	if (conn_type == IOT_CONNECT_TYPE_COMMUNICATION) {
		target_cli = ctx->reged_cli;
		ctx->reged_cli = NULL;
	} else {
		target_cli = ctx->client_ctx;
		ctx->client_ctx = NULL;
	}

	if (!target_cli) {
		IOT_ERROR("There is no mqtt_ctx!!");
		return IOT_ERROR_INVALID_ARGS;
	}

	IOT_DEBUG("disconnect type %s",
		(conn_type == IOT_CONNECT_TYPE_REGISTRATION) ?
			"registration" : "communication");

	_iot_es_st_mqtt_disconnect(target_cli);

	free(target_cli);

	return IOT_ERROR_NONE;
}
