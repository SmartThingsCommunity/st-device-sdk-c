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
#include <stdbool.h>
#include <cJSON.h>

#include "iot_main.h"
#include "iot_internal.h"
#include "iot_uuid.h"
#include "iot_util.h"
#include "iot_debug.h"
#include "iot_nv_data.h"
#include "iot_bsp_system.h"

iot_error_t iot_mqtt_connect(struct iot_mqtt_ctx *target_cli,
		char *username, char *sign_data)
{
	st_mqtt_connect_data conn_data = st_mqtt_connect_data_initializer;
	int ret;
	iot_error_t iot_ret = IOT_ERROR_NONE;
	bool reboot;
	struct iot_uuid iot_uuid;
	char *client_id = NULL;
	struct iot_context *ctx = target_cli->iot_ctx;
	struct iot_cloud_prov_data *cloud_prov;
	char *root_cert = NULL;
	unsigned int root_cert_len;
	st_mqtt_broker_info_t broker_info;

	/* Use mac based random client_id for GreatGate */
	iot_ret = iot_random_uuid_from_mac(&iot_uuid);
	if (iot_ret != IOT_ERROR_NONE) {
		IOT_ERROR("Cannot get mac based random uuid");
		return iot_ret;
	}

	client_id = (char *)malloc(40);
	if (!client_id) {
		IOT_ERROR("Cannot malloc for client_id");
		return IOT_ERROR_MEM_ALLOC;
	}

	iot_ret = iot_util_convert_uuid_str(&iot_uuid, client_id, 40);
	if (iot_ret != IOT_ERROR_NONE) {
		IOT_ERROR("Cannot convert str for client_id");
		goto done_mqtt_connect;
	}

	st_mqtt_create(&target_cli->cli, IOT_DEFAULT_TIMEOUT);

	cloud_prov = &ctx->prov_data.cloud;
	if (!cloud_prov->broker_url) {
		IOT_ERROR("cloud_prov_data url does not exist!");
		iot_ret = IOT_ERROR_INVALID_ARGS;
		goto done_mqtt_connect;
	}

	iot_ret = iot_nv_get_root_certificate(&root_cert, &root_cert_len);
	if (iot_ret != IOT_ERROR_NONE) {
		IOT_ERROR("failed to get root cert");
		goto done_mqtt_connect;
	}

	broker_info.url = cloud_prov->broker_url;
	broker_info.port = cloud_prov->broker_port;
	broker_info.ca_cert = (const unsigned char *)root_cert;
	broker_info.ca_cert_len = root_cert_len;
	broker_info.ssl = 1;

	IOT_INFO("url: %s, port: %d", cloud_prov->broker_url, cloud_prov->broker_port);

	conn_data.clientid  = client_id;
	conn_data.username  = username;
	conn_data.password  = sign_data;

	IOT_INFO("mqtt connect,\nid : %s\nusername : %s\npassword : %s",
		 conn_data.clientid,
		 conn_data.username,
		 conn_data.password);

	ret = st_mqtt_connect(target_cli->cli, &broker_info, &conn_data);
	if (ret) {
		IOT_ERROR("%s error(%d)", __func__, ret);
		switch (ret) {
		case E_ST_MQTT_UNNACCEPTABLE_PROTOCOL:
			/* fall through */
		case E_ST_MQTT_SERVER_UNAVAILABLE:
			/* This case means Server can't start service for MQTT Things
			 * This case is totally server-side issue, so we just report it to Apps
			 */
			iot_ret = IOT_ERROR_MQTT_SERVER_UNAVAIL;
			break;

		case E_ST_MQTT_CLIENTID_REJECTED:
			/* fall through */
		case E_ST_MQTT_BAD_USERNAME_OR_PASSWORD:
			/* fall through */
		case E_ST_MQTT_NOT_AUTHORIZED:
			/* These cases are related to device's clientID, serialNumber, deviceId & JWT
			 * So we try to cleanup all data & reboot
			 */
			IOT_WARN("Rejected by Server!! cleanup all & reboot");

			reboot = true;
			iot_command_send((struct iot_context *)target_cli->iot_ctx,
				IOT_COMMAND_SELF_CLEANUP, &reboot, sizeof(bool));
			iot_ret = IOT_ERROR_MQTT_REJECT_CONNECT;
			break;

		default:
			/* On the others, we can't narrow down the causes. Some cases are related to
			 * network conditions (outside of the device) or, related to WIFI conditions
			 * (inside of the device). So we try to do re-connecting limitedly
			 */
			iot_ret = IOT_ERROR_MQTT_CONNECT_FAIL;
			break;
		}
	}

#if defined(STDK_MQTT_TASK)
        if ((ret = st_mqtt_starttask(target_cli->cli)) < 0) {
            IOT_ERROR("Returned code from start tasks is %d", ret);
			st_mqtt_disconnect(target_cli->cli);
			iot_ret = IOT_ERROR_MQTT_CONNECT_FAIL;
			goto done_mqtt_connect;
		} else
			IOT_INFO("Use MQTTStartTask");
#endif

done_mqtt_connect:
	if (iot_ret != IOT_ERROR_NONE && target_cli->cli) {
		st_mqtt_destroy(target_cli->cli);
		target_cli->cli = NULL;
	}
	if (root_cert)
		free((void *)root_cert);

	free(client_id);
	return iot_ret;
}

iot_error_t iot_mqtt_publish(struct iot_context *ctx, void *payload)
{
	int ret;
	iot_error_t result = IOT_ERROR_NONE;
	struct iot_mqtt_ctx *mqtt_ctx;
	st_mqtt_msg msg;
	char *topic;
	struct iot_registered_data *iot_reg_data;

	if (ctx == NULL) {
		IOT_ERROR("ctx is not intialized");
		return IOT_ERROR_BAD_REQ;
	}

	mqtt_ctx = ctx->reged_cli;

	if (!ctx->iot_reg_data.updated) {
		IOT_ERROR("Failed as there is no deviceID");
		return IOT_ERROR_BAD_REQ;
	}

	iot_reg_data = &(ctx->iot_reg_data);

	topic = malloc(IOT_TOPIC_SIZE);
	snprintf(topic, IOT_TOPIC_SIZE, IOT_PUB_TOPIC_EVENT, iot_reg_data->deviceId);

	msg.qos = st_mqtt_qos1;
	msg.retained = false;

	msg.payload = payload;
	msg.payloadlen = strlen(msg.payload);
	msg.topic = topic;

	IOT_INFO("publish event, topic : %s, payload :\n%s", topic, msg.payload);

	ret = st_mqtt_publish(mqtt_ctx->cli, &msg);
	if (ret) {
		IOT_WARN("MQTT pub error(%d)", ret);
		result = IOT_ERROR_MQTT_PUBLISH_FAIL;
	}

	free(topic);
	return result;
}

void _iot_mqtt_noti_sub_callback(st_mqtt_msg *md, void *userData)
{
	struct iot_context *ctx = (struct iot_context *)userData;
	char *mqtt_payload = md->payload;

	iot_noti_sub_cb(ctx, mqtt_payload);
	IOT_DEBUG("raw msg (len:%d) : %s", md->payloadlen, mqtt_payload);
}

void _iot_mqtt_cmd_sub_callback(st_mqtt_msg *md, void *userData)
{
	struct iot_context *ctx = (struct iot_context *)userData;
	char *mqtt_payload = md->payload;

	iot_cap_sub_cb(ctx->cap_handle_list, mqtt_payload);
	IOT_DEBUG("raw msg (len:%d) : %s", md->payloadlen, mqtt_payload);
}

iot_error_t iot_mqtt_subscribe(struct iot_mqtt_ctx *mqtt_ctx)
{
	int ret;
	iot_error_t result = IOT_ERROR_NONE;
	struct iot_context *ctx = (struct iot_context *)mqtt_ctx->iot_ctx;
	char *topicfilter;
	struct iot_registered_data *iot_reg_data;

	if (!ctx) {
		IOT_ERROR("Cannot get iot context");
		return IOT_ERROR_BAD_REQ;
	}

	if (!ctx->iot_reg_data.updated) {
		IOT_ERROR("Failed as there is no deviceID");
		return IOT_ERROR_BAD_REQ;
	}

	iot_reg_data = &(ctx->iot_reg_data);

	/* register notification subscribe */
	if (mqtt_ctx->noti_filter != NULL) {
		IOT_WARN("reged_cli already has noti topic : %s !!!",
			mqtt_ctx->noti_filter);
		free((void *)mqtt_ctx->noti_filter);
	}

	topicfilter = malloc(IOT_TOPIC_SIZE);

	sprintf(topicfilter, IOT_SUB_TOPIC_NOTIFICATION,
		iot_reg_data->deviceId);
	mqtt_ctx->noti_filter = (const char *)topicfilter;

	IOT_DEBUG("noti subscribe topic : %s", mqtt_ctx->noti_filter);

	ret = st_mqtt_subscribe(mqtt_ctx->cli, mqtt_ctx->noti_filter, st_mqtt_qos1,
			_iot_mqtt_noti_sub_callback, ctx);
	if (ret) {
		IOT_WARN("subscribe error(%d)", ret);
		result = IOT_ERROR_BAD_REQ;
		goto error_mqtt_sub_noti;
	}

	/* register command subscribe */
	if (mqtt_ctx->cmd_filter != NULL) {
		IOT_WARN("reged_cli has already cmd topic : %s !!!",
			mqtt_ctx->cmd_filter);
		free((void *)mqtt_ctx->cmd_filter);
	}

	topicfilter = malloc(IOT_TOPIC_SIZE);

	snprintf(topicfilter, IOT_TOPIC_SIZE, IOT_SUB_TOPIC_COMMAND,
		iot_reg_data->deviceId);
	mqtt_ctx->cmd_filter = (const char *)topicfilter;

	IOT_DEBUG("cmd subscribe topic : %s", mqtt_ctx->cmd_filter);

	ret = st_mqtt_subscribe(mqtt_ctx->cli, mqtt_ctx->cmd_filter, st_mqtt_qos1,
			_iot_mqtt_cmd_sub_callback, ctx);
	if (ret) {
		IOT_WARN("failed cmd sub registration(%d)", ret);
		result = IOT_ERROR_BAD_REQ;
		goto error_mqtt_sub_cmd;
	}

	return IOT_ERROR_NONE;

error_mqtt_sub_cmd:
	if (st_mqtt_unsubscribe(mqtt_ctx->cli, mqtt_ctx->cmd_filter))
		IOT_WARN("error for MQTTUnsub : %s", mqtt_ctx->cmd_filter);

	free((void *)mqtt_ctx->cmd_filter);

error_mqtt_sub_noti:
	free((void *)mqtt_ctx->noti_filter);

	return result;
}

iot_error_t iot_mqtt_unsubscribe(struct iot_mqtt_ctx *mqtt_ctx)
{
	int ret;

	/* Unregister command subscribe */
	if (mqtt_ctx->cmd_filter) {
		ret = st_mqtt_unsubscribe(mqtt_ctx->cli, mqtt_ctx->cmd_filter);
		if (ret)
			IOT_WARN("error for MQTTUnsub cmd (%d)", ret);

		free((void *)mqtt_ctx->cmd_filter);
		mqtt_ctx->cmd_filter = NULL;

	} else {
		IOT_DEBUG("There is no subfilter for MQTT cmd");
	}

	/* Unregister notification subscribe */
	if (mqtt_ctx->noti_filter) {
		ret = st_mqtt_unsubscribe(mqtt_ctx->cli, mqtt_ctx->noti_filter);
		if (ret)
			IOT_WARN("error for MQTTUnsub noti (%d)", ret);

		free((void *)mqtt_ctx->noti_filter);
		mqtt_ctx->noti_filter = NULL;

	} else {
		IOT_DEBUG("There is no subfilter for MQTT noti");
	}

	return IOT_ERROR_NONE;
}

void iot_mqtt_disconnect(struct iot_mqtt_ctx *target_cli)
{
	int ret;

	/* Internal MQTT connection was disconnected,
	 * even if it returns errors
	 */
	ret = st_mqtt_disconnect(target_cli->cli);
	if (ret)
		IOT_WARN("Disconnect error(%d)", ret);
}

static void mqtt_reg_sub_cb(st_mqtt_msg *md, void *userData)
{
	struct iot_context *ctx = (struct iot_context *)userData;
	struct iot_registered_data *reged_data = &ctx->iot_reg_data;
	char * mqtt_payload = md->payload;
	char * registed_msg = NULL;
	cJSON *json = NULL;
	cJSON *svr_did = NULL;
	cJSON *event = NULL;
	cJSON *cur_time = NULL;
	char time_str[11] = {0,};
	char *svr_did_str = NULL;
	enum iot_command_type iot_cmd;

	/*parsing mqtt_payload*/
	json = cJSON_Parse(mqtt_payload);
	if (json == NULL) {
		IOT_ERROR("mqtt_payload(%s) parsing failed", mqtt_payload);
		goto reg_sub_out;
	}

	registed_msg = cJSON_PrintUnformatted(json);
	if (registed_msg == NULL) {
		IOT_ERROR("There are no registed msg, payload : %s", mqtt_payload);
		goto reg_sub_out;
	}
	IOT_INFO("Registered MSG : %s", registed_msg);

	event = cJSON_GetObjectItem(json, "event");
	if (event != NULL) {
		if (!strncmp(event->valuestring, "expired.jwt", 11)) {
			cur_time = cJSON_GetObjectItem(json, "currentTime");
			if (cur_time == NULL) {
				IOT_ERROR("%s : there is no currentTime in json, mqtt_payload : \n%s",
					__func__, mqtt_payload);
				goto reg_sub_out;
			}

			snprintf(time_str, sizeof(time_str), "%d", cur_time->valueint);
			IOT_INFO("Set SNTP with current time %s", time_str);
			iot_bsp_system_set_time_in_sec(time_str);

			iot_cmd = IOT_COMMAND_CLOUD_REGISTERING;
			if (iot_command_send(ctx, iot_cmd, NULL, 0) != IOT_ERROR_NONE)
				IOT_ERROR("Cannot send cloud registering cmd!!");
		} else if (!strncmp(event->valuestring, "error", 5)) {
			bool reboot;
			reboot = true;
			iot_command_send(ctx, IOT_COMMAND_SELF_CLEANUP, &reboot, sizeof(bool));
			goto reg_sub_out;
		} else {
			IOT_ERROR("event type %s is not defined", event->valuestring);
			goto reg_sub_out;
		}
	}

	svr_did = cJSON_GetObjectItem(json, "deviceId");
	if (svr_did != NULL && !reged_data->updated) {
		svr_did_str = cJSON_PrintUnformatted(svr_did);
		if (svr_did_str == NULL) {
			IOT_ERROR("Can't print server's did str!!");
			goto reg_sub_out;
		}

		memset(reged_data->deviceId, 0, IOT_REG_UUID_STR_LEN + 1);
		/* svr_did_str has/included ["] also - "xxxxx-xxxx-xxx" */
		memcpy(reged_data->deviceId, (svr_did_str + 1), IOT_REG_UUID_STR_LEN);

		reged_data->updated = true;
		reged_data->new_reged = false;

		iot_cmd = IOT_COMMAND_CLOUD_REGISTERED;
		if (iot_command_send(ctx, iot_cmd, NULL, 0) != IOT_ERROR_NONE)
			IOT_ERROR("Cannot send cloud registered cmd!!");
	}

reg_sub_out:
	if (svr_did_str != NULL)
		free(svr_did_str);

	if (registed_msg != NULL)
		free(registed_msg);

	if (json != NULL)
		cJSON_Delete(json);
}

iot_error_t iot_mqtt_registration(struct iot_mqtt_ctx *mqtt_ctx)
{
	int ret;
	char *reg_topic = NULL;
	char *dev_sn = NULL;
	unsigned int devsn_len;
	iot_error_t iot_err = IOT_ERROR_NONE;
	cJSON *root = NULL;
	st_mqtt_msg msg;
	char str_dump[40], valid_id = 0;
	struct iot_devconf_prov_data *devconf;
	struct iot_context *ctx;

	if (!mqtt_ctx) {
		IOT_ERROR("There is no iot_mqtt_ctx!!");
		return IOT_ERROR_INVALID_ARGS;
	}

	/* We assume that registration process is always doing after first connection */
	if (mqtt_ctx->noti_filter != NULL) {
		IOT_ERROR("mqtt_ctx already has noti topic : %s !!!",
			mqtt_ctx->noti_filter);
		return IOT_ERROR_INVALID_ARGS;
	}

	reg_topic = malloc(IOT_TOPIC_SIZE);
	if (!reg_topic) {
		IOT_ERROR("Cannot malloc for registration topic");
		return IOT_ERROR_MEM_ALLOC;
	}

	/* Step 1. Subscribe to registration topic with "serial-num"*/
	if (iot_nv_get_serial_number(&dev_sn, &devsn_len) != IOT_ERROR_NONE) {
		IOT_ERROR("failed to get serial num");
		free(reg_topic);
		return IOT_ERROR_BAD_REQ;
	}

	sprintf(reg_topic, IOT_SUB_TOPIC_REGISTRATION, dev_sn);
	mqtt_ctx->noti_filter = (const char *)reg_topic;
	free(dev_sn);

	IOT_DEBUG("noti subscribe topic : %s", mqtt_ctx->noti_filter);

	/* register notification subscribe for registration */
	ret = st_mqtt_subscribe(mqtt_ctx->cli, mqtt_ctx->noti_filter,
			st_mqtt_qos1, mqtt_reg_sub_cb, mqtt_ctx->iot_ctx);
	if (ret) {
		IOT_ERROR("%s error MQTTsub(%d)", __func__, ret);
		iot_err = IOT_ERROR_BAD_REQ;
		goto failed_regist;
	}

	/* Step 2. Publish target's registration info to server */
	ctx = (struct iot_context *)mqtt_ctx->iot_ctx;
	ctx->iot_reg_data.updated = false;

	iot_err = iot_util_convert_uuid_str(&ctx->prov_data.cloud.location_id,
				str_dump, sizeof(str_dump));
	if (iot_err != IOT_ERROR_NONE) {
		IOT_ERROR("%s error location_id convt (%d)", __func__, iot_err);
		iot_err = IOT_ERROR_BAD_REQ;
		goto failed_regist;
	}

	root = cJSON_CreateObject();
	if (!root) {
		IOT_ERROR("error cjson create");
		iot_err = IOT_ERROR_BAD_REQ;
		goto failed_regist;
	}

	devconf = &ctx->devconf;

	cJSON_AddItemToObject(root, "locationId",
		cJSON_CreateString(str_dump));

	/* label is optional value */
	if (ctx->prov_data.cloud.label)
		cJSON_AddItemToObject(root, "label",
			cJSON_CreateString(ctx->prov_data.cloud.label));
	else
		IOT_WARN("There is no label for registration");

	cJSON_AddItemToObject(root, "mnId",
		cJSON_CreateString(devconf->mnid));

	cJSON_AddItemToObject(root, "vid",
		cJSON_CreateString(devconf->vid));

	cJSON_AddItemToObject(root, "deviceTypeId",
		cJSON_CreateString(devconf->device_type));

	cJSON_AddItemToObject(root, "lookupId",
		cJSON_CreateString(ctx->lookup_id));

	/* room id is optional value */
	for (int i = 0; i < sizeof(ctx->prov_data.cloud.room_id); i++)
		valid_id |= ctx->prov_data.cloud.room_id.id[i];

	if (valid_id) {
		iot_err = iot_util_convert_uuid_str(&ctx->prov_data.cloud.room_id,
				str_dump, sizeof(str_dump));
		if (iot_err != IOT_ERROR_NONE) {
			IOT_WARN("fail room_id convt (%d)", iot_err);
			iot_err = IOT_ERROR_NONE;
		} else {
			cJSON_AddItemToObject(root, "roomId",
				cJSON_CreateString(str_dump));
		}
	}

	msg.payload = cJSON_PrintUnformatted(root);
	if (!msg.payload) {
		IOT_ERROR("Failed to make payload for MQTTpub");
		iot_err = IOT_ERROR_MEM_ALLOC;
	} else {
		IOT_DEBUG("publish resource payload : \n%s", msg.payload);

		msg.qos = st_mqtt_qos1;
		msg.retained = false;
		msg.payloadlen = strlen(msg.payload);
		msg.topic = IOT_PUB_TOPIC_REGISTRATION;

		ret = st_mqtt_publish(mqtt_ctx->cli, &msg);
		if (ret) {
			IOT_ERROR("error MQTTpub(%d)", ret);
			iot_err = IOT_ERROR_BAD_REQ;
		}

		cJSON_free(msg.payload);
	}

	cJSON_Delete(root);

failed_regist:
	if (iot_err != IOT_ERROR_NONE) {
		mqtt_ctx->noti_filter = NULL;
		free(reg_topic);
	}

	return iot_err;
}

