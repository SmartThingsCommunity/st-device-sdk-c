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
#include "iot_wt.h"
#include "iot_os_util.h"
#include "iot_bsp_system.h"
#include "security/iot_security_manager.h"

#include "JSON.h"
#if defined(STDK_IOT_CORE_SERIALIZE_CBOR)
#include <cbor.h>
#endif

gg_connection_request_status _check_connection_response(char *response_payload, size_t response_payload_len)
{
	JSON_H *response_json = NULL;
	JSON_H *event_json = NULL;
	JSON_H *cur_time_json = NULL;
	char time_str[11] = {0,};
	iot_error_t err;
	gg_connection_request_status response_ret = GG_CONNECTION_REQUEST_STATUS_FAIL;
	char *response_payload_str = NULL;

	/* parsing response payload */
#if defined(STDK_IOT_CORE_SERIALIZE_CBOR)
	char *payload_json = NULL;
	size_t payload_json_len = 0;

	err = iot_serialize_cbor2json((uint8_t *)response_payload,
			(size_t)response_payload_len,
			&payload_json, &payload_json_len);
	if (err) {
		IOT_ERROR("iot_serialize_cbor2json = %d", err);
		return GG_CONNECTION_REQUEST_STATUS_FAIL;
	}

	if ((payload_json == NULL) || (payload_json_len == 0)) {
		IOT_ERROR("cbor2json failed (json buffer is null)");
		return GG_CONNECTION_REQUEST_STATUS_FAIL;
	}

	response_json = JSON_PARSE(payload_json);
	free(payload_json);
#else
	response_json = JSON_PARSE(response_payload);
#endif
	if (response_json == NULL) {
		IOT_ERROR("Response payload parsing failed");
		return GG_CONNECTION_REQUEST_STATUS_FAIL;
	}

	response_payload_str = JSON_PRINT(response_json);
	IOT_INFO("Connection response payload %s", response_payload_str);
	free(response_payload_str);

	event_json = JSON_GET_OBJECT_ITEM(response_json, "event");
	if (event_json != NULL) {
		if (!strncmp(event_json->valuestring, "expired.jwt", 11)) {
			cur_time_json = JSON_GET_OBJECT_ITEM(response_json, "currentTime");
			if (cur_time_json == NULL) {
				IOT_ERROR("There is no currentTime in json");
				response_ret = GG_CONNECTION_REQUEST_STATUS_FAIL;
				goto out;
			}
			snprintf(time_str, sizeof(time_str), "%d", cur_time_json->valueint);
			IOT_INFO("Set SNTP with current time %s", time_str);
			iot_bsp_system_set_time_in_sec(time_str);

			response_ret = GG_CONNECTION_REQUEST_STATUS_FAIL;
		} else if (!strncmp(event_json->valuestring, "connect.success", 15)) {
			response_ret = GG_CONNECTION_REQUEST_STATUS_SUCCESS;
		} else {
			IOT_ERROR("No connection response payload %s", event_json->valuestring);
			response_ret = GG_CONNECTION_REQUEST_STATUS_WAITING;
		}
	} else {
		IOT_ERROR("No event item in payload");
		response_ret = GG_CONNECTION_REQUEST_STATUS_WAITING;
	}

out:
	if (response_json)
		JSON_DELETE(response_json);

	return response_ret;
}

static void mqtt_reg_sub_cb(st_mqtt_msg *md, void *userData)
{
	struct iot_context *ctx = (struct iot_context *)userData;
	struct iot_registered_data *reged_data = &ctx->iot_reg_data;
	char * mqtt_payload = md->payload;
	char * registered_msg = NULL;
	JSON_H *json = NULL;
	JSON_H *item = NULL;
	JSON_H *event = NULL;
	JSON_H *cur_time = NULL;
	JSON_H *dip_key = NULL;
	JSON_H *dip_item = NULL;
	char time_str[11] = {0,};
	char *svr_did_str = NULL;
	enum iot_command_type iot_cmd;
	struct iot_dip_data *reged_dip = NULL;
	struct iot_uuid *reged_location = NULL;
	iot_error_t err;

	/*parsing mqtt_payload*/
#if defined(STDK_IOT_CORE_SERIALIZE_CBOR)
	char *payload_json = NULL;
	size_t payload_json_len = 0;

	err = iot_serialize_cbor2json((uint8_t *)mqtt_payload,
			(size_t)md->payloadlen,
			&payload_json, &payload_json_len);
	if (err) {
		IOT_ERROR("iot_serialize_cbor2json = %d", err);
		goto reg_sub_out;
	}

	if ((payload_json == NULL) || (payload_json_len == 0)) {
		IOT_ERROR("cbor2json failed (json buffer is null)");
		goto reg_sub_out;
	}

	json = JSON_PARSE(payload_json);
	free(payload_json);
#else
	json = JSON_PARSE(mqtt_payload);
#endif
	if (json == NULL) {
		IOT_ERROR("mqtt_payload(%s) parsing failed", mqtt_payload);
		goto reg_sub_out;
	}

	registered_msg = JSON_PRINT(json);
	if (registered_msg == NULL) {
		IOT_ERROR("There are no registered msg, payload : %s", mqtt_payload);
		goto reg_sub_out;
	}
	IOT_INFO("Registered MSG : %s", registered_msg);

	event = JSON_GET_OBJECT_ITEM(json, "event");
	if (event != NULL) {
		if (!strncmp(event->valuestring, "expired.jwt", 11)) {
			cur_time = JSON_GET_OBJECT_ITEM(json, "currentTime");
			if (cur_time == NULL) {
				IOT_ERROR("%s : there is no currentTime in json, mqtt_payload : \n%s",
					__func__, mqtt_payload);
				goto reg_sub_out;
			}

			snprintf(time_str, sizeof(time_str), "%d", cur_time->valueint);
			IOT_INFO("Set SNTP with current time %s", time_str);
			iot_bsp_system_set_time_in_sec(time_str);

			iot_cmd = IOT_COMMAND_CLOUD_REGISTERING;
			if (iot_command_send(ctx, iot_cmd, NULL, 0) != IOT_ERROR_NONE) {
				IOT_ERROR("Cannot send cloud registering cmd!!");
			}
		} else if (!strncmp(event->valuestring, "error", 5)) {
			/* TODO : signaling restart onboarding */
			IOT_ERROR("TODO : signaling restart onboarding %d", __LINE__);
			goto reg_sub_out;
		} else {
			IOT_ERROR("event type %s is not defined", event->valuestring);
			goto reg_sub_out;
		}
	}

	/* dip_key is optional values */
	dip_key =JSON_GET_OBJECT_ITEM(json, "deviceIntegrationProfileKey");
	if (dip_key != NULL) {
		reged_dip = iot_os_malloc(sizeof(struct iot_dip_data));
		if (!reged_dip) {
			IOT_ERROR("Can't alloc iot_dip_data!!");
			goto reg_sub_out;
		}
		memset(reged_dip, 0, sizeof(struct iot_dip_data));

		dip_item = JSON_GET_OBJECT_ITEM(dip_key, "id");
		if (!dip_item) {
			IOT_ERROR("Can't find id for dip_key!!");
			iot_os_free(reged_dip);
			goto reg_sub_out;
		}

		err = iot_util_convert_str_uuid(JSON_GET_STRING_VALUE(dip_item),
				&reged_dip->dip_id);
		if (err != IOT_ERROR_NONE) {
			IOT_ERROR("Can't convert str to uuid(%d)", err);
			iot_os_free(reged_dip);
			goto reg_sub_out;
		}

		dip_item = JSON_GET_OBJECT_ITEM(dip_key, "majorVersion");
		if (!dip_item) {
			IOT_ERROR("Can't find majorVersion for dip_key!!");
			iot_os_free(reged_dip);
			goto reg_sub_out;
		}
		reged_dip->dip_major_version = dip_item->valueint;

		/* minorVersion is optional, default 0 */
		dip_item = JSON_GET_OBJECT_ITEM(dip_key, "minorVersion");
		if (dip_item) {
			reged_dip->dip_minor_version = dip_item->valueint;
		}

		if (reged_data->dip)
			iot_os_free(reged_data->dip);

		reged_data->dip = reged_dip;
	}

	item = JSON_GET_OBJECT_ITEM(json, "locationId");
	if (item != NULL) {
		reged_location = iot_os_malloc(sizeof(struct iot_uuid));
		if (!reged_location) {
			IOT_ERROR("Can't alloc iot_uuid for location!!");
			goto reg_sub_out;
		}
		memset(reged_location, 0, sizeof(struct iot_uuid));

		err = iot_util_convert_str_uuid(JSON_GET_STRING_VALUE(item),
				reged_location);
		if (err != IOT_ERROR_NONE) {
			IOT_ERROR("Can't convert str to uuid(%d)", err);
			iot_os_free(reged_location);
			goto reg_sub_out;
		}

		if (reged_data->locationId)
			iot_os_free(reged_data->locationId);

		reged_data->locationId = reged_location;
	} else {
		IOT_WARN("Server does not send locationId!!");
	}

	item = JSON_GET_OBJECT_ITEM(json, "deviceId");
	if (item != NULL && !reged_data->updated) {
		svr_did_str = JSON_PRINT(item);
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
		if (iot_command_send(ctx, iot_cmd, NULL, 0) != IOT_ERROR_NONE) {
			IOT_ERROR("Cannot send cloud registered cmd!!");
		}
	}

reg_sub_out:
	if (svr_did_str != NULL)
		free(svr_did_str);

	if (registered_msg != NULL)
		free(registered_msg);

	if (json != NULL)
		JSON_DELETE(json);
}

STATIC_FUNCTION
void _iot_mqtt_registration_client_callback(st_mqtt_event event, void *event_data, void *user_data)
{
	struct iot_context *ctx = (struct iot_context *)user_data;
	switch (event) {
		case ST_MQTT_EVENT_MSG_DELIVERED:
			{
				st_mqtt_msg *md = event_data;
				if (ctx->sign_up_connection_request_status
						!= GG_CONNECTION_REQUEST_STATUS_SUCCESS) {
					ctx->sign_up_connection_request_status =
						_check_connection_response(md->payload, md->payloadlen);
					return;
				}

				if (!strncmp(md->topic, IOT_SUB_TOPIC_REGISTRATION_PREFIX, IOT_SUB_TOPIC_REGISTRATION_PREFIX_SIZE)) {
					mqtt_reg_sub_cb(md, user_data);
				} else {
					IOT_WARN("No msg delivery handler for %s", (char *)md->topic);
				}
				IOT_DEBUG("raw msg (len:%d) : %s", md->payloadlen, (char *)md->payload);
				break;
			}
		default:
			IOT_WARN("No MQTT event handler for %d", event);
			break;
	}
}

STATIC_FUNCTION
int _iot_parse_sequence_num(char *payload)
{
	JSON_H *json = NULL;
	JSON_H *device_events = NULL;
	JSON_H *first_event = NULL;
	JSON_H *provider_data = NULL;
	JSON_H *sequence_number = NULL;
	int seq_num = 0;
#if defined(STDK_IOT_CORE_SERIALIZE_CBOR)
	char *payload_json = NULL;
	size_t payload_json_len = 0;

	if (iot_serialize_cbor2json((uint8_t *)payload, strlen(payload), &payload_json, &payload_json_len)) {
		IOT_ERROR("cbor2json failed");
		return 0;
	}

	if ((payload_json == NULL) || (payload_json_len == 0)) {
		IOT_ERROR("json buffer is null");
		return 0;
	}

	json = JSON_PARSE(payload_json);
	free(payload_json);
#else
	json = JSON_PARSE(payload);
#endif
	if (json == NULL) {
		IOT_ERROR("Cannot parse by json");
		return 0;
	}

	device_events = JSON_GET_OBJECT_ITEM(json, "deviceEvents");
	if (device_events == NULL) {
		IOT_ERROR("there is no events in raw_msgn");
		goto out;
	}

	first_event = JSON_GET_CHILD_ITEM(device_events);
	if (first_event == NULL) {
		IOT_ERROR("there is no event in raw_msgn");
		goto out;
	}

	provider_data = JSON_GET_OBJECT_ITEM(first_event, "providerData");
	if (provider_data == NULL) {
		IOT_ERROR("there is no provider_data in raw_msgn");
		goto out;
	}

	sequence_number = JSON_GET_OBJECT_ITEM(provider_data, "sequenceNumber");
	if (sequence_number == NULL) {
		IOT_ERROR("there is no sequence number in raw_msgn");
		goto out;
	}

	seq_num = JSON_GET_NUMBER_VALUE(sequence_number);
out:
	if (json)
		JSON_DELETE(json);

	return seq_num;
}

STATIC_FUNCTION
void _iot_mqtt_signin_client_callback(st_mqtt_event event, void *event_data, void *user_data)
{
	struct iot_context *ctx = (struct iot_context *)user_data;

	switch (event) {
		case ST_MQTT_EVENT_MSG_DELIVERED:
			{
				st_mqtt_msg *md = event_data;
				if (ctx->sign_in_connection_request_status
						!= GG_CONNECTION_REQUEST_STATUS_SUCCESS) {
					ctx->sign_in_connection_request_status =
						_check_connection_response(md->payload, md->payloadlen);
					return;
				}

				char *payload_json = NULL;
#if defined(STDK_IOT_CORE_SERIALIZE_CBOR)
				size_t payload_json_len = 0;

				if (iot_serialize_cbor2json((uint8_t *)md->payload, md->payloadlen, &payload_json, &payload_json_len)) {
					IOT_ERROR("cbor2json failed");
					return;
				}

				if ((payload_json == NULL) || (payload_json_len == 0)) {
					IOT_ERROR("json buffer is null");
					return;
				}
#else
				payload_json = md->payload;
#endif
				IOT_DEBUG("raw msg : %s", payload_json);
				if (!strncmp(md->topic, IOT_SUB_TOPIC_COMMAND_PREFIX, IOT_SUB_TOPIC_COMMAND_PREFIX_SIZE)) {
					/* Send commands to each registered capability callback handler
					 * and registered noti callback handler. 
					 * application can choose one of both handlers to handle commands */
					iot_cap_sub_cb(ctx->cap_handle_list, payload_json);
					iot_cap_commands_cb(ctx, payload_json);
				} else if (!strncmp(md->topic, IOT_SUB_TOPIC_NOTIFICATION_PREFIX, IOT_SUB_TOPIC_NOTIFICATION_PREFIX_SIZE)) {
					iot_noti_sub_cb(ctx, payload_json);
				} else {
					IOT_WARN("No msg delivery handler for %s", (char *)md->topic);
				}
#if defined(STDK_IOT_CORE_SERIALIZE_CBOR)
				free(payload_json);
#endif
			}
			break;
		case ST_MQTT_EVENT_PUBLISH_FAILED:
		case ST_MQTT_EVENT_PUBLISH_TIMEOUT:
			{
				if (event == ST_MQTT_EVENT_PUBLISH_FAILED) {
					iot_set_st_ecode(ctx, IOT_ST_ECODE_CE40);
				} else if (event == ST_MQTT_EVENT_PUBLISH_TIMEOUT) {
					iot_set_st_ecode(ctx, IOT_ST_ECODE_CE41);
				}
				st_mqtt_msg *md = event_data;
				char *mqtt_payload = md->payload;
				iot_noti_data_t noti_data;

				noti_data.type = IOT_NOTI_TYPE_SEND_FAILED;
				noti_data.raw.send_fail.failed_sequence_num = _iot_parse_sequence_num(mqtt_payload);

				if (noti_data.raw.send_fail.failed_sequence_num < 0) {
					IOT_ERROR("No sequence number");
					break;
				}
				iot_command_send(ctx, IOT_COMMAND_NOTIFICATION_RECEIVED,
					&noti_data, sizeof(noti_data));
				IOT_DEBUG("raw msg (len:%d) : %s", md->payloadlen, mqtt_payload);
				break;
			}
			break;
		default:
			IOT_WARN("No MQTT event handler for %d", event);
			break;
	}
}

#if defined(STDK_IOT_CORE_SERIALIZE_CBOR)
STATIC_FUNCTION
void *_iot_es_mqtt_registration_cbor(struct iot_context *ctx,
			char *dip_id, size_t *msglen, bool self_reged)
{
	struct iot_devconf_prov_data *devconf;
	struct iot_device_info *dev_info;
	struct timeval tv = {0,};
	CborEncoder root = {0};
	CborEncoder root_map = {0};
	CborEncoder dip_key_map = {0};
	uint8_t *buf;
	uint8_t *tmp;
	size_t buflen = 256;
	size_t olen;

	if (!ctx) {
		IOT_ERROR("ctx is null");
		return NULL;
	}
	dev_info = &(ctx->device_info);

	devconf = &ctx->devconf;
	if ((self_reged == false) && !devconf->hashed_sn) {
		IOT_ERROR("There are no hashed_sn");
		return NULL;
	}

retry:
	buflen += 128;

	buf = (uint8_t *)malloc(buflen);
	if (buf == NULL) {
		IOT_ERROR("failed to malloc for cbor");
		return NULL;
	}
	memset(buf, 0, buflen);

	cbor_encoder_init(&root, buf, buflen, 0);

	cbor_encoder_create_map(&root, &root_map, CborIndefiniteLength);

	/* location id is optional value */
	if (ctx->prov_data.cloud.location) {
		cbor_encode_text_stringz(&root_map, "locationId");
		cbor_encode_text_stringz(&root_map, ctx->prov_data.cloud.location);
	} else if (self_reged == true) {
		/* But location is mandatory for self-registration */
		IOT_ERROR("There is no location for self-registration!!");
		cbor_encoder_close_container_checked(&root, &root_map);
		goto exit_failed;
	}

	/* label is optional value */
	if (ctx->prov_data.cloud.label) {
		cbor_encode_text_stringz(&root_map, "label");
		cbor_encode_text_stringz(&root_map, ctx->prov_data.cloud.label);
	} else {
		IOT_WARN("There is no label for registration");
	}

	cbor_encode_text_stringz(&root_map, "mnId");
	cbor_encode_text_stringz(&root_map, devconf->mnid);

	cbor_encode_text_stringz(&root_map, "vid");
	cbor_encode_text_stringz(&root_map, devconf->vid);

	cbor_encode_text_stringz(&root_map, "deviceTypeId");
	cbor_encode_text_stringz(&root_map, devconf->device_type);

	cbor_encode_text_stringz(&root_map, "lookupId");
	cbor_encode_text_stringz(&root_map, ctx->lookup_id);

	/* room id is optional value */
	if (ctx->prov_data.cloud.room && (self_reged == false)) {
		cbor_encode_text_stringz(&root_map, "roomId");
		cbor_encode_text_stringz(&root_map, ctx->prov_data.cloud.room);
	} else if (self_reged == false) {
		/* Do not send serialHash & provisioningTs for self-registration */
		cbor_encode_text_stringz(&root_map, "serialHash");
		cbor_encode_text_stringz(&root_map, devconf->hashed_sn);

		gettimeofday(&tv, NULL);

		cbor_encode_text_stringz(&root_map, "provisioningTs");
		cbor_encode_int(&root_map, tv.tv_sec);
	}
	/* firmwareVersion is mandatory on the device_info */
	cbor_encode_text_stringz(&root_map, "firmwareVersion");
	cbor_encode_text_stringz(&root_map, dev_info->firmware_version);

	/* Add optional information if it available */
	if (dev_info->opt_info) {

		if (dev_info->model_number) {
			cbor_encode_text_stringz(&root_map, "modelNumber");
			cbor_encode_text_stringz(&root_map, dev_info->model_number);
		}

		if (dev_info->marketing_name) {
			cbor_encode_text_stringz(&root_map, "marketingName");
			cbor_encode_text_stringz(&root_map, dev_info->marketing_name);
		}

		if (dev_info->manufacturer_name) {
			cbor_encode_text_stringz(&root_map, "manufacturerName");
			cbor_encode_text_stringz(&root_map, dev_info->manufacturer_name);
		}

		if (dev_info->manufacturer_code) {
			cbor_encode_text_stringz(&root_map, "manufacturerCode");
			cbor_encode_text_stringz(&root_map, dev_info->manufacturer_code);
		}
	}

	if (iot_os_get_os_name() && strlen(iot_os_get_os_name()) > 0) {
		cbor_encode_text_stringz(&root_map, "osType");
		cbor_encode_text_stringz(&root_map, iot_os_get_os_name());
	}

	if (iot_os_get_os_version_string() && strlen(iot_os_get_os_version_string()) > 0) {
		cbor_encode_text_stringz(&root_map, "osVersion");
		cbor_encode_text_stringz(&root_map, iot_os_get_os_version_string());
	}

	cbor_encode_text_stringz(&root_map, "stdkVersion");
	cbor_encode_text_stringz(&root_map, STDK_VERSION_STRING);

	/* dip is optional values */
	if (dip_id) {
		cbor_encode_text_stringz(&root_map, "deviceIntegrationProfileKey");
		cbor_encoder_create_map(&root_map, &dip_key_map, CborIndefiniteLength);

		cbor_encode_text_stringz(&dip_key_map, "id");
		cbor_encode_text_stringz(&dip_key_map, dip_id);

		cbor_encode_text_stringz(&dip_key_map, "majorVersion");
		cbor_encode_int(&dip_key_map, devconf->dip->dip_major_version);

		cbor_encode_text_stringz(&dip_key_map, "minorVersion");
		cbor_encode_int(&dip_key_map, devconf->dip->dip_minor_version);

		cbor_encoder_close_container_checked(&root_map, &dip_key_map);
	}

	cbor_encoder_close_container_checked(&root, &root_map);

	olen = cbor_encoder_get_buffer_size(&root, buf);
	if (olen < buflen) {
		tmp = (uint8_t *)realloc(buf, olen + 1);
		if (!tmp) {
			IOT_WARN("realloc failed for cbor");
		} else {
			buf = tmp;
		}
	} else {
		IOT_ERROR("allocated size is not enough (%d < %d)",
				(int)buflen, (int)olen);
		if (buflen < IOT_CBOR_MAX_BUF_LEN) {
			free(buf);
			goto retry;
		} else {
			goto exit_failed;
		}
	}

	*msglen = olen;
	return (void *)buf;

exit_failed:
	free(buf);

	return NULL;
}
#else /* !STDK_IOT_CORE_SERIALIZE_CBOR */
STATIC_FUNCTION
void *_iot_es_mqtt_registration_json(struct iot_context *ctx,
			char *dip_id, size_t *msglen, bool self_reged)
{
	struct iot_devconf_prov_data *devconf;
	struct iot_device_info *dev_info;
	struct timeval tv = {0,};
	JSON_H *root = NULL;
	JSON_H *dip_key = NULL;
	char *payload = NULL;

	if (!ctx) {
		IOT_ERROR("ctx is null");
		return NULL;
	}
	dev_info = &(ctx->device_info);

	devconf = &ctx->devconf;
	if ((self_reged == false) && !devconf->hashed_sn) {
		IOT_ERROR("There are no hashed_sn");
		return NULL;
	}

	root = JSON_CREATE_OBJECT();
	if (!root) {
		IOT_ERROR("failed to create json");
		return NULL;
	}

	/* location id is optional value */
	if (ctx->prov_data.cloud.location) {
		JSON_ADD_ITEM_TO_OBJECT(root, "locationId",
		JSON_CREATE_STRING(ctx->prov_data.cloud.location));
	} else if (self_reged == true) {
		/* But location is mandatory for self-registration */
		IOT_ERROR("There is no location for self-registration!!");
		JSON_DELETE(root);
		return NULL;
	}

	/* label is optional value */
	if (ctx->prov_data.cloud.label) {
		JSON_ADD_ITEM_TO_OBJECT(root, "label",
			JSON_CREATE_STRING(ctx->prov_data.cloud.label));
	} else {
		IOT_WARN("There is no label for registration");
	}

	JSON_ADD_ITEM_TO_OBJECT(root, "mnId",
		JSON_CREATE_STRING(devconf->mnid));

	JSON_ADD_ITEM_TO_OBJECT(root, "vid",
		JSON_CREATE_STRING(devconf->vid));

	JSON_ADD_ITEM_TO_OBJECT(root, "deviceTypeId",
		JSON_CREATE_STRING(devconf->device_type));

	JSON_ADD_ITEM_TO_OBJECT(root, "lookupId",
		JSON_CREATE_STRING(ctx->lookup_id));

	if (ctx->prov_data.cloud.room && (self_reged == false)) {
		JSON_ADD_ITEM_TO_OBJECT(root, "roomId",
			JSON_CREATE_STRING(ctx->prov_data.cloud.room));
	} else if (self_reged == false) {
		/* Do not send serialHash & provisioningTs for self-registration */
		JSON_ADD_ITEM_TO_OBJECT(root, "serialHash",
			JSON_CREATE_STRING(devconf->hashed_sn));

		gettimeofday(&tv, NULL);

		JSON_ADD_ITEM_TO_OBJECT(root, "provisioningTs",
			JSON_CREATE_NUMBER(tv.tv_sec));
	}

	/* firmwareVersion is mandatory on the device_info */
	JSON_ADD_ITEM_TO_OBJECT(root, "firmwareVersion",
		JSON_CREATE_STRING(dev_info->firmware_version));

	/* Add optional information if it available */
	if (dev_info->opt_info) {
		if (dev_info->model_number) {
			JSON_ADD_ITEM_TO_OBJECT(root, "modelNumber",
				JSON_CREATE_STRING(dev_info->model_number));
		}

		if (dev_info->marketing_name) {
			JSON_ADD_ITEM_TO_OBJECT(root, "marketingName",
				JSON_CREATE_STRING(dev_info->marketing_name));
		}

		if (dev_info->manufacturer_name) {
			JSON_ADD_ITEM_TO_OBJECT(root, "manufacturerName",
				JSON_CREATE_STRING(dev_info->manufacturer_name));
		}

		if (dev_info->manufacturer_code) {
			JSON_ADD_ITEM_TO_OBJECT(root, "manufacturerCode",
				JSON_CREATE_STRING(dev_info->manufacturer_code));
		}
	}

	if (iot_os_get_os_name() && strlen(iot_os_get_os_name()) > 0) {
		JSON_ADD_ITEM_TO_OBJECT(root, "osType",
			JSON_CREATE_STRING(iot_os_get_os_name()));
	}

	if (iot_os_get_os_version_string() && strlen(iot_os_get_os_version_string()) > 0) {
		JSON_ADD_ITEM_TO_OBJECT(root, "osVersion",
			JSON_CREATE_STRING(iot_os_get_os_version_string()));
	}

	/* STDK release version */
	JSON_ADD_ITEM_TO_OBJECT(root, "stdkVersion",
		JSON_CREATE_STRING(STDK_VERSION_STRING));

	/* dip is optional values */
	if (dip_id) {
		dip_key = JSON_CREATE_OBJECT();
		if (!dip_key) {
			IOT_WARN("Can't create dip_key obj");
			goto exit_json_making;
		}

		JSON_ADD_ITEM_TO_OBJECT(dip_key, "id",
			JSON_CREATE_STRING(dip_id));

		JSON_ADD_NUMBER_TO_OBJECT(dip_key,
			"majorVersion", devconf->dip->dip_major_version);

		JSON_ADD_NUMBER_TO_OBJECT(dip_key,
			"minorVersion", devconf->dip->dip_minor_version);

		JSON_ADD_ITEM_TO_OBJECT(root,
			"deviceIntegrationProfileKey", dip_key);
	}

exit_json_making:
	payload = JSON_PRINT(root);

	*msglen = strlen(payload);

	JSON_DELETE(root);


	return (void *)payload;
}
#endif /* STDK_IOT_CORE_SERIALIZE_CBOR */

STATIC_FUNCTION
iot_error_t _iot_es_mqtt_registration(struct iot_context *ctx, st_mqtt_client mqtt_ctx)
{
	int ret;
	iot_error_t iot_err = IOT_ERROR_NONE;
	st_mqtt_msg msg;
	size_t str_id_len = 40;
	char *dip_id = NULL;
	size_t msglen = 0;

	if (!mqtt_ctx) {
		IOT_ERROR("There is no iot_mqtt_ctx!!");
		return IOT_ERROR_INVALID_ARGS;
	}

	/* Step 2. Publish target's registration info to server */
	ctx->iot_reg_data.updated = false;

	/* dip id is optional value */
	if (ctx->devconf.dip) {
		dip_id = (char *)malloc(str_id_len);
		if (!dip_id) {
			IOT_ERROR("malloc failed for DIP id");
			iot_err = IOT_ERROR_MEM_ALLOC;
			goto failed_regist;
		}
		memset(dip_id, 0, str_id_len);

		iot_err = iot_util_convert_uuid_str(&ctx->devconf.dip->dip_id,
					dip_id, str_id_len);
		if (iot_err != IOT_ERROR_NONE) {
			IOT_ERROR("%s error DIP_id convt (%d)", __func__, iot_err);
			iot_err = IOT_ERROR_BAD_REQ;
			goto failed_regist;
		}
	}

#if defined(STDK_IOT_CORE_SERIALIZE_CBOR)
	msg.payload = _iot_es_mqtt_registration_cbor(ctx, dip_id, &msglen,
					ctx->iot_reg_data.self_reged);
#else
	msg.payload = _iot_es_mqtt_registration_json(ctx, dip_id, &msglen,
					ctx->iot_reg_data.self_reged);
#endif
	if (!msg.payload) {
		IOT_ERROR("Failed to make payload for MQTTpub");
		iot_err = IOT_ERROR_MEM_ALLOC;
	} else {
		IOT_DEBUG("publish resource payload : \n%s", msg.payload);

		msg.qos = st_mqtt_qos1;
		msg.retained = false;
		msg.payloadlen = (int)msglen;
		msg.topic = IOT_PUB_TOPIC_REGISTRATION;

		ret = st_mqtt_publish(mqtt_ctx, &msg);
		if (ret) {
			IOT_ERROR("error MQTTpub(%d)", ret);
			iot_err = IOT_ERROR_BAD_REQ;
		}

#if defined(STDK_IOT_CORE_SERIALIZE_CBOR)
		free(msg.payload);
#else
		JSON_FREE(msg.payload);
#endif
	}

failed_regist:
	if (dip_id)
		free(dip_id);

	return iot_err;
}

void _iot_es_mqtt_disconnect(struct iot_context *ctx, st_mqtt_client target_cli)
{
	int ret;

#if defined(STDK_MQTT_TASK)
	st_mqtt_endtask(target_cli);
#endif

	/* Internal MQTT connection was disconnected,
	 * even if it returns errors
	 */
	ret = st_mqtt_disconnect(target_cli);
	if (ret) {
		IOT_WARN("Disconnect error(%d)", ret);
	}
}

iot_error_t _iot_es_mqtt_connect(struct iot_context *ctx, st_mqtt_client target_cli,
		char *username, char *sign_data)
{
	st_mqtt_connect_data conn_data = st_mqtt_connect_data_initializer;
	st_mqtt_broker_info_t broker_info;
	int ret;
	iot_error_t iot_ret = IOT_ERROR_NONE;
	bool reboot;
	char client_id[IOT_REG_UUID_STR_LEN + 1] = {0, };
	struct iot_cloud_prov_data *cloud_prov;
	char *root_cert = NULL;
	size_t root_cert_len;

	/* Use mac based random client_id for GreatGate */
	iot_ret = iot_get_random_id_str(client_id, sizeof(client_id));
	if (iot_ret != IOT_ERROR_NONE) {
		IOT_ERROR("Cannot get random_id for client_id");
		return iot_ret;
	}

	cloud_prov = &ctx->prov_data.cloud;
	if (!cloud_prov->broker_url) {
		IOT_ERROR("cloud_prov_data url does not exist!");
		iot_ret = IOT_ERROR_INVALID_ARGS;
		goto done_mqtt_connect;
	}

	iot_ret = iot_nv_get_certificate(IOT_SECURITY_CERT_ID_ROOT_CA, &root_cert, &root_cert_len);
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

	ret = st_mqtt_connect(target_cli, &broker_info, &conn_data);
	if (ret) {
		IOT_ERROR("%s error(%d)", __func__, ret);
		switch (ret) {
		case E_ST_MQTT_UNNACCEPTABLE_PROTOCOL:
			/* fall through */
		case E_ST_MQTT_SERVER_UNAVAILABLE:
			/* This case means Server can't start service for MQTT Things
			 * This case is totally server-side issue, so we just report it to Apps
			 */
			ctx->mqtt_connect_critical_reject_count = 0;
			iot_ret = IOT_ERROR_MQTT_SERVER_UNAVAIL;
			break;

		case E_ST_MQTT_CLIENTID_REJECTED:
			/* fall through */
		case E_ST_MQTT_BAD_USERNAME_OR_PASSWORD:
			/* fall through */
		case E_ST_MQTT_NOT_AUTHORIZED:
			/* These cases are related to device's clientID, serialNumber, deviceId & web token
			 * So we try to cleanup all data & reboot
			 */
			if (ctx->mqtt_connect_critical_reject_count++ < IOT_MQTT_CONNECT_CRITICAL_REJECT_MAX) {
				IOT_WARN("MQTT critical reject retry %d", ctx->mqtt_connect_critical_reject_count);
				iot_ret = IOT_ERROR_MQTT_CONNECT_FAIL;
				break;
			}
			IOT_WARN("Rejected by Server!! cleanup all & reboot");

			iot_cleanup(ctx, true);
			iot_ret = IOT_ERROR_MQTT_REJECT_CONNECT;
			break;

		case E_ST_MQTT_PACKET_TIMEOUT:
			ctx->mqtt_connect_critical_reject_count = 0;
			iot_ret = IOT_ERROR_MQTT_CONNECT_TIMEOUT;
			break;

		default:
			/* On the others, we can't narrow down the causes. Some cases are related to
			 * network conditions (outside of the device) or, related to WIFI conditions
			 * (inside of the device). So we try to do re-connecting limitedly
			 */
			ctx->mqtt_connect_critical_reject_count = 0;
			iot_ret = IOT_ERROR_MQTT_CONNECT_FAIL;
			break;
		}
	} else {
		ctx->mqtt_connect_critical_reject_count = 0;
	}

#if defined(STDK_MQTT_TASK)
	if ((ret = st_mqtt_starttask(target_cli)) < 0) {
		IOT_ERROR("Returned code from start tasks is %d", ret);
		st_mqtt_disconnect(target_cli);
		iot_ret = IOT_ERROR_MQTT_CONNECT_FAIL;
		goto done_mqtt_connect;
	} else {
		IOT_INFO("Use MQTTStartTask");
	}
#endif

done_mqtt_connect:
	if (root_cert)
		free((void *)root_cert);

	return iot_ret;
}

iot_error_t iot_es_connect(struct iot_context *ctx, int conn_type)
{
	iot_security_buffer_t token_buf = { 0 };
	iot_wt_params_t wt_params = { 0 };
	st_mqtt_client mqtt_cli = NULL;
	iot_error_t iot_ret;
	iot_os_timer connection_response_timer = NULL;
	int ret;

	if (!ctx) {
		IOT_ERROR("invalid args");
		return IOT_ERROR_INVALID_ARGS;
	}

	if (ctx->rate_limit) {
		if (!(iot_os_timer_isexpired(ctx->rate_limit_timeout))) {
			unsigned int remaining_time = iot_os_timer_left_ms(ctx->rate_limit_timeout);
			IOT_WARN("Server rate limit break times.. please wait %d seconds to connect", remaining_time/1000);
			iot_os_delay(remaining_time);
		}
	}
	ctx->rate_limit = false;

	iot_ret = iot_nv_get_serial_number((char **)&wt_params.sn, &wt_params.sn_len);
	if (iot_ret != IOT_ERROR_NONE) {
		IOT_ERROR("failed to get serial num");
		goto out;
	}

	wt_params.mnid = iot_os_strdup(ctx->devconf.mnid);
	if (!wt_params.mnid) {
		IOT_ERROR("failed to strdup for mnid");
		goto out;
	} else {
		wt_params.mnid_len = strlen(wt_params.mnid);
	}

#if defined(CONIFG_STDK_IOT_CORE_EASYSETUP_SELF_CONTAINED_JWT)
	size_t str_id_len = 40;
	if (ctx->devconf.dip) {
		wt_params.dipid_len = str_id_len;
		wt_params.dipid = (char *)malloc(str_id_len);
		if (!wt_params.dipid) {
			IOT_ERROR("malloc failed for DIP id");
			iot_ret = IOT_ERROR_MEM_ALLOC;
			goto out;
		}
		memset(wt_params.dipid, 0, str_id_len);

		iot_ret = iot_util_convert_uuid_str(&ctx->devconf.dip->dip_id,
					wt_params.dipid, str_id_len);
		if (iot_ret != IOT_ERROR_NONE) {
			IOT_ERROR("%s error DIP_id convt (%d)", __func__, iot_ret);
			iot_ret = IOT_ERROR_BAD_REQ;
			goto out;
		}
		iot_ret = _iot_nv_get_certificate_serial_number(&wt_params.cert_sn);
		if (iot_ret != IOT_ERROR_NONE) {
			IOT_ERROR("%s error get cert serial from nv (%d)", __func__, iot_ret);
			iot_ret = IOT_ERROR_BAD_REQ;
			goto out;
		}
	}
#endif

	iot_ret = iot_wt_create((const iot_wt_params_t *)&wt_params, &token_buf);
	if (iot_ret != IOT_ERROR_NONE) {
		IOT_ERROR("failed to make wt-token");
		goto out;
	}

	iot_ret = iot_os_timer_init(&connection_response_timer);
	if (iot_ret != IOT_ERROR_NONE) {
		IOT_WARN("Response timer init error(%d)", iot_ret);
		iot_ret = IOT_ERROR_BAD_REQ;
		goto out;
	}

	if (conn_type == IOT_CONNECT_TYPE_COMMUNICATION) {
		char* topicfilter[2] = {NULL, };
		int qos[2] = {st_mqtt_qos1, st_mqtt_qos1};
		IOT_INFO("connect_type: log-in");
		/* Using for new MQTT PUB/SUB connection after registration */
		if (!ctx->iot_reg_data.updated) {
			IOT_ERROR("failed to get user id");
			goto out;
		}

		ret = st_mqtt_create(&mqtt_cli, _iot_mqtt_signin_client_callback, ctx);
		if (ret) {
			IOT_ERROR("Cannot create mqtt client");
			goto out;
		}

		ctx->mqtt_connection_try_count++;
		iot_ret = _iot_es_mqtt_connect(ctx, mqtt_cli, (char *)ctx->iot_reg_data.deviceId, (char *)token_buf.p);
		if (iot_ret != IOT_ERROR_NONE) {
			IOT_ERROR("failed to connect");
			goto out;
		} else {
			ctx->mqtt_connection_success_count++;
			IOT_INFO("MQTT connect success sucess/try : %d/%d", ctx->mqtt_connection_success_count, ctx->mqtt_connection_try_count);
		}

		iot_os_timer_count_ms(connection_response_timer, GG_CONNECTION_RESPONSE_TIMEOUT_MS);

		topicfilter[0] = iot_os_malloc(IOT_TOPIC_SIZE);
		if (topicfilter[0] == NULL) {
			IOT_ERROR("failed to malloc topicfilter");
			iot_ret = IOT_ERROR_MEM_ALLOC;
			goto mqtt_communication_connection_out;
		}
		snprintf(topicfilter[0], IOT_TOPIC_SIZE, IOT_SUB_TOPIC_NOTIFICATION, ctx->iot_reg_data.deviceId);
		IOT_DEBUG("noti subscribe topic : %s", topicfilter[0]);

		topicfilter[1] = iot_os_malloc(IOT_TOPIC_SIZE);
		if (topicfilter[1] == NULL) {
			IOT_ERROR("failed to malloc topicfilter");
			iot_ret = IOT_ERROR_MEM_ALLOC;
			goto mqtt_communication_connection_out;
		}
		snprintf(topicfilter[1], IOT_TOPIC_SIZE, IOT_SUB_TOPIC_COMMAND, ctx->iot_reg_data.deviceId);
		IOT_DEBUG("cmd subscribe topic : %s", topicfilter[1]);

		ret = st_mqtt_subscribe(mqtt_cli, 2, topicfilter, qos);
		if (ret) {
			IOT_WARN("subscribe error(%d)", ret);
			iot_ret = IOT_ERROR_BAD_REQ;
			_iot_es_mqtt_disconnect(ctx, mqtt_cli);
			goto mqtt_communication_connection_out;
		}

		ctx->sign_in_connection_request_status = GG_CONNECTION_REQUEST_STATUS_WAITING;
		while(!iot_os_timer_isexpired(connection_response_timer) &&
				st_mqtt_yield(mqtt_cli, 0) >= 0) {
			if (ctx->sign_in_connection_request_status != GG_CONNECTION_REQUEST_STATUS_WAITING)
				break;
		}

		if (ctx->sign_in_connection_request_status
						!= GG_CONNECTION_REQUEST_STATUS_SUCCESS) {
			IOT_WARN("GG connection fail");
			iot_ret = IOT_ERROR_MQTT_CONNECT_FAIL;
			_iot_es_mqtt_disconnect(ctx, mqtt_cli);
			goto mqtt_communication_connection_out;
		}

		ctx->mqtt_event_topic = malloc(IOT_TOPIC_SIZE);
		if (!ctx->mqtt_event_topic) {
			IOT_ERROR("failed to malloc for mqtt_event_topic");
			iot_ret = IOT_ERROR_MEM_ALLOC;
			_iot_es_mqtt_disconnect(ctx, mqtt_cli);
			goto mqtt_communication_connection_out;
		}
		snprintf(ctx->mqtt_event_topic, IOT_TOPIC_SIZE, IOT_PUB_TOPIC_EVENT, ctx->iot_reg_data.deviceId);

		ctx->mqtt_health_topic = malloc(IOT_TOPIC_SIZE);
		if (!ctx->mqtt_health_topic) {
			IOT_ERROR("failed to malloc for mqtt_health_topic");
			iot_ret = IOT_ERROR_MEM_ALLOC;
			_iot_es_mqtt_disconnect(ctx, mqtt_cli);
			goto mqtt_communication_connection_out;
		}
		snprintf(ctx->mqtt_health_topic, IOT_TOPIC_SIZE, IOT_PUB_TOPIC_HEALTH);

		ctx->evt_mqttcli = mqtt_cli;
mqtt_communication_connection_out:
		if (topicfilter[0] != NULL) {
			iot_os_free(topicfilter[0]);
		}

		if (topicfilter[1] != NULL) {
			iot_os_free(topicfilter[1]);
		}
	} else {
		char *serial_number = (wt_params.cert_sn ? wt_params.cert_sn : wt_params.sn);
		char *topicfilter = NULL;
		int qos = st_mqtt_qos1;
		IOT_INFO("connect_type: registration");

		ret = st_mqtt_create(&mqtt_cli, _iot_mqtt_registration_client_callback, ctx);
		if (ret) {
			IOT_ERROR("Cannot create mqtt client");
			goto out;
		}

		iot_ret = _iot_es_mqtt_connect(ctx, mqtt_cli, serial_number, (char *)token_buf.p);
		if (iot_ret != IOT_ERROR_NONE) {
			IOT_ERROR("failed to connect");
			goto out;
		} else {
			IOT_INFO("MQTT connect success");
		}

		iot_os_timer_count_ms(connection_response_timer, GG_CONNECTION_RESPONSE_TIMEOUT_MS);

		/* register notification subscribe for registration */
		topicfilter = iot_os_malloc(IOT_TOPIC_SIZE);
		if (topicfilter == NULL) {
			IOT_ERROR("failed to malloc topicfilter");
			iot_ret = IOT_ERROR_MEM_ALLOC;
			goto mqtt_communication_connection_out;
		}
		snprintf(topicfilter, IOT_TOPIC_SIZE, IOT_SUB_TOPIC_REGISTRATION, serial_number);
		IOT_DEBUG("noti subscribe topic : %s", topicfilter);
		ret = st_mqtt_subscribe(mqtt_cli, 1, &topicfilter, &qos);
		if (ret) {
			IOT_ERROR("%s error MQTTsub(%d)", __func__, ret);
			iot_ret = IOT_ERROR_BAD_REQ;
			_iot_es_mqtt_disconnect(ctx, mqtt_cli);
			goto mqtt_registration_connection_out;
		}

		ctx->sign_up_connection_request_status = GG_CONNECTION_REQUEST_STATUS_WAITING;
		while(!iot_os_timer_isexpired(connection_response_timer) &&
				st_mqtt_yield(mqtt_cli, 0) >= 0) {
			if (ctx->sign_up_connection_request_status != GG_CONNECTION_REQUEST_STATUS_WAITING)
				break;
		}

		if (ctx->sign_up_connection_request_status
						!= GG_CONNECTION_REQUEST_STATUS_SUCCESS) {
			IOT_WARN("GG connection fail");
			iot_ret = IOT_ERROR_MQTT_CONNECT_FAIL;
			_iot_es_mqtt_disconnect(ctx, mqtt_cli);
			goto mqtt_registration_connection_out;
		}

		iot_ret = _iot_es_mqtt_registration(ctx, mqtt_cli);
		if (iot_ret != IOT_ERROR_NONE) {
			IOT_ERROR("failed to register");
			_iot_es_mqtt_disconnect(ctx, mqtt_cli);
			goto mqtt_registration_connection_out;
		}

		ctx->reg_mqttcli = mqtt_cli;
mqtt_registration_connection_out:
		if (topicfilter != NULL) {
			iot_os_free(topicfilter);
		}
	}

out:
	if (connection_response_timer)
		iot_os_timer_destroy(&connection_response_timer);

	if (wt_params.sn)
		iot_os_free((void *)wt_params.sn);

	if (wt_params.mnid)
		iot_os_free((void *)wt_params.mnid);

    if (wt_params.dipid)
		iot_os_free((void *)wt_params.dipid);

	if (token_buf.p)
		free(token_buf.p);

	if (iot_ret)
		st_mqtt_destroy(mqtt_cli);

	return iot_ret;
}

iot_error_t iot_es_disconnect(struct iot_context *ctx, int conn_type)
{
	st_mqtt_client target_cli = NULL;

	if (!ctx) {
		IOT_ERROR("There is no ctx!!");
		return IOT_ERROR_INVALID_ARGS;
	}

	if (conn_type == IOT_CONNECT_TYPE_COMMUNICATION) {
		target_cli = ctx->evt_mqttcli;
		if (ctx->mqtt_event_topic)
			free(ctx->mqtt_event_topic);
		ctx->mqtt_event_topic = NULL;
		if (ctx->mqtt_health_topic)
			free(ctx->mqtt_health_topic);
		ctx->mqtt_health_topic = NULL;
		ctx->evt_mqttcli = NULL;
	} else {
		target_cli = ctx->reg_mqttcli;
		ctx->reg_mqttcli = NULL;
	}

	if (!target_cli) {
		IOT_ERROR("There is no mqtt_ctx!!");
		return IOT_ERROR_INVALID_ARGS;
	}

	IOT_DEBUG("disconnect type %s",
		(conn_type == IOT_CONNECT_TYPE_REGISTRATION) ?
			"registration" : "communication");

	_iot_es_mqtt_disconnect(ctx, target_cli);

	st_mqtt_destroy(target_cli);

	return IOT_ERROR_NONE;
}
