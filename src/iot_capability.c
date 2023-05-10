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

#include <stdlib.h>
#include <string.h>
#if defined(STDK_IOT_CORE_SERIALIZE_CBOR)
#include <cbor.h>
#endif

#include "iot_internal.h"
#include "iot_util.h"
#include "iot_debug.h"
#include "iot_capability.h"
#include "iot_os_util.h"
#include "iot_bsp_system.h"
#include "JSON.h"
#include "st_caps.h"

#define MAX_SQNUM 0x7FFFFFFF

STATIC_FUNCTION
iot_error_t _iot_parse_noti_data(void *data, iot_noti_data_t *noti_data);

static iot_error_t _iot_parse_cmd_data(JSON_H* cmditem, char** component,
			char** capability, char** command, iot_cap_cmd_data_t* cmd_data);
static JSON_H *_iot_make_evt_data(const char* component, const char* capability, iot_cap_evt_data_t* evt_data, int seq_num);
static void _iot_free_val(iot_cap_val_t* val);
static void _iot_free_unit(iot_cap_unit_t* unit);
static void _iot_free_cmd_data(iot_cap_cmd_data_t* cmd_data);
static void _iot_free_evt_data(iot_cap_evt_data_t* evt_data);
static IOT_EVENT* _iot_cap_create_attr(const char *attribute,
			iot_cap_val_t *value, const char *unit, const char *data);

/**************************************************************
*                       Synchronous Call                      *
**************************************************************/
/* External API */
DEPRECATED IOT_EVENT* st_cap_attr_create_int(const char *attribute, int integer, const char *unit)
{
	iot_cap_val_t value;
	value.type = IOT_CAP_VAL_TYPE_INTEGER;
	value.integer = integer;

	return _iot_cap_create_attr(attribute, &value, unit, NULL);
}

DEPRECATED IOT_EVENT* st_cap_attr_create_number(const char *attribute, double number, const char *unit)
{
	iot_cap_val_t value;
	value.type = IOT_CAP_VAL_TYPE_NUMBER;
	value.number = number;

	return _iot_cap_create_attr(attribute, &value, unit, NULL);
}

DEPRECATED IOT_EVENT* st_cap_attr_create_string(const char *attribute, char *string, const char *unit)
{
	iot_cap_val_t value;
	value.type = IOT_CAP_VAL_TYPE_STRING;
	value.string = string;

	return _iot_cap_create_attr(attribute, &value, unit, NULL);
}

DEPRECATED IOT_EVENT* st_cap_attr_create_string_array(const char *attribute,
			uint8_t str_num, char *string_array[], const char *unit)
{
	iot_cap_val_t value;
	value.type = IOT_CAP_VAL_TYPE_STR_ARRAY;
	value.str_num = str_num;
	value.strings = string_array;

	return _iot_cap_create_attr(attribute, &value, unit, NULL);
}

DEPRECATED IOT_EVENT* st_cap_attr_create(const char *attribute,
			iot_cap_val_t *value, const char *unit, const char *data)
{
	return _iot_cap_create_attr(attribute, value, unit, data);
}

IOT_EVENT* st_cap_create_attr_with_id(IOT_CAP_HANDLE *cap_handle, const char *attribute,
			iot_cap_val_t *value, const char *unit, const char *data, char *command_id)
{
	iot_cap_evt_data_t* evt_data;

	evt_data = (iot_cap_evt_data_t *)st_cap_create_attr(cap_handle, attribute, value, unit, data);

	if (evt_data != NULL && command_id != NULL) {
		evt_data->options.command_id = iot_os_strdup(command_id);
	}

	return (IOT_EVENT*)evt_data;
}

static IOT_EVENT* _iot_cap_create_attr(const char *attribute,
			iot_cap_val_t *value, const char *unit, const char *data)
{
	int i;
	iot_cap_evt_data_t* evt_data;

	if (!attribute) {
		IOT_ERROR("attribute is NULL");
		return NULL;
	}

	if (!value) {
		IOT_ERROR("value is NULL");
		return NULL;
	}

	evt_data = iot_os_malloc(sizeof(iot_cap_evt_data_t));
	if (!evt_data) {
		IOT_ERROR("failed to malloc for evt_data");
		return NULL;
	}
	memset(evt_data, 0, sizeof(iot_cap_evt_data_t));


	evt_data->evt_type = iot_os_strdup(attribute);
	switch (value->type) {
	case IOT_CAP_VAL_TYPE_BOOLEAN:
		evt_data->evt_value.type = IOT_CAP_VAL_TYPE_BOOLEAN;
		evt_data->evt_value.boolean = value->boolean;
		break;
	case IOT_CAP_VAL_TYPE_INTEGER:
		evt_data->evt_value.type = IOT_CAP_VAL_TYPE_INTEGER;
		evt_data->evt_value.integer = value->integer;
		break;
	case IOT_CAP_VAL_TYPE_NUMBER:
		evt_data->evt_value.type = IOT_CAP_VAL_TYPE_NUMBER;
		evt_data->evt_value.number = value->number;
		break;
	case IOT_CAP_VAL_TYPE_STRING:
		evt_data->evt_value.type = IOT_CAP_VAL_TYPE_STRING;
		if (value->string) {
			evt_data->evt_value.string = iot_os_strdup(value->string);
		} else {
			IOT_ERROR("There is no string value");
			_iot_free_evt_data(evt_data);
			iot_os_free(evt_data);
			return NULL;
		}
		break;
	case IOT_CAP_VAL_TYPE_STR_ARRAY:
		evt_data->evt_value.type = IOT_CAP_VAL_TYPE_STR_ARRAY;
		evt_data->evt_value.str_num = value->str_num;
		evt_data->evt_value.strings = iot_os_malloc(value->str_num * sizeof(char*));
		if (value->str_num != 0 && !evt_data->evt_value.strings) {
			IOT_ERROR("failed to malloc for string array");
			_iot_free_evt_data(evt_data);
			iot_os_free(evt_data);
			return NULL;
		} else if (evt_data->evt_value.strings) {
			memset(evt_data->evt_value.strings, 0, value->str_num * sizeof(char*));
		}
		for (i = 0; i < value->str_num; i++) {
			if (value->strings[i]) {
				evt_data->evt_value.strings[i] = iot_os_strdup(value->strings[i]);
			} else {
				IOT_ERROR("found no string value in array");
				_iot_free_evt_data(evt_data);
				iot_os_free(evt_data);
				return NULL;
			}
		}
		break;
	case IOT_CAP_VAL_TYPE_JSON_OBJECT:
		evt_data->evt_value.type = IOT_CAP_VAL_TYPE_JSON_OBJECT;
		evt_data->evt_value.json_object = iot_os_strdup(value->json_object);
		break;
	default:
		IOT_ERROR("unknown attribute data type");
		_iot_free_evt_data(evt_data);
		iot_os_free(evt_data);
		return NULL;
	}

	if (unit != NULL) {
		evt_data->evt_unit.type = IOT_CAP_UNIT_TYPE_STRING;
		evt_data->evt_unit.string = iot_os_strdup(unit);
	} else {
		evt_data->evt_unit.type = IOT_CAP_UNIT_TYPE_UNUSED;
	}

	if (data != NULL) {
		evt_data->evt_value_data = iot_os_strdup(data);
	}

	return (IOT_EVENT*)evt_data;
}

IOT_EVENT* st_cap_create_attr(IOT_CAP_HANDLE *cap_handle, const char *attribute,
			iot_cap_val_t *value, const char *unit, const char *data)
{
	return st_cap_create_attr_with_option(cap_handle, attribute, value, unit, data, NULL);
}

IOT_EVENT* st_cap_create_attr_with_option(IOT_CAP_HANDLE *cap_handle, const char *attribute,
			iot_cap_val_t *value, const char *unit, const char *data, iot_cap_attr_option_t *options)
{
	iot_cap_evt_data_t* evt_data = NULL;

	if (cap_handle == NULL) {
		IOT_ERROR("There is no cap handle");
		return NULL;
	}

	evt_data = (iot_cap_evt_data_t *)_iot_cap_create_attr(attribute, value, unit, data);
	if (evt_data == NULL)
		return NULL;

	evt_data->ref_cap = (struct iot_cap_handle *)cap_handle;

	if (options != NULL)
	{
		evt_data->options.state_change = options->state_change;
		if (options->command_id)
		{
			evt_data->options.command_id = iot_os_strdup(options->command_id);
			if (evt_data->options.command_id == NULL)
			{
				goto failed_creat_attr_option;
			}
		}

		if (options->displayed != NULL)
		{
			evt_data->options.displayed = (bool *)iot_os_malloc(sizeof(bool));
			if (evt_data->options.displayed != NULL)
			{
				*(evt_data->options.displayed) = *(options->displayed);
			}
			else
			{
				goto failed_creat_attr_option;
			}
		}
	}

	return (IOT_EVENT*)evt_data;

failed_creat_attr_option:

	if (evt_data->options.displayed != NULL)
	{
		iot_os_free(evt_data->options.displayed);
		evt_data->options.displayed = NULL;
	}

	if (evt_data->options.command_id != NULL)
	{
		iot_os_free(evt_data->options.command_id);
		evt_data->options.command_id = NULL;
	}

	if (evt_data != NULL)
	{
		_iot_free_evt_data(evt_data);
		iot_os_free(evt_data);
	}

	return NULL;
}

DEPRECATED void st_cap_attr_free(IOT_EVENT* event)
{
	iot_cap_evt_data_t* evt_data = (iot_cap_evt_data_t*) event;

	if (evt_data) {
		_iot_free_evt_data(evt_data);
		iot_os_free(evt_data);
	}
}

void st_cap_free_attr(IOT_EVENT* event)
{
	iot_cap_evt_data_t* evt_data = (iot_cap_evt_data_t*) event;

	if (evt_data) {
		_iot_free_evt_data(evt_data);
		iot_os_free(evt_data);
	}
}

IOT_CAP_HANDLE *st_cap_handle_init(IOT_CTX *iot_ctx, const char *component,
			const char *capability, st_cap_init_cb init_cb, void *init_usr_data)
{
	struct iot_cap_handle *handle = NULL;
	struct iot_cap_handle_list *cur_list;
	struct iot_cap_handle_list *new_list;
	struct iot_context *ctx = (struct iot_context*)iot_ctx;

	if (!ctx || !capability) {
	    return NULL;
	}

	handle = iot_os_malloc(sizeof(struct iot_cap_handle));
	if (!handle) {
		IOT_ERROR("failed to malloc for iot_cap_handle");
		return NULL;
	}

	memset(handle, 0, sizeof(struct iot_cap_handle));

	if (component) {
		handle->component = iot_os_strdup(component);
	} else {
		handle->component = iot_os_strdup("main");
	}
	if (!handle->component) {
		IOT_ERROR("failed to malloc for component");
		iot_os_free(handle);
		return NULL;
	}

	handle->capability = iot_os_strdup(capability);
	if (!handle->capability) {
		IOT_ERROR("failed to malloc for capability");
		iot_os_free((void *)handle->component);
		iot_os_free(handle);
		return NULL;
	}

	handle->cmd_list = NULL;

	new_list = (iot_cap_handle_list_t *)iot_os_malloc(sizeof(iot_cap_handle_list_t));
	if (!new_list) {
		IOT_ERROR("failed to malloc for handle list");
		iot_os_free((void *)handle->component);
		iot_os_free((void *)handle->capability);
		iot_os_free(handle);
		return NULL;
	}

	if (ctx->cap_handle_list == NULL) {
		ctx->cap_handle_list = new_list;
		cur_list = ctx->cap_handle_list;
	} else {
		cur_list = ctx->cap_handle_list;
		while (cur_list->next != NULL)
			cur_list = cur_list->next;
		cur_list->next = new_list;
		cur_list = cur_list->next;
	}
	cur_list->next = NULL;
	cur_list->handle = handle;

	if (init_cb)
		handle->init_cb = init_cb;

	if (init_usr_data)
		handle->init_usr_data = init_usr_data;

	handle->ctx = ctx;
	return (IOT_CAP_HANDLE*)handle;
}

int st_conn_set_noti_cb(IOT_CTX *iot_ctx,
		st_cap_noti_cb noti_cb, void *noti_usr_data)
{
	struct iot_context *ctx = (struct iot_context*)iot_ctx;

	if (!ctx || !noti_cb) {
		IOT_ERROR("There is no ctx or cb !!!");
		return IOT_ERROR_INVALID_ARGS;
	}

	ctx->noti_cb = noti_cb;

	if (noti_usr_data)
		ctx->noti_usr_data = noti_usr_data;

	return IOT_ERROR_NONE;
}

int st_cap_cmd_set_cb(IOT_CAP_HANDLE *cap_handle, const char *cmd_type,
		st_cap_cmd_cb cmd_cb, void *usr_data)
{
	struct iot_cap_handle *handle = (struct iot_cap_handle*)cap_handle;
	struct iot_cap_cmd_set *command;
	struct iot_cap_cmd_set_list *cur_list;
	struct iot_cap_cmd_set_list *new_list;
	const char *needle_str, *cmd_str;
	size_t str_len;

	if (!handle || !cmd_type || !cmd_cb) {
		IOT_ERROR("There is no handle or cb data");
		return IOT_ERROR_INVALID_ARGS;
	}

	needle_str = cmd_type;
	str_len = strlen(needle_str);

	cur_list = handle->cmd_list;
	while (cur_list) {
		cmd_str = cur_list->command->cmd_type;
		if (cmd_str && !strncmp(cmd_str, needle_str, str_len)) {
			IOT_ERROR("There is already same handle for : %s",
						needle_str);
			return IOT_ERROR_INVALID_ARGS;
		}
		cur_list = cur_list->next;
	}

	command = (iot_cap_cmd_set_t *)iot_os_malloc(sizeof(iot_cap_cmd_set_t));
	if (!command) {
		IOT_ERROR("failed to malloc for cmd set");
		return IOT_ERROR_MEM_ALLOC;
	}
	command->cmd_type = iot_os_strdup(needle_str);
	command->cmd_cb = cmd_cb;
	command->usr_data = usr_data;

	new_list = (iot_cap_cmd_set_list_t *)iot_os_malloc(sizeof(iot_cap_cmd_set_list_t));
	if (!new_list) {
		IOT_ERROR("failed to malloc for cmd set list");
		iot_os_free(command->cmd_type);
		iot_os_free(command);
		return IOT_ERROR_MEM_ALLOC;
	}
	new_list->command = command;
	new_list->next = handle->cmd_list;
	handle->cmd_list = new_list;

	return IOT_ERROR_NONE;
}

DEPRECATED int st_cap_attr_send(IOT_CAP_HANDLE *cap_handle,
		uint8_t evt_num, IOT_EVENT *event[])
{
	iot_cap_evt_data_t** evt_data = (iot_cap_evt_data_t**)event;
	int ret;
	struct iot_context *ctx;
	st_mqtt_msg msg = {0};
	struct iot_cap_handle *handle = (struct iot_cap_handle*)cap_handle;
	int i;
	JSON_H *evt_root = NULL;
	JSON_H *evt_arr = NULL;
	JSON_H *evt_item = NULL;

	if (!handle || !handle->component || !handle->capability || !handle->ctx || !evt_data || !evt_num) {
		IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_CAPABILITY_SEND_EVENT_NO_DATA_ERROR, 0, 0);
		IOT_ERROR("There is no handle or evt_data");
		return IOT_ERROR_INVALID_ARGS;
	}

	ctx = handle->ctx;
	if (ctx->curr_state != IOT_STATE_CLOUD_CONNECTED || ctx->evt_mqttcli == NULL) {
		IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_CAPABILITY_SEND_EVENT_NO_CONNECT_ERROR, ctx->curr_state, 0);
		IOT_ERROR("Target has not connected to server yet!!");
		return IOT_ERROR_BAD_REQ;
	}

	if (ctx->rate_limit) {
		if ((iot_os_timer_isexpired(ctx->rate_limit_timeout))) {
			ctx->rate_limit = false;
		} else {
			IOT_WARN("Exceed rate limit. Can't send attributes for a while");
			return IOT_ERROR_BAD_REQ;
		}
	}

	if (ctx->event_sequence_num == MAX_SQNUM) {
		ctx->event_sequence_num = 0;
	}
	ctx->event_sequence_num = (ctx->event_sequence_num + 1) & MAX_SQNUM;

	evt_root = JSON_CREATE_OBJECT();
	evt_arr = JSON_CREATE_ARRAY();

	JSON_ADD_ITEM_TO_OBJECT(evt_root, "deviceEvents", evt_arr);

	/* Make event data format & enqueue data */
	for (i = 0; i < evt_num; i++) {
		evt_item = _iot_make_evt_data(handle->component, handle->capability, evt_data[i], ctx->event_sequence_num);
		if (evt_item == NULL) {
			IOT_ERROR("Cannot make evt_data!!");
			JSON_DELETE(evt_root);
			return IOT_ERROR_BAD_REQ;
		}
		JSON_ADD_ITEM_TO_ARRAY(evt_arr, evt_item);
	}

#if defined(STDK_IOT_CORE_SERIALIZE_CBOR)
	iot_serialize_json2cbor(evt_root, (uint8_t **)&msg.payload, (size_t *)&msg.payloadlen);
#else
	msg.payload = JSON_PRINT(evt_root);
	if (msg.payload != NULL) {
		msg.payloadlen = strlen(msg.payload);
	}
#endif
	JSON_DELETE(evt_root);
	if (msg.payload == NULL) {
		IOT_ERROR("Fail to transfer to payload");
		return IOT_ERROR_BAD_REQ;
	}
	msg.qos = st_mqtt_qos1;
	msg.retained = false;
	msg.topic = ctx->mqtt_event_topic;

	IOT_INFO("publish event, topic : %s, payload :\n%s",
		ctx->mqtt_event_topic, (char *)msg.payload);

	ret = st_mqtt_publish_async(ctx->evt_mqttcli, &msg);
	if (ret) {
		IOT_WARN("MQTT pub error(%d)", ret);
		free(msg.payload);
		return IOT_ERROR_MQTT_PUBLISH_FAIL;
	}

#if !defined(STDK_MQTT_TASK)
	iot_os_eventgroup_set_bits(ctx->iot_events, IOT_EVENT_BIT_CAPABILITY);
#endif
	IOT_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_CAPABILITY_SEND_EVENT_SUCCESS, evt_num, 0);

	free(msg.payload);
	return ctx->event_sequence_num;
}

int st_cap_send_attr(IOT_EVENT *event[], uint8_t evt_num)
{
	iot_cap_evt_data_t** evt_data = (iot_cap_evt_data_t**)event;
	int ret;
	struct iot_context *ctx = NULL;
	st_mqtt_msg msg = {0};
	int i;
	JSON_H *evt_root = NULL;
	JSON_H *evt_arr = NULL;
	JSON_H *evt_item = NULL;

	if (!evt_data || !evt_num || !evt_data[0] || !evt_data[0]->ref_cap || !evt_data[0]->ref_cap->ctx) {
		IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_CAPABILITY_SEND_EVENT_NO_DATA_ERROR, 0, 0);
		IOT_ERROR("There is no ctx or evt_data");
		return IOT_ERROR_INVALID_ARGS;
	}
	ctx = evt_data[0]->ref_cap->ctx;

	if (ctx->curr_state != IOT_STATE_CLOUD_CONNECTED || ctx->evt_mqttcli == NULL) {
		IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_CAPABILITY_SEND_EVENT_NO_CONNECT_ERROR, ctx->curr_state, 0);
		IOT_ERROR("Target has not connected to server yet!!");
		return IOT_ERROR_BAD_REQ;
	}

	if (ctx->rate_limit) {
		if ((iot_os_timer_isexpired(ctx->rate_limit_timeout))) {
			ctx->rate_limit = false;
		} else {
			IOT_WARN("Exceed rate limit. Can't send attributes for a while");
			return IOT_ERROR_BAD_REQ;
		}
	}

	if (ctx->event_sequence_num == MAX_SQNUM) {
		ctx->event_sequence_num = 0;
	}
	ctx->event_sequence_num = (ctx->event_sequence_num + 1) & MAX_SQNUM;

	evt_root = JSON_CREATE_OBJECT();
	evt_arr = JSON_CREATE_ARRAY();

	JSON_ADD_ITEM_TO_OBJECT(evt_root, "deviceEvents", evt_arr);

	/* Make event data format & enqueue data */
	for (i = 0; i < evt_num; i++) {
		if (!evt_data[i] || !(evt_data[i]->ref_cap) || ctx != evt_data[i]->ref_cap->ctx) {
			IOT_ERROR("There si no capability reference in event data or ctx not matched");
			JSON_DELETE(evt_root);
			return IOT_ERROR_BAD_REQ;
		}
		evt_item = _iot_make_evt_data(evt_data[i]->ref_cap->component, evt_data[i]->ref_cap->capability,
				evt_data[i], ctx->event_sequence_num);
		if (evt_item == NULL) {
			IOT_ERROR("Cannot make evt_data!!");
			JSON_DELETE(evt_root);
			return IOT_ERROR_BAD_REQ;
		}
		JSON_ADD_ITEM_TO_ARRAY(evt_arr, evt_item);
	}

#if defined(STDK_IOT_CORE_SERIALIZE_CBOR)
	iot_serialize_json2cbor(evt_root, (uint8_t **)&msg.payload, (size_t *)&msg.payloadlen);
#else
	msg.payload = JSON_PRINT(evt_root);
	if (msg.payload != NULL) {
		msg.payloadlen = strlen(msg.payload);
	}
#endif
	JSON_DELETE(evt_root);
	if (msg.payload == NULL) {
		IOT_ERROR("Fail to transfer to payload");
		return IOT_ERROR_BAD_REQ;
	}
	msg.qos = st_mqtt_qos1;
	msg.retained = false;
	msg.topic = ctx->mqtt_event_topic;

	IOT_INFO("publish event, topic : %s, payload :\n%s",
		ctx->mqtt_event_topic, (char *)msg.payload);

	ret = st_mqtt_publish_async(ctx->evt_mqttcli, &msg);
	if (ret) {
		IOT_WARN("MQTT pub error(%d)", ret);
		free(msg.payload);
		return IOT_ERROR_MQTT_PUBLISH_FAIL;
	}

#if !defined(STDK_MQTT_TASK)
	iot_os_eventgroup_set_bits(ctx->iot_events, IOT_EVENT_BIT_CAPABILITY);
#endif
	IOT_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_CAPABILITY_SEND_EVENT_SUCCESS, evt_num, 0);

	free(msg.payload);
	return ctx->event_sequence_num;
}

STATIC_FUNCTION
iot_error_t _iot_parse_noti_data(void *data, iot_noti_data_t *noti_data)
{
	iot_error_t err = IOT_ERROR_NONE;
	JSON_H *json = NULL;
	JSON_H *noti_type = NULL;
	JSON_H *item = NULL;
	char *noti_type_string = NULL;
	char *payload = NULL;
	char time_str[11] = {0,};

	json = JSON_PARSE(data);
	if (json == NULL) {
		IOT_ERROR("Cannot parse by json");
		return IOT_ERROR_BAD_REQ;
	}

	payload = JSON_PRINT(json);
	IOT_INFO("payload : %s", payload);
	free(payload);

	noti_type = JSON_GET_OBJECT_ITEM(json, "event");
	if (noti_type == NULL) {
		IOT_ERROR("there is no event in raw_msgn");
		err = IOT_ERROR_BAD_REQ;
		goto out_noti_parse;
	}

	noti_type_string = JSON_GET_STRING_VALUE(noti_type);
	if (noti_type_string == NULL) {
		IOT_ERROR("there is no event type string");
		goto out_noti_parse;
	}
	if (!strncmp(noti_type_string, SERVER_NOTI_TYPE_DEVICE_DELETED, strlen(SERVER_NOTI_TYPE_DEVICE_DELETED))) {
		IOT_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_CAPABILITY_DEVICE_DELETED_RECEIVED, 0, 0);

		noti_data->type = _IOT_NOTI_TYPE_DEV_DELETED;
	} else if (!strncmp(noti_type_string, SERVER_NOTI_TYPE_EXPIRED_JWT, strlen(SERVER_NOTI_TYPE_EXPIRED_JWT))) {
		noti_data->type = _IOT_NOTI_TYPE_JWT_EXPIRED;

		item = JSON_GET_OBJECT_ITEM(json, "currentTime");
		if (item == NULL) {
			IOT_ERROR("there is no currentTime in raw_msgn");
			err = IOT_ERROR_BAD_REQ;
			goto out_noti_parse;
		}

		snprintf(time_str, sizeof(time_str), "%d", item->valueint);
		IOT_INFO("Set SNTP with current time %s", time_str);
		iot_bsp_system_set_time_in_sec(time_str);
		IOT_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_CAPABILITY_EXPIRED_JWT_RECEIVED, item->valueint, 0);
	} else if (!strncmp(noti_type_string, SERVER_NOTI_TYPE_RATE_LIMIT_REACHED, strlen(SERVER_NOTI_TYPE_RATE_LIMIT_REACHED))) {
		noti_data->type = _IOT_NOTI_TYPE_RATE_LIMIT;

		item = JSON_GET_OBJECT_ITEM(json, "count");
		if (item == NULL) {
			IOT_ERROR("there is no count in raw_msgn");
			err = IOT_ERROR_BAD_REQ;
			goto out_noti_parse;
		}
		noti_data->raw.rate_limit.count = item->valueint;

		item = JSON_GET_OBJECT_ITEM(json, "threshold");
		if (item == NULL) {
			IOT_ERROR("there is no threshold in raw_msgn");
			err = IOT_ERROR_BAD_REQ;
			goto out_noti_parse;
		}
		noti_data->raw.rate_limit.threshold = item->valueint;

		item = JSON_GET_OBJECT_ITEM(json, "remainingTime");
		if (item == NULL) {
			IOT_ERROR("there is no remainingTime in raw_msgn");
			err = IOT_ERROR_BAD_REQ;
			goto out_noti_parse;
		}
		noti_data->raw.rate_limit.remainingTime = item->valueint;

		item = JSON_GET_OBJECT_ITEM(json, "sequenceNumber");
		if (item == NULL) {
			IOT_ERROR("there is no sequenceNumber in raw_msgn");
			err = IOT_ERROR_BAD_REQ;
			goto out_noti_parse;
		}
		noti_data->raw.rate_limit.sequenceNumber = item->valueint;
		IOT_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_CAPABILITY_RATE_LIMIT_RECEIVED, noti_data->raw.rate_limit.sequenceNumber, 0);
	} else if (!strncmp(noti_type_string, SERVER_NOTI_TYPE_QUOTA_REACHED, strlen(SERVER_NOTI_TYPE_QUOTA_REACHED))) {
		noti_data->type = _IOT_NOTI_TYPE_QUOTA_REACHED;

		item = JSON_GET_OBJECT_ITEM(json, "used");
		if (item == NULL) {
			IOT_ERROR("there is no used in raw_msgn");
			err = IOT_ERROR_BAD_REQ;
			goto out_noti_parse;
		}
		noti_data->raw.quota.used = item->valueint;

		item = JSON_GET_OBJECT_ITEM(json, "limit");
		if (item == NULL) {
			IOT_ERROR("there is no limit in raw_msgn");
			err = IOT_ERROR_BAD_REQ;
			goto out_noti_parse;
		}
		noti_data->raw.quota.limit = item->valueint;
		IOT_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_CAPABILITY_QUOTA_LIMIT_RECEIVED, noti_data->raw.quota.used, noti_data->raw.quota.limit);
	} else if (!strncmp(noti_type_string, SERVER_NOTI_TYPE_PREFERENCE_UPDATED, strlen(SERVER_NOTI_TYPE_PREFERENCE_UPDATED))) {
		noti_data->type = _IOT_NOTI_TYPE_PREFERENCE_UPDATED;

		item = JSON_GET_OBJECT_ITEM(json, "values");
		if (item == NULL) {
			IOT_ERROR("there is value in updated preference");
			err = IOT_ERROR_BAD_REQ;
			goto out_noti_parse;
		} else {
			size_t item_size = JSON_GET_ARRAY_SIZE(item);

			if (item_size == 0) {
				IOT_INFO("No references");
				err = IOT_ERROR_BAD_REQ;
				goto out_noti_parse;
			}
			noti_data->raw.preferences.preferences_num = item_size;
			noti_data->raw.preferences.preferences_data = iot_os_malloc(
					sizeof(iot_preference_data) * item_size);
			if (!noti_data->raw.preferences.preferences_data) {
				IOT_ERROR("Failed to alloc preferences data");
				err = IOT_ERROR_BAD_REQ;
				goto out_noti_parse;
			}
			memset(noti_data->raw.preferences.preferences_data, 0, sizeof(iot_preference_data) * item_size);

			for (int i = 0; i < item_size; i++) {
				JSON_H *sub_item = JSON_GET_ARRAY_ITEM(item, i);
				JSON_H *preference_type = JSON_GET_OBJECT_ITEM(sub_item, "preferenceType");
				JSON_H *preference_value = JSON_GET_OBJECT_ITEM(sub_item, "value");

				noti_data->raw.preferences.preferences_data[i].preference_name =
					iot_os_strdup(JSON_GET_OBJECT_ITEM_STRING(sub_item));

				if (preference_value == NULL) {
					noti_data->raw.preferences.preferences_data[i].preference_data.type =
						IOT_CAP_VAL_TYPE_NULL;
				} else if (!strncmp(JSON_GET_STRING_VALUE(preference_type), "string", 6)) {
					noti_data->raw.preferences.preferences_data[i].preference_data.type =
						IOT_CAP_VAL_TYPE_STRING;
					noti_data->raw.preferences.preferences_data[i].preference_data.string =
						iot_os_strdup(JSON_GET_STRING_VALUE(preference_value));
				} else if (!strncmp(JSON_GET_STRING_VALUE(preference_type), "number", 6)) {
					noti_data->raw.preferences.preferences_data[i].preference_data.type =
						IOT_CAP_VAL_TYPE_NUMBER;
					noti_data->raw.preferences.preferences_data[i].preference_data.number =
						JSON_GET_NUMBER_VALUE(preference_value);
				} else if (!strncmp(JSON_GET_STRING_VALUE(preference_type), "boolean", 7)) {
					noti_data->raw.preferences.preferences_data[i].preference_data.type =
						IOT_CAP_VAL_TYPE_BOOLEAN;
					noti_data->raw.preferences.preferences_data[i].preference_data.boolean =
						JSON_IS_TRUE(preference_value);
				} else if (!strncmp(JSON_GET_STRING_VALUE(preference_type), "integer", 7)) {
					noti_data->raw.preferences.preferences_data[i].preference_data.type =
						IOT_CAP_VAL_TYPE_INTEGER;
					noti_data->raw.preferences.preferences_data[i].preference_data.integer =
						preference_value->valueint;
				} else {
					noti_data->raw.preferences.preferences_data[i].preference_data.type =
						IOT_CAP_VAL_TYPE_UNKNOWN;
				}
			}
		}
	} else {
		IOT_WARN("There is no noti_type matched");
		err = IOT_ERROR_BAD_REQ;
	}

out_noti_parse:

	if (json)
		JSON_DELETE(json);

	return err;
}


void iot_noti_sub_cb(struct iot_context *ctx, char *payload)
{
	iot_error_t err;
	iot_noti_data_t noti_data;

	if (!ctx || !payload) {
		IOT_ERROR("There is no ctx or payload");
		return;
	}

	memset(&noti_data, 0, sizeof(iot_noti_data_t));

	IOT_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_CAPABILITY_NOTI_RECEIVED, 0, 0);
	err = _iot_parse_noti_data((void *)payload, &noti_data);
	if (err != IOT_ERROR_NONE) {
		IOT_INFO("Ignore notification");
		return;
	}
	if (noti_data.type == IOT_NOTI_TYPE_RATE_LIMIT) {
		ctx->rate_limit = true;
		iot_os_timer_count_ms(ctx->rate_limit_timeout, IOT_RATE_LIMIT_BREAK_TIME);
	}

	iot_command_send(ctx, IOT_COMMAND_NOTIFICATION_RECEIVED,
		&noti_data, sizeof(noti_data));
}

static iot_error_t _iot_process_cmd(iot_cap_handle_list_t *cap_handle_list, char *component_name,
			char *capability_name, char *command_name, iot_cap_cmd_data_t *cmd_data)
{
	struct iot_cap_handle_list *handle_list = NULL;
	struct iot_cap_handle *handle = NULL;
	struct iot_cap_cmd_set_list *command_list = NULL;
	struct iot_cap_cmd_set *command = NULL;

	/* find handle with capability */
	handle_list = cap_handle_list;
	while (handle_list != NULL) {
		handle = handle_list->handle;
		if (handle && !strcmp(component_name, handle->component) && !strcmp(capability_name, handle->capability)) {
			IOT_DEBUG("found handle for [%s]%s", component_name, capability_name);
			break;
		}
		handle_list = handle_list->next;
	}

	if (handle_list == NULL) {
		IOT_ERROR("Cannot find handle for [%s]%s", component_name, capability_name);
		return IOT_ERROR_BAD_REQ;
	}

	/* find cmd set */
	command_list = handle->cmd_list;
	while (command_list != NULL) {
		command = command_list->command;
		if (!strcmp(command_name, command->cmd_type)) {
			command->cmd_cb((IOT_CAP_HANDLE *)handle,
				cmd_data, command->usr_data);
			break;
		}
		command_list = command_list->next;
	}

	if (command_list == NULL) {
		IOT_WARN("Not registed cmd set received '%s'", command_name);
		return IOT_ERROR_BAD_REQ;
	}

	IOT_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_CAPABILITY_COMMAND_SUCCEED, 0, 0);
	return IOT_ERROR_NONE;
}

void iot_cap_sub_cb(iot_cap_handle_list_t *cap_handle_list, char *payload)
{
	JSON_H *json = NULL;
	JSON_H *cap_cmds = NULL;
	JSON_H *cmditem = NULL;
	char *raw_data = NULL;
	iot_error_t err;
	int i;
	int arr_size = 0;

	if (!cap_handle_list || !payload) {
		IOT_ERROR("There is no cap_handle_list or payload");
		return;
	}

	json = JSON_PARSE(payload);
	if (json == NULL) {
		IOT_ERROR("Cannot parse by json");
		goto out;
	}

	raw_data = JSON_PRINT(json);
	IOT_INFO("command : %s", raw_data);
	free(raw_data);

	cap_cmds = JSON_GET_OBJECT_ITEM(json, "commands");
	if (cap_cmds == NULL) {
		IOT_ERROR("there is no commands in raw_data");
		goto out;
	}

	arr_size = JSON_GET_ARRAY_SIZE(cap_cmds);
	IOT_DEBUG("cap_cmds arr_size=%d", arr_size);
	IOT_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_CAPABILITY_COMMANDS_RECEIVED, arr_size, 0);

	if (arr_size == 0) {
		IOT_ERROR("There are no commands data");
		goto out;
	}

	for (i = 0; i < arr_size; i++) {
		char *component_name = NULL;
		char *capability_name = NULL;
		char *command_name = NULL;
		iot_cap_cmd_data_t cmd_data;

		cmd_data.num_args = 0;
		cmd_data.total_commands_num = arr_size;
		cmd_data.order_of_command = i + 1;
		cmd_data.command_id = NULL;

		cmditem = JSON_GET_ARRAY_ITEM(cap_cmds, i);
		if (!cmditem) {
			IOT_ERROR("Cannot get %dth commands data", i);
			continue;
		}

		IOT_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_CAPABILITY_PROCESS_COMMAND, i + 1, 0);
		err = _iot_parse_cmd_data(cmditem, &component_name, &capability_name, &command_name, &cmd_data);
		if (err != IOT_ERROR_NONE) {
			IOT_ERROR("Cannot parse %dth command data", i);
		} else {
			_iot_process_cmd(cap_handle_list, component_name, capability_name, command_name, &cmd_data);
		}

		if (cmd_data.num_args != 0) {
			_iot_free_cmd_data(&cmd_data);
			cmd_data.num_args = 0;
		}

		if (component_name != NULL) {
			iot_os_free(component_name);
			component_name = NULL;
		}

		if (capability_name != NULL) {
			iot_os_free(capability_name);
			capability_name = NULL;
		}

		if (command_name != NULL) {
			iot_os_free(command_name);
			command_name = NULL;
		}

		if (cmd_data.command_id != NULL) {
			iot_os_free(cmd_data.command_id);
			cmd_data.command_id = NULL;
		}
	}

out:
	if (json != NULL)
		JSON_DELETE(json);
}

static iot_error_t _iot_parse_cmd_data_v2(JSON_H* cmditem, st_command_data *cmd_data)
{
	JSON_H *cap_component = NULL;
	JSON_H *cap_capability = NULL;
	JSON_H *cap_command = NULL;
	JSON_H *cap_args = NULL;
	JSON_H *subitem = NULL;
	JSON_H *command_id = NULL;
	int arr_size = 0;
	int i;

	cap_component = JSON_GET_OBJECT_ITEM(cmditem, "component");
	cap_capability = JSON_GET_OBJECT_ITEM(cmditem, "capability");
	cap_command = JSON_GET_OBJECT_ITEM(cmditem, "command");
	cap_args = JSON_GET_OBJECT_ITEM(cmditem, "arguments");
	command_id = JSON_GET_OBJECT_ITEM(cmditem, "id");

	if (cap_component == NULL || cap_capability == NULL || cap_command == NULL) {
		IOT_ERROR("Cannot find value index!!");
		return IOT_ERROR_BAD_REQ;
	}

	cmd_data->command_id = iot_os_strdup(command_id->valuestring);
	cmd_data->custom_component_name = iot_os_strdup(cap_component->valuestring);
	cmd_data->custom_cap_name = iot_os_strdup(cap_capability->valuestring);
	cmd_data->custom_command_name = iot_os_strdup(cap_command->valuestring);

	IOT_DEBUG("component:%s, capability:%s command:%s", cmd_data->custom_component_name,
														cmd_data->custom_cap_name,
														cmd_data->custom_command_name);

	arr_size = JSON_GET_ARRAY_SIZE(cap_args);
	IOT_DEBUG("cap_args arr_size=%d", arr_size);
	subitem = JSON_GET_ARRAY_ITEM(cap_args, 0);
	cmd_data->param_list = (st_data *)iot_os_malloc(sizeof(st_data) * arr_size);
	cmd_data->param_num = arr_size;
	memset(cmd_data->param_list, 0, sizeof(st_data) * arr_size);

	if (subitem != NULL) {
		for (i = 0; i < arr_size; i++) {
			if (JSON_IS_BOOL(subitem)) {
				cmd_data->param_list[i].data_type = ST_DATA_TYPE_BOOLEAN;
				if (JSON_IS_TRUE(subitem)) {
					IOT_DEBUG("[%d] True", i);
					cmd_data->param_list[i].data.boolean = true;
				} else {
					IOT_DEBUG("[%d] False", i);
					cmd_data->param_list[i].data.boolean = false;
				}
			}
			else if (JSON_IS_NUMBER(subitem)) {
				IOT_DEBUG("[%d] %f", i, JSON_GET_NUMBER_VALUE(subitem));
				cmd_data->param_list[i].data_type = ST_DATA_TYPE_NUMBER;
				cmd_data->param_list[i].data.number = JSON_GET_NUMBER_VALUE(subitem);
			}
			else if (JSON_IS_STRING(subitem)) {
				IOT_DEBUG("[%d] %s", i, JSON_GET_STRING_VALUE(subitem));
				cmd_data->param_list[i].data_type = ST_DATA_TYPE_STRING;
				cmd_data->param_list[i].data.string = JSON_GET_STRING_VALUE(subitem);
			}
			else if (JSON_IS_OBJECT(subitem) || JSON_IS_ARRAY(subitem)) {
				cmd_data->param_list[i].data_type = ST_DATA_TYPE_RAW_JSON;
				cmd_data->param_list[i].data.raw_json = JSON_PRINT(subitem);
				IOT_DEBUG("[%d] %s", i, cmd_data->param_list[i].data.raw_json);
			}
			subitem = subitem->next;
		}
	}

	return IOT_ERROR_NONE;
}

static void _iot_free_cmd_data_v2(st_command_data *cmd_data)
{
	int i;

	if (cmd_data == NULL) {
		return;
	}

	for (i = 0; i < cmd_data->param_num; i++) {
		if (cmd_data->param_list[i].data_type == ST_DATA_TYPE_RAW_JSON)
			free(cmd_data->param_list[i].data.raw_json);
	}

	if (cmd_data->param_list)
		iot_os_free(cmd_data->param_list);

	if (cmd_data->custom_command_name)
		iot_os_free(cmd_data->custom_command_name);
	if (cmd_data->custom_cap_name)
		iot_os_free(cmd_data->custom_cap_name);
	if (cmd_data->custom_component_name)
		iot_os_free(cmd_data->custom_component_name);
	if (cmd_data->command_id)
		iot_os_free(cmd_data->command_id);

}

void iot_cap_commands_cb(struct iot_context *ctx, char *payload)
{
	JSON_H *json = NULL;
	JSON_H *cap_cmds = NULL;
	JSON_H *cmditem = NULL;
	char *raw_data = NULL;
	iot_error_t err;
	int i;
	int arr_size = 0;
	iot_noti_data_t command_noti = {.type = IOT_NOTI_TYPE_COMMANDS,
									.raw.commands.commands_data = NULL,
									.raw.commands.commands_num = 0};

	if (!payload) {
		IOT_ERROR("There is no payload");
		return;
	}

	json = JSON_PARSE(payload);
	if (json == NULL) {
		IOT_ERROR("Cannot parse by json");
		goto out;
	}

	raw_data = JSON_PRINT(json);
	IOT_INFO("command : %s", raw_data);
	free(raw_data);

	cap_cmds = JSON_GET_OBJECT_ITEM(json, "commands");
	if (cap_cmds == NULL) {
		IOT_ERROR("there is no commands in raw_data");
		goto out;
	}

	arr_size = JSON_GET_ARRAY_SIZE(cap_cmds);
	IOT_DEBUG("cap_cmds arr_size=%d", arr_size);
	IOT_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_CAPABILITY_COMMANDS_RECEIVED, arr_size, 0);

	if (arr_size == 0) {
		IOT_ERROR("There are no commands data");
		goto out;
	}

	command_noti.raw.commands.commands_num = arr_size;
	command_noti.raw.commands.commands_data = (st_command_data *)iot_os_malloc(sizeof(st_command_data) * arr_size);
	memset(command_noti.raw.commands.commands_data, 0, sizeof(st_command_data) * arr_size);

	for (i = 0; i < arr_size; i++) {
		cmditem = JSON_GET_ARRAY_ITEM(cap_cmds, i);
		if (!cmditem) {
			IOT_ERROR("Cannot get %dth commands data", i);
			continue;
		}

		IOT_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_CAPABILITY_PROCESS_COMMAND, i + 1, 0);
		err = _iot_parse_cmd_data_v2(cmditem, &command_noti.raw.commands.commands_data[i]);
		if (err != IOT_ERROR_NONE) {
			IOT_ERROR("Cannot parse %dth command data", i);
			goto out;
		}
	}

	if (ctx->noti_cb)
		ctx->noti_cb(&command_noti, ctx->noti_usr_data);
out:
	for (i = 0; i < arr_size; i++) {
		_iot_free_cmd_data_v2(&command_noti.raw.commands.commands_data[i]);
	}
	if (command_noti.raw.commands.commands_data)
		iot_os_free(command_noti.raw.commands.commands_data);
	if (json != NULL)
		JSON_DELETE(json);
}


/* Internal API */
static iot_error_t _iot_parse_cmd_data(JSON_H* cmditem, char** component,
			char** capability, char** command, iot_cap_cmd_data_t* cmd_data)
{
	JSON_H *cap_component = NULL;
	JSON_H *cap_capability = NULL;
	JSON_H *cap_command = NULL;
	JSON_H *cap_args = NULL;
	JSON_H *subitem = NULL;
	JSON_H *command_id = NULL;
	int arr_size = 0;
	int num_args = 0;
	int i;

	cap_component = JSON_GET_OBJECT_ITEM(cmditem, "component");
	cap_capability = JSON_GET_OBJECT_ITEM(cmditem, "capability");
	cap_command = JSON_GET_OBJECT_ITEM(cmditem, "command");
	cap_args = JSON_GET_OBJECT_ITEM(cmditem, "arguments");
	command_id = JSON_GET_OBJECT_ITEM(cmditem, "id");

	if (cap_component == NULL || cap_capability == NULL || cap_command == NULL) {
		IOT_ERROR("Cannot find value index!!");
		return IOT_ERROR_BAD_REQ;
	}

	*component = iot_os_strdup(cap_component->valuestring);
	*capability = iot_os_strdup(cap_capability->valuestring);
	*command = iot_os_strdup(cap_command->valuestring);

	IOT_DEBUG("component:%s, capability:%s command:%s", *component, *capability, *command);

	arr_size = JSON_GET_ARRAY_SIZE(cap_args);
	IOT_DEBUG("cap_args arr_size=%d", arr_size);
	subitem = JSON_GET_ARRAY_ITEM(cap_args, 0);

	if (subitem != NULL) {
		for (i = 0; i < arr_size; i++) {
			if (JSON_IS_BOOL(subitem)) {
				cmd_data->args_str[num_args] = NULL;
				cmd_data->cmd_data[num_args].type = IOT_CAP_VAL_TYPE_BOOLEAN;
				if (JSON_IS_TRUE(subitem)) {
					IOT_DEBUG("[%d] True", num_args);
					cmd_data->cmd_data[num_args].boolean = true;
				} else {
					IOT_DEBUG("[%d] False", num_args);
					cmd_data->cmd_data[num_args].boolean = false;
				}
				num_args++;
			}
			else if (JSON_IS_NUMBER(subitem)) {
				IOT_DEBUG("[%d] %d | %f", num_args, subitem->valueint, subitem->valuedouble);
				cmd_data->args_str[num_args] = NULL;
				cmd_data->cmd_data[num_args].type = IOT_CAP_VAL_TYPE_INT_OR_NUM;
				cmd_data->cmd_data[num_args].integer = subitem->valueint;
				cmd_data->cmd_data[num_args].number = subitem->valuedouble;
				num_args++;
			}
			else if (JSON_IS_STRING(subitem)) {
				IOT_DEBUG("[%d] %s", num_args, JSON_GET_STRING_VALUE(subitem));
				cmd_data->args_str[num_args] = NULL;
				cmd_data->cmd_data[num_args].type = IOT_CAP_VAL_TYPE_STRING;
				cmd_data->cmd_data[num_args].string = iot_os_strdup(JSON_GET_STRING_VALUE(subitem));
				num_args++;
			}
			else if (JSON_IS_OBJECT(subitem) || JSON_IS_ARRAY(subitem)) {
				cmd_data->args_str[num_args] = NULL;
				cmd_data->cmd_data[num_args].type = IOT_CAP_VAL_TYPE_JSON_OBJECT;
				cmd_data->cmd_data[num_args].json_object = JSON_PRINT(subitem);
				IOT_DEBUG("[%d] %s", num_args, cmd_data->cmd_data[num_args].json_object);
				num_args++;
			}
			subitem = subitem->next;
		}
	}
	cmd_data->num_args = num_args;

	if (command_id != NULL) {
		cmd_data->command_id = iot_os_strdup(JSON_GET_STRING_VALUE(command_id));
	}

	return IOT_ERROR_NONE;
}

static JSON_H *_iot_make_evt_data(const char* component, const char* capability, iot_cap_evt_data_t* evt_data, int seq_num)
{
	JSON_H *evt_item = NULL;
	JSON_H *evt_subarr = NULL;
	JSON_H *evt_subjson = NULL;
	JSON_H *evt_subdata = NULL;
	JSON_H *prov_data = NULL;
	JSON_H *visibility_data = NULL;
	char time_in_ms[16]; /* 155934720000 is '2019-06-01 00:00:00.00 UTC' */

	evt_item = JSON_CREATE_OBJECT();

	if (evt_data->options.command_id != NULL) {
		/* commandId */
		JSON_ADD_STRING_TO_OBJECT(evt_item, "commandId", evt_data->options.command_id);
	}

	/* component */
	JSON_ADD_STRING_TO_OBJECT(evt_item, "component", component);

	/* capability */
	JSON_ADD_STRING_TO_OBJECT(evt_item, "capability", capability);

	/* attribute */
	JSON_ADD_STRING_TO_OBJECT(evt_item, "attribute", evt_data->evt_type);

	/* value */
	if (evt_data->evt_value.type == IOT_CAP_VAL_TYPE_BOOLEAN) {
		JSON_ADD_BOOL_TO_OBJECT(evt_item, "value", evt_data->evt_value.boolean);
	} else if (evt_data->evt_value.type == IOT_CAP_VAL_TYPE_INTEGER) {
		JSON_ADD_NUMBER_TO_OBJECT(evt_item, "value", evt_data->evt_value.integer);
	} else if (evt_data->evt_value.type == IOT_CAP_VAL_TYPE_NUMBER) {
		JSON_ADD_NUMBER_TO_OBJECT(evt_item, "value", evt_data->evt_value.number);
	} else if (evt_data->evt_value.type == IOT_CAP_VAL_TYPE_STRING) {
		JSON_ADD_STRING_TO_OBJECT(evt_item, "value", evt_data->evt_value.string);
	} else if (evt_data->evt_value.type == IOT_CAP_VAL_TYPE_STR_ARRAY) {
		if (evt_data->evt_value.str_num == 0) {
			evt_subarr = JSON_CREATE_ARRAY();
		} else {
			evt_subarr = JSON_CREATE_STRING_ARRAY(
				(const char**)evt_data->evt_value.strings, evt_data->evt_value.str_num);
		}
		JSON_ADD_ITEM_TO_OBJECT(evt_item, "value", evt_subarr);
	} else if (evt_data->evt_value.type == IOT_CAP_VAL_TYPE_JSON_OBJECT) {
		evt_subjson = JSON_PARSE(evt_data->evt_value.json_object);
		JSON_ADD_ITEM_TO_OBJECT(evt_item, "value", evt_subjson);
	} else {
		IOT_ERROR("Event data value type error :%d", evt_data->evt_value.type);
		JSON_DELETE(evt_item);
		return NULL;
	}

	/* unit */
	if (evt_data->evt_unit.type == IOT_CAP_UNIT_TYPE_STRING)
			JSON_ADD_STRING_TO_OBJECT(evt_item, "unit", evt_data->evt_unit.string);

	/* data */
	if (evt_data->evt_value_data) {
		evt_subdata = JSON_PARSE(evt_data->evt_value_data);
		JSON_ADD_ITEM_TO_OBJECT(evt_item, "data", evt_subdata);
	}

	/* visibility */
	if (evt_data->options.displayed != NULL)
	{
		visibility_data = JSON_CREATE_OBJECT();
		JSON_ADD_BOOL_TO_OBJECT(visibility_data, "displayed", *(evt_data->options.displayed));

		JSON_ADD_ITEM_TO_OBJECT(evt_item, "visibility", visibility_data);
	}

	/* providerData */
	prov_data = JSON_CREATE_OBJECT();
	JSON_ADD_NUMBER_TO_OBJECT(prov_data, "sequenceNumber", seq_num);

	if (iot_get_time_in_ms(time_in_ms, sizeof(time_in_ms)) != IOT_ERROR_NONE)
		IOT_WARN("Cannot add optional timestamp value");
	else
		JSON_ADD_STRING_TO_OBJECT(prov_data, "timestamp", time_in_ms);

	if (evt_data->options.state_change)
		JSON_ADD_STRING_TO_OBJECT(prov_data, "stateChange", "Y");

	JSON_ADD_ITEM_TO_OBJECT(evt_item, "providerData", prov_data);

	return evt_item;
}

void iot_cap_call_init_cb(iot_cap_handle_list_t *cap_handle_list)
{
	struct iot_cap_handle *handle = NULL;
	struct iot_cap_handle_list *cur_list;

	if (!cap_handle_list) {
		IOT_ERROR("There is no cap_handle_list");
		return;
	}

	cur_list = cap_handle_list;
	while (cur_list != NULL) {
		handle = cur_list->handle;
		if (handle && handle->init_cb) {
			IOT_INFO("Call init_cb for %s capability",
				handle->capability ? handle->capability : "NULL");
			handle->init_cb((IOT_CAP_HANDLE*)handle, handle->init_usr_data);
		}
		cur_list = cur_list->next;
	}
}

static void _iot_free_val(iot_cap_val_t* val)
{
	int i;

	if (val == NULL) {
		return;
	}

	if (val->type == IOT_CAP_VAL_TYPE_STRING
				&& val->string != NULL) {
		iot_os_free(val->string);
	}
	else if (val->type == IOT_CAP_VAL_TYPE_STR_ARRAY
				&& val->strings != NULL) {
		for (i = 0; i < val->str_num; i++) {
			if (val->strings[i] != NULL) {
				iot_os_free(val->strings[i]);
			}
		}
		iot_os_free(val->strings);
	} else if (val->type == IOT_CAP_VAL_TYPE_JSON_OBJECT) {
		iot_os_free(val->json_object);
	}
}

static void _iot_free_unit(iot_cap_unit_t* unit)
{
	if (unit == NULL) {
		return;
	}

	if (unit->type == IOT_CAP_UNIT_TYPE_STRING
				&& unit->string != NULL) {
		iot_os_free(unit->string);
	}
}

static void _iot_free_cmd_data(iot_cap_cmd_data_t* cmd_data)
{
	int i;

	if (cmd_data == NULL) {
		return;
	}

	for (i = 0; i < cmd_data->num_args; i++) {
		if (cmd_data->args_str[i] != NULL) {
			free(cmd_data->args_str[i]);
		}
		_iot_free_val(&cmd_data->cmd_data[i]);
	}
}

static void _iot_free_evt_data(iot_cap_evt_data_t* evt_data)
{
	if (evt_data == NULL) {
		return;
	}

	if (evt_data->evt_type != NULL) {
		iot_os_free((void *)evt_data->evt_type);
	}
	_iot_free_val(&evt_data->evt_value);
	_iot_free_unit(&evt_data->evt_unit);

	if (evt_data->evt_value_data != NULL) {
		iot_os_free(evt_data->evt_value_data);
	}

	if (evt_data->options.command_id != NULL) {
		iot_os_free(evt_data->options.command_id);
	}

	if (evt_data->options.displayed != NULL) {
		iot_os_free(evt_data->options.displayed);
	}
}

static JSON_H *_iot_make_evt_data_v2(st_attr_data *attr_data, int seq_num)
{
	JSON_H *evt_item = NULL;
	JSON_H *evt_subjson = NULL;
	JSON_H *evt_subdata = NULL;
	JSON_H *prov_data = NULL;
	JSON_H *visibility_data = NULL;
	char time_in_ms[16]; /* 155934720000 is '2019-06-01 00:00:00.00 UTC' */

	evt_item = JSON_CREATE_OBJECT();

	/* component */
	if (attr_data->component_type == ST_COMPONENT_DEFULAT) {
		JSON_ADD_STRING_TO_OBJECT(evt_item, "component", "main");
	} else if (attr_data->component_type == ST_COMPONENT_CUSTOM) {
		if (attr_data->custom_component_name)
			JSON_ADD_STRING_TO_OBJECT(evt_item, "component", attr_data->custom_component_name);
		else
			goto err_make_evt_item;
	} else
		goto err_make_evt_item;

	/* capability && attribute */
	if (attr_data->attr_type == ST_ATTR_CUSTOM) {
		if (attr_data->custom_cap_name && attr_data->custom_attr_name) {
			JSON_ADD_STRING_TO_OBJECT(evt_item, "capability", attr_data->custom_cap_name);
			JSON_ADD_STRING_TO_OBJECT(evt_item, "attribute", attr_data->custom_attr_name);
		} else
			goto err_make_evt_item;
	} else
		goto err_make_evt_item;

	/* value */
	switch (attr_data->value.data_type) {
		case ST_DATA_TYPE_STRING:
			JSON_ADD_STRING_TO_OBJECT(evt_item, "value", attr_data->value.data.string);
			break;
		case ST_DATA_TYPE_NUMBER:
			JSON_ADD_NUMBER_TO_OBJECT(evt_item, "value", attr_data->value.data.number);
			break;
		case ST_DATA_TYPE_JSON_OBJECT:
			break;
		case ST_DATA_TYPE_JSON_ARRAY:
			break;
		case ST_DATA_TYPE_BOOLEAN:
			JSON_ADD_BOOL_TO_OBJECT(evt_item, "value", attr_data->value.data.boolean);
			break;
		case ST_DATA_TYPE_NULL:
			break;
		case ST_DATA_TYPE_RAW_JSON:
			evt_subjson = JSON_PARSE(attr_data->value.data.raw_json);
			JSON_ADD_ITEM_TO_OBJECT(evt_item, "value", evt_subjson);
			break;
	}

	/* unit */
	if (attr_data->unit)
		JSON_ADD_STRING_TO_OBJECT(evt_item, "unit", attr_data->unit);

	/* data */
	if (attr_data->data) {
		evt_subdata = JSON_PARSE(attr_data->data);
		JSON_ADD_ITEM_TO_OBJECT(evt_item, "data", evt_subdata);
	}

	/* visibility */
	if (!attr_data->support_history) {
		visibility_data = JSON_CREATE_OBJECT();
		JSON_ADD_BOOL_TO_OBJECT(visibility_data, "displayed", false);
		JSON_ADD_ITEM_TO_OBJECT(evt_item, "visibility", visibility_data);
	}

	/* providerData */
	prov_data = JSON_CREATE_OBJECT();
	JSON_ADD_NUMBER_TO_OBJECT(prov_data, "sequenceNumber", seq_num);

	if (iot_get_time_in_ms(time_in_ms, sizeof(time_in_ms)) != IOT_ERROR_NONE)
		IOT_WARN("Cannot add optional timestamp value");
	else
		JSON_ADD_STRING_TO_OBJECT(prov_data, "timestamp", time_in_ms);

	if (attr_data->state_change)
		JSON_ADD_STRING_TO_OBJECT(prov_data, "stateChange", "Y");

	JSON_ADD_ITEM_TO_OBJECT(evt_item, "providerData", prov_data);

	/* related command ID */
	if (attr_data->related_command_id != NULL)
		JSON_ADD_STRING_TO_OBJECT(evt_item, "commandId", attr_data->related_command_id);

	return evt_item;
err_make_evt_item:
	if (evt_item) {
		JSON_DELETE(evt_item);
	}

	return NULL;
}

int st_cap_send_attr_v2(IOT_CTX *iot_ctx, st_attr_data* attr_data[], uint8_t attr_num)
{
	int ret;
	struct iot_context *ctx = (struct iot_context *)iot_ctx;
	st_mqtt_msg msg = {0};
	int i;
	JSON_H *evt_root = NULL;
	JSON_H *evt_arr = NULL;
	JSON_H *evt_item = NULL;

	if (!ctx || attr_num == 0) {
		IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_CAPABILITY_SEND_EVENT_NO_DATA_ERROR, 0, 0);
		IOT_ERROR("There is no ctx or attr_data");
		return IOT_ERROR_INVALID_ARGS;
	}

	if (ctx->curr_state != IOT_STATE_CLOUD_CONNECTED || ctx->evt_mqttcli == NULL) {
		IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_CAPABILITY_SEND_EVENT_NO_CONNECT_ERROR, ctx->curr_state, 0);
		IOT_ERROR("Target has not connected to server yet!!");
		return IOT_ERROR_BAD_REQ;
	}

	if (ctx->rate_limit) {
		if ((iot_os_timer_isexpired(ctx->rate_limit_timeout))) {
			ctx->rate_limit = false;
		} else {
			IOT_WARN("Exceed rate limit. Can't send attributes for a while");
			return IOT_ERROR_BAD_REQ;
		}
	}

	if (ctx->event_sequence_num == MAX_SQNUM) {
		ctx->event_sequence_num = 0;
	}
	ctx->event_sequence_num = (ctx->event_sequence_num + 1) & MAX_SQNUM;

	evt_root = JSON_CREATE_OBJECT();
	evt_arr = JSON_CREATE_ARRAY();

	JSON_ADD_ITEM_TO_OBJECT(evt_root, "deviceEvents", evt_arr);

	/* Make event data format & enqueue data */
	for (i = 0; i < attr_num; i++) {
		if (!attr_data[i]) {
			IOT_ERROR("There si no capability reference in event data or ctx not matched");
			JSON_DELETE(evt_root);
			return IOT_ERROR_BAD_REQ;
		}
		evt_item = _iot_make_evt_data_v2(attr_data[i], ctx->event_sequence_num);
		if (evt_item == NULL) {
			IOT_ERROR("Cannot make evt_data!!");
			JSON_DELETE(evt_root);
			return IOT_ERROR_BAD_REQ;
		}
		JSON_ADD_ITEM_TO_ARRAY(evt_arr, evt_item);
	}

#if defined(STDK_IOT_CORE_SERIALIZE_CBOR)
	iot_serialize_json2cbor(evt_root, (uint8_t **)&msg.payload, (size_t *)&msg.payloadlen);
#else
	msg.payload = JSON_PRINT(evt_root);
	if (msg.payload != NULL) {
		msg.payloadlen = strlen(msg.payload);
	}
#endif
	JSON_DELETE(evt_root);
	if (msg.payload == NULL) {
		IOT_ERROR("Fail to transfer to payload");
		return IOT_ERROR_BAD_REQ;
	}
	msg.qos = st_mqtt_qos1;
	msg.retained = false;
	msg.topic = ctx->mqtt_event_topic;

	IOT_INFO("publish event, topic : %s, payload :\n%s",
		ctx->mqtt_event_topic, (char *)msg.payload);

	ret = st_mqtt_publish_async(ctx->evt_mqttcli, &msg);
	if (ret) {
		IOT_WARN("MQTT pub error(%d)", ret);
		free(msg.payload);
		return IOT_ERROR_MQTT_PUBLISH_FAIL;
	}

#if !defined(STDK_MQTT_TASK)
	iot_os_eventgroup_set_bits(ctx->iot_events, IOT_EVENT_BIT_CAPABILITY);
#endif
	IOT_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_CAPABILITY_SEND_EVENT_SUCCESS, attr_num, 0);

	free(msg.payload);
	return ctx->event_sequence_num;
}
/* External API */
