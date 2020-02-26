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

#include <stdlib.h>
#include <string.h>
#include <cJSON.h>
#if defined(STDK_IOT_CORE_SERIALIZE_CBOR)
#include <cbor.h>
#endif

#include "iot_internal.h"
#include "iot_util.h"
#include "iot_debug.h"
#include "iot_capability.h"
#include "iot_os_util.h"
#include "iot_bsp_system.h"

#define MAX_SQNUM 0x7FFFFFFF

static int32_t sqnum = 0;

static iot_error_t _iot_parse_noti_data(void *data, iot_noti_data_t *noti_data);
static iot_error_t _iot_parse_cmd_data(cJSON* cmditem, char** component,
			char** capability, char** command, iot_cap_cmd_data_t* cmd_data);
static iot_error_t _iot_make_evt_data(const char* component, const char* capability,
			uint8_t arr_size, iot_cap_evt_data_t** evt_data_arr, iot_cap_msg_t *msg);
static void _iot_free_val(iot_cap_val_t* val);
static void _iot_free_unit(iot_cap_unit_t* unit);
static void _iot_free_cmd_data(iot_cap_cmd_data_t* cmd_data);
static void _iot_free_evt_data(iot_cap_evt_data_t* evt_data);

/**************************************************************
*                       Synchronous Call                      *
**************************************************************/
/* External API */
IOT_EVENT* st_cap_attr_create_int(const char *attribute, int integer, const char *unit)
{
	iot_cap_evt_data_t* evt_data;

	if (!attribute) {
		IOT_ERROR("attribute is NULL");
		return NULL;
	}

	evt_data = malloc(sizeof(iot_cap_evt_data_t));
	if (!evt_data) {
		IOT_ERROR("failed to malloc for evt_data");
		return NULL;
	}

	memset(evt_data, 0, sizeof(iot_cap_evt_data_t));
	evt_data->evt_type = strdup(attribute);
	evt_data->evt_value.type = IOT_CAP_VAL_TYPE_INTEGER;
	evt_data->evt_value.integer = integer;

	if (unit != NULL) {
		evt_data->evt_unit.type = IOT_CAP_UNIT_TYPE_STRING;
		evt_data->evt_unit.string = strdup(unit);
	} else {
		evt_data->evt_unit.type = IOT_CAP_UNIT_TYPE_UNUSED;
	}

	return (IOT_EVENT*)evt_data;
}

IOT_EVENT* st_cap_attr_create_number(const char *attribute, double number, const char *unit)
{
	iot_cap_evt_data_t* evt_data;

	if (!attribute) {
		IOT_ERROR("attribute is NULL");
		return NULL;
	}

	evt_data = malloc(sizeof(iot_cap_evt_data_t));
	if (!evt_data) {
		IOT_ERROR("failed to malloc for evt_data");
		return NULL;
	}

	memset(evt_data, 0, sizeof(iot_cap_evt_data_t));
	evt_data->evt_type = strdup(attribute);
	evt_data->evt_value.type = IOT_CAP_VAL_TYPE_NUMBER;
	evt_data->evt_value.number = number;

	if (unit != NULL) {
		evt_data->evt_unit.type = IOT_CAP_UNIT_TYPE_STRING;
		evt_data->evt_unit.string = strdup(unit);
	} else {
		evt_data->evt_unit.type = IOT_CAP_UNIT_TYPE_UNUSED;
	}

	return (IOT_EVENT*)evt_data;
}

IOT_EVENT* st_cap_attr_create_string(const char *attribute, char *string, const char *unit)
{
	iot_cap_evt_data_t* evt_data;

	if (!attribute || !string) {
		IOT_ERROR("attribute or string is NULL");
		return NULL;
	}

	evt_data = malloc(sizeof(iot_cap_evt_data_t));
	if (!evt_data) {
		IOT_ERROR("failed to malloc for evt_data");
		return NULL;
	}

	memset(evt_data, 0, sizeof(iot_cap_evt_data_t));
	evt_data->evt_type = strdup(attribute);
	evt_data->evt_value.type = IOT_CAP_VAL_TYPE_STRING;
	evt_data->evt_value.string = strdup(string);

	if (unit != NULL) {
		evt_data->evt_unit.type = IOT_CAP_UNIT_TYPE_STRING;
		evt_data->evt_unit.string = strdup(unit);
	} else {
		evt_data->evt_unit.type = IOT_CAP_UNIT_TYPE_UNUSED;
	}

	return (IOT_EVENT*)evt_data;
}

IOT_EVENT* st_cap_attr_create_string_array(const char *attribute,
			uint8_t str_num, char *string_array[], const char *unit)
{
	iot_cap_evt_data_t* evt_data;

	if (!attribute) {
		IOT_ERROR("attribute is NULL");
		return NULL;
	}

	if (!string_array || str_num <= 0) {
		IOT_ERROR("string_array is NULL");
		return NULL;
	}

	evt_data = malloc(sizeof(iot_cap_evt_data_t));
	if (!evt_data) {
		IOT_ERROR("failed to malloc for evt_data");
		return NULL;
	}

	memset(evt_data, 0, sizeof(iot_cap_evt_data_t));
	evt_data->evt_value.type = IOT_CAP_VAL_TYPE_STR_ARRAY;
	evt_data->evt_value.str_num = str_num;
	evt_data->evt_value.strings = malloc(str_num * sizeof(char*));
	if (!evt_data->evt_value.strings) {
		IOT_ERROR("failed to malloc for string array");
		free(evt_data);
		return NULL;
	}

	for (int i = 0; i < str_num; i++) {
		if (string_array[i])
			evt_data->evt_value.strings[i] = strdup(string_array[i]);
	}

	evt_data->evt_type = strdup(attribute);
	if (unit != NULL) {
		evt_data->evt_unit.type = IOT_CAP_UNIT_TYPE_STRING;
		evt_data->evt_unit.string = strdup(unit);
	} else {
		evt_data->evt_unit.type = IOT_CAP_UNIT_TYPE_UNUSED;
	}

	return (IOT_EVENT*)evt_data;
}

void st_cap_attr_free(IOT_EVENT* event)
{
	iot_cap_evt_data_t* evt_data = (iot_cap_evt_data_t*) event;

	if (evt_data) {
		_iot_free_evt_data(evt_data);
		free(evt_data);
	}
}

IOT_CAP_HANDLE *st_cap_handle_init(IOT_CTX *iot_ctx, const char *component,
			const char *capability, st_cap_init_cb init_cb, void *init_usr_data)
{
	struct iot_cap_handle *handle = NULL;
	struct iot_cap_handle_list *cur_list;
	struct iot_cap_handle_list *new_list;
	struct iot_context *ctx = (struct iot_context*)iot_ctx;

	handle = malloc(sizeof(struct iot_cap_handle));
	if (!handle) {
		IOT_ERROR("failed to malloc for iot_cap_handle");
		return NULL;
	}

	memset(handle, 0, sizeof(struct iot_cap_handle));

	if (component) {
		handle->component = strdup(component);
	} else {
		handle->component = strdup("main");
	}
	if (!handle->component) {
		IOT_ERROR("failed to malloc for component");
		free(handle);
		return NULL;
	}

	handle->capability = strdup(capability);
	if (!handle->capability) {
		IOT_ERROR("failed to malloc for capability");
		free((void *)handle->component);
		free(handle);
		return NULL;
	}

	handle->cmd_list = NULL;

	new_list = (iot_cap_handle_list_t *)malloc(sizeof(iot_cap_handle_list_t));
	if (!new_list) {
		IOT_ERROR("failed to malloc for handle list");
		free((void *)handle->component);
		free((void *)handle->capability);
		free(handle);
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

	new_list = (iot_cap_cmd_set_list_t *)malloc(sizeof(iot_cap_cmd_set_list_t));
	if (!new_list) {
		IOT_ERROR("failed to malloc for cmd set list");
		return IOT_ERROR_MEM_ALLOC;
	}

	cur_list = handle->cmd_list;

	if (cur_list == NULL) {
		handle->cmd_list = new_list;
		cur_list = handle->cmd_list;
	} else {
		while (cur_list->next != NULL) {
			cmd_str = cur_list->command->cmd_type;
			if (cmd_str && !strncmp(cmd_str, needle_str, str_len)) {
				IOT_ERROR("There is already same handle for : %s",
							needle_str);
				return IOT_ERROR_INVALID_ARGS;
			}
			cur_list = cur_list->next;
		}

		cur_list->next = new_list;
		cur_list = cur_list->next;
	}

	command = (iot_cap_cmd_set_t *)malloc(sizeof(iot_cap_cmd_set_t));
	if (!command) {
		IOT_ERROR("failed to malloc for cmd set");
		return IOT_ERROR_MEM_ALLOC;
	}

	command->cmd_type = strdup(needle_str);
	command->cmd_cb = cmd_cb;
	command->usr_data = usr_data;

	cur_list->command = command;
	cur_list->next = NULL;

	return IOT_ERROR_NONE;
}

int st_cap_attr_send(IOT_CAP_HANDLE *cap_handle,
		uint8_t evt_num, IOT_EVENT *event[])
{
	iot_cap_evt_data_t** evt_data = (iot_cap_evt_data_t**)event;
	int ret;
	struct iot_context *ctx;
	iot_cap_msg_t final_msg;
	struct iot_cap_handle *handle = (struct iot_cap_handle*)cap_handle;
	iot_error_t err;

	if (!handle || !evt_data || !evt_num) {
		IOT_ERROR("There is no handle or evt_data");
		return IOT_ERROR_INVALID_ARGS;
	}

	ctx = handle->ctx;
	if (ctx->curr_state < IOT_STATE_CLOUD_CONNECTING) {
		IOT_ERROR("Target has not connected to server yet!!");
		return IOT_ERROR_BAD_REQ;
	}

	sqnum = (sqnum + 1) & MAX_SQNUM;	// Use only positive number

	/* Make event data format & enqueue data */
	err = _iot_make_evt_data(handle->component,
			handle->capability, evt_num, evt_data, &final_msg);
	if (err != IOT_ERROR_NONE) {
		IOT_ERROR("Cannot make evt_data!!");
		return err;
	}

	ret = iot_os_queue_send(ctx->pub_queue, &final_msg, 0);
	if (ret != IOT_OS_TRUE) {
		IOT_WARN("Cannot put the paylod into pub_queue");
		free(final_msg.msg);

		return IOT_ERROR_BAD_REQ;
	} else {
		iot_os_eventgroup_set_bits(ctx->iot_events,
			IOT_EVENT_BIT_CAPABILITY);

		return sqnum;
	}
}

static iot_error_t _iot_parse_noti_data(void *data, iot_noti_data_t *noti_data)
{
	iot_error_t err = IOT_ERROR_NONE;
	size_t noti_str_len;
	cJSON *json = NULL;
	cJSON *noti_type = NULL;
	cJSON *item = NULL;
	char *payload = NULL;
	char time_str[11] = {0,};

#if defined(STDK_IOT_CORE_SERIALIZE_CBOR)
	char *payload_json = NULL;
	size_t payload_json_len = 0;

	if (iot_serialize_cbor2json((uint8_t *)data, strlen(data), &payload_json, &payload_json_len)) {
		IOT_ERROR("cbor2json failed");
		return IOT_ERROR_BAD_REQ;
	}

	if ((payload_json == NULL) || (payload_json_len == 0)) {
		IOT_ERROR("json buffer is null");
		return IOT_ERROR_BAD_REQ;
	}

	json = cJSON_Parse(payload_json);
	free(payload_json);
#else
	json = cJSON_Parse(data);
#endif
	if (json == NULL) {
		IOT_ERROR("Cannot parse by json");
		return IOT_ERROR_BAD_REQ;
	}

	payload = cJSON_PrintUnformatted(json);
	IOT_INFO("payload : %s", payload);
	free(payload);

	noti_type = cJSON_GetObjectItem(json, "event");
	if (noti_type == NULL) {
		IOT_ERROR("there is no event in raw_msgn");
		err = IOT_ERROR_BAD_REQ;
		goto out_noti_parse;
	}

	noti_str_len = strlen(noti_type->valuestring);
	switch (noti_type->valuestring[0]) {
	case 'd':	/* device.deleted */
		if (noti_str_len != 14) {
			IOT_ERROR("Untargeted event str_len : %s",
				noti_type->valuestring);
			err = IOT_ERROR_BAD_REQ;
			break;
		}

		noti_data->type = _IOT_NOTI_TYPE_DEV_DELETED;
		break;

	case 'e':	/* expired.jwt */
		if (noti_str_len != 11) {
			IOT_ERROR("Untargeted event str_len : %s",
				noti_type->valuestring);
			err = IOT_ERROR_BAD_REQ;
			break;
		}

		noti_data->type = _IOT_NOTI_TYPE_JWT_EXPIRED;

		item = cJSON_GetObjectItem(json, "currentTime");
		if (item == NULL) {
			IOT_ERROR("there is no currentTime in raw_msgn");
			err = IOT_ERROR_BAD_REQ;
			goto out_noti_parse;
		}

		snprintf(time_str, sizeof(time_str), "%d", item->valueint);
		IOT_INFO("Set SNTP with current time %s", time_str);
		iot_bsp_system_set_time_in_sec(time_str);
		break;

	case 'r':	/* rate.limit.reached */
		if (noti_str_len != 18) {
			IOT_ERROR("Untargeted event str_len : %s",
				noti_type->valuestring);
			err = IOT_ERROR_BAD_REQ;
			break;
		}

		noti_data->type = _IOT_NOTI_TYPE_RATE_LIMIT;

		item = cJSON_GetObjectItem(json, "count");
		if (item == NULL) {
			IOT_ERROR("there is no count in raw_msgn");
			err = IOT_ERROR_BAD_REQ;
			goto out_noti_parse;
		}
		noti_data->raw.rate_limit.count = item->valueint;

		item = cJSON_GetObjectItem(json, "threshold");
		if (item == NULL) {
			IOT_ERROR("there is no threshold in raw_msgn");
			err = IOT_ERROR_BAD_REQ;
			goto out_noti_parse;
		}
		noti_data->raw.rate_limit.threshold = item->valueint;

		item = cJSON_GetObjectItem(json, "remainingTime");
		if (item == NULL) {
			IOT_ERROR("there is no remainingTime in raw_msgn");
			err = IOT_ERROR_BAD_REQ;
			goto out_noti_parse;
		}
		noti_data->raw.rate_limit.remainingTime = item->valueint;

		item = cJSON_GetObjectItem(json, "sequenceNumber");
		if (item == NULL) {
			IOT_ERROR("there is no sequenceNumber in raw_msgn");
			err = IOT_ERROR_BAD_REQ;
			goto out_noti_parse;
		}
		noti_data->raw.rate_limit.sequenceNumber = item->valueint;
		break;
	case 'q':	/* quota.reached */
		if (noti_str_len != 13) {
			IOT_ERROR("Untargeted event str_len : %s",
				noti_type->valuestring);
			err = IOT_ERROR_BAD_REQ;
			break;
		}

		noti_data->type = _IOT_NOTI_TYPE_QUOTA_REACHED;

		item = cJSON_GetObjectItem(json, "used");
		if (item == NULL) {
			IOT_ERROR("there is no used in raw_msgn");
			err = IOT_ERROR_BAD_REQ;
			goto out_noti_parse;
		}
		noti_data->raw.quota.used = item->valueint;

		item = cJSON_GetObjectItem(json, "limit");
		if (item == NULL) {
			IOT_ERROR("there is no limit in raw_msgn");
			err = IOT_ERROR_BAD_REQ;
			goto out_noti_parse;
		}
		noti_data->raw.quota.limit = item->valueint;
		break;
	}

out_noti_parse:

	if (json)
		cJSON_Delete(json);

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

	err = _iot_parse_noti_data((void *)payload, &noti_data);
	if (err != IOT_ERROR_NONE) {
		IOT_ERROR("Cannot parse notification data");
		return;
	}

	iot_command_send(ctx, IOT_COMMAND_NOTIFICATION_RECEIVED,
		&noti_data, sizeof(noti_data));
}

void iot_cap_sub_cb(iot_cap_handle_list_t *cap_handle_list, char *payload)
{
	cJSON *json = NULL;
	cJSON *cap_cmds = NULL;
	cJSON *cmditem = NULL;
	char *com = NULL;
	char *cap = NULL;
	char *cmd = NULL;
	char *raw_data = NULL;
	iot_cap_cmd_data_t cmd_data;
	iot_error_t err;
	struct iot_cap_handle *handle = NULL;
	struct iot_cap_handle_list *handle_list;
	struct iot_cap_cmd_set *command;
	struct iot_cap_cmd_set_list *command_list;
	int k;
	int arr_size = 0;

	if (!cap_handle_list || !payload) {
		IOT_ERROR("There is no cap_handle_list or payload");
		return;
	}
	cmd_data.num_args = 0;

#if defined(STDK_IOT_CORE_SERIALIZE_CBOR)
	char *payload_json = NULL;
	size_t payload_json_len = 0;

	if (iot_serialize_cbor2json((uint8_t *)payload, strlen(payload), &payload_json, &payload_json_len)) {
		IOT_ERROR("cbor2json failed");
		return;
	}

	if ((payload_json == NULL) || (payload_json_len == 0)) {
		IOT_ERROR("json buffer is null");
		return;
	}

	json = cJSON_Parse(payload_json);
	free(payload_json);
#else
	json = cJSON_Parse(payload);
#endif
	if (json == NULL) {
		IOT_ERROR("Cannot parse by json");
		goto out;
	}

	raw_data = cJSON_PrintUnformatted(json);
	IOT_INFO("command : %s", raw_data);
	free(raw_data);

	cap_cmds = cJSON_GetObjectItem(json, "commands");
	if (cap_cmds == NULL) {
		IOT_ERROR("there is no commands in raw_data");
		goto out;
	}

	arr_size = cJSON_GetArraySize(cap_cmds);
	IOT_DEBUG("cap_cmds arr_size=%d", arr_size);

	if (arr_size == 0) {
		IOT_ERROR("There are no commands data");
		goto out;
	}

	for (k = 0; k < arr_size; k++) {
		cmditem = cJSON_GetArrayItem(cap_cmds, k);
		if (!cmditem) {
			IOT_ERROR("Cannot get %dth commands data", k);
			break;
		}

		err = _iot_parse_cmd_data(cmditem, &com, &cap, &cmd, &cmd_data);
		if (err != IOT_ERROR_NONE) {
			IOT_ERROR("Cannot parse command data");
			break;
		}

		/* find handle with capability */
		handle_list = cap_handle_list;
		while (handle_list != NULL) {
			handle = handle_list->handle;
			if (handle && !strcmp(com, handle->component)) {
				if (!strcmp(cap, handle->capability)) {
					IOT_DEBUG("found '%s' capability from '%s'", cap, com);
					break;
				}
			}

			handle_list = handle_list->next;
		}

		if (handle_list == NULL) {
			IOT_ERROR("Cannot find handle for '%s'", cap);
			break;
		}

		/* find cmd set */
		command_list = handle->cmd_list;
		while (command_list != NULL) {
			command = command_list->command;
			if (!strcmp(cmd, command->cmd_type)) {
				command->cmd_cb((IOT_CAP_HANDLE *)handle,
					&cmd_data, command->usr_data);
				break;
			}

			command_list = command_list->next;
		}

		if (command_list == NULL) {
			IOT_WARN("Not registed cmd set received '%s'", cmd);
		}

		if (cmd_data.num_args != 0) {
			_iot_free_cmd_data(&cmd_data);
			cmd_data.num_args = 0;
		}

		if (com != NULL) {
			free(com);
			com = NULL;
		}

		if (cap != NULL) {
			free(cap);
			cap = NULL;
		}

		if (cmd != NULL) {
			free(cmd);
			cmd = NULL;
		}
	}

out:
	if (cmd_data.num_args != 0)
		_iot_free_cmd_data(&cmd_data);

	if (com != NULL)
		free(com);

	if (cap != NULL)
		free(cap);

	if (cmd != NULL)
		free(cmd);

	if (json != NULL)
		cJSON_Delete(json);
}


/* Internal API */
static iot_error_t _iot_parse_cmd_data(cJSON* cmditem, char** component,
			char** capability, char** command, iot_cap_cmd_data_t* cmd_data)
{
	cJSON *cap_component = NULL;
	cJSON *cap_capability = NULL;
	cJSON *cap_command = NULL;
	cJSON *cap_args = NULL;
	cJSON *subitem = NULL;
	cJSON *arg_json = NULL;
	int arr_size = 0;
	int num_args = 0;

	cap_component = cJSON_GetObjectItem(cmditem, "component");
	cap_capability = cJSON_GetObjectItem(cmditem, "capability");
	cap_command = cJSON_GetObjectItem(cmditem, "command");
	cap_args = cJSON_GetObjectItem(cmditem, "arguments");

	if (cap_capability == NULL || cap_command == NULL) {
		IOT_ERROR("Cannot find value index!!");
		return IOT_ERROR_BAD_REQ;
	}

	*component = strdup(cap_component->valuestring);
	*capability = strdup(cap_capability->valuestring);
	*command = strdup(cap_command->valuestring);

	IOT_DEBUG("component:%s, capability:%s command:%s", *component, *capability, *command);

	arr_size = cJSON_GetArraySize(cap_args);
	IOT_DEBUG("cap_args arr_size=%d", arr_size);
	subitem = cJSON_GetArrayItem(cap_args, 0);

	if (subitem != NULL) {
		for (int i = 0; i < arr_size; i++) {
			if (cJSON_IsNumber(subitem)) {
				IOT_DEBUG("[%d] %d | %f", num_args, subitem->valueint, subitem->valuedouble);
				cmd_data->args_str[num_args] = NULL;
				cmd_data->cmd_data[num_args].type = IOT_CAP_VAL_TYPE_INT_OR_NUM;
				cmd_data->cmd_data[num_args].integer = subitem->valueint;
				cmd_data->cmd_data[num_args].number = subitem->valuedouble;
				num_args++;
			}
			else if (cJSON_IsString(subitem)) {
				IOT_DEBUG("[%d] %s", num_args, cJSON_GetStringValue(subitem));
				cmd_data->args_str[num_args] = NULL;
				cmd_data->cmd_data[num_args].type = IOT_CAP_VAL_TYPE_STRING;
				cmd_data->cmd_data[num_args].string = strdup(cJSON_GetStringValue(subitem));
				num_args++;
			}
			else if (cJSON_IsObject(subitem)) {
				arg_json = subitem->child;
				while (arg_json != NULL) {
					cmd_data->args_str[num_args] = strdup(arg_json->string);
					if (cJSON_IsNumber(arg_json)) {
						IOT_DEBUG("[%d] %d | %f", num_args, arg_json->valueint, arg_json->valuedouble);
						cmd_data->cmd_data[num_args].type = IOT_CAP_VAL_TYPE_INT_OR_NUM;
						cmd_data->cmd_data[num_args].integer = arg_json->valueint;
						cmd_data->cmd_data[num_args].number = arg_json->valuedouble;
					} else if (cJSON_IsString(arg_json)) {
						IOT_DEBUG("[%d] %s", num_args, cJSON_GetStringValue(arg_json));
						cmd_data->cmd_data[num_args].type = IOT_CAP_VAL_TYPE_STRING;
						cmd_data->cmd_data[num_args].string = strdup(cJSON_GetStringValue(arg_json));
					}
					num_args++;
					arg_json = arg_json->next;
				}
			}
			subitem = subitem->next;
		}
	}
	cmd_data->num_args = num_args;

	return IOT_ERROR_NONE;
}


#if defined(STDK_IOT_CORE_SERIALIZE_CBOR)
static iot_error_t _iot_make_evt_data_cbor(const char* component, const char* capability,
			uint8_t arr_size, iot_cap_evt_data_t** evt_data_arr, iot_cap_msg_t *msg)
{
	CborEncoder root = {0};
	CborEncoder root_map = {0};
	CborEncoder event_array = {0};
	CborEncoder event_map = {0};
	CborEncoder sub_array = {0};
	CborEncoder provider_map = {0};
	char time_in_ms[16] = {0}; /* 155934720000 is '2019-06-01 00:00:00.00 UTC' */
	uint8_t *buf;
	uint8_t *tmp;
	size_t buflen = 128;
	size_t olen;
	char **str_array_ptr;
	int i;
	int j;

	if (!msg) {
		IOT_ERROR("msg is NULL");
		return IOT_ERROR_INVALID_ARGS;
	}
retry:
	buflen += 128;

	buf = (uint8_t *)malloc(buflen);
	if (buf == NULL) {
		IOT_ERROR("failed to malloc for cbor");
		return IOT_ERROR_MEM_ALLOC;
	}
	memset(buf, 0, buflen);

	cbor_encoder_init(&root, buf, buflen, 0);

	cbor_encoder_create_map(&root, &root_map, CborIndefiniteLength);

	cbor_encode_text_stringz(&root_map, "deviceEvents");
	cbor_encoder_create_array(&root_map, &event_array, CborIndefiniteLength);

	cbor_encoder_create_map(&event_array, &event_map, CborIndefiniteLength);

	for (i = 0; i < arr_size; i++) {
		/* component */
		cbor_encode_text_stringz(&event_map, "component");
		cbor_encode_text_stringz(&event_map, component);

		/* capability */
		cbor_encode_text_stringz(&event_map, "capability");
		cbor_encode_text_stringz(&event_map, capability);

		/* attribute */
		cbor_encode_text_stringz(&event_map, "attribute");
		cbor_encode_text_stringz(&event_map, evt_data_arr[i]->evt_type);

		/* value */
		cbor_encode_text_stringz(&event_map, "value");
		switch (evt_data_arr[i]->evt_value.type) {
		case IOT_CAP_VAL_TYPE_INTEGER:
			cbor_encode_int(&event_map, evt_data_arr[i]->evt_value.integer);
			break;
		case IOT_CAP_VAL_TYPE_NUMBER:
			cbor_encode_double(&event_map, evt_data_arr[i]->evt_value.number);
			break;
		case IOT_CAP_VAL_TYPE_STRING:
			cbor_encode_text_stringz(&event_map, evt_data_arr[i]->evt_value.string);
			break;
		case IOT_CAP_VAL_TYPE_STR_ARRAY:
			cbor_encoder_create_array(&event_map, &sub_array, CborIndefiniteLength);
			str_array_ptr = (char **)evt_data_arr[i]->evt_value.strings;
			for (j = 0; j < evt_data_arr[i]->evt_value.str_num; j++) {
				cbor_encode_text_stringz(&sub_array, str_array_ptr[j]);
			}
			cbor_encoder_close_container_checked(&event_map, &sub_array);
			break;
		default:
			IOT_ERROR("'%s' is not supported event type",
					evt_data_arr[i]->evt_value.type);
			goto exit_failed;
		}

		/* unit */
		if (evt_data_arr[i]->evt_unit.type == IOT_CAP_UNIT_TYPE_STRING) {
			cbor_encode_text_stringz(&event_map, "unit");
			cbor_encode_text_stringz(&event_map, evt_data_arr[i]->evt_unit.string);
		}

		/* providerData */
		cbor_encode_text_stringz(&event_map, "providerData");
		cbor_encoder_create_map(&event_map, &provider_map, CborIndefiniteLength);
		cbor_encode_text_stringz(&provider_map, "sequenceNumber");
		cbor_encode_int(&provider_map, sqnum);
		if (iot_get_time_in_ms(time_in_ms, sizeof(time_in_ms))) {
			IOT_WARN("cannot add timestamp");
		} else {
			cbor_encode_text_stringz(&provider_map, "timestamp");
			cbor_encode_text_stringz(&provider_map, time_in_ms);
		}
		cbor_encoder_close_container_checked(&event_map, &provider_map);
	}

	cbor_encoder_close_container_checked(&event_array, &event_map);
	cbor_encoder_close_container_checked(&root_map, &event_array);
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

	msg->msg = (char *)buf;
	msg->msglen = olen;

	return IOT_ERROR_NONE;

exit_failed:
	free(buf);

	return IOT_ERROR_INVALID_ARGS;
}

#else /* !STDK_IOT_CORE_SERIALIZE_CBOR */
static iot_error_t _iot_make_evt_data_json(const char* component, const char* capability,
			uint8_t arr_size, iot_cap_evt_data_t** evt_data_arr, iot_cap_msg_t *msg)
{
	char *data = NULL;
	cJSON *evt_root = NULL;
	cJSON *evt_arr = NULL;
	cJSON *evt_item = NULL;
	cJSON *evt_subarr = NULL;
	cJSON *prov_data = NULL;
	char time_in_ms[16]; /* 155934720000 is '2019-06-01 00:00:00.00 UTC' */
	iot_error_t err = IOT_ERROR_NONE;

	if (!msg) {
		IOT_ERROR("msg is NULL");
		return IOT_ERROR_INVALID_ARGS;
	}

	evt_root = cJSON_CreateObject();
	evt_arr = cJSON_CreateArray();

	for (int i = 0; i < arr_size; i++) {
		evt_item = cJSON_CreateObject();

		/* component */
		cJSON_AddStringToObject(evt_item, "component", component);

		/* capability */
		cJSON_AddStringToObject(evt_item, "capability", capability);

		/* attribute */
		cJSON_AddStringToObject(evt_item, "attribute", evt_data_arr[i]->evt_type);

		/* value */
		if (evt_data_arr[i]->evt_value.type == IOT_CAP_VAL_TYPE_INTEGER) {
			cJSON_AddNumberToObject(evt_item, "value", evt_data_arr[i]->evt_value.integer);
		} else if (evt_data_arr[i]->evt_value.type == IOT_CAP_VAL_TYPE_NUMBER) {
			cJSON_AddNumberToObject(evt_item, "value", evt_data_arr[i]->evt_value.number);
		} else if (evt_data_arr[i]->evt_value.type == IOT_CAP_VAL_TYPE_STRING) {
			cJSON_AddStringToObject(evt_item, "value", evt_data_arr[i]->evt_value.string);
		} else if (evt_data_arr[i]->evt_value.type == IOT_CAP_VAL_TYPE_STR_ARRAY) {
			evt_subarr = cJSON_CreateStringArray(
				(const char**)evt_data_arr[i]->evt_value.strings, evt_data_arr[i]->evt_value.str_num);
			cJSON_AddItemToObject(evt_item, "value", evt_subarr);
		} else {
			IOT_ERROR("Event data value type error :%d", evt_data_arr[i]->evt_value.type);
			err = IOT_ERROR_INVALID_ARGS;
			goto out;
		}

		/* unit */
		if (evt_data_arr[i]->evt_unit.type == IOT_CAP_UNIT_TYPE_STRING)
			cJSON_AddStringToObject(evt_item, "unit", evt_data_arr[i]->evt_unit.string);

		/* providerData */
		prov_data = cJSON_CreateObject();
		cJSON_AddNumberToObject(prov_data, "sequenceNumber", sqnum);

		if (iot_get_time_in_ms(time_in_ms, sizeof(time_in_ms)) != IOT_ERROR_NONE)
			IOT_WARN("Cannot add optional timestamp value");
		else
			cJSON_AddStringToObject(prov_data, "timestamp", time_in_ms);

		cJSON_AddItemToObject(evt_item, "providerData", prov_data);

		cJSON_AddItemToArray(evt_arr, evt_item);
	}

	cJSON_AddItemToObject(evt_root, "deviceEvents", evt_arr);

	data = cJSON_PrintUnformatted(evt_root);
	if (!data) {
		err = IOT_ERROR_MEM_ALLOC;
	} else {
		IOT_DEBUG("%s", data);
		msg->msg = data;
		msg->msglen = strlen(data);
	}

out:
	if (evt_root != NULL)
		cJSON_Delete(evt_root);

	return err;
}
#endif /* STDK_IOT_CORE_SERIALIZE_CBOR */

static iot_error_t _iot_make_evt_data(const char* component, const char* capability,
			uint8_t arr_size, iot_cap_evt_data_t** evt_data_arr, iot_cap_msg_t *msg)
{
#if defined(STDK_IOT_CORE_SERIALIZE_CBOR)
	return _iot_make_evt_data_cbor(component, capability, arr_size, evt_data_arr, msg);
#else
	return _iot_make_evt_data_json(component, capability, arr_size, evt_data_arr, msg);
#endif
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
	if (val == NULL) {
		return;
	}

	if (val->type == IOT_CAP_VAL_TYPE_STRING
				&& val->string != NULL) {
		free(val->string);
	}
	else if (val->type == IOT_CAP_VAL_TYPE_STR_ARRAY
				&& val->strings != NULL) {
		for (int i = 0; i < val->str_num; i++) {
			if (val->strings[i] != NULL) {
				free(val->strings[i]);
			}
		}
		free(val->strings);
	}
}

static void _iot_free_unit(iot_cap_unit_t* unit)
{
	if (unit == NULL) {
		return;
	}

	if (unit->type == IOT_CAP_UNIT_TYPE_STRING
				&& unit->string != NULL) {
		free(unit->string);
	}
}

static void _iot_free_cmd_data(iot_cap_cmd_data_t* cmd_data)
{
	if (cmd_data == NULL) {
		return;
	}

	for (int i = 0; i < cmd_data->num_args; i++) {
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
		free((void *)evt_data->evt_type);
	}
	_iot_free_val(&evt_data->evt_value);
	_iot_free_unit(&evt_data->evt_unit);
}
/* External API */
