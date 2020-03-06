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

#include <string.h>
#include "cJSON.h"
#include "es_tcp_httpd.h"
#include "iot_main.h"
#include "iot_internal.h"
#include "iot_debug.h"
#include "iot_easysetup.h"
#include "iot_bsp_wifi.h"

static struct iot_context *context;

static const char http_status_200[] = "HTTP/1.1 200 OK";
static const char http_status_400[] = "HTTP/1.1 400 Bad Request";
static const char http_status_500[] = "HTTP/1.1 500 Internal Server Error";
static const char http_header[] = "\r\nServer: SmartThings Device SDK\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: ";

#define MAX_PAYLOAD_LENGTH	1024
#define ARRAY_SIZE(x) (int)(sizeof(x)/sizeof(x[0]))

static int ref_step;
#if defined(CONFIG_STDK_IOT_CORE_EASYSETUP_HTTP_LOG_SUPPORT)
static bool dump_enable;
static char *log_buffer;
unsigned int log_len;
#endif

const char *post_cgi_cmds[]=
{
	IOT_ES_URI_POST_KEYINFO,
	IOT_ES_URI_POST_CONFIRMINFO,
	IOT_ES_URI_POST_CONFIRM,
	IOT_ES_URI_POST_WIFIPROVISIONINGINFO,
	IOT_ES_URI_POST_SETUPCOMPLETE,
	IOT_ES_URI_POST_LOGS,
};

const char *get_cgi_cmds[]=
{
	IOT_ES_URI_GET_DEVICEINFO,
	IOT_ES_URI_GET_WIFISCANINFO,
	IOT_ES_URI_GET_POST_RESPONSE,
	IOT_ES_URI_GET_LOGS_SYSTEMINFO,
	IOT_ES_URI_GET_LOGS_DUMP,
};

#if defined(CONFIG_STDK_IOT_CORE_EASYSETUP_HTTP_LOG_SUPPORT)
void iot_debug_save_log(char* buf)
{
	if(dump_enable) {
		if ((strlen(log_buffer) + strlen(buf) + 4) > MAX_PAYLOAD_LENGTH)
			log_len = 0;
		log_len += snprintf(log_buffer + log_len, strlen(buf) + 4, "%s\n", buf);
		log_buffer[log_len] = '\n';
	}
}

char *iot_debug_get_log(void)
{
	return log_buffer;
}
#endif

/**
 * @brief	http GET method payload handler
 * @details	This function handle GET method cgi request
 * @param[in]	ctx		iot_context handle
 * @param[in]	cmd		GET method uri
 * @param[out]	out_payload		output payload buffer for GET method. caller has full responsibility to free this memory.
 * @return	iot_error_t
 * @retval	IOT_ERROR_NONE		success
 */
iot_error_t _iot_easysetup_gen_get_payload(struct iot_context *ctx, const char *cmd, char **out_payload)
{
	iot_error_t err = IOT_ERROR_NONE;
	struct iot_easysetup_payload response;
	int cur_step;

	if (!strcmp(cmd, IOT_ES_URI_GET_DEVICEINFO)) {
		cur_step = IOT_EASYSETUP_STEP_DEVICEINFO;
		err = iot_state_update(ctx, IOT_STATE_PROV_CONN_MOBILE, 0);
		if (err != IOT_ERROR_NONE) {
			IOT_ERROR("failed handle cmd (%d): %d", IOT_STATE_PROV_CONN_MOBILE, err);
			err = IOT_ERROR_EASYSETUP_INTERNAL_SERVER_ERROR;
			goto fail_status_update;
		}
	} else if (!strcmp(cmd, IOT_ES_URI_GET_WIFISCANINFO)) {
		cur_step = IOT_EASYSETUP_STEP_WIFISCANINFO;
	} else if (!strcmp(cmd, IOT_ES_URI_GET_LOGS_SYSTEMINFO)) {
		cur_step = IOT_EASYSETUP_STEP_LOG_SYSTEMINFO;
	} else if (!strcmp(cmd, IOT_ES_URI_GET_LOGS_DUMP)) {
		cur_step = IOT_EASYSETUP_STEP_LOG_GET_DUMP;
	} else {
		err = IOT_ERROR_EASYSETUP_INVALID_CMD;
		IOT_ERROR("Invalid command %s", cmd);
		goto get_exit;
	}

	if ((cur_step != ref_step) && (cur_step < IOT_EASYSETUP_STEP_LOG_SYSTEMINFO)) {
		if ((cur_step == IOT_EASYSETUP_STEP_WIFISCANINFO) && (ref_step == IOT_EASYSETUP_STEP_CONFIRM)) {
			ref_step = IOT_EASYSETUP_STEP_WIFISCANINFO;
		} else {
			err = IOT_ERROR_EASYSETUP_INVALID_CMD;
			IOT_ERROR("Invalid command step %s", cmd);
			goto get_exit;
		}
	}

	if (cur_step < IOT_EASYSETUP_STEP_LOG_SYSTEMINFO)
		ref_step++;

	err = iot_easysetup_request(ctx, cur_step, NULL);
	if (err) {
		IOT_ERROR("easysetup request failed %d (%d)", cur_step, err);
		err = IOT_ERROR_EASYSETUP_INTERNAL_SERVER_ERROR;
		goto get_exit;
	}
	IOT_INFO("waiting.. response for [%s]", cmd);
	iot_os_eventgroup_wait_bits(ctx->iot_events,
			IOT_EVENT_BIT_EASYSETUP_RESP, true, false, IOT_OS_MAX_DELAY);
	err = iot_os_queue_receive(ctx->easysetup_resp_queue, &response, 0);
	if (response.step != cur_step) {
		IOT_ERROR("unexpected response %d:%d", cur_step, response.step);
		if (response.payload)
			free(response.payload);
		err = IOT_ERROR_EASYSETUP_INTERNAL_SERVER_ERROR;
	} else {
		if (!response.err) {
			*out_payload = response.payload;
			IOT_DEBUG("payload: %s", *out_payload);
		}
		err = response.err;
	}

fail_status_update:
	if (err) {
		iot_error_t err1;
		ref_step = 0;
		err1 = iot_state_update(ctx, IOT_STATE_CHANGE_FAILED, ctx->curr_state);
		if (err1) {
			IOT_ERROR("cannot update state to failed (%d)", err1);
			err = IOT_ERROR_EASYSETUP_INTERNAL_SERVER_ERROR;
		}
	}

get_exit:
	return err;
}

/**
 * @brief		http POST method payload handler
 * @details		This function handle POST method cgi request
 * @param[in]		ctx		iot_context handle
 * @param[in]		cmd		POST method uri
 * @param[in]		in_payload	client updated payload via POST method has given to here. this shouldn't be freed inside of this function.
 * @param[out]		out_payload	output payload for http response. caller has full responsibility to free this memory
 * @return		iot_error_t
 * @retval		IOT_ERROR_NONE		success
 */
iot_error_t _iot_easysetup_gen_post_payload(struct iot_context *ctx, const char *cmd, char *in_payload, char **out_payload)
{
	iot_error_t err = IOT_ERROR_NONE;
	struct iot_easysetup_payload response;
	int cur_step;
	unsigned int curr_event;

	if (!in_payload)
		return IOT_ERROR_EASYSETUP_INVALID_REQUEST;

	if (!strcmp(cmd, IOT_ES_URI_POST_KEYINFO)) {
		cur_step = IOT_EASYSETUP_STEP_KEYINFO;
	} else if (!strcmp(cmd, IOT_ES_URI_POST_CONFIRMINFO)) {
		cur_step = IOT_EASYSETUP_STEP_CONFIRMINFO;
	} else if (!strcmp(cmd, IOT_ES_URI_POST_CONFIRM)) {
		cur_step = IOT_EASYSETUP_STEP_CONFIRM;
	} else if (!strcmp(cmd, IOT_ES_URI_POST_WIFIPROVISIONINGINFO)) {
		cur_step = IOT_EASYSETUP_STEP_WIFIPROVIONINGINFO;
	} else if (!strcmp(cmd, IOT_ES_URI_POST_SETUPCOMPLETE)) {
		cur_step = IOT_EASYSETUP_STEP_SETUPCOMPLETE;
	} else if (!strcmp(cmd, IOT_ES_URI_POST_LOGS)) {
		cur_step = IOT_EASYSETUP_STEP_LOG_CREATE_DUMP;
	} else {
		err = IOT_ERROR_EASYSETUP_INVALID_CMD;
		IOT_ERROR("Invalid command %s", cmd);
		goto post_exit;
	}

	if ((cur_step != ref_step) && (cur_step < IOT_EASYSETUP_STEP_LOG_SYSTEMINFO)) {
		if (cur_step == IOT_EASYSETUP_STEP_WIFIPROVIONINGINFO) {
		   if ((ref_step == IOT_EASYSETUP_STEP_CONFIRM) || (ref_step == IOT_EASYSETUP_STEP_CONFIRMINFO))
			   ref_step = IOT_EASYSETUP_STEP_WIFIPROVIONINGINFO;
		   else {
			   err = IOT_ERROR_EASYSETUP_INVALID_CMD;
			   IOT_ERROR("Invalid command step %s", cmd);
			   goto post_exit;
		   }
		} else {
			err = IOT_ERROR_EASYSETUP_INVALID_CMD;
			IOT_ERROR("Invalid command step %s", cmd);
			goto post_exit;
		}
	}

	if (cur_step < IOT_EASYSETUP_STEP_LOG_SYSTEMINFO)
		ref_step++;

	err = iot_easysetup_request(ctx, cur_step, in_payload);
	if (err) {
		IOT_ERROR("easysetup request failed %d (%d)", cur_step, err);
		goto post_exit;
	}
	IOT_INFO("waiting.. response for [%s]", cmd);

	for( ; ; ) {
		curr_event = iot_os_eventgroup_wait_bits(ctx->iot_events,
				IOT_EVENT_BIT_EASYSETUP_RESP, true, false, IOT_OS_MAX_DELAY);
		if (curr_event & IOT_EVENT_BIT_EASYSETUP_RESP)
			break;
	}

	err = iot_os_queue_receive(ctx->easysetup_resp_queue, &response, 0);
	if (response.step != cur_step) {
		IOT_ERROR("unexpected response %d:%d", cur_step, response.step);
		if (response.payload)
			free(response.payload);
		err = IOT_ERROR_EASYSETUP_INTERNAL_SERVER_ERROR;
	} else {
		if (!response.err) {
			*out_payload = response.payload;
			IOT_DEBUG("payload: %s", *out_payload);
		}
		err = response.err;
	}

	if (err) {
		iot_error_t err1;
		ref_step = 0;
		err1 = iot_state_update(ctx, IOT_STATE_CHANGE_FAILED, ctx->curr_state);
		if (err1) {
			IOT_ERROR("cannot update state to failed (%d)", err1);
			err = IOT_ERROR_EASYSETUP_INTERNAL_SERVER_ERROR;
		}
	} else {
		iot_error_t err1;
		switch (cur_step) {
		case IOT_EASYSETUP_STEP_SETUPCOMPLETE:
			err1 = iot_state_update(ctx, IOT_STATE_PROV_DONE, 0);
			if (err1) {
				IOT_ERROR("cannot update state to prov_done (%d)", err1);
				err = IOT_ERROR_EASYSETUP_INTERNAL_SERVER_ERROR;
			}
			break;
		case IOT_EASYSETUP_STEP_CONFIRMINFO:
		case IOT_EASYSETUP_STEP_CONFIRM:
		case IOT_EASYSETUP_STEP_WIFIPROVIONINGINFO:
			break;
		}
	}
post_exit:
	return err;
}
static inline bool _is_400_error(iot_error_t err)
{
	if (err <= IOT_ERROR_EASYSETUP_400_BASE
		&& err > IOT_ERROR_EASYSETUP_500_BASE)
		return true;
	else
		return false;
}

static void http_msg_handler(const char* uri, char **buffer, enum cgi_type type, char* data_buf)
{
	unsigned int buffer_len;
	char *buf = NULL;
	char *payload = NULL;
	char *ptr = NULL;
	cJSON *root = NULL;
	cJSON *item = NULL;
	iot_error_t err = IOT_ERROR_NONE;

	if (type == POST) {
			err = _iot_easysetup_gen_post_payload(context, uri, data_buf, &payload);
			if (!err) {
				buffer_len = strlen(payload) + strlen(http_status_200) + strlen(http_header) + 9;
				buf = malloc(buffer_len);
				if (!buf) {
					IOT_ERROR("failed to malloc buffer for the post msg");
					goto cgi_out;
				}
				snprintf(buf, buffer_len, "%s%s%4d\r\n\r\n%s",
						http_status_200, http_header, (int)strlen(payload), payload);
				IOT_INFO("%s ok", uri);
			} else if (err == IOT_ERROR_EASYSETUP_INVALID_CMD) {
				goto cgi_out;
			} else {
				IOT_INFO("%s not ok", uri);
			}
	} else if (type == GET) {
		err = _iot_easysetup_gen_get_payload(context, uri, &payload);
		if (!err) {
			buffer_len = strlen(payload) + strlen(http_status_200) + strlen(http_header) + 9;
			buf = malloc(buffer_len);
			if (!buf) {
				IOT_ERROR("failed to malloc buffer for the get msg");
				goto cgi_out;
			}
			snprintf(buf, buffer_len, "%s%s%4d\r\n\r\n%s",
						http_status_200, http_header, (int)strlen(payload), payload);
			IOT_INFO("%s ok", uri);
		} else if (err == IOT_ERROR_EASYSETUP_INVALID_CMD) {
			goto cgi_out;
		} else {
			IOT_INFO("%s not ok", uri);
		}
	} else {
		IOT_ERROR("Not supported curl message type : %d", type);
		err = IOT_ERROR_EASYSETUP_INVALID_CMD;
	}

	if (err) {
		item = cJSON_CreateObject();
		if (!item) {
			IOT_ERROR("json create failed");
			goto cgi_out;
		}
		cJSON_AddItemToObject(item, "code", cJSON_CreateNumber((double) err));
		cJSON_AddItemToObject(item, "message", cJSON_CreateString(""));
		root = cJSON_CreateObject();
		if (!root) {
			IOT_ERROR("json create failed");
			cJSON_Delete(item);
			goto cgi_out;
		}
		cJSON_AddItemToObject(root, "error", (cJSON *)item);

		ptr = cJSON_PrintUnformatted(root);
		IOT_DEBUG("%s", ptr);

		buffer_len = strlen(ptr) + strlen(http_status_500) + strlen(http_header) + 9;
		buf = malloc(buffer_len);
		if (!buf) {
			IOT_ERROR("failed to malloc buffer for the error msg");
			goto cgi_out;
		}
		if (_is_400_error(err)) {
			snprintf(buf, buffer_len, "%s%s%4d\r\n\r\n%s",
				http_status_400, http_header, (int)strlen(ptr), ptr);
		} else {
			snprintf(buf, buffer_len, "%s%s%4d\r\n\r\n%s",
				http_status_500, http_header, (int)strlen(ptr), ptr);
		}
	}
	IOT_DEBUG("%s", buf);
	*buffer = buf;

cgi_out:
	if (root)
		cJSON_Delete(root);
	if (payload)
		free(payload);
	if (ptr)
		free(ptr);
}

void http_packet_handle(const char *name, char **buf, char *payload, enum cgi_type type)
{
	bool msg_processed = false;
	int i;

	if (type == GET) {
		for (i = 0; i < ARRAY_SIZE(get_cgi_cmds) ; i++) {
			if (!strcmp(name,  get_cgi_cmds[i])) {
					http_msg_handler(name, buf, GET, payload);
				msg_processed = true;
				break;
			}
		}
	} else if (type == POST) {
		for (i = 0; i < ARRAY_SIZE(post_cgi_cmds) ; i++) {
			if (!strcmp(name,  post_cgi_cmds[i])) {
				http_msg_handler(name, buf, POST, payload);
				msg_processed = true;
				break;
			}
		}
	}

	if (!msg_processed) {
		IOT_WARN("not supported uri <%s>", name);
		http_msg_handler(name, buf, ERROR, payload);
	}
}

iot_error_t iot_easysetup_init(struct iot_context *ctx)
{
	ENTER();
	if (!ctx)
		return IOT_ERROR_INVALID_ARGS;

	context = ctx;

	es_tcp_init();
	ref_step = 0;

#if defined(CONFIG_STDK_IOT_CORE_EASYSETUP_HTTP_LOG_SUPPORT)
	if ((log_buffer = (char *)malloc(CONFIG_STDK_IOT_CORE_EASYSETUP_HTTP_LOG_SIZE)) == NULL) {
		IOT_ERROR("failed to malloc for log buffer");
		return IOT_ERROR_MEM_ALLOC;
		}
	memset(log_buffer, '\0', CONFIG_STDK_IOT_CORE_EASYSETUP_HTTP_LOG_SIZE);
	log_len = 0;
	dump_enable= true;
#endif
	IOT_INFO("es_httpd_init done");

	return IOT_ERROR_NONE;
}

void iot_easysetup_deinit(struct iot_context *ctx)
{
	ENTER();
	if (!ctx)
		return;

	es_tcp_deinit();

#if defined(CONFIG_STDK_IOT_CORE_EASYSETUP_HTTP_LOG_SUPPORT)
	dump_enable = false;
	free(log_buffer);
#endif
	IOT_INFO("es_httpd_deinit done");
}
