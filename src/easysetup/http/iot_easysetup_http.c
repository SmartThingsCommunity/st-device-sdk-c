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
#include "lwip_httpd/httpd.h"
#include "lwip_httpd/fs.h"

#include "cJSON.h"
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

#define LWIP_HTTPD_POST_MAX_PAYLOAD_LEN     512
static char *http_post_payload;
static u16_t http_post_payload_len = 0;
static int post_cmd_index;
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

err_t httpd_post_begin(void *connection, const char *uri, const char *http_request,
					u16_t http_request_len, int content_len, char *response_uri,
					u16_t response_uri_len, u8_t *post_auto_wnd)
{
	int i;

	if (!uri || (uri[0] == '\0') || (uri[0] != '/'))
		return ERR_ARG;

	for (i = 0; i < ARRAY_SIZE(post_cgi_cmds); i++) {
		if (!strcmp(&uri[1], post_cgi_cmds[i])) {
			post_cmd_index = i;
			break;
		}
	}
	if (i == ARRAY_SIZE(post_cgi_cmds))
		return ERR_ARG;

	return ERR_OK;
}

err_t httpd_post_receive_data(void *connection, struct pbuf *p)
{
	struct pbuf *q = p;
	u32_t http_post_payload_full_flag = 0;

	ENTER();

	memset(http_post_payload, '\0', LWIP_HTTPD_POST_MAX_PAYLOAD_LEN);

	while(q != NULL)
	{
		if(http_post_payload_len + q->len <= LWIP_HTTPD_POST_MAX_PAYLOAD_LEN) {
			memcpy(http_post_payload+http_post_payload_len, q->payload, q->len);
			http_post_payload_len += q->len;
		} else {
			http_post_payload_full_flag = 1;
			break;
		}
		q = q->next;
	}

	pbuf_free(p);

	if (http_post_payload_full_flag) {
		http_post_payload_full_flag = 0;
		http_post_payload_len = 0;
	} else {
		IOT_DEBUG("payload=%s", http_post_payload);
		http_post_payload_len = 0;
	}
	return ERR_OK;
}

void httpd_post_finished(void *connection, char *response_uri, u16_t response_uri_len)
{
	snprintf(response_uri, response_uri_len, IOT_ES_URI_GET_POST_RESPONSE"?%s", post_cgi_cmds[post_cmd_index]);
	IOT_DEBUG("%s", response_uri);
}

static inline bool _is_400_error(iot_error_t err)
{
	if (err <= IOT_ERROR_EASYSETUP_400_BASE
		&& err > IOT_ERROR_EASYSETUP_500_BASE)
		return true;
	else
		return false;
}

void httpd_cgi_handler(const char* uri, int iNumParams, char **pcParam, char **pcValue, void *connection_state)
{
	struct fs_file *file = (struct fs_file *) connection_state;
	unsigned int buffer_len;
	char *buffer = NULL;
	char *payload = NULL;
	char *ptr = NULL;
	cJSON *root = NULL;
	cJSON *item = NULL;
	iot_error_t err = IOT_ERROR_NONE;

	if (!file)
		return;

	if (!strcmp(uri, IOT_ES_URI_GET_POST_RESPONSE)) {
		if (!iNumParams) {
			IOT_WARN("invalid arg %d", iNumParams);
			err = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		} else {
			err = _iot_easysetup_gen_post_payload(context, pcParam[0], http_post_payload, &payload);
			if (!err) {
				buffer_len = strlen(payload) + strlen(http_status_200) + strlen(http_header) + 9;

				if ((buffer = (char *)malloc(buffer_len)) == NULL) {
					IOT_ERROR("failed to malloc for buffer");
					goto cgi_out;
				}
				snprintf(buffer, buffer_len, "%s%s%4d\r\n\r\n%s",
						http_status_200, http_header, (int)strlen(payload), payload);
				IOT_INFO("%s ok", pcParam[0]);
			} else if (err == IOT_ERROR_EASYSETUP_INVALID_CMD) {
				goto cgi_out;
			} else {
				IOT_INFO("%s not ok", pcParam[0]);
			}
		}
	} else {
		err = _iot_easysetup_gen_get_payload(context, uri, &payload);
		if (!err) {
			buffer_len = strlen(payload) + strlen(http_status_200) + strlen(http_header) + 9;

			if ((buffer = (char *)malloc(buffer_len)) == NULL) {
				IOT_ERROR("failed to malloc for buffer");
				goto cgi_out;
			}
			snprintf(buffer, buffer_len, "%s%s%4d\r\n\r\n%s",
						http_status_200, http_header, (int)strlen(payload), payload);
			IOT_INFO("%s ok", uri);
		} else if (err == IOT_ERROR_EASYSETUP_INVALID_CMD) {
			goto cgi_out;
		} else {
			IOT_INFO("%s not ok", pcParam[0]);
		}
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

		if ((buffer = (char *)malloc(buffer_len)) == NULL) {
			IOT_ERROR("failed to malloc for buffer");
			goto cgi_out;
		}
		if (_is_400_error(err)) {
			snprintf(buffer, buffer_len, "%s%s%4d\r\n\r\n%s",
				http_status_400, http_header, (int)strlen(ptr), ptr);
		} else {
			snprintf(buffer, buffer_len, "%s%s%4d\r\n\r\n%s",
				http_status_500, http_header, (int)strlen(ptr), ptr);
		}
	}
	IOT_DEBUG("%s", buffer);

	file->data = buffer;
	file->len = file->index = strlen(buffer);
	file->pextension = NULL;
	file->flags = FS_FILE_FLAGS_HEADER_INCLUDED;

cgi_out:
	if (root)
		cJSON_Delete(root);
	if (payload)
		free(payload);
	if (ptr)
		free(ptr);
}

int fs_open_custom(struct fs_file *file, const char *name)
{
	int ret = 0;
	int i;

	for (i = 0; i < ARRAY_SIZE(get_cgi_cmds) ; i++) {
		if (!strcmp(name,  get_cgi_cmds[i])) {
			file->state = file;
			ret = 1;
			break;
		}
	}

	if (!ret)
		IOT_WARN("not supported uri <%s>", name);

	return ret;
}

void fs_close_custom(struct fs_file *file)
{
	if (file->data) {
		free((void*)file->data);
		file->data = NULL;
		file->len = file->index = 0;
	}
}

void *fs_state_init(struct fs_file *file, const char *name) { return NULL; }
void fs_state_free(struct fs_file *file, void *state) { return; }

iot_error_t iot_easysetup_init(struct iot_context *ctx)
{
	ENTER();
	if (!ctx)
		return IOT_ERROR_INVALID_ARGS;

	context = ctx;

	ctx->es_httpd_handle = es_httpd_init();

	if (ctx->es_httpd_handle == NULL) {
		IOT_ERROR("es_httpd_init failed");
		return IOT_ERROR_UNINITIALIZED;
	} else {
		if (!http_post_payload) {
			http_post_payload = malloc(LWIP_HTTPD_POST_MAX_PAYLOAD_LEN);
			if (!http_post_payload) {
				es_httpd_deinit(ctx->es_httpd_handle);
				return IOT_ERROR_MEM_ALLOC;
			}
			http_post_payload_len = 0;
		}
	}
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
	if (!ctx || !ctx->es_httpd_handle)
		return;
	es_httpd_deinit(ctx->es_httpd_handle);
	ctx->es_httpd_handle = NULL;
#if defined(CONFIG_STDK_IOT_CORE_EASYSETUP_HTTP_LOG_SUPPORT)
	dump_enable = false;
	free(log_buffer);
#endif
	free(http_post_payload);
	http_post_payload = NULL;
	IOT_INFO("es_httpd_deinit done");
}
