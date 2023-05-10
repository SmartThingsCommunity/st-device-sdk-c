/* ***************************************************************************
 *
 * Copyright 2021 Samsung Electronics All Rights Reserved.
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
#include "easysetup_ble.h"
#include "iot_main.h"
#include "iot_internal.h"
#include "iot_debug.h"
#include "iot_easysetup.h"
#include "iot_bsp_wifi.h"

#if defined(CONFIG_STDK_IOT_CORE_EASYSETUP_X509)
#define CONNECTION_TYPE "close"
#else
#define CONNECTION_TYPE "keep-alive"
#endif
#define MAX_PAYLOAD_LENGTH	1024
#define ARRAY_SIZE(x) (int)(sizeof(x)/sizeof(x[0]))

struct iot_context *context;
#define END_OF_HTTP_HEADER	"\r\n\r\n"
STATIC_VARIABLE int ref_step;
#if defined(CONFIG_STDK_IOT_CORE_EASYSETUP_LOG_SUPPORT_NO_USE_LOGFILE)
static bool dump_enable;
static char *log_buffer;
unsigned int log_len;
#endif

extern int trans_len;

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

bool msg_disassemble(uint8_t *buf, uint32_t len);

#if defined(CONFIG_STDK_IOT_CORE_EASYSETUP_LOG_SUPPORT_NO_USE_LOGFILE)
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
STATIC_FUNCTION
iot_error_t _iot_easysetup_gen_get_payload(struct iot_context *ctx, int cmd, char *in_payload, char **out_payload)
{
	iot_error_t err = IOT_ERROR_NONE;
	struct iot_easysetup_payload response;
	int cur_step;
	unsigned char curr_event;

	if (cmd == IOT_EASYSETUP_INVALID_STEP) {
		IOT_ERROR("Invalid command %d", cmd);
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_CMD, cmd);
		err = IOT_ERROR_EASYSETUP_INVALID_CMD;
		goto get_exit;
	}

	cur_step = cmd;

	if (cur_step == IOT_EASYSETUP_STEP_DEVICEINFO) {
		if ((ctx->status_maps & IOT_STATUS_PROVISIONING) && ctx->status_cb) {
			ctx->status_cb(IOT_STATUS_PROVISIONING, IOT_STAT_LV_CONN, ctx->status_usr_data);
			ctx->reported_stat = IOT_STATUS_PROVISIONING | IOT_STAT_LV_CONN << 8;
		}
	}

	if ((cur_step != ref_step) && (cur_step < IOT_EASYSETUP_STEP_LOG_SYSTEMINFO)) {
		if ((cur_step == IOT_EASYSETUP_STEP_WIFISCANINFO) && (ref_step == IOT_EASYSETUP_STEP_CONFIRM)) {
			ref_step = IOT_EASYSETUP_STEP_WIFISCANINFO;
		} else if ((cur_step == IOT_EASYSETUP_STEP_WIFISCANINFO) && (ref_step == IOT_EASYSETUP_STEP_WIFIPROVIONINGINFO)) {
			ref_step = IOT_EASYSETUP_STEP_WIFISCANINFO;
		} else {
			IOT_ERROR("Invalid command step %d", cmd);
			IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_CMD, cmd);
			err = IOT_ERROR_EASYSETUP_INVALID_SEQUENCE;
			goto fail_status_update;
		}
	}

	if (cur_step < IOT_EASYSETUP_STEP_LOG_SYSTEMINFO)
		ref_step++;
	else
		ref_step = 0;

	err = iot_easysetup_request(ctx, cur_step, in_payload);
	if (err) {
		IOT_ERROR("easysetup request failed %d (%d)", cur_step, err);
		if (err == IOT_ERROR_EASYSETUP_QUEUE_SEND_ERROR) {
			IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_QUEUE_FAIL, 1);
		} else {
			IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INTERNAL_SERVER_ERROR, err);
			err = IOT_ERROR_EASYSETUP_INTERNAL_SERVER_ERROR;
		}
		goto get_exit;
	}
	IOT_INFO("waiting.. response for [%d]", cmd);
	IOT_ES_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_EASYSETUP_WAIT_RESPONSE, cmd);
	curr_event = iot_os_eventgroup_wait_bits(ctx->iot_events,
			IOT_EVENT_BIT_EASYSETUP_RESP, true, IOT_OS_MAX_DELAY);
	if (curr_event & IOT_EVENT_BIT_EASYSETUP_RESP) {
		IOT_DEBUG("easysetup response for [%d]", cmd);
	} else {
		IOT_ERROR("unexpected event for [%d]: 0x%x", cmd, curr_event);
	}
	err = iot_util_queue_receive(ctx->easysetup_resp_queue, &response);
	if ((err == IOT_ERROR_NONE) && (response.step != cur_step)) {
		IOT_ERROR("unexpected response %d:%d", cur_step, response.step);
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INTERNAL_SERVER_ERROR, response.step);
		if (response.payload)
			free(response.payload);
		err = IOT_ERROR_EASYSETUP_INTERNAL_SERVER_ERROR;
	} else if (err == IOT_ERROR_NONE) {
		if (!response.err) {
			*out_payload = response.payload;
		}
		err = response.err;
	} else {
		IOT_ERROR("easysetup response queue receive failed");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_QUEUE_FAIL, 0);
		err = IOT_ERROR_EASYSETUP_QUEUE_RECV_ERROR;
	}

fail_status_update:
	if (err) {
		iot_error_t err1;
		ref_step = 0;
		if (cur_step >= IOT_EASYSETUP_STEP_LOG_SYSTEMINFO || err == IOT_ERROR_EASYSETUP_INVALID_SEQUENCE) {
			/* TODO : signaling restart onboarding */
			IOT_ERROR("mock : signaling restart onboarding %d", __LINE__);
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
STATIC_FUNCTION
iot_error_t _iot_easysetup_gen_post_payload(struct iot_context *ctx, int cmd, char *in_payload, char **out_payload)
{
	iot_error_t err = IOT_ERROR_NONE;
	struct iot_easysetup_payload response;
	int cur_step;
	unsigned char curr_event;

	if (!in_payload && cmd != IOT_EASYSETUP_STEP_SETUPCOMPLETE && cmd != IOT_EASYSETUP_STEP_LOG_CREATE_DUMP) {
		IOT_ERROR("Invalid payload");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_REQUEST, 0);
		err = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		return err;
	}

	if (cmd == IOT_EASYSETUP_INVALID_STEP) {
		IOT_ERROR("Invalid command %d", cmd);
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_CMD, cmd);
		err = IOT_ERROR_EASYSETUP_INVALID_CMD;
		goto post_exit;
	}

	cur_step = cmd;

	if ((cur_step != ref_step) && (cur_step < IOT_EASYSETUP_STEP_LOG_SYSTEMINFO)) {
		if (cur_step == IOT_EASYSETUP_STEP_WIFIPROVIONINGINFO) {
		   if ((ref_step == IOT_EASYSETUP_STEP_CONFIRM) || (ref_step == IOT_EASYSETUP_STEP_CONFIRMINFO))
			   ref_step = IOT_EASYSETUP_STEP_WIFIPROVIONINGINFO;
		   else {
			   IOT_ERROR("Invalid command sequence %d", cmd);
			   IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_SEQUENCE, cmd);
			   err = IOT_ERROR_EASYSETUP_INVALID_SEQUENCE;
			   goto post_exit;
		   }
		}
        else {
			IOT_ERROR("Invalid command sequence %d", cmd);
			IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_SEQUENCE, cmd);
			err = IOT_ERROR_EASYSETUP_INVALID_SEQUENCE;
			goto post_exit;
		}
	}

	if (cur_step < IOT_EASYSETUP_STEP_LOG_SYSTEMINFO)
		ref_step++;
	else
		ref_step = 0;

	err = iot_easysetup_request(ctx, cur_step, in_payload);
	if (err) {
		IOT_ERROR("easysetup request failed %d (%d)", cur_step, err);
		if (err == IOT_ERROR_EASYSETUP_QUEUE_SEND_ERROR) {
			IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_QUEUE_FAIL, 1);
		} else {
			IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INTERNAL_SERVER_ERROR, err);
			err = IOT_ERROR_EASYSETUP_INTERNAL_SERVER_ERROR;
		}
		goto post_exit;
	}
	IOT_INFO("waiting.. response for [%d]", cmd);
	IOT_ES_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_EASYSETUP_WAIT_RESPONSE, cmd);

	curr_event = iot_os_eventgroup_wait_bits(ctx->iot_events,
			IOT_EVENT_BIT_EASYSETUP_RESP, true, IOT_OS_MAX_DELAY);
	if (curr_event & IOT_EVENT_BIT_EASYSETUP_RESP) {
		IOT_DEBUG("easysetup response for [%d]", cmd);
	} else {
		IOT_ERROR("unexpected event for [%d]: 0x%x", cmd, curr_event);
	}

	err = iot_util_queue_receive(ctx->easysetup_resp_queue, &response);
	if ((err == IOT_ERROR_NONE) && (response.step != cur_step)) {
		IOT_ERROR("unexpected response %d:%d", cur_step, response.step);
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INTERNAL_SERVER_ERROR, response.step);
		if (response.payload)
			free(response.payload);
		err = IOT_ERROR_EASYSETUP_INTERNAL_SERVER_ERROR;
	} else if (err == IOT_ERROR_NONE) {
		if (!response.err) {
			*out_payload = response.payload;
		}
		err = response.err;
	} else {
		IOT_ERROR("easysetup response queue receive failed");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_QUEUE_FAIL, 0);
		err = IOT_ERROR_EASYSETUP_QUEUE_RECV_ERROR;
	}

	if (err) {
		iot_error_t err1;
		ref_step = 0;
		if (cur_step >= IOT_EASYSETUP_STEP_LOG_SYSTEMINFO) {
			/* TODO : signaling restart onboarding */
			IOT_ERROR("mock : signaling restart onboarding %d", __LINE__);
		}
	} else {
		iot_error_t err1;
		switch (cur_step) {
		case IOT_EASYSETUP_STEP_SETUPCOMPLETE:
			err1 = iot_state_update(ctx, IOT_STATE_PROV_DONE, 0);
			if (err1) {
				IOT_ERROR("cannot update state to prov_done (%d)", err1);
				IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INTERNAL_SERVER_ERROR, err1);
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

void ble_msg_handler(int cmd, uint8_t **buffer, enum cgi_type type, char* data_buf)
{
	char *payload = NULL;
	iot_error_t err = IOT_ERROR_NONE;

    IOT_INFO("cmd : %d", cmd);

	if (type == D2D_POST) {
		err = _iot_easysetup_gen_post_payload(context, cmd, data_buf, &payload);
		if (err) {
			IOT_INFO("post cmd[%d] not ok", cmd);
			IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_CMD_FAIL, cmd);
		}
    } else if (type == D2D_GET) {
        err = _iot_easysetup_gen_get_payload(context, cmd, data_buf, &payload);
        if (err) {
                IOT_INFO("get cmd[%d] not ok", cmd);
                IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_CMD_FAIL, cmd);
        }
	} else {
		IOT_ERROR("Not supported message type : %d", type);
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_CMD, type);
		err = IOT_ERROR_EASYSETUP_INVALID_CMD;
	}

    if (cmd == IOT_EASYSETUP_STEP_DEVICEINFO)
    {
        msg_disassemble((uint8_t*)payload, strlen(payload));
    }
    else 
    {
        msg_disassemble((uint8_t*)payload, trans_len);
    }

	if (payload)
		free(payload);
}

iot_error_t iot_easysetup_init(struct iot_context *ctx)
{
	iot_error_t err;

	ENTER();
	IOT_REMARK("IOT_STATE_PROV_ES_START");
	IOT_ES_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_EASYSETUP_INIT, 0);
	if (!ctx)
		return IOT_ERROR_INVALID_ARGS;

	err = iot_security_cipher_init(ctx->easysetup_security_context);
	if (err != IOT_ERROR_NONE) {
		IOT_ERROR("failed to init cipher");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_CIPHER_ERROR, err);
		return IOT_ERROR_EASYSETUP_CIPHER_ERROR;
	}

	context = ctx;

	ref_step = 0;

#if defined(CONFIG_STDK_IOT_CORE_EASYSETUP_LOG_SUPPORT_NO_USE_LOGFILE)
	if ((log_buffer = (char *)malloc(CONFIG_STDK_IOT_CORE_EASYSETUP_HTTP_LOG_SIZE)) == NULL) {
		IOT_ERROR("failed to malloc for log buffer");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_MEM_ALLOC_ERROR, 0);
		iot_security_cipher_deinit(ctx->easysetup_security_context);
		return IOT_ERROR_MEM_ALLOC;
		}
	memset(log_buffer, '\0', CONFIG_STDK_IOT_CORE_EASYSETUP_HTTP_LOG_SIZE);
	log_len = 0;
	dump_enable= true;
#endif

	es_ble_init();

	IOT_REMARK("IOT_STATE_PROV_ES_INIT_DONE");
	IOT_ES_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_EASYSETUP_INIT, 1);

	return IOT_ERROR_NONE;
}

void iot_easysetup_deinit(struct iot_context *ctx)
{
	iot_error_t err;

	ENTER();
	IOT_ES_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_EASYSETUP_DEINIT, 0);
	if (!ctx)
		return;

	es_ble_deinit();

#if defined(CONFIG_STDK_IOT_CORE_EASYSETUP_LOG_SUPPORT_NO_USE_LOGFILE)
	if (log_buffer) {
		dump_enable = false;
		free(log_buffer);
		log_buffer = NULL;
	}
#endif
	iot_os_eventgroup_clear_bits(ctx->iot_events, IOT_EVENT_BIT_EASYSETUP_RESP);

	err = iot_security_cipher_deinit(ctx->easysetup_security_context);
	if (err != IOT_ERROR_NONE) {
		IOT_ERROR("failed to iot_security_cipher_deinit, error (%d)", err);
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_DEINIT, err);
	} else {
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_EASYSETUP_DEINIT, 1);
	}

	IOT_REMARK("IOT_STATE_PROV_ES_DONE");
}
