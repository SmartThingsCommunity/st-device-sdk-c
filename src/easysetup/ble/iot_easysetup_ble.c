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
#include "iot_bsp_ble.h"
#include "iot_nv_data.h"

#define MAX_PAYLOAD_LENGTH	1024

struct iot_context *context;
STATIC_VARIABLE int ref_step;
#if defined(CONFIG_STDK_IOT_CORE_EASYSETUP_LOG_SUPPORT_NO_USE_LOGFILE)
static bool dump_enable;
static char *log_buffer;
unsigned int log_len;

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
 * @brief            ble event callback
 * @details          This function handle ble event
 * @param[in]        event           ble event
 * @param[in]        error           error code for gatt connection
 */
STATIC_FUNCTION
void _iot_easysetup_ble_event_cb(iot_ble_event_t event, iot_error_t error)
{
	iot_error_t err = IOT_ERROR_NONE;

	switch (event) {
		case IOT_BLE_EVENT_GATT_JOIN:
			IOT_INFO("BLE Gatt Connection");
			ref_step = 0;
			break;
		case IOT_BLE_EVENT_GATT_LEAVE:
			IOT_INFO("BLE Gatt Disconnection");
			st_conn_ownership_confirm((IOT_CTX *)context, true);
			iot_os_eventgroup_clear_bits(context->iot_events, IOT_EVENT_BIT_EASYSETUP_RESP);
			if (context->easysetup_security_context->cipher_params) {
				err = iot_security_cipher_deinit(context->easysetup_security_context);
				if (err != IOT_ERROR_NONE) {
					IOT_ERROR("failed to iot_security_cipher_deinit, error (%d)", err);
					IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_DEINIT, err);
				} else {
					IOT_ES_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_EASYSETUP_DEINIT, 1);
				}
			}


			if (ref_step != IOT_EASYSETUP_BLE_STEP_SETUPCOMPLETE + 1) {
				iot_device_cleanup(context);

				context->curr_state = IOT_STATE_INITIALIZED;
				iot_state_update(context, IOT_STATE_PROV_ENTER, 0);
			}


			es_reset_transferdata();
			break;
		case IOT_BLE_EVENT_GATT_FAIL:
			IOT_ERROR("BLE Gatt Connection failed %d", error);
			iot_set_st_ecode_from_conn_error(context, error);
			break;
		default:
			IOT_ERROR("Unknown event 0x%x", event);
			break;
       }
}



/**
 * @brief            ble payload handler
 * @details          This function handle ble request
 * @param[in]        ctx           iot_context handle
 * @param[in]        cmd           request cmd
 * @param[in]        in_payload    client request payload. this shouldn't be freed inside of this function.
 * @param[out]       out_payload   output payload for ble response. caller has full responsibility to free this memory
 * @param[out]       payload_len   payload length for log get dump cmd
 * @return           iot_error_t
 * @retval           IOT_ERROR_NONE       success
 */
STATIC_FUNCTION
iot_error_t _iot_easysetup_gen_payload(struct iot_context *ctx, int cmd, char *in_payload, char **out_payload, size_t *payload_len)
{
       iot_error_t err = IOT_ERROR_NONE;
       struct iot_easysetup_payload response;
       int cur_step;
       unsigned char curr_event;

       cur_step = cmd;

       if (cur_step == IOT_EASYSETUP_BLE_STEP_DEVICEINFO) {
              if ((ctx->status_maps & IOT_STATUS_PROVISIONING) && ctx->status_cb) {
                     ctx->status_cb(IOT_STATUS_PROVISIONING, IOT_STAT_LV_CONN, ctx->status_usr_data);
                     ctx->reported_stat = IOT_STATUS_PROVISIONING | IOT_STAT_LV_CONN << 8;
              }
       }

       if ((cur_step != ref_step) && (cur_step < IOT_EASYSETUP_BLE_STEP_LOG_SYSTEMINFO)) {
              if (cur_step == IOT_EASYSETUP_BLE_STEP_WIFISCANINFO) {
                     ref_step = IOT_EASYSETUP_BLE_STEP_WIFISCANINFO;
              } else if (cur_step == IOT_EASYSETUP_BLE_STEP_SETUPCOMPLETE) {
                     ref_step = IOT_EASYSETUP_BLE_STEP_SETUPCOMPLETE;
              } else if (cur_step == IOT_EASYSETUP_BLE_STEP_CONFIRMINFO) {
                     ref_step = IOT_EASYSETUP_BLE_STEP_CONFIRMINFO;
              } else {
                     IOT_ERROR("Invalid command step %d", cmd);
                     IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_CMD, cmd);
                     err = IOT_ERROR_EASYSETUP_INVALID_CMD;
                     goto post_exit;
              }
       }

	if (cur_step < IOT_EASYSETUP_BLE_STEP_LOG_SYSTEMINFO)
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
			*payload_len = response.payload_len;
		}
		err = response.err;
	} else {
		IOT_ERROR("easysetup response queue receive failed");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_QUEUE_FAIL, 0);
		err = IOT_ERROR_EASYSETUP_QUEUE_RECV_ERROR;
	}

	if (err) {
		ref_step = 0;
		if ((cur_step >= IOT_EASYSETUP_BLE_STEP_LOG_SYSTEMINFO) || (err == IOT_ERROR_EASYSETUP_INVALID_SEQUENCE)) {
			/* TODO : signaling restart onboarding */
			IOT_ERROR("mock : signaling restart onboarding %d", __LINE__);
		}
	} else {
		switch (cur_step) {
		case IOT_EASYSETUP_BLE_STEP_OFFLINE_DIAGNOSTICS_CONNECTOION_INFO:
		case IOT_EASYSETUP_BLE_STEP_OFFLINE_DIAGNOSTICS_RECOVERY:
			ref_step = 0;
			break;
		case IOT_EASYSETUP_BLE_STEP_CONFIRMINFO:
		case IOT_EASYSETUP_BLE_STEP_CONFIRM:
		case IOT_EASYSETUP_BLE_STEP_WIFIPROVIONINGINFO:
			break;
		}
	}
post_exit:
	return err;
}

STATIC_FUNCTION
iot_error_t _iot_easysetup_ble_msg_decrypt(iot_security_context_t *security_context, int cmd, unsigned char *encrypt_msg, size_t encrypt_msg_len, char **out_msg)
{
	iot_error_t err;
	iot_security_buffer_t decrypt_buf = {0 };
	iot_security_buffer_t plain_buf = { 0 };

	switch (cmd) {
		case IOT_EASYSETUP_BLE_STEP_DEVICEINFO:
		case IOT_EASYSETUP_BLE_STEP_KEYINFO:
		case IOT_EASYSETUP_BLE_STEP_LOG_SYSTEMINFO:
		case IOT_EASYSETUP_BLE_STEP_LOG_GET_DUMP:
			*out_msg = (char *)encrypt_msg;
			return IOT_ERROR_NONE;
	}

	if (!security_context->cipher_params || !encrypt_msg || encrypt_msg_len == 0) {
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INTERNAL_SERVER_ERROR, 0);
		return IOT_ERROR_EASYSETUP_INTERNAL_SERVER_ERROR;
	}

	if ((decrypt_buf.p = iot_os_malloc(encrypt_msg_len)) == NULL) {
		IOT_ERROR("failed to malloc for decode_buf");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_MEM_ALLOC_ERROR, 0);
		err = IOT_ERROR_EASYSETUP_MEM_ALLOC_ERROR;
		goto dec_fail;
	}

	decrypt_buf.len = encrypt_msg_len;

	memcpy(decrypt_buf.p, encrypt_msg, decrypt_buf.len);

	err = iot_security_cipher_aes_decrypt(security_context, &decrypt_buf, &plain_buf);
	if (err != IOT_ERROR_NONE) {
		IOT_ERROR("aes decrypt error (%d)", err);
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_AES256_DECRYPTION_ERROR, err);
		err = IOT_ERROR_EASYSETUP_AES256_DECRYPTION_ERROR;
		goto dec_fail;
	}

	iot_os_free(decrypt_buf.p);
	*out_msg = (char *)plain_buf.p;
	return IOT_ERROR_NONE;

dec_fail:
	if (decrypt_buf.p) {
		iot_os_free(decrypt_buf.p);
	}
	if (plain_buf.p) {
		iot_os_free(plain_buf.p);
	}
	return err;
}

STATIC_FUNCTION
iot_error_t _iot_easysetup_ble_msg_encrypt(struct iot_context *context, int cmd, unsigned char *payload,
                                        size_t payload_len, iot_security_buffer_t **encrypt_buf, int *buf_len)
{
	iot_error_t err = IOT_ERROR_NONE;
	iot_security_buffer_t msg_buf = { 0 };
	iot_security_context_t *security_context = context->easysetup_security_context;
	uint32_t offset = 0;
	uint32_t buf_idx;

	// payload max size = 3byte unsigned integer max - aes encryption padding size
	static const uint32_t payload_size_limit = 0x00ffffff - 16;

	if (!security_context->cipher_params || !payload) {
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INTERNAL_SERVER_ERROR, 0);
		err = IOT_ERROR_INVALID_ARGS;
		goto enc_fail;
	}

	if (payload_len == 0) {
		payload_len = strlen((char *)payload);
	}

	*buf_len = (int)(payload_len / payload_size_limit) + 1;
	*encrypt_buf = (iot_security_buffer_t *)iot_os_malloc(sizeof(iot_security_buffer_t) * (*buf_len));
	if(*encrypt_buf == NULL) {
		IOT_ERROR("memory alloc fail for encrypt buf array");
		err = IOT_ERROR_MEM_ALLOC;
		goto enc_fail;
	}
	memset(*encrypt_buf, 0, sizeof(iot_security_buffer_t) * (*buf_len));

	if ((cmd == IOT_EASYSETUP_BLE_STEP_DEVICEINFO) ||
		(cmd == IOT_EASYSETUP_BLE_STEP_LOG_GET_DUMP)) {
		for (buf_idx=0; buf_idx<*buf_len; buf_idx++) {
			if (payload_len > payload_size_limit * (buf_idx + 1)) {
				(*encrypt_buf)[buf_idx].len = payload_size_limit;
			} else {
				(*encrypt_buf)[buf_idx].len = payload_len - (payload_size_limit * buf_idx);
			}
			(*encrypt_buf)[buf_idx].p = (unsigned char *)iot_os_malloc((*encrypt_buf)[buf_idx].len);
			if(*encrypt_buf == NULL) {
				IOT_ERROR("memory alloc fail for encrypt buffer");
				err = IOT_ERROR_MEM_ALLOC;
				goto enc_fail;
			}
			memcpy((*encrypt_buf)[buf_idx].p, payload + (payload_size_limit * buf_idx), (*encrypt_buf)[buf_idx].len);
		}
	} else {
		for (buf_idx=0; buf_idx<*buf_len; buf_idx++) {
			if (payload_len > payload_size_limit * (buf_idx + 1)) {
				msg_buf.len = payload_size_limit;
			} else {
				msg_buf.len = payload_len - (payload_size_limit * buf_idx);
			}
			msg_buf.p = payload + (payload_size_limit * buf_idx);
			err = iot_security_cipher_aes_encrypt(security_context, &msg_buf, &(*encrypt_buf)[buf_idx]);
			if (err != IOT_ERROR_NONE) {
				IOT_ERROR("aes encryption error (%d)", err);
				IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_AES256_ENCRYPTION_ERROR, err);
				goto enc_fail;
			}
		}
	}

enc_fail:
	return err;
}


void iot_easysetup_ble_msg_handler(int cmd, char* data_buf, size_t data_buf_len)
{
	char *payload = NULL;
	cJSON *root = NULL;
	iot_error_t err = IOT_ERROR_NONE;
	iot_security_buffer_t *encrypted_payload = NULL;
	int encrypted_payload_len;
	char *in_payload = NULL;
	size_t payload_len = 0;
	int index;

	IOT_INFO("cmd : %d", cmd);

	if ((cmd < IOT_EASYSETUP_BLE_STEP_DEVICEINFO) || (cmd >= IOT_EASYSETUP_BLE_INVALID_STEP)) {
		IOT_ERROR("Not supported cmd : %d", cmd);
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_CMD, cmd);
		err = IOT_ERROR_EASYSETUP_INVALID_CMD;
		goto err_report;
	}

	if (cmd == IOT_EASYSETUP_BLE_STEP_SETUPCOMPLETE_RESPONSE)
		goto err_report;

	if (data_buf_len) {
		err = _iot_easysetup_ble_msg_decrypt(context->easysetup_security_context,
					cmd, (unsigned char *)data_buf, data_buf_len, &in_payload);
		if (err) {
			IOT_ERROR("message decryption fail (%d)", err);
			IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_CMD_FAIL, cmd);
			goto err_report;
		}
	}

	err = _iot_easysetup_gen_payload(context, cmd, in_payload, &payload, &payload_len);
	if (err) {
		IOT_INFO("post cmd[%d] not ok", cmd);
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_CMD_FAIL, cmd);
	}

err_report:
	if ((err) || (cmd == IOT_EASYSETUP_BLE_STEP_SETUPCOMPLETE_RESPONSE)) {
		if (payload)
			free(payload);

		payload = NULL;

		root = cJSON_CreateObject();
		if (!root) {
			IOT_ERROR("json create failed");
			IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_JSON_CREATE_ERROR, 0);
			goto out;
		}
		cJSON_AddItemToObject(root, "errorcode", cJSON_CreateNumber((double) -(err)));

		payload = cJSON_PrintUnformatted(root);
		IOT_INFO("%s", payload);
	}

	err = _iot_easysetup_ble_msg_encrypt(context, cmd, (unsigned char *)payload, payload_len, &encrypted_payload, &encrypted_payload_len);
	if (err) {
		IOT_ERROR("encryption is failed (%d)", err);
		goto out;
	}

	for (index=0; index<encrypted_payload_len; index++) {
		IOT_INFO("es_ble_msg_disassemble start [%d]", encrypted_payload[index].len);
		err = es_msg_disassemble((uint8_t*)encrypted_payload[index].p, encrypted_payload[index].len, encrypted_payload_len - index - 1, cmd + 1);
		if (err) {
			IOT_INFO("to send the message is failed[%d]", err);
			IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INTERNAL_SERVER_ERROR, err);
		}
	}

out:
	if (root) {
		JSON_DELETE(root);
	}
	if (payload) {
		free(payload);
	}
	if (encrypted_payload != NULL) {
		for (index=0; index<encrypted_payload_len; index++) {
			if (encrypted_payload[index].p != NULL) {
				iot_os_free(encrypted_payload[index].p);
				encrypted_payload[index].p = NULL;
			}
		}
		iot_os_free(encrypted_payload);
		encrypted_payload = NULL;
	}
}

iot_error_t iot_easysetup_init(struct iot_context *ctx)
{
	iot_error_t err;

	ENTER();
	IOT_REMARK("IOT_STATE_PROV_ES_START");
	IOT_ES_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_EASYSETUP_INIT, 0);
	if (!ctx)
		return IOT_ERROR_INVALID_ARGS;

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

	if (ctx->es_ble_ready == false) {
		err = iot_bsp_ble_register_event_cb(_iot_easysetup_ble_event_cb);
		if (err != IOT_ERROR_NONE) {
			IOT_WARN("wifi event callback isn't registered %d", err);
			IOT_ES_DUMP(IOT_DEBUG_LEVEL_WARN, IOT_DUMP_EASYSETUP_INIT, err);
		}

		es_ble_init();
		ctx->es_ble_ready = true;
    }
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

	if (!ctx->es_ble_ready) {
		es_ble_deinit();
	}

#if defined(CONFIG_STDK_IOT_CORE_EASYSETUP_LOG_SUPPORT_NO_USE_LOGFILE)
	if (log_buffer) {
		dump_enable = false;
		free(log_buffer);
		log_buffer = NULL;
	}
#endif
	iot_os_eventgroup_clear_bits(ctx->iot_events, IOT_EVENT_BIT_EASYSETUP_RESP);
	ref_step = 0;

	if (ctx->easysetup_security_context->cipher_params) {
		err = iot_security_cipher_deinit(ctx->easysetup_security_context);
		if (err != IOT_ERROR_NONE) {
			IOT_ERROR("failed to iot_security_cipher_deinit, error (%d)", err);
			IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_DEINIT, err);
		} else {
			IOT_ES_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_EASYSETUP_DEINIT, 1);
		}
	}

	IOT_REMARK("IOT_STATE_PROV_ES_DONE");
}
