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
#include "iot_bsp_ble.h"
#include "iot_debug.h"
#include "iot_easysetup.h"
#include "iot_internal.h"
#include "iot_main.h"
#include "iot_nv_data.h"

#define MAX_PAYLOAD_LENGTH 1024

struct iot_context *context;
STATIC_VARIABLE int ref_step;
#if defined(CONFIG_STDK_IOT_CORE_EASYSETUP_LOG_SUPPORT_NO_USE_LOGFILE)
static bool dump_enable;
static char *log_buffer;
unsigned int log_len;

void iot_debug_save_log(char *buf)
{
    if (dump_enable) {
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

STATIC_FUNCTION
iot_error_t _iot_easysetup_con_timer_init(struct iot_context *ctx)
{
    iot_error_t err = IOT_ERROR_NONE;
    int ret;

    if (ctx->cloud_con_timer) {
        iot_os_timer_delete(ctx->cloud_con_timer);
        ctx->cloud_con_timer = NULL;
    }

    ctx->cloud_con_timer = iot_os_timer_create(NULL, CLOUD_CON_TIMER_MS, ctx);
    if (!ctx->cloud_con_timer) {
        err = IOT_ERROR_BAD_REQ;
        IOT_ERROR("Failed to create cloud con timer");
    } else {
        ret = iot_os_timer_start(ctx->cloud_con_timer);
        if (ret) {
            err = IOT_ERROR_BAD_REQ;
            IOT_ERROR("Failed to start timer");
        } else {
            IOT_INFO("cloud connection start");
        }
    }

    return err;
}

void _ble_deinit_request_handler(struct iot_context *ctx, device_work_param param)
{
    ctx->es_ble_ready = false;
    es_ble_deinit();
}

void _send_ble_deinit_request()
{
    device_work_data_t work;
    iot_error_t err;

    work.handler = _ble_deinit_request_handler;
    work.param = NULL;
    work.owner_id = NULL;

    err = iot_util_queue_send(context->work_queue, &work);
    if (err != IOT_ERROR_NONE) {
        IOT_ERROR("Failed to send work queue %d", err);
        return;
    }
    iot_os_eventgroup_set_bits(context->work_queue_signal, DEVICE_PENDING_WORK_SIGNAL);
}

/**
 * @brief            ble event callback
 * @details          This function handle ble event
 * @param[in]        event           ble event
 * @param[in]        error           error code for gatt connection
 */
STATIC_FUNCTION
void _iot_easysetup_ble_conn_cb(iot_ble_conn_evt_t evt)
{
    iot_error_t err = IOT_ERROR_NONE;

    if (context->cloud_con_timer) {
        iot_os_timer_delete(context->cloud_con_timer);
        context->cloud_con_timer = NULL;
    }

    switch (evt) {
        case IOT_BLE_CONNECTION_EVENT_CONNECTED:
            IOT_INFO("BLE Gatt Connection");
            ref_step = 0;
            if (context->wifi_update_enabled) {
                IOT_INFO("BLE connection after onboarding");
            }
            context->ble_connected = true;
            context->wifi_candidate_frequency = 0;
            break;
        case IOT_BLE_CONNECTION_EVENT_DISCONNECTED:
            IOT_INFO("BLE Gatt Disconnection");
            st_conn_ownership_confirm((IOT_CTX *)context, true);
            if (context->offline_diagnostics_wifiupdate_timeout) {
                iot_os_timer_delete(context->offline_diagnostics_wifiupdate_timeout);
                context->offline_diagnostics_wifiupdate_timeout = NULL;
            }
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

            if (context->wifi_update_enabled == false) {
                device_work_data_t work;
                while (iot_util_queue_receive(context->work_queue, &work) == IOT_ERROR_NONE) {
                }
                iot_device_cleanup(context);
                context->curr_state = IOT_STATE_INITIALIZED;
                iot_state_update(context, IOT_STATE_PROV_ENTER, 0);
            } else {
                IOT_INFO("BLE disconnection after onboarding");
                IOT_INFO("get wifi provisioning info");
                err = iot_nv_get_wifi_prov_data(&context->prov_data.wifi);
                context->is_wifi_station = false;
                if (err) {
                    IOT_ERROR("get wifi prov fail");
                }
            }
            context->ble_connected = false;
            context->d2d_event_request = false;

            if (context->cloud_con_timer) {
                iot_os_timer_delete(context->cloud_con_timer);
                context->cloud_con_timer = NULL;
            }

            /* we don't need this lookup_id anymore */
            if (context->lookup_id) {
                free(context->lookup_id);
                context->lookup_id = NULL;
            }

            context->otm_confirmed = false;
            es_reset_transferdata();
#if !(defined(CONFIG_STDK_IOT_CORE_EASYSETUP_WIFI_UPDATE) || \
      defined(CONFIG_STDK_IOT_CORE_EASYSETUP_OFFLINE_DIAGNOSTICS))
            // If there is no other ble service required except onboarding,
            // cleanup after onbarding complete.
            if (context->wifi_update_enabled) {
                _send_ble_deinit_request();
            }
#endif
            break;
        default:
            IOT_ERROR("Unknown event 0x%x", evt);
            break;
    }
}

static iot_ble_cbs_t ble_cbs = {
    .conn_cb = _iot_easysetup_ble_conn_cb,
    .write_cb = es_msg_assemble,
};

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
iot_error_t _iot_easysetup_gen_payload(struct iot_context *ctx, int cmd, char *in_payload, char **out_payload,
                                       size_t *payload_len)
{
    iot_error_t err = IOT_ERROR_NONE;
    struct iot_easysetup_payload request = {0};
    struct iot_easysetup_payload *response = NULL;
    int cur_step;

    cur_step = cmd;

    if (cur_step == IOT_EASYSETUP_BLE_STEP_DEVICEINFO) {
        if (ctx->status_cb) {
            ctx->status_cb(ST_DEVICE_STATUS_ONBOARDING_START, ctx->status_usr_data);
            ctx->device_status = ST_DEVICE_STATUS_ONBOARDING_START;
        }
    }

    if ((!context->otm_confirmed) && (cur_step >= IOT_EASYSETUP_BLE_STEP_WIFISCANINFO)) {
        if ((cur_step != IOT_EASYSETUP_BLE_STEP_LOG_SYSTEMINFO) && (cur_step != IOT_EASYSETUP_BLE_STEP_LOG_GET_DUMP)) {
            err = IOT_ERROR_EASYSETUP_INVALID_CMD;
            goto post_exit;
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

    request.step = cur_step;
    request.payload = in_payload;
    response = iot_easysetup_get_response(ctx, request);
    if (response == NULL) {
        err = IOT_ERROR_EASYSETUP_INTERNAL_SERVER_ERROR;
        goto post_exit;
    }

    if (response->step != cur_step) {
        IOT_ERROR("unexpected response %d:%d", cur_step, response->step);
        IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INTERNAL_SERVER_ERROR, response->step);
        if (response->payload) {
            free(response->payload);
        }
        err = IOT_ERROR_EASYSETUP_INTERNAL_SERVER_ERROR;
    } else {
        if (!response->err) {
            *out_payload = response->payload;
            *payload_len = response->payload_len;
        }
        err = response->err;
    }

    if (err != IOT_ERROR_NONE && err != IOT_ERROR_EASYSETUP_REQUEST_PENDING) {
        ref_step = 0;
        if ((cur_step >= IOT_EASYSETUP_BLE_STEP_LOG_SYSTEMINFO) || (err == IOT_ERROR_EASYSETUP_INVALID_SEQUENCE)) {
            /* TODO : signaling restart onboarding */
            IOT_ERROR("mock : signaling restart onboarding %d", __LINE__);
        }
    } else {
        switch (cur_step) {
            case IOT_EASYSETUP_BLE_STEP_OFFLINE_DIAGNOSTICS_CONNECTION_INFO:
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
    if (response) {
        iot_os_free(response);
    }
    return err;
}

STATIC_FUNCTION
iot_error_t _iot_easysetup_ble_msg_decrypt(iot_security_context_t *security_context, int cmd,
                                           unsigned char *encrypt_msg, size_t encrypt_msg_len, char **out_msg)
{
    iot_error_t err;
    iot_security_buffer_t decrypt_buf = {0};
    iot_security_buffer_t plain_buf = {0};

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
    iot_security_buffer_t msg_buf = {0};
    iot_security_context_t *security_context = context->easysetup_security_context;
    uint32_t buf_idx;

    uint32_t max_att_len = iot_bsp_ble_get_mtu();
    if (max_att_len < MIN_MTU_SIZE) {
        IOT_WARN("mtu size(%d) is under the minimum mtu size", max_att_len);
        max_att_len = MIN_MTU_SIZE;
    } else if (max_att_len > MAX_ATT_VALUE_LEN) {
        IOT_WARN("mtu size(%d) is over the maximum mtu size", max_att_len);
        max_att_len = MAX_ATT_VALUE_LEN;
    }
    uint32_t payload_size_limit = ((max_att_len - INDICATION_HEADER_LEN - RESPONSE_HEADER_LEN) << 8) - 16;

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
    if (*encrypt_buf == NULL) {
        IOT_ERROR("memory alloc fail for encrypt buf array");
        err = IOT_ERROR_MEM_ALLOC;
        goto enc_fail;
    }
    memset(*encrypt_buf, 0, sizeof(iot_security_buffer_t) * (*buf_len));

    if ((cmd == IOT_EASYSETUP_BLE_STEP_DEVICEINFO) ||
        (cmd == IOT_EASYSETUP_BLE_STEP_LOG_GET_DUMP && !context->wifi_update_enabled)) {
        for (buf_idx = 0; buf_idx < *buf_len; buf_idx++) {
            if (payload_len > payload_size_limit * (buf_idx + 1)) {
                (*encrypt_buf)[buf_idx].len = payload_size_limit;
            } else {
                (*encrypt_buf)[buf_idx].len = payload_len - (payload_size_limit * buf_idx);
            }
            (*encrypt_buf)[buf_idx].p = (unsigned char *)iot_os_malloc((*encrypt_buf)[buf_idx].len);
            if (*encrypt_buf == NULL) {
                IOT_ERROR("memory alloc fail for encrypt buffer");
                err = IOT_ERROR_MEM_ALLOC;
                goto enc_fail;
            }
            memcpy((*encrypt_buf)[buf_idx].p, payload + (payload_size_limit * buf_idx), (*encrypt_buf)[buf_idx].len);
        }
    } else {
        for (buf_idx = 0; buf_idx < *buf_len; buf_idx++) {
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

iot_error_t iot_easysetup_ble_send_response(int cmd, char *payload, size_t payload_len)
{
    iot_error_t err = IOT_ERROR_NONE;
    int encrypted_payload_len;
    iot_security_buffer_t *encrypted_payload = NULL;
    int index;

    err = _iot_easysetup_ble_msg_encrypt(context, cmd, (unsigned char *)payload, payload_len, &encrypted_payload,
                                         &encrypted_payload_len);
    if (err) {
        IOT_ERROR("encryption is failed (%d)", err);
        goto out;
    }

    for (index = 0; index < encrypted_payload_len; index++) {
        IOT_INFO("es_ble_msg_disassemble start [%d]", encrypted_payload[index].len);
        err = es_msg_disassemble((uint8_t *)encrypted_payload[index].p, encrypted_payload[index].len,
                                 encrypted_payload_len - index - 1, cmd + 1);
        if (err) {
            IOT_INFO("to send the message is failed[%d]", err);
            IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INTERNAL_SERVER_ERROR, err);
        }
    }

out:
    if (encrypted_payload != NULL) {
        for (index = 0; index < encrypted_payload_len; index++) {
            if (encrypted_payload[index].p != NULL) {
                iot_os_free(encrypted_payload[index].p);
                encrypted_payload[index].p = NULL;
            }
        }
        iot_os_free(encrypted_payload);
        encrypted_payload = NULL;
    }

    return err;
}

void iot_easysetup_ble_msg_handler(int cmd, char *data_buf, size_t data_buf_len)
{
    char *payload = NULL;
    cJSON *root = NULL;
    iot_error_t err = IOT_ERROR_NONE;
    char *in_payload = NULL;
    size_t payload_len = 0;

    IOT_INFO("cmd : %d", cmd);

    if ((cmd < IOT_EASYSETUP_BLE_STEP_DEVICEINFO) || (cmd >= IOT_EASYSETUP_BLE_INVALID_STEP)) {
        IOT_ERROR("Not supported cmd : %d", cmd);
        IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_CMD, cmd);
        err = IOT_ERROR_EASYSETUP_INVALID_CMD;
        goto err_report;
    }

    if (cmd == IOT_EASYSETUP_BLE_STEP_SETUPCOMPLETE)
        _iot_easysetup_con_timer_init(context);

    if (cmd == IOT_EASYSETUP_BLE_STEP_SETUPCOMPLETE_RESPONSE)
        goto err_report;

    if (data_buf_len) {
        err = _iot_easysetup_ble_msg_decrypt(context->easysetup_security_context, cmd, (unsigned char *)data_buf,
                                             data_buf_len, &in_payload);
        if (err) {
            IOT_ERROR("message decryption fail (%d)", err);
            IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_CMD_FAIL, cmd);
            goto err_report;
        }
    }

    err = _iot_easysetup_gen_payload(context, cmd, in_payload, &payload, &payload_len);
    if (err != IOT_ERROR_NONE && err != IOT_ERROR_EASYSETUP_REQUEST_PENDING) {
        IOT_INFO("post cmd[%d] not ok", cmd);
        IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_CMD_FAIL, cmd);
    } else if (cmd == IOT_EASYSETUP_BLE_STEP_SETUPCOMPLETE || err == IOT_ERROR_EASYSETUP_REQUEST_PENDING) {
        goto out;
    }

err_report:
    if ((err) || (cmd == IOT_EASYSETUP_BLE_STEP_SETUPCOMPLETE_RESPONSE)) {
        if (payload)
            free(payload);

        payload = NULL;

        if (cmd == IOT_EASYSETUP_BLE_STEP_SETUPCOMPLETE_RESPONSE) {
            switch (context->es_network_status) {
                case IOT_ERROR_NONE:
                    err = context->es_network_status;
                    break;
                case IOT_ERROR_MQTT_REJECT_CONNECT:
                    err = IOT_ERROR_EASYSETUP_REGISTER_FAILED_REGISTRATION;
                    IOT_ES_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_EASYSETUP_REGISTER_FAILED_REGISTRATION, 0);
                    break;
                case IOT_ERROR_CONN_STA_AUTH_FAIL:
                    err = IOT_ERROR_EASYSETUP_UNAVAILABLE_PASSWORD;
                    IOT_ES_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_EASYSETUP_UNAVAILABLE_PASSWORD, 0);
                    break;
                case IOT_ERROR_CONN_STA_DHCP_FAIL:
                    err = IOT_ERROR_EASYSETUP_WIFI_DHCP_FAIL;
                    IOT_ES_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_EASYSETUP_WIFI_DHCP_FAIL, 0);
                    break;
                case IOT_ERROR_CONN_DNS_QUERY_FAIL:
                case IOT_ERROR_CONN_STA_NO_INTERNET:
                    err = IOT_ERROR_EASYSETUP_NOT_CONNECTED_WIRELESS_NETWORK;
                    IOT_ES_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_EASYSETUP_NOT_CONNECTED_WIRELESS_NETWORK, 0);
                    break;
                case IOT_ERROR_CONN_STA_AP_NOT_FOUND:
                case IOT_ERROR_CONN_STA_ASSOC_FAIL:
                case IOT_ERROR_CONN_STA_CONN_FAIL:
                    err = IOT_ERROR_EASYSETUP_WIFI_NOT_DISCOVERED;
                    IOT_ES_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_EASYSETUP_WIFI_NOT_DISCOVERED, 0);
                    break;
                case IOT_ERROR_CONN_OPERATE_FAIL:
                    err = IOT_ERROR_EASYSETUP_WIFI_NOT_DISCOVERED;
                    IOT_ES_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_EASYSETUP_WIFI_NOT_DISCOVERED, 0);
                    break;
                default:
                    err = IOT_ERROR_EASYSETUP_WIFI_NOT_DISCOVERED;
                    break;
            }
        }

        root = cJSON_CreateObject();
        if (!root) {
            IOT_ERROR("json create failed");
            IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_JSON_CREATE_ERROR, 0);
            goto out;
        }
        cJSON_AddItemToObject(root, "errorcode", cJSON_CreateNumber((double)-(err)));

        payload = cJSON_PrintUnformatted(root);
        IOT_INFO("%s", payload);
    }

    err = iot_easysetup_ble_send_response(cmd, payload, payload_len);

out:
    if (root) {
        JSON_DELETE(root);
    }
    if (payload) {
        free(payload);
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
    dump_enable = true;
#endif

    context->otm_confirmed = false;

    if (ctx->es_ble_ready == false) {
        err = iot_bsp_ble_init(&ble_cbs);
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
        ctx->wifi_update_enabled = false;
    } else {
        ctx->d2d_event_request = false;
        if (!ctx->es_network_status) {
            ctx->wifi_update_enabled = true;
            IOT_INFO("set wifi provisioning info");
            err = iot_nv_set_wifi_prov_data(&ctx->prov_data.wifi);
            if (err) {
                IOT_ERROR("failed to set the wifi prov data");
                IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_WIFI_DATA_WRITE_FAIL, err);
            }
        } else if (ctx->wifi_update_enabled) {
            IOT_INFO("get wifi provisioning info");
            err = iot_nv_get_wifi_prov_data(&ctx->prov_data.wifi);
            ctx->is_wifi_station = false;
            if (err) {
                IOT_ERROR("get wifi prov fail");
            }
        }

        iot_easysetup_ble_msg_handler(IOT_EASYSETUP_BLE_STEP_SETUPCOMPLETE_RESPONSE, NULL, 0);

        if (ctx->es_network_status != IOT_ERROR_NONE) {
            err = iot_state_update(ctx, IOT_STATE_PROV_CONFIRM, 0);
            if (err) {
                IOT_ERROR("cannot update state to confirm state(%d)", err);
                IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INTERNAL_SERVER_ERROR, err);
                err = IOT_ERROR_EASYSETUP_INTERNAL_SERVER_ERROR;
            }
            return;
        }
        err = iot_easysetup_start_ble_advertisement(ctx);
        if (err != IOT_ERROR_NONE) {
            IOT_ERROR("Can't create ble advertise packet for easysetup.(%d)", err);
        }
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
