/* ***************************************************************************
 *
 * Copyright 2019-2020 Samsung Electronics All Rights Reserved.
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
#include <stdbool.h>

#include "iot_main.h"
#include "iot_internal.h"
#include "iot_debug.h"
#include "iot_bsp_wifi.h"
#include "iot_nv_data.h"
#include "iot_easysetup.h"
#include "iot_capability.h"
#include "iot_os_util.h"
#include "iot_util.h"
#include "iot_bsp_system.h"

#if defined(CONFIG_STDK_IOT_CORE_LOG_FILE)
#include "iot_log_file.h"
#endif

#define NEXT_STATE_TIMEOUT_MS	(100000)
#define EASYSETUP_TIMEOUT_MS	(300000) /* 5 min */
#define REGISTRATION_TIMEOUT_MS	(900000) /* 15 min */
#define RECOVER_TRY_MAX			(5)

#define IOT_DUMP_MAIN(LVL, LOGID, arg) \
	IOT_DUMP(IOT_DEBUG_LEVEL_##LVL, IOT_DUMP_MAIN_##LOGID, __LINE__, arg)

#define IOT_DUMP_MAIN_ARG2(LVL, LOGID, arg1, arg2) \
	IOT_DUMP(IOT_DEBUG_LEVEL_##LVL, IOT_DUMP_MAIN_##LOGID, arg1, arg2)

static iot_error_t _do_state_updating(struct iot_context *ctx,
		iot_state_t new_state, int opt, unsigned int *timeout_ms);

STATIC_FUNCTION
iot_error_t _iot_command_peek(struct iot_context *ctx, enum iot_command_type peek_cmd)
{
	struct iot_command cmd_data;
	int ret;
	iot_error_t err;
	bool *cmd_only = NULL;

	if (peek_cmd != IOT_COMMAND_CHECK_PROV_STATUS) {
		IOT_ERROR("Unsupported peek cmd(%d)", peek_cmd);
		return IOT_ERROR_INVALID_ARGS;
	}

	cmd_only = iot_os_malloc(sizeof(bool));
	if (!cmd_only) {
		IOT_ERROR("failed to malloc for iot_command_peek param");
		return IOT_ERROR_MEM_ALLOC;
	}
	*cmd_only = true;

	cmd_data.param = cmd_only;
	cmd_data.cmd_type = peek_cmd;

	ret = iot_os_queue_send(ctx->cmd_queue, &cmd_data, 0);
	if (ret != IOT_OS_TRUE) {
		IOT_ERROR("Cannot put the cmd into cmd_queue");
		iot_os_free(cmd_data.param);
		err = IOT_ERROR_BAD_REQ;
	} else {
		iot_os_eventgroup_set_bits(ctx->iot_events,
			IOT_EVENT_BIT_COMMAND);
		err = IOT_ERROR_NONE;
	}

	return err;
}

STATIC_FUNCTION
iot_error_t _check_prov_data_validation(struct iot_device_prov_data *prov_data)
{
	struct iot_wifi_prov_data *wifi = &(prov_data->wifi);
	struct iot_cloud_prov_data *cloud = &(prov_data->cloud);

	if (wifi->ssid[0] == '\0') {
		IOT_ERROR("There is no ssid on prov_data");
		return IOT_ERROR_INVALID_ARGS;
	}

	if (!cloud->broker_url) {
		IOT_ERROR("There is no broker_url on prov_data");
		return IOT_ERROR_INVALID_ARGS;
	}

	if (cloud->broker_port < 0) {
		IOT_ERROR("There is wrong port(%d) on prov_data", cloud->broker_port);
		return IOT_ERROR_INVALID_ARGS;
	}
	return IOT_ERROR_NONE;
}

STATIC_FUNCTION
void _delete_easysetup_resources_all(struct iot_context *ctx)
{
	ctx->es_res_created = false;

	if (ctx->pin) {
		iot_os_free(ctx->pin);
		ctx->pin = NULL;
	}
	if (ctx->easysetup_security_context) {
		iot_security_deinit(ctx->easysetup_security_context);
		ctx->easysetup_security_context = NULL;
	}
	if (ctx->easysetup_req_queue) {
		iot_os_queue_delete(ctx->easysetup_req_queue);
		ctx->easysetup_req_queue = NULL;
	}
	if (ctx->easysetup_resp_queue) {
		iot_os_queue_delete(ctx->easysetup_resp_queue);
		ctx->easysetup_resp_queue = NULL;
	}
}

STATIC_FUNCTION
iot_error_t _create_easysetup_resources(struct iot_context *ctx, iot_pin_t *pin_num)
{
	iot_error_t ret;

	/* If PIN type used, iot_pin_t should be set */
	if (ctx->devconf.ownership_validation_type & IOT_OVF_TYPE_PIN) {
		if (!ctx->pin) {
			if ((ctx->pin = iot_os_malloc(sizeof(iot_pin_t))) == NULL) {
				IOT_ERROR("failed to malloc for pin");
				IOT_DUMP_MAIN(ERROR, BASE, 0xDEADBEEF);
				return IOT_ERROR_MEM_ALLOC;
			}
		}

		if (pin_num) {
			memcpy(ctx->pin, pin_num, sizeof(iot_pin_t));
		} else {
			ret = IOT_ERROR_INVALID_ARGS;
			goto create_fail;
		}
	}

	ctx->easysetup_security_context = iot_security_init();
	if (ctx->easysetup_security_context == NULL) {
		IOT_DUMP_MAIN(ERROR, BASE, 0xDEADBEEF);
		ret = IOT_ERROR_SECURITY_INIT;
		goto create_fail;
	}

	if (!ctx->easysetup_req_queue) {
		ctx->easysetup_req_queue = iot_os_queue_create(1, sizeof(struct iot_easysetup_payload));
		if (!ctx->easysetup_req_queue) {
			IOT_ERROR("failed to create Queue for easysetup request\n");
			IOT_DUMP_MAIN(ERROR, BASE, 0xDEADBEEF);
			ret = IOT_ERROR_BAD_REQ;
			goto create_fail;
		}
	}

	if (!ctx->easysetup_resp_queue) {
		ctx->easysetup_resp_queue = iot_os_queue_create(1, sizeof(struct iot_easysetup_payload));
		if (!ctx->easysetup_resp_queue) {
			IOT_ERROR("failed to create Queue for easysetup response\n");
			IOT_DUMP_MAIN(ERROR, BASE, 0xDEADBEEF);
			ret = IOT_ERROR_BAD_REQ;
			goto create_fail;
		}
	}

	ctx->es_res_created = true;
	return IOT_ERROR_NONE;

create_fail:
	_delete_easysetup_resources_all(ctx);
	return ret;
}

static void _do_update_timeout(struct iot_context *ctx, unsigned int needed_tout)
{
	IOT_INFO("Current timeout : %u for %d/%d", needed_tout,
		ctx->curr_state, ctx->req_state);
	iot_os_timer_count_ms(ctx->state_timer, needed_tout);
}

STATIC_FUNCTION
void _do_status_report(struct iot_context *ctx,
	iot_state_t target_state, bool is_final)
{
	iot_status_t fn_stat = 0;
	iot_stat_lv_t fn_stat_lv = 0;
	unsigned int curr_stat = 0;
	bool is_report = false;

	switch (target_state) {
	case IOT_STATE_CHANGE_FAILED:
		if (ctx->reported_stat) {
			fn_stat = (ctx->reported_stat & IOT_STATUS_ALL);
			fn_stat_lv = IOT_STAT_LV_FAIL;
			is_report = true;
		}
		break;

	case IOT_STATE_INITIALIZED:
		if (!is_final) {
			fn_stat = IOT_STATUS_IDLE;
			fn_stat_lv = IOT_STAT_LV_STAY;
			is_report = true;
		}
		break;

	case IOT_STATE_PROV_ENTER:
		if (is_final) {
			fn_stat = IOT_STATUS_PROVISIONING;
			fn_stat_lv = IOT_STAT_LV_START;
			is_report = true;
		}
		break;

	case IOT_STATE_PROV_CONN_MOBILE:
		if (!is_final) {
			fn_stat = IOT_STATUS_PROVISIONING;
			fn_stat_lv = IOT_STAT_LV_CONN;
			is_report = true;
		}
		break;

	case IOT_STATE_PROV_CONFIRM:
		if (ctx->curr_otm_feature == OVF_BIT_BUTTON) {
			fn_stat = IOT_STATUS_NEED_INTERACT;
			fn_stat_lv = IOT_STAT_LV_STAY;
			is_report = true;
		}
		break;

	case IOT_STATE_PROV_DONE:
		if (is_final) {
			fn_stat = IOT_STATUS_PROVISIONING;
			fn_stat_lv = IOT_STAT_LV_DONE;
			is_report = true;
		}
		break;

	case IOT_STATE_CLOUD_REGISTERING:
		if (!is_final) {
			fn_stat = IOT_STATUS_CONNECTING;
			fn_stat_lv = IOT_STAT_LV_SIGN_UP;
			is_report = true;
		}
		break;

	case IOT_STATE_CLOUD_CONNECTING:
		if (!is_final) {
			fn_stat = IOT_STATUS_CONNECTING;
			fn_stat_lv = IOT_STAT_LV_SIGN_IN;
			is_report = true;
		}
		break;

	case IOT_STATE_CLOUD_CONNECTED:
		if (!is_final) {
			fn_stat = IOT_STATUS_CONNECTING;
			fn_stat_lv = IOT_STAT_LV_DONE;
			is_report = true;
		}
		break;

	case IOT_STATE_CLOUD_DISCONNECTED:
		if (!is_final) {
			fn_stat = IOT_STATUS_IDLE;
			fn_stat_lv = IOT_STAT_LV_STAY;
			is_report = true;
		}
		break;

	default:
		IOT_INFO("Unsupported state %d for %d/%d", target_state, fn_stat, fn_stat_lv);
		break;
	}

	if (is_report && (fn_stat & ctx->status_maps)) {
		/* we assume that fn_stat uses only 8bits */
		curr_stat = fn_stat | (fn_stat_lv << 8);

		if (ctx->reported_stat != curr_stat) {
			IOT_INFO("Call usr status_cb with %d/%d", fn_stat, fn_stat_lv);
			ctx->status_cb(fn_stat, fn_stat_lv, ctx->status_usr_data);
			ctx->reported_stat = curr_stat;
		}
	}

}

static void _clear_cmd_status(struct iot_context *ctx, enum iot_command_type cmd_type)
{
	if (cmd_type != IOT_COMMNAD_STATE_UPDATE) {
		ctx->cmd_count[cmd_type]--;
		if (!ctx->cmd_count[cmd_type])
		ctx->cmd_status &= ~(1u << cmd_type);
	}
}

static bool _unlikely_with_stored_dip(struct iot_dip_data *chk_dip)
{
	iot_error_t err = IOT_ERROR_NONE;
	struct iot_dip_data old_dip;
	int idx;

	if (chk_dip == NULL) {
		return true;
	}

	err = iot_misc_info_load(IOT_MISC_INFO_DIP, (void *)&old_dip);
	if (err != IOT_ERROR_NONE) {
		IOT_ERROR("failed to load stored DIP!! (%d)", err);
		IOT_DUMP_MAIN(ERROR, BASE, err);
		return true;
	}

	for (idx = 0; idx < IOT_UUID_BYTES; idx++) {
		if (chk_dip->dip_id.id[idx] != old_dip.dip_id.id[idx]) {
			return true;
		}
	}

	if (chk_dip->dip_major_version != old_dip.dip_major_version) {
		return true;
	}

	if (chk_dip->dip_minor_version != old_dip.dip_minor_version) {
		return true;
	}

	return false;
}

static iot_error_t _prepare_self_reged(struct iot_context *ctx)
{
	iot_error_t err = IOT_ERROR_NONE;
	struct iot_uuid old_location;
	char *location_str = NULL;
	char *lookup_str = NULL;

	if (!ctx) {
		return IOT_ERROR_INVALID_ARGS;
	}

	/* Make new lookup_id for self-registration */
	lookup_str = (char *)iot_os_malloc(IOT_REG_UUID_STR_LEN + 1);
	if (!lookup_str) {
		IOT_ERROR("Failed to malloc for lookup_str");
		IOT_DUMP_MAIN(ERROR, BASE, 0xDEADBEEF);
		return IOT_ERROR_MEM_ALLOC;
	}
	memset(lookup_str, 0, (IOT_REG_UUID_STR_LEN +1));

	err = iot_get_random_id_str(lookup_str,
			(IOT_REG_UUID_STR_LEN + 1));
	if (err != IOT_ERROR_NONE) {
		IOT_ERROR("Failed to get new lookup_str(%d)", err);
		IOT_DUMP_MAIN(ERROR, BASE, err);
		goto error_prepare_self;
	}

	/* Load previous locationId from NV */
	err = iot_misc_info_load(IOT_MISC_INFO_LOCATION,
			(void *)&old_location);
	if (err != IOT_ERROR_NONE) {
		IOT_ERROR("Failed to load old_location(%d)", err);
		IOT_DUMP_MAIN(ERROR, BASE, err);
		goto error_prepare_self;
	}

	location_str = (char *)iot_os_malloc(IOT_REG_UUID_STR_LEN +1);
	if (!location_str) {
		IOT_ERROR("Failed to malloc for location_str");
		IOT_DUMP_MAIN(ERROR, BASE, 0xDEADBEEF);
		err = IOT_ERROR_MEM_ALLOC;
		goto error_prepare_self;
	}
	memset(location_str, 0, (IOT_REG_UUID_STR_LEN +1));

	err = iot_util_convert_uuid_str(&old_location, location_str,
			(IOT_REG_UUID_STR_LEN + 1));
	if (err != IOT_ERROR_NONE) {
		IOT_ERROR("Failed to convert location_str(%d)", err);
		IOT_DUMP_MAIN(ERROR, BASE, err);
		goto error_prepare_self;
	}

	/* lookup_id & location are runtime allocated string
	 * during D2D process, so free it first to avoid memory-leak
	 */
	if (ctx->lookup_id) {
		iot_os_free(ctx->lookup_id);
	}
	ctx->lookup_id = lookup_str;

	if (ctx->prov_data.cloud.location) {
		iot_os_free(ctx->prov_data.cloud.location);
	}
	ctx->prov_data.cloud.location = location_str;

	return IOT_ERROR_NONE;

error_prepare_self:
	if (lookup_str) {
		iot_os_free(lookup_str);
	}

	if (location_str) {
		iot_os_free(location_str);
	}

	return err;
}


static iot_error_t _do_iot_main_command(struct iot_context *ctx,
	struct iot_command *cmd)
{
	iot_error_t err = IOT_ERROR_NONE;
	iot_state_t next_state;
	int state_opt = IOT_STATE_OPT_NONE;
	iot_wifi_conf *conf = NULL;
	char *usr_id = NULL;
	size_t str_len;
	struct iot_state_data *state_data;
	unsigned int needed_tout = 0;
	iot_noti_data_t *noti = NULL;
	bool is_diff_dip = false;
	bool *reboot = NULL;
	bool *cmd_only = NULL;

	IOT_INFO("curr_main_cmd:%d, curr_main_state:%d/%d",
		cmd->cmd_type, ctx->curr_state, ctx->req_state);

	/* Some State has to queue several commands sequentially
	 * But sometimes next command queuing or next process can make error
	 * after the first command queued successfully.
	 * So to prevent the first command handling after error occurred,
	 * added command skipping coroutine
	 */
	if (ctx->cmd_err && (cmd->cmd_type < IOT_COMMAND_TYPE_MAX)) {
		IOT_WARN("iot-core had errors!!(0x%0x), skip cmd", ctx->cmd_err);
		IOT_DUMP_MAIN_ARG2(WARN, COMMAND, ctx->cmd_err, ctx->curr_state);
		goto out_do_cmd;
	}

	switch (cmd->cmd_type) {
		case IOT_COMMNAD_STATE_UPDATE:
			state_data = (struct iot_state_data *)cmd->param;
			if (!state_data) {
				IOT_ERROR("There is no state_data for cmd :%d", cmd->cmd_type);
				IOT_DUMP_MAIN(ERROR, BASE, 0xDEADBEEF);
				break;
			}

			if ((ctx->curr_state > IOT_STATE_UNKNOWN) &&
					(ctx->curr_state == state_data->iot_state)) {
				IOT_WARN("Redundant command. state update in progress !");
				break;
			}

			err = _do_state_updating(ctx, state_data->iot_state,
					state_data->opt, &needed_tout);
			if (err != IOT_ERROR_NONE) {
				IOT_ERROR("failed to handle new state : %d", state_data->iot_state);
				IOT_DUMP_MAIN(ERROR, BASE, state_data->iot_state);
			} else {
				if (needed_tout) {
					/* Internal state will be updated with timeout */
					ctx->cmd_err = 0;
					ctx->req_state = state_data->iot_state;
					_do_update_timeout(ctx, needed_tout);
				}

				/* Call the user's status_cb function if it's available */
				if (ctx->status_cb)
					_do_status_report(ctx, state_data->iot_state, false);
			}

			break;

		/* For Resource control */
		case IOT_COMMAND_READY_TO_CTL:
			ctx->rcv_fail_state = IOT_STATE_INITIALIZED;
			ctx->rcv_try_cnt = 0;
			iot_cap_call_init_cb(ctx->cap_handle_list);
			break;

		/* For Device control */
		case IOT_COMMAND_NETWORK_MODE:
			conf = (iot_wifi_conf *)cmd->param;
			if (!conf) {
				IOT_ERROR("failed to get iot_wifi_conf\n");
				IOT_DUMP_MAIN(ERROR, BASE, 0xDEADBEEF);
			} else {
				err = iot_bsp_wifi_set_mode(conf);
				if (err < 0) {
					IOT_ERROR("failed to set wifi_set_mode\n");
					IOT_DUMP_MAIN(ERROR, BASE, err);
				}
			}

			if (!conf || err < 0) {
				if (ctx->req_state != IOT_STATE_CHANGE_FAILED) {
					ctx->cmd_err |= (1u << cmd->cmd_type);
					next_state = IOT_STATE_CHANGE_FAILED;
					state_opt = ctx->req_state;
					err = iot_state_update(ctx,
							next_state, state_opt);
				} else {
					IOT_WARN("Duplicated error handling, skip updating!!");
					err = IOT_ERROR_DUPLICATED_CMD;
				}
				break;
			}

			switch (conf->mode) {
			case IOT_WIFI_MODE_SOFTAP:
				if (ctx->req_state == IOT_STATE_PROV_ENTER) {
					err = iot_easysetup_init(ctx);
					IOT_MEM_CHECK("ES_INIT DONE >>PT<<");

					if (err != IOT_ERROR_NONE) {
						IOT_ERROR("failed to iot_easysetup_init(%d)", err);
						IOT_DUMP_MAIN(ERROR, BASE, err);

						if (ctx->req_state != IOT_STATE_CHANGE_FAILED) {
							ctx->cmd_err |= (1u << cmd->cmd_type);
							next_state = IOT_STATE_CHANGE_FAILED;
							state_opt = ctx->req_state;
							err = iot_state_update(ctx,
								next_state, state_opt);
						} else {
							IOT_WARN("Duplicated error handling, skip updating!!");
							err = IOT_ERROR_DUPLICATED_CMD;
						}
					} else {
						ctx->es_http_ready = true;
					}
				}
				break;
			default:
				break;
			}
			break;

		/* For state related control */
		case IOT_COMMAND_CHECK_PROV_STATUS:
			if (cmd->param) {
				cmd_only = (bool *)cmd->param;
			}
			ctx->iot_reg_data.new_reged = false;

			/* Now we allow D2D process reentrant and prov_data could be loaded
			 * at the init state or previous D2D, so free it first to avoid memory-leak
			 */
			iot_api_prov_data_mem_free(&ctx->prov_data);
			err = iot_nv_get_prov_data(&ctx->prov_data);
			if (err != IOT_ERROR_NONE) {
				IOT_DEBUG("There are no prov data in NV\n");
				err = iot_nv_erase(IOT_NVD_DEVICE_ID);
				if ((err != IOT_ERROR_NONE) && (err != IOT_ERROR_NV_DATA_NOT_EXIST)) {
					IOT_ERROR("Can't remove deviceId for new registraiton");
				}

				ctx->iot_reg_data.new_reged = true;
				next_state = IOT_STATE_PROV_ENTER;
			} else {
				err = _check_prov_data_validation(&ctx->prov_data);
				if (err != IOT_ERROR_NONE) {
					IOT_WARN("There are no valid prov data in NV\n");
					err = iot_nv_erase(IOT_NVD_DEVICE_ID);
					if ((err != IOT_ERROR_NONE) && (err != IOT_ERROR_NV_DATA_NOT_EXIST)) {
						IOT_ERROR("Can't remove deviceId for new registraiton");
					}

					ctx->iot_reg_data.new_reged = true;
					next_state = IOT_STATE_PROV_ENTER;
				} else {
					next_state = IOT_STATE_PROV_DONE;
				}
			}

			if (cmd_only && *cmd_only) {
				iot_os_eventgroup_set_bits(ctx->usr_events,
						IOT_USR_INTERACT_BIT_CMD_DONE);
				/* We don't need recovering for command only case */
				if (err != IOT_ERROR_NONE) {
					IOT_WARN("Internal WARN(%d) happened for command only", err);
				}

				return IOT_ERROR_NONE;
			} else {
				err = iot_state_update(ctx, next_state, state_opt);
			}
			break;

		case IOT_COMMAND_CHECK_CLOUD_STATE:
			ctx->iot_reg_data.self_reged = false;

			if (ctx->iot_reg_data.new_reged) {
				next_state = IOT_STATE_CLOUD_REGISTERING;
			} else if (ctx->iot_reg_data.updated) {
				next_state = IOT_STATE_CLOUD_CONNECTING;
			} else {
				err = iot_nv_get_device_id(&usr_id, &str_len);
				if (err != IOT_ERROR_NONE) {
					IOT_WARN("There are no reged data in NV\n");
					if (ctx->req_state == IOT_STATE_PROV_DONE) {
						/* Current server does not send any notification when the device
						 * tries to start registration process with invalid information
						 * such as manuall or forcely reboot case after provisioning step.
						 * So, we forcely remove all data & reboot the device
						 */
						IOT_WARN("Some thing went wrong, got provisioning but no deviceId");
						IOT_DUMP_MAIN(WARN, BASE, 0xC1EAC1EA);

						if (ctx->es_http_ready) {
							ctx->es_http_ready = false;
							iot_easysetup_deinit(ctx);
						}

						if (ctx->es_res_created)
							_delete_easysetup_resources_all(ctx);

						iot_device_cleanup(ctx);

						ctx->cmd_err |= (1u << cmd->cmd_type);
						next_state = IOT_STATE_CHANGE_FAILED;
						state_opt = ctx->req_state;
						/* The device will be reboot forcely */
						IOT_REBOOT();
					} else {
						next_state = IOT_STATE_CLOUD_REGISTERING;
					}
				} else {
					if (str_len > IOT_REG_UUID_STR_LEN) {
						IOT_WARN("Long deviceID in NV %s, use it insize\n",
							usr_id);
						memcpy(ctx->iot_reg_data.deviceId, usr_id,
							IOT_REG_UUID_STR_LEN);
						ctx->iot_reg_data.deviceId[IOT_REG_UUID_STR_LEN] = '\0';
					} else {
						memcpy(ctx->iot_reg_data.deviceId, usr_id, str_len);
						ctx->iot_reg_data.deviceId[str_len] = '\0';

						IOT_INFO("Current deviceID: %s (%d)\n",
							ctx->iot_reg_data.deviceId, str_len);
					}

					if (ctx->devconf.dip) {
						is_diff_dip = _unlikely_with_stored_dip(ctx->devconf.dip);
					} else {
						is_diff_dip = false;
					}

					if (is_diff_dip) {
						err = _prepare_self_reged(ctx);
						if (err != IOT_ERROR_NONE) {
							IOT_ERROR("Failed to prepare self registration(%d)", err);
							IOT_DUMP_MAIN(ERROR, BASE, err);
							is_diff_dip = false;
						}
					}

					if (is_diff_dip) {
						ctx->iot_reg_data.self_reged = true;
						next_state = IOT_STATE_CLOUD_REGISTERING;
					} else {
						ctx->iot_reg_data.updated = true;
						next_state = IOT_STATE_CLOUD_CONNECTING;
					}

					free(usr_id);
				}
			}

			err = iot_state_update(ctx, next_state, state_opt);
			break;

		case IOT_COMMAND_CLOUD_REGISTERING:
			/* if there is previous connection, disconnect it first. */
			if (ctx->reg_mqttcli != NULL) {
				IOT_INFO("There is active registering, disconnect it first.\n");
				iot_es_disconnect(ctx, IOT_CONNECT_TYPE_REGISTRATION);
			}

			err = iot_es_connect(ctx, IOT_CONNECT_TYPE_REGISTRATION);
			if (err == IOT_ERROR_MQTT_REJECT_CONNECT) {
				/* This error case will be happended when server replies
				 * some specific response, so the trial to connect with server
				 * is succeeded (with REJECT). By this reason, we don't want
				 * to change the STATE by the failure.
				 */
				IOT_WARN("Intended error case(reboot), go to STATE_UNKONWN\n");
				err = iot_state_update(ctx, IOT_STATE_UNKNOWN, state_opt);
			} else if (err != IOT_ERROR_NONE) {
				IOT_ERROR("failed to iot_es_connect for registration\n");
				IOT_DUMP_MAIN(ERROR, BASE, err);

				if (ctx->req_state != IOT_STATE_CHANGE_FAILED) {
					ctx->cmd_err |= (1u << cmd->cmd_type);
					next_state = IOT_STATE_CHANGE_FAILED;
					state_opt = ctx->req_state;
					err = iot_state_update(ctx,
							next_state, state_opt);
				} else {
					IOT_WARN("Duplicated error handling, skip updating!!");
					err = IOT_ERROR_DUPLICATED_CMD;
				}
			}

			IOT_MEM_CHECK("CLOUD_REGISTERING DONE >>PT<<");
			break;

		case IOT_COMMAND_CLOUD_REGISTERED:
			if (iot_es_disconnect(ctx, IOT_CONNECT_TYPE_REGISTRATION) != IOT_ERROR_NONE) {
				IOT_ERROR("failed to _iot_es_disconnect for registration\n");
			}

			if (ctx->prov_data.cloud.location) {
				iot_os_free(ctx->prov_data.cloud.location);
				ctx->prov_data.cloud.location = NULL;
			}

			if (ctx->prov_data.cloud.room) {
				iot_os_free(ctx->prov_data.cloud.room);
				ctx->prov_data.cloud.room = NULL;
			}

			if (ctx->iot_reg_data.updated) {
				if (ctx->iot_reg_data.dip) {
					err = iot_misc_info_store(IOT_MISC_INFO_DIP,
							(const void *)ctx->iot_reg_data.dip);
					if (err != IOT_ERROR_NONE) {
						IOT_ERROR("Store DIP failed!! (%d)", err);
						IOT_DUMP_MAIN(ERROR, BASE, err);
					}

					iot_os_free(ctx->iot_reg_data.dip);
					ctx->iot_reg_data.dip = NULL;
				}

				if (ctx->iot_reg_data.locationId) {
					err = iot_misc_info_store(IOT_MISC_INFO_LOCATION,
							(const void *)ctx->iot_reg_data.locationId);
					if (err != IOT_ERROR_NONE) {
						IOT_ERROR("Store LocationId failed!! (%d)", err);
						IOT_DUMP_MAIN(ERROR, BASE, err);
					}

					iot_os_free(ctx->iot_reg_data.locationId);
					ctx->iot_reg_data.locationId = NULL;
				} else {
					IOT_WARN("There is no locationId!!");
					IOT_DUMP_MAIN(WARN, BASE, 0xBAD2C1EA);
				}

				err = iot_nv_set_device_id(ctx->iot_reg_data.deviceId);
				if (err != IOT_ERROR_NONE) {
					IOT_ERROR("Set deviceId failed!! (%d)", err);
					IOT_DUMP_MAIN(ERROR, BASE, err);
				}
			} else {
				IOT_ERROR("Rgistration data updated failed!!");
				err = IOT_ERROR_REG_UPDATED;
				IOT_DUMP_MAIN(ERROR, BASE, err);
			}

			if (err != IOT_ERROR_NONE) {
				ctx->cmd_err |= (1u << cmd->cmd_type);
				next_state = IOT_STATE_CHANGE_FAILED;
				state_opt = ctx->req_state;
			} else {
				next_state = IOT_STATE_CLOUD_CONNECTING;
			}

			IOT_MEM_CHECK("CLOUD_REGISTERED DONE >>PT<<");

			err = iot_state_update(ctx, next_state, state_opt);
			break;

		case IOT_COMMAND_CLOUD_CONNECTING:
			/* we don't need this lookup_id anymore */
			if (ctx->lookup_id) {
				free(ctx->lookup_id);
				ctx->lookup_id = NULL;
			}

			/* we don't need this hashed_sn anymore*/
			if (ctx->devconf.hashed_sn) {
				free(ctx->devconf.hashed_sn);
				ctx->devconf.hashed_sn = NULL;
			}

			/* if there is previous connection, disconnect it first. */
			if (ctx->evt_mqttcli != NULL) {
				IOT_INFO("There is previous connecting, disconnect it first.\n");
				iot_es_disconnect(ctx, IOT_CONNECT_TYPE_COMMUNICATION);
			}

			err = iot_es_connect(ctx, IOT_CONNECT_TYPE_COMMUNICATION);
			if (err == IOT_ERROR_MQTT_REJECT_CONNECT) {
				/* This error case will be happended when server replies
				 * some specific response, so the trial to connect with server
				 * is succeeded (with REJECT). By this reason, we don't want
				 * to change the STATE by the failure.
				 */
				IOT_WARN("Intended error case(reboot), go to STATE_UNKONWN\n");
				IOT_DUMP_MAIN(WARN, BASE, err);
				next_state = IOT_STATE_UNKNOWN;
			} else if (err != IOT_ERROR_NONE) {
				IOT_ERROR("failed to iot_es_connect for communication\n");

				ctx->cmd_err |= (1u << cmd->cmd_type);
				next_state = IOT_STATE_CHANGE_FAILED;
				state_opt = ctx->req_state;
			} else {
				next_state = IOT_STATE_CLOUD_CONNECTED;
			}

			IOT_MEM_CHECK("CLOUD_CONNECTTING DONE >>PT<<");

			err = iot_state_update(ctx, next_state, state_opt);
			break;

		case IOT_COMMAND_NOTIFICATION_RECEIVED:
			noti = (iot_noti_data_t *)cmd->param;
			if (!noti) {
				IOT_ERROR("There is no noti handler");
				IOT_DUMP_MAIN(ERROR, BASE, 0xDEADBEEF);
				break;
			}
			IOT_DUMP_MAIN(INFO, BASE, noti->type);

			if (noti->type == (iot_noti_type_t)_IOT_NOTI_TYPE_DEV_DELETED) {
				IOT_INFO("cleanup device");
				IOT_DUMP_MAIN(WARN, BASE, 0xC1EAC1EA);

				iot_device_cleanup(ctx);
				if (ctx->noti_cb)
					ctx->noti_cb(noti, ctx->noti_usr_data);

				IOT_REBOOT();
			} else if (noti->type == (iot_noti_type_t)_IOT_NOTI_TYPE_RATE_LIMIT) {
				IOT_INFO("rate limit");
				IOT_DUMP_MAIN(WARN, BASE, 0xBAD22222);

				if (ctx->noti_cb)
					ctx->noti_cb(noti, ctx->noti_usr_data);
			} else if (noti->type == (iot_noti_type_t)_IOT_NOTI_TYPE_QUOTA_REACHED) {
				IOT_INFO("quota reached");
				IOT_DUMP_MAIN(WARN, BASE, 0xBAD200BE);

				if (ctx->noti_cb)
					ctx->noti_cb(noti, ctx->noti_usr_data);
			} else if (noti->type == (iot_noti_type_t)_IOT_NOTI_TYPE_SEND_FAILED) {
				IOT_INFO("send failed seq number : %d", noti->raw.send_fail.failed_sequence_num);

				if (ctx->noti_cb)
					ctx->noti_cb(noti, ctx->noti_usr_data);
			} else if (noti->type == (iot_noti_type_t)_IOT_NOTI_TYPE_JWT_EXPIRED) {
				iot_es_disconnect(ctx, IOT_CONNECT_TYPE_COMMUNICATION);
				iot_es_connect(ctx, IOT_CONNECT_TYPE_COMMUNICATION);
			}

			break;

		case IOT_COMMAND_CHANGE_STATE_TIMEOUT:
			state_data = (struct iot_state_data *)cmd->param;
			if (!state_data) {
				IOT_ERROR("There is no state_data for cmd :%d", cmd->cmd_type);
				IOT_DUMP_MAIN(ERROR, BASE, 0xDEADBEEF);
				break;
			}

			if ((ctx->curr_state == ctx->req_state) || (state_data->iot_state != ctx->req_state)) {
				IOT_INFO("Already iot-stat updated or mis-matched, can't change timeout : %d for %d",
					state_data->opt, state_data->iot_state);
			} else {
				IOT_INFO("We've got timemout changing cmd for %d", state_data->iot_state);
				IOT_DUMP_MAIN(INFO, BASE, ((state_data->iot_state << 8u) | state_data->opt));
				_do_update_timeout(ctx, (unsigned int)state_data->opt);
			}
			break;

		case IOT_COMMAND_SELF_CLEANUP:
			IOT_WARN("self device cleanup");
			if (cmd->param) {
				reboot = (bool *)cmd->param;
				IOT_DUMP_MAIN(WARN, BASE, (int)*reboot);
			} else {
				IOT_DUMP_MAIN(WARN, BASE, 0);
			}

			if (ctx->es_http_ready) {
				ctx->es_http_ready = false;
				iot_easysetup_deinit(ctx);
			}

			if (ctx->es_res_created)
				_delete_easysetup_resources_all(ctx);

			iot_device_cleanup(ctx);

			if (reboot && *reboot) {
				IOT_REBOOT();
			} else {
				err = iot_state_update(ctx, IOT_STATE_UNKNOWN,
						IOT_STATE_OPT_CLEANUP);
			}

			break;

		default:
			break;
	}

out_do_cmd:
	if (err == IOT_ERROR_NONE || err == IOT_ERROR_DUPLICATED_CMD) {
		_clear_cmd_status(ctx, cmd->cmd_type);
	} else {
		IOT_ERROR("failed to handle cmd: %d\n", cmd->cmd_type);
		IOT_DUMP_MAIN_ARG2(ERROR, COMMAND, cmd->cmd_type, ctx->curr_state);
	}

	return err;
}

static void _do_cmd_tout_check(struct iot_context *ctx)
{
	char is_expired;
	iot_state_t next_state;

	/* If the iot-core is stayed in IOT_STATE_UNKNOWN,
	 * we don't need to check timeout & condition
	 */
	if ((ctx->curr_state == IOT_STATE_UNKNOWN) &&
			(ctx->req_state == IOT_STATE_UNKNOWN))
		return;

	/* If device comes to connected_state, we don't need timeout checking */
	if (ctx->curr_state == IOT_STATE_CLOUD_CONNECTED)
		is_expired = 0;
	else
		is_expired = iot_os_timer_isexpired(ctx->state_timer);

	if ((ctx->curr_state != ctx->req_state) || is_expired) {
		if (is_expired && !ctx->cmd_err) {
			IOT_WARN("New state changing timeout");
			IOT_DUMP_MAIN(WARN, BASE, 0x8BADF00D);

			next_state = IOT_STATE_CHANGE_FAILED;
			if (iot_state_update(ctx, next_state, ctx->req_state)
					!= IOT_ERROR_NONE) {
				IOT_ERROR("Failed state error updated (%d/%d)",
					ctx->curr_state, ctx->req_state);
				IOT_DUMP_MAIN(ERROR, BASE, ctx->req_state);
			}
		} else if (!ctx->cmd_status) {
			/* All command processes are done for req_state */
			if (!ctx->cmd_err) {
				IOT_INFO("New state updated for %d", ctx->req_state);
				ctx->curr_state = ctx->req_state;

				if (ctx->status_cb)
					_do_status_report(ctx, ctx->curr_state, true);
			} else {
				/* Some command makes error, so do not update state */
				IOT_ERROR("Some cmd(0x%0x) failed for %d state",
					ctx->cmd_err, ctx->req_state);
			}
		}
	}
}

static void _throw_away_all_cmd_queue(struct iot_context *ctx)
{
	struct iot_command cmd;
	enum iot_command_type cmd_type;

	if (!ctx) {
		IOT_ERROR("There is no ctx!!");
		IOT_DUMP_MAIN(ERROR, BASE, 0xDEADBEEF);
		return;
	}

	cmd.param = NULL;
	while (iot_os_queue_receive(ctx->cmd_queue,
				&cmd, 0) == IOT_OS_TRUE) {
		_clear_cmd_status(ctx, cmd.cmd_type);
		if (cmd.param) {
			free(cmd.param);
			cmd.param = NULL;
		}
	}

	if (ctx->cmd_status) {
		IOT_WARN("There are unfinished cmds : 0x%x", ctx->cmd_status);
		for (cmd_type = IOT_COMMAND_READY_TO_CTL;
				cmd_type <= IOT_COMMAND_TYPE_MAX; cmd_type++) {
			if (ctx->cmd_count[cmd_type]) {
				IOT_WARN("Remained cmd[%d] = %d", cmd_type,
					ctx->cmd_count[cmd_type]);
				ctx->cmd_count[cmd_type] = 0;
			}
		}
		ctx->cmd_status = 0;
	}
}

static void _iot_main_task(struct iot_context *ctx)
{
	struct iot_command cmd;
	unsigned char curr_events;
	iot_error_t err = IOT_ERROR_NONE;
	struct iot_easysetup_payload easysetup_req;
#if !defined(STDK_MQTT_TASK)
	iot_state_t next_state;
	unsigned int task_cycle = IOT_MAIN_TASK_DEFAULT_CYCLE;
#endif

	for( ; ; ) {
#if defined(STDK_MQTT_TASK)
		curr_events = iot_os_eventgroup_wait_bits(ctx->iot_events,
			IOT_EVENT_BIT_ALL, true, false, 500);
#else
		curr_events = iot_os_eventgroup_wait_bits(ctx->iot_events,
			IOT_EVENT_BIT_ALL, true, task_cycle);
#endif
		if (curr_events & IOT_EVENT_BIT_COMMAND) {
			cmd.param = NULL;

			iot_os_mutex_lock(&ctx->iot_cmd_lock);
			if (iot_os_queue_receive(ctx->cmd_queue,
					&cmd, 0) != IOT_OS_FALSE) {

				IOT_DEBUG("cmd: %d\n", cmd.cmd_type);

				err = _do_iot_main_command(ctx, &cmd);
				if (cmd.param)
					free(cmd.param);

				if (err != IOT_ERROR_NONE) {
					IOT_ERROR("failed handle cmd (%d): %d\n", cmd.cmd_type, err);
					IOT_DUMP_MAIN(ERROR, BASE, err);
				}

				/* Set bit again to check whether the several cmds are already
				 * stacked up in the queue.
				 */
				iot_os_eventgroup_set_bits(ctx->iot_events, IOT_EVENT_BIT_COMMAND);
			}
			iot_os_mutex_unlock(&ctx->iot_cmd_lock);
		}

		if ((curr_events & IOT_EVENT_BIT_EASYSETUP_REQ) &&
						ctx->easysetup_req_queue) {
			easysetup_req.payload = NULL;
			easysetup_req.err = IOT_ERROR_NONE;
			if (iot_os_queue_receive(ctx->easysetup_req_queue,
					&easysetup_req, 0) != IOT_OS_FALSE) {
				IOT_DEBUG("request step: %d\n", easysetup_req.step);

				err = iot_easysetup_request_handler(ctx, easysetup_req);
				if (err != IOT_ERROR_NONE) {
					IOT_ERROR("failed handle easysetup request step %d: %d\n", easysetup_req.step, err);
					IOT_DUMP_MAIN(ERROR, BASE, err);
				} else {
					/* The SDK can't detect mobile's disconnecting after easy-setupcomplete
					 * so to guarantee final msg sending to mobile before disconnecting
					 * add some experiential delay after easy-setupcomplete
					 */
					if (easysetup_req.step == IOT_EASYSETUP_STEP_SETUPCOMPLETE) {
						iot_os_delay(1000); /* delay for easysetup/httpd */
					}
				}

				/* Set bit again to check whether the several cmds are already
				 * stacked up in the queue.
				 */
				iot_os_eventgroup_set_bits(ctx->iot_events, IOT_EVENT_BIT_EASYSETUP_REQ);
			}
		}

#if !defined(STDK_MQTT_TASK)
		/* check if there is MQTT packet from GG */
		task_cycle = IOT_MAIN_TASK_DEFAULT_CYCLE;
		if (ctx->reg_mqttcli) {
			int rc = st_mqtt_yield(ctx->reg_mqttcli, 0);
			if (rc < 0) {
				iot_es_disconnect(ctx, IOT_CONNECT_TYPE_REGISTRATION);
				IOT_WARN("Report Disconnected..");
				next_state = IOT_STATE_CLOUD_DISCONNECTED;
				err = iot_state_update(ctx, next_state, 0);
				IOT_DUMP_MAIN(WARN, BASE, err);

				IOT_WARN("Try MQTT self re-registering..\n");
				next_state = IOT_STATE_CLOUD_REGISTERING;
				err = iot_state_update(ctx, next_state, 0);
				IOT_DUMP_MAIN(WARN, BASE, err);
			} else if (rc > 0) {
				task_cycle = 0;
			}
		} else if (ctx->evt_mqttcli) {
			int rc = st_mqtt_yield(ctx->evt_mqttcli, 0);
			if (rc < 0) {
				iot_es_disconnect(ctx, IOT_CONNECT_TYPE_COMMUNICATION);
				IOT_WARN("Report Disconnected..");
				next_state = IOT_STATE_CLOUD_DISCONNECTED;
				err = iot_state_update(ctx, next_state, 0);
				IOT_DUMP_MAIN(WARN, BASE, err);

				IOT_WARN("Try MQTT self re-connecting..\n");
				next_state = IOT_STATE_CLOUD_CONNECTING;
				err = iot_state_update(ctx, next_state, 0);
				IOT_DUMP_MAIN(WARN, BASE, err);
			} else if (rc > 0) {
				task_cycle = 0;
			}
		}
#endif
		_do_cmd_tout_check(ctx);
	}
}

IOT_CTX* st_conn_init(unsigned char *onboarding_config, unsigned int onboarding_config_len,
					unsigned char *device_info, unsigned int device_info_len)
{
	struct iot_context *ctx = NULL;
	iot_error_t iot_err;
	struct iot_devconf_prov_data *devconf_prov;
	struct iot_device_info *dev_info;

	if (!onboarding_config || !device_info) {
		IOT_ERROR("invalid parameters\n");
		return NULL;
	}

	ctx = iot_os_malloc(sizeof(struct iot_context));
	if (!ctx) {
		IOT_ERROR("failed to malloc for iot_context\n");
		return NULL;
	}

	/* Initialize all values */
	memset(ctx, 0, sizeof(struct iot_context));

	iot_err = iot_os_timer_init(&ctx->state_timer);
	if (iot_err != IOT_ERROR_NONE) {
		IOT_ERROR("failed to malloc for state_timer\n");
		free(ctx);
		return NULL;
	}

	iot_err = iot_os_timer_init(&ctx->rate_limit_timeout);
	if (iot_err != IOT_ERROR_NONE) {
		IOT_ERROR("failed to malloc for rate_limit_timeout\n");
		iot_os_timer_destroy(&ctx->state_timer);
		free(ctx);
		return NULL;
	}

	// Initialize device nv section
	iot_err = iot_nv_init(device_info, device_info_len);
	if (iot_err != IOT_ERROR_NONE) {
		IOT_ERROR("NV init fail");
		goto error_main_bsp_init;
	}

#if defined(CONFIG_STDK_IOT_CORE_LOG_FILE)
	/* Initialize logging task */
#if defined(CONFIG_STDK_IOT_CORE_LOG_FILE_RAM_ONLY)
	iot_err = iot_log_file_init(RAM_ONLY);
#elif defined(CONFIG_STDK_IOT_CORE_LOG_FILE_FLASH_WITH_RAM)
	iot_err = iot_log_file_init(FLASH_WITH_RAM);
#else
#error "Need to choice STDK_IOT_CORE_LOG_FILE_TYPE first"
#endif
	if (iot_err != IOT_ERROR_NONE) {
		IOT_ERROR("log file init fail");
		goto error_main_log_file_init;
	}
#endif

	// Initialize device profile & device info
	devconf_prov = &(ctx->devconf);
	iot_err = iot_api_onboarding_config_load(onboarding_config, onboarding_config_len, devconf_prov);
	if (iot_err != IOT_ERROR_NONE) {
		IOT_ERROR("failed loading onboarding profile (%d)", iot_err);
		IOT_DUMP_MAIN(ERROR, BASE, iot_err);
		goto error_main_load_onboarding_config;
	}

	dev_info = &(ctx->device_info);
	iot_err = iot_api_device_info_load(device_info, device_info_len, dev_info);
	if (iot_err != IOT_ERROR_NONE) {
		IOT_ERROR("failed loading device info (%d)", iot_err);
		IOT_DUMP_MAIN(ERROR, BASE, iot_err);
		goto error_main_load_device_info;
	}

	// Initialize Wi-Fi
	iot_bsp_wifi_init();

	/* create queue */
	ctx->cmd_queue = iot_os_queue_create(IOT_QUEUE_LENGTH,
			sizeof(struct iot_command));

	if (!ctx->cmd_queue) {
		IOT_ERROR("failed to create Queue for iot core task\n");
		IOT_DUMP_MAIN(ERROR, BASE, IOT_QUEUE_LENGTH);
		goto error_main_init_cmd_q;
	}

	/* create msg queue for IOT_STATE */
	ctx->usr_events = iot_os_eventgroup_create();
	if (!ctx->usr_events) {
		IOT_ERROR("failed to create EventGroup for usr_events\n");
		IOT_DUMP_MAIN(ERROR, BASE, 0xDEADBEEF);
		goto error_main_init_usr_evts;
	}

	/* create msg eventgroup for each queue handling */
	ctx->iot_events = iot_os_eventgroup_create();
	if (!ctx->iot_events) {
		IOT_ERROR("failed to create EventGroup for iot_task\n");
		IOT_DUMP_MAIN(ERROR, BASE, 0xDEADBEEF);
		goto error_main_init_events;
	}

	ctx->iot_reg_data.new_reged = false;
	ctx->curr_state = ctx->req_state = IOT_STATE_UNKNOWN;

	/* create mutex for iot-core's command handling */
	if (iot_os_mutex_init(&ctx->iot_cmd_lock) != IOT_OS_TRUE) {
		IOT_ERROR("failed to init iot_cmd_lock\n");
		IOT_DUMP_MAIN(ERROR, BASE, 0xDEADBEEF);
		goto error_main_cmd_mutex_init;
	}

	/* create mutex for user level st_conn_xxx APIs */
	if (iot_os_mutex_init(&ctx->st_conn_lock) != IOT_OS_TRUE) {
		IOT_ERROR("failed to init st_conn_lock\n");
		IOT_DUMP_MAIN(ERROR, BASE, 0xDEADBEEF);
		goto error_main_conn_mutex_init;
	}

	/* create task */
	if (iot_os_thread_create(_iot_main_task, IOT_TASK_NAME,
			IOT_TASK_STACK_SIZE, (void *)ctx, IOT_TASK_PRIORITY,
			&ctx->main_thread) != IOT_OS_TRUE) {
		IOT_ERROR("failed to create iot_task\n");
		IOT_DUMP_MAIN(ERROR, BASE, IOT_TASK_STACK_SIZE);
		goto error_main_task_init;
	}

	IOT_MEM_CHECK("MAIN_INIT_ALL_DONE >>PT<<");

#ifdef VER_EXTRA_STR
	IOT_INFO("stdk_version : %d.%d.%d-%s",
		VER_MAJOR, VER_MINOR, VER_PATCH, VER_EXTRA_STR);
#else
	IOT_INFO("stdk_version : %s", STDK_VERSION_STRING);
#endif

	IOT_DUMP_MAIN(INFO, BASE, STDK_VERSION_CODE);

	return (IOT_CTX*)ctx;

error_main_task_init:
	iot_os_mutex_destroy(&ctx->st_conn_lock);

error_main_conn_mutex_init:
	iot_os_mutex_destroy(&ctx->iot_cmd_lock);

error_main_cmd_mutex_init:
	iot_os_eventgroup_delete(ctx->iot_events);

error_main_init_events:
	iot_os_eventgroup_delete(ctx->usr_events);

error_main_init_usr_evts:
	iot_os_queue_delete(ctx->cmd_queue);

error_main_init_cmd_q:
	iot_api_device_info_mem_free(dev_info);

error_main_load_device_info:
	iot_api_onboarding_config_mem_free(devconf_prov);

error_main_load_onboarding_config:
#if defined(CONFIG_STDK_IOT_CORE_LOG_FILE)
	iot_log_file_exit();

error_main_log_file_init:
#endif
	iot_nv_deinit();

error_main_bsp_init:
	iot_os_timer_destroy(&ctx->rate_limit_timeout);
	iot_os_timer_destroy(&ctx->state_timer);
	free(ctx);

	return NULL;
}

static iot_error_t _do_recovery(struct iot_context *ctx,
			iot_state_t fail_state)
{
	iot_error_t iot_err = IOT_ERROR_NONE;

	IOT_WARN("state changing fail for %d, curr_state :%d",
		fail_state, ctx->curr_state);

	if ((fail_state != IOT_STATE_PROV_ENTER) && (fail_state != IOT_STATE_PROV_CONFIRM)) {
		if (fail_state != ctx->rcv_fail_state) {
			ctx->rcv_try_cnt = 0;
			ctx->rcv_fail_state = fail_state;
		} else {
			ctx->rcv_try_cnt++;
		}
	}

	/* Repeated same exceptional cases
	 * So try do something more first
	 */
	if (ctx->rcv_try_cnt > RECOVER_TRY_MAX) {
		IOT_WARN("Recovery state:[%d] repeated MAX times(%d)",
			fail_state, ctx->rcv_try_cnt);
		IOT_DUMP_MAIN(WARN, BASE, fail_state);
		switch (fail_state) {
		case IOT_STATE_CLOUD_REGISTERING:
			/* fall through */
		case IOT_STATE_CLOUD_CONNECTING:
			/* wifi off */
			iot_err = iot_wifi_ctrl_request(ctx, IOT_WIFI_MODE_OFF);
			if (iot_err != IOT_ERROR_NONE) {
				IOT_ERROR("Can't send WIFI off command(%d)",
					iot_err);
				IOT_DUMP_MAIN(ERROR, BASE, iot_err);
				break;
			}

			/* wifi on againg by station */
			iot_err = iot_wifi_ctrl_request(ctx, IOT_WIFI_MODE_STATION);
			if (iot_err != IOT_ERROR_NONE) {
				IOT_ERROR("Can't send WIFI station command(%d)",
					iot_err);
				IOT_DUMP_MAIN(ERROR, BASE, iot_err);
			}
			break;

		default:
			IOT_WARN("No action for repeating state:[%d] failure (%d)",
				fail_state, ctx->rcv_try_cnt);
			IOT_DUMP_MAIN(WARN, BASE, ctx->rcv_try_cnt);
			break;
		}

		/* reset rcv_try_cnt */
		ctx->rcv_try_cnt = 0;
	}

	if (ctx->curr_state == fail_state) {
		/* We assume that these are intentional timeout cases
		 * when target didn't receive PROV_CONFIRM, CLOUD_REGISTERED
		 */
		switch (fail_state) {
		case IOT_STATE_PROV_ENTER:
		case IOT_STATE_PROV_CONFIRM:
			IOT_ERROR("Failed process [%d] on time, STOP", fail_state);
			IOT_DUMP_MAIN(ERROR, BASE, 0xDEADFEED);

			if (ctx->scan_result) {
				free(ctx->scan_result);
				ctx->scan_result = NULL;
			}
			ctx->scan_num = 0;

			/* change its state by UNKNOWN to prevent self-reentrant */
			iot_err = iot_state_update(ctx, IOT_STATE_UNKNOWN, 0);
			break;

		case IOT_STATE_CLOUD_REGISTERING:
			IOT_ERROR("Failed to go to CLOUD_REGISTERED on time");
			IOT_DUMP_MAIN(ERROR, BASE, 0xC1EAC1EA);

			iot_device_cleanup(ctx);
			IOT_REBOOT();
			break;

		case IOT_STATE_CLOUD_CONNECTING:
			IOT_ERROR("Failed to go to CLOUD_CONNECTED on time");
			/* wifi off */
			iot_err = iot_wifi_ctrl_request(ctx, IOT_WIFI_MODE_OFF);
			if (iot_err != IOT_ERROR_NONE) {
				IOT_ERROR("Can't send WIFI off command(%d)",
					iot_err);
				IOT_DUMP_MAIN(ERROR, BASE, iot_err);
				break;
			}

			/* wifi on againg for station */
			iot_err = iot_wifi_ctrl_request(ctx, IOT_WIFI_MODE_STATION);
			if (iot_err != IOT_ERROR_NONE) {
				IOT_ERROR("Can't send WIFI station command(%d)",
					iot_err);
				IOT_DUMP_MAIN(ERROR, BASE, iot_err);
				break;
			}

			/* retry CLOUD_CONNECTING */
			iot_err = iot_command_send(ctx,
						IOT_COMMAND_CLOUD_CONNECTING,
						NULL, 0);
			break;

		default:
			IOT_WARN("No action for state:[%d] failure",
				fail_state);
			IOT_DUMP_MAIN(WARN, BASE, fail_state);
			break;

		}
	} else {
		/* These are exceptional timeout cases
		 * when the target can't do somthing
		 */
		switch (fail_state) {
		case IOT_STATE_PROV_ENTER:
		case IOT_STATE_PROV_CONFIRM:
			IOT_ERROR("Failed to do process [%d] on time, STOP",
				fail_state);
			IOT_DUMP_MAIN(ERROR, BASE, 0xDEADFEED);

			if (ctx->scan_result) {
				free(ctx->scan_result);
				ctx->scan_result = NULL;
			}
			ctx->scan_num = 0;

			/* change its state by UNKNOWN to prevent self-reentrant */
			iot_err = iot_state_update(ctx, IOT_STATE_UNKNOWN, 0);
			break;

		case IOT_STATE_PROV_DONE:
			IOT_ERROR("Failed to do process [%d] on time, retry",
				fail_state);
			/* wifi off */
			iot_err = iot_wifi_ctrl_request(ctx, IOT_WIFI_MODE_OFF);
			if (iot_err != IOT_ERROR_NONE) {
				IOT_ERROR("Can't send WIFI off command(%d)",
					iot_err);
				IOT_DUMP_MAIN(ERROR, BASE, iot_err);
				break;
			}

			iot_err = iot_state_update(ctx, fail_state, 0);
			break;

		case IOT_STATE_CLOUD_REGISTERING:
			/* fall through */
		case IOT_STATE_CLOUD_CONNECTING:
			IOT_ERROR("Failed to do process [%d] on time, retry",
				fail_state);
			iot_err = iot_state_update(ctx,
						IOT_STATE_CLOUD_DISCONNECTED, 0);
			if (iot_err != IOT_ERROR_NONE) {
				IOT_ERROR("Can't update Disconnected state(%d)",
					iot_err);
				IOT_DUMP_MAIN(ERROR, BASE, iot_err);
			}

			IOT_WARN("Self retry/recovery it again\n");
			iot_err = iot_state_update(ctx, fail_state, 0);
			break;

		default:
			IOT_WARN("No action for process:[%d] failure",
				fail_state);
			IOT_DUMP_MAIN(WARN, BASE, fail_state);
			break;
		}
	}

	return iot_err;
}


static iot_error_t _do_state_updating(struct iot_context *ctx,
		iot_state_t new_state, int opt, unsigned int *timeout_ms)
{
	iot_error_t iot_err = IOT_ERROR_INVALID_ARGS;
	enum iot_command_type iot_cmd;

	/* Set default timeout value for next state */
	*timeout_ms = NEXT_STATE_TIMEOUT_MS;

	switch (new_state) {
	case IOT_STATE_INITIALIZED:
		iot_cmd = IOT_COMMAND_CHECK_PROV_STATUS;
		iot_err = iot_command_send(ctx, iot_cmd, NULL, 0);
		IOT_DUMP_MAIN_ARG2(INFO, STATE, new_state, iot_err);
		break;

	case IOT_STATE_PROV_ENTER:
		iot_err = iot_wifi_ctrl_request(ctx, IOT_WIFI_MODE_SCAN);
		if (iot_err != IOT_ERROR_NONE) {
			IOT_ERROR("Can't control WIFI mode scan.(%d)", iot_err);
			IOT_DUMP_MAIN(ERROR, BASE, iot_err);
 			break;
 		}

		/*wifi soft-ap mode w/ ssid E4 format*/
		iot_err = iot_wifi_ctrl_request(ctx, IOT_WIFI_MODE_SOFTAP);
		if (iot_err != IOT_ERROR_NONE) {
			IOT_ERROR("Can't send WIFI mode softap.(%d)", iot_err);
			IOT_DUMP_MAIN(ERROR, BASE, iot_err);
 			break;
 		}

		/* Update next state waiting time for Easy-setup process */
		*timeout_ms = EASYSETUP_TIMEOUT_MS;
		IOT_MEM_CHECK("ES_PROV_ENTER DONE >>PT<<");
		break;

	case IOT_STATE_PROV_CONN_MOBILE:
		IOT_INFO("Notification only with IOT_STATE_PROV_CONN_MOBILE");
		*timeout_ms = 0;
		iot_err = IOT_ERROR_NONE;
		break;

	case IOT_STATE_PROV_CONFIRM:
		IOT_REMARK("the state changes to IOT_STATE_PROV_CONFIRM");
		iot_err = IOT_ERROR_NONE;
		break;

	case IOT_STATE_PROV_DONE:
		/* Wakeup user interaction by provisioning done */
		iot_os_eventgroup_set_bits(ctx->usr_events,
			IOT_USR_INTERACT_BIT_PROV_DONE);

		iot_err = iot_wifi_ctrl_request(ctx, IOT_WIFI_MODE_STATION);
		if (iot_err != IOT_ERROR_NONE) {
			IOT_ERROR("Can't send WIFI mode command(%d)", iot_err);
			IOT_DUMP_MAIN(ERROR, BASE, iot_err);
		} else {
			iot_cmd = IOT_COMMAND_CHECK_CLOUD_STATE;
			iot_err = iot_command_send(ctx, iot_cmd, NULL, 0);
		}

		break;

	case IOT_STATE_CLOUD_REGISTERING:
		if (ctx->es_res_created)
			_delete_easysetup_resources_all(ctx);

		*timeout_ms = REGISTRATION_TIMEOUT_MS;
		iot_cmd = IOT_COMMAND_CLOUD_REGISTERING;
		iot_err = iot_command_send(ctx, iot_cmd, NULL, 0);
		IOT_REMARK("the state changes to IOT_STATE_CLOUD_REGISTERING");
		break;

	case IOT_STATE_CLOUD_CONNECTING:
		if (ctx->es_res_created)
			_delete_easysetup_resources_all(ctx);

		iot_cmd = IOT_COMMAND_CLOUD_CONNECTING;
		iot_err = iot_command_send(ctx, iot_cmd, NULL, 0);
		break;

	case IOT_STATE_CLOUD_CONNECTED:
		iot_cmd = IOT_COMMAND_READY_TO_CTL;
		iot_err = iot_command_send(ctx, iot_cmd, NULL, 0);
		IOT_DUMP_MAIN_ARG2(INFO, STATE, new_state, iot_err);
		break;

	case IOT_STATE_CLOUD_DISCONNECTED:
		iot_err = IOT_ERROR_NONE;
		*timeout_ms = IOT_OS_MAX_DELAY;
		break;

	case IOT_STATE_CHANGE_FAILED:
		iot_err = _do_recovery(ctx, (iot_state_t)opt);
		*timeout_ms = IOT_OS_MAX_DELAY;
		break;

	case IOT_STATE_UNKNOWN:
		/* At this state, iot-core can't make next decision by itself
		 * So just wait(stop) process until external triggering happened
		 * such as reboot, re-start command from user-apps
		 */
		IOT_WARN("Iot-core task will be stopped, needed ext-triggering\n");
		IOT_DUMP_MAIN_ARG2(WARN, STATE, new_state, iot_err);

		/* wifi off */
		iot_err = iot_wifi_ctrl_request(ctx, IOT_WIFI_MODE_OFF);
		if (iot_err != IOT_ERROR_NONE) {
			IOT_ERROR("Can't send WIFI off command(%d)",
				iot_err);
			IOT_DUMP_MAIN(ERROR, BASE, iot_err);
		}

		if (ctx->es_http_ready) {
			ctx->es_http_ready = false;
			iot_easysetup_deinit(ctx);
		}

		if (ctx->es_res_created)
			_delete_easysetup_resources_all(ctx);

		/* This is final state of iot-core, so update it now */
		ctx->curr_state = ctx->req_state = IOT_STATE_UNKNOWN;

		/* clear reported_stat for the next connection */
		if (ctx->status_cb) {
			_do_status_report(ctx, IOT_STATE_CLOUD_DISCONNECTED, false);
		}

		/* Reset recovery flags */
		ctx->rcv_fail_state = IOT_STATE_UNKNOWN;
		ctx->rcv_try_cnt = 0;

		if (opt == IOT_STATE_OPT_CLEANUP) {
			iot_os_eventgroup_set_bits(ctx->usr_events,
				IOT_USR_INTERACT_BIT_STATE_UNKNOWN | IOT_USR_INTERACT_BIT_CLEANUP_DONE);
		} else {
			iot_os_eventgroup_set_bits(ctx->usr_events,
				IOT_USR_INTERACT_BIT_STATE_UNKNOWN);
		}

		*timeout_ms = IOT_OS_MAX_DELAY;
		iot_err = IOT_ERROR_NONE;
		break;

	default:
		IOT_ERROR("Unsupported new IOT_STATE!!(%d)\n", new_state);
		IOT_DUMP_MAIN(ERROR, STATE, new_state);
		break;

	}

	return iot_err;
}

#define WAIT_USR_INTERACT() \
do { \
	iot_os_mutex_unlock(&ctx->st_conn_lock); \
	\
	curr_events = iot_os_eventgroup_wait_bits(ctx->usr_events, \
		IOT_USR_INTERACT_BITS_ST_CONN, true, IOT_OS_MAX_DELAY); \
	\
	iot_os_mutex_lock(&ctx->st_conn_lock); \
	\
	if (curr_events & IOT_USR_INTERACT_BIT_PROV_CONFIRM) { \
		if (ctx->devconf.ownership_validation_type & IOT_OVF_TYPE_BUTTON) { \
			_do_status_report(ctx, IOT_STATE_PROV_CONFIRM, false); \
		} \
	\
		iot_err = IOT_ERROR_NONE; \
	} else if (curr_events & IOT_USR_INTERACT_BIT_PROV_DONE) { \
		iot_err = IOT_ERROR_NONE; \
	} else { \
		IOT_ERROR("Can't go to PROV_CONFIRM (0x%0x)", curr_events); \
		iot_err = IOT_ERROR_TIMEOUT; \
	} \
} while(0)

#define SET_STATUS_CB(cb, maps, usr_data) \
do { \
	ctx->status_cb = cb; \
	ctx->status_maps = maps; \
	ctx->status_usr_data = usr_data; \
} while(0)

#define UNSET_STATUS_CB() \
do { \
	ctx->status_cb = NULL; \
	ctx->status_maps = 0; \
	ctx->status_usr_data = NULL; \
} while(0)

#define IS_CTX_VALID(ctx) ( \
	ctx ? ( \
	ctx->cmd_queue ? ( \
	ctx->usr_events ? ( \
	ctx->iot_events ? true : false) : false) : false) : false)

int st_conn_start(IOT_CTX *iot_ctx, st_status_cb status_cb,
		iot_status_t maps, void *usr_data, iot_pin_t *pin_num)
{
	struct iot_state_data state_data;
	iot_error_t iot_err;
	struct iot_context *ctx = (struct iot_context*)iot_ctx;
	unsigned char curr_events;
	iot_os_thread curr_thread;

	if (!IS_CTX_VALID(ctx))
		return IOT_ERROR_INVALID_ARGS;

	if (iot_os_thread_get_current_handle(&curr_thread) == IOT_OS_TRUE) {
		if (curr_thread == ctx->main_thread) {
			IOT_WARN("Can't support it on same thread!!");
			IOT_DUMP_MAIN(ERROR, BASE, 0xDEADBABE);
			return IOT_ERROR_BAD_REQ;
		}
	} else {
		IOT_WARN("Can't get thread info. Please check it called same thread or not!!");
		IOT_DUMP_MAIN(WARN, BASE, 0xDEADBABE);
	}

	if (iot_os_mutex_lock(&ctx->st_conn_lock) != IOT_OS_TRUE)
		return IOT_ERROR_BAD_REQ;

	IOT_INFO("%s start (%s)", __func__, pin_num ? "pin" : "no-pin");
	IOT_DUMP_MAIN(INFO, BASE, (pin_num ? 1 : 0));

	if ((ctx->curr_state != IOT_STATE_UNKNOWN) || (ctx->req_state != IOT_STATE_UNKNOWN)) {
		IOT_WARN("Can't start it, iot_main_task is already working(%d)", ctx->curr_state);
		IOT_DUMP_MAIN(WARN, BASE, ctx->curr_state);

		iot_err = IOT_ERROR_BAD_REQ;
		goto end_st_conn_start;
	}

	if (ctx->devconf.ownership_validation_type & IOT_OVF_TYPE_BUTTON) {
		if (!status_cb) {
			IOT_ERROR("There is no status_cb for otm");
			IOT_DUMP_MAIN(ERROR, BASE, 0);
			iot_err = IOT_ERROR_BAD_REQ;
			goto end_st_conn_start;
		}
	}

	if (ctx->es_res_created) {
		IOT_WARN("Already easysetup resources are created!!");
	} else {
		iot_err = _create_easysetup_resources(ctx, pin_num);
		if (iot_err != IOT_ERROR_NONE) {
			IOT_ERROR("failed to create easysetup resources(%d)", iot_err);
			IOT_DUMP_MAIN(ERROR, BASE, iot_err);
			goto end_st_conn_start;
		}
	}

	state_data.iot_state = IOT_STATE_INITIALIZED;
	state_data.opt = IOT_STATE_OPT_NONE;

	ctx->add_justworks = false;

	if (status_cb) {
		SET_STATUS_CB(status_cb, maps, usr_data);
	}

	iot_os_eventgroup_clear_bits(ctx->usr_events, IOT_USR_INTERACT_BITS_ST_CONN);

	iot_err = iot_command_send(ctx, IOT_COMMNAD_STATE_UPDATE,
				&state_data, sizeof(struct iot_state_data));

	if (iot_err != IOT_ERROR_NONE) {
		IOT_ERROR("failed to send command(%d)", iot_err);
		IOT_DUMP_MAIN(ERROR, BASE, iot_err);
		if (ctx->status_cb) {
			UNSET_STATUS_CB();
		}

		if (ctx->es_res_created) {
			_delete_easysetup_resources_all(ctx);
		}
		goto end_st_conn_start;
	}

	WAIT_USR_INTERACT();

	IOT_INFO("%s done (%d)", __func__, iot_err);
	IOT_DUMP_MAIN(INFO, BASE, iot_err);

end_st_conn_start:
	iot_os_mutex_unlock(&ctx->st_conn_lock);
	return iot_err;
}

int st_conn_cleanup(IOT_CTX *iot_ctx, bool reboot)
{
	iot_error_t iot_err;
	unsigned char curr_events;
	struct iot_context *ctx = (struct iot_context*)iot_ctx;
	iot_os_thread curr_thread;

	if (!IS_CTX_VALID(ctx))
		return IOT_ERROR_INVALID_ARGS;

	if (iot_os_thread_get_current_handle(&curr_thread) == IOT_OS_TRUE) {
		if (curr_thread == ctx->main_thread) {
			IOT_WARN("Can't support it on same thread!!");
			IOT_DUMP_MAIN(ERROR, BASE, 0xDEADBABE);
			return IOT_ERROR_BAD_REQ;
		}
	} else {
		IOT_WARN("Can't get thread info. Please check it called same thread or not!!");
		IOT_DUMP_MAIN(WARN, BASE, 0xDEADBABE);
	}

	if (iot_os_mutex_lock(&ctx->st_conn_lock) != IOT_OS_TRUE)
		return IOT_ERROR_BAD_REQ;

	IOT_INFO("%s start (%d)", __func__, reboot);
	IOT_DUMP_MAIN(INFO, BASE, reboot);

	/* remove all queued commands */
	iot_os_mutex_lock(&ctx->iot_cmd_lock);
	_throw_away_all_cmd_queue(ctx);
	iot_os_mutex_unlock(&ctx->iot_cmd_lock);

	iot_os_eventgroup_clear_bits(ctx->usr_events, IOT_USR_INTERACT_BIT_CLEANUP_DONE);

	iot_err = iot_command_send(ctx,
			IOT_COMMAND_SELF_CLEANUP, &reboot, sizeof(bool));
	if (iot_err != IOT_ERROR_NONE) {
		IOT_ERROR("failed to send cleanup(%d)", iot_err);
		IOT_DUMP_MAIN(ERROR, BASE, iot_err);
		goto err_cleanup;
	}

	curr_events = iot_os_eventgroup_wait_bits(ctx->usr_events,
		IOT_USR_INTERACT_BIT_CLEANUP_DONE, true, (NEXT_STATE_TIMEOUT_MS * 2));

	if (!(curr_events & IOT_USR_INTERACT_BIT_CLEANUP_DONE)) {
		IOT_ERROR("Timeout happened for st_conn_cleanup");
		IOT_DUMP_MAIN(ERROR, BASE, 0x8BADF00D);
		iot_err = IOT_ERROR_TIMEOUT;
	}

	IOT_INFO("%s done (%d)", __func__, iot_err);
	IOT_DUMP_MAIN(INFO, BASE, iot_err);

err_cleanup:
	iot_os_mutex_unlock(&ctx->st_conn_lock);

	return iot_err;
}

int st_conn_start_ex(IOT_CTX *iot_ctx, iot_ext_args_t *ext_args)
{
	struct iot_state_data state_data;
	iot_error_t iot_err;
	struct iot_context *ctx = (struct iot_context*)iot_ctx;
	unsigned char curr_events;
	iot_os_thread curr_thread;

	if (!IS_CTX_VALID(ctx) || !ext_args) {
		IOT_ERROR("invalid parameters\n");
		return IOT_ERROR_INVALID_ARGS;
	}

	if (iot_os_thread_get_current_handle(&curr_thread) == IOT_OS_TRUE) {
		if (curr_thread == ctx->main_thread) {
			IOT_WARN("Can't support it on same thread!!");
			IOT_DUMP_MAIN(ERROR, BASE, 0xDEADBABE);
			return IOT_ERROR_BAD_REQ;
		}
	} else {
		IOT_WARN("Can't get thread info. Please check it called same thread or not!!");
		IOT_DUMP_MAIN(WARN, BASE, 0xDEADBABE);
	}

	if ((ext_args->start_pt != IOT_STATUS_CONNECTING) &&
			(ext_args->start_pt != IOT_STATUS_PROVISIONING)) {
		IOT_ERROR("Unsupported request (%d)\n", ext_args->start_pt);
		return IOT_ERROR_BAD_REQ;
	}

	if (!(ext_args->skip_usr_confirm) &&
			(ctx->devconf.ownership_validation_type & IOT_OVF_TYPE_BUTTON)) {
		if (!ext_args->status_cb && (ext_args->start_pt == IOT_STATUS_PROVISIONING)) {
			IOT_ERROR("There is no status_cb for otm");
			return IOT_ERROR_BAD_REQ;
		}
	}

	if (iot_os_mutex_lock(&ctx->st_conn_lock) != IOT_OS_TRUE)
		return IOT_ERROR_BAD_REQ;

	IOT_INFO("%s start (%d/%d)", __func__,
		ext_args->start_pt, ext_args->skip_usr_confirm);
	IOT_DUMP_MAIN(INFO, BASE, ((ext_args->start_pt << 8u) | ext_args->skip_usr_confirm));

	if ((ctx->curr_state != IOT_STATE_UNKNOWN) || (ctx->req_state != IOT_STATE_UNKNOWN)) {
		IOT_WARN("iot-core is already working(%d), stop & remove all cmd first",
			ctx->curr_state);
		IOT_DUMP_MAIN(WARN, BASE, ctx->curr_state);

		/* remove all queued commands */
		iot_os_mutex_lock(&ctx->iot_cmd_lock);
		_throw_away_all_cmd_queue(ctx);
		iot_os_mutex_unlock(&ctx->iot_cmd_lock);

		/* if there is previous connection, disconnect it first. */
		if (ctx->evt_mqttcli != NULL) {
			IOT_INFO("There is previous connecting, disconnect it first.\n");
			iot_es_disconnect(ctx, IOT_CONNECT_TYPE_COMMUNICATION);
		}

		if (ctx->reg_mqttcli != NULL) {
			IOT_INFO("There is active registering, disconnect it first.\n");
			iot_es_disconnect(ctx, IOT_CONNECT_TYPE_REGISTRATION);
		}

		iot_os_eventgroup_clear_bits(ctx->usr_events, IOT_USR_INTERACT_BIT_STATE_UNKNOWN);

		/* change its state by UNKNOWN to reset all */
		iot_err = iot_state_update(ctx, IOT_STATE_UNKNOWN, 0);
		if (iot_err != IOT_ERROR_NONE) {
			IOT_ERROR("failed to change IOT_STATE_UNKNOWN(%d)", iot_err);
			IOT_DUMP_MAIN(ERROR, BASE, iot_err);
			goto end_st_conn_start_ex;
		}

		/* Wait until IOT_STATE_UNKNOWN changing done */
		curr_events = iot_os_eventgroup_wait_bits(ctx->usr_events,
			IOT_USR_INTERACT_BIT_STATE_UNKNOWN, true, (NEXT_STATE_TIMEOUT_MS * 2));

		if (!(curr_events & IOT_USR_INTERACT_BIT_STATE_UNKNOWN)) {
			IOT_ERROR("Timeout happened to change IOT_STATE_UNKNOWN");
			IOT_DUMP_MAIN(ERROR, BASE, 0x8BADF00D);
			iot_err = IOT_ERROR_TIMEOUT;
			goto end_st_conn_start_ex;
		}
	}

	/* Forcely set iot_state by initialized */
	ctx->curr_state = ctx->req_state = IOT_STATE_INITIALIZED;

	if (ext_args->start_pt == IOT_STATUS_CONNECTING) {
		iot_os_eventgroup_clear_bits(ctx->usr_events, IOT_USR_INTERACT_BIT_CMD_DONE);

		/* Check if STDK can try to connect to sever */
		iot_err = _iot_command_peek(ctx, IOT_COMMAND_CHECK_PROV_STATUS);
		if (iot_err != IOT_ERROR_NONE) {
			IOT_ERROR("failed to send check_prov(%d)", iot_err);
			IOT_DUMP_MAIN(ERROR, BASE, iot_err);
			goto end_st_conn_start_ex;
		}

		curr_events = iot_os_eventgroup_wait_bits(ctx->usr_events,
			IOT_USR_INTERACT_BIT_CMD_DONE, true, (NEXT_STATE_TIMEOUT_MS * 2));

		if (!(curr_events & IOT_USR_INTERACT_BIT_CMD_DONE)) {
			IOT_ERROR("Timeout happened for check_prov");
			iot_err = IOT_ERROR_TIMEOUT;
			goto end_st_conn_start_ex;
		}

		if (ctx->iot_reg_data.new_reged) {
			IOT_ERROR("Can't support request to go to connecting");
			iot_err = IOT_ERROR_BAD_REQ;
			goto end_st_conn_start_ex;
		}

		ctx->iot_reg_data.updated = false;
		state_data.iot_state = IOT_STATE_PROV_DONE;
		state_data.opt = IOT_STATE_OPT_NONE;
	} else {
		if (ctx->es_res_created) {
			IOT_WARN("Already easysetup resources are created!!");
		} else {
			iot_err = _create_easysetup_resources(ctx, ext_args->pin_num);
			if (iot_err != IOT_ERROR_NONE) {
				IOT_ERROR("failed to create easysetup resources(%d)", iot_err);
				IOT_DUMP_MAIN(ERROR, BASE, iot_err);
				goto end_st_conn_start_ex;
			}
		}

		ctx->iot_reg_data.new_reged = true;
		state_data.iot_state = IOT_STATE_PROV_ENTER;
		state_data.opt = IOT_STATE_OPT_NONE;

		if (ext_args->skip_usr_confirm) {
			ctx->add_justworks = true;
			IOT_DEBUG("Skip user confirm adding by JUSTWORK");
		} else {
			ctx->add_justworks = false;
		}
	}

	if (ext_args->status_cb) {
		SET_STATUS_CB(ext_args->status_cb, ext_args->maps, ext_args->usr_data);
	}

	if (ext_args->start_pt == IOT_STATUS_PROVISIONING) {
		iot_os_eventgroup_clear_bits(ctx->usr_events, IOT_USR_INTERACT_BITS_ST_CONN);
	}

	iot_err = iot_command_send(ctx, IOT_COMMNAD_STATE_UPDATE,
				&state_data, sizeof(struct iot_state_data));

	if (iot_err != IOT_ERROR_NONE) {
		IOT_ERROR("failed to send command(%d)", iot_err);
		IOT_DUMP_MAIN(ERROR, BASE, iot_err);
		if (ctx->status_cb) {
			UNSET_STATUS_CB();
		}

		if (ctx->es_res_created) {
			_delete_easysetup_resources_all(ctx);
		}
		goto end_st_conn_start_ex;
	}

	if (ext_args->start_pt == IOT_STATUS_PROVISIONING) {
		WAIT_USR_INTERACT();
	}

	IOT_INFO("%s done (%d)", __func__, iot_err);
	IOT_DUMP_MAIN(INFO, BASE, iot_err);

end_st_conn_start_ex:
	iot_os_mutex_unlock(&ctx->st_conn_lock);
	return iot_err;
}

int st_info_get(IOT_CTX *iot_ctx, iot_info_type_t info_type, iot_info_data_t *info_data)
{
	iot_error_t iot_err = IOT_ERROR_NONE;
	struct iot_context *ctx = (struct iot_context*)iot_ctx;

	if (!IS_CTX_VALID(ctx) || !info_data) {
		IOT_ERROR("invalid parameters\n");
		return IOT_ERROR_INVALID_ARGS;
	}

	if (iot_os_mutex_lock(&ctx->st_conn_lock) != IOT_OS_TRUE)
		return IOT_ERROR_BAD_REQ;

	IOT_INFO("%s start (%d)", __func__, info_type);
	IOT_DUMP_MAIN(INFO, BASE, info_type);

	switch (info_type) {
	case IOT_INFO_TYPE_IOT_STATUS_AND_STAT:
		if (ctx->reported_stat) {
			info_data->st_status.iot_status = (ctx->reported_stat & IOT_STATUS_ALL);
			info_data->st_status.stat_lv = (ctx->reported_stat >> 8u);
		} else {
			IOT_WARN("There is no reported_stat!!");
			iot_err = IOT_ERROR_BAD_REQ;
		}
		break;

	case IOT_INFO_TYPE_IOT_PROVISIONED:
		info_data->provisioned = iot_nv_prov_data_exist();
		break;

	default:
		IOT_ERROR("Unsupported iot_info_type!!(%d)\n", info_type);
		iot_err = IOT_ERROR_INVALID_ARGS;
		break;
	}

	IOT_INFO("%s done (%d)", __func__, iot_err);
	IOT_DUMP_MAIN(INFO, BASE, iot_err);

	iot_os_mutex_unlock(&ctx->st_conn_lock);
	return iot_err;
}
