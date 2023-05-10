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

#if defined(STDK_IOT_CORE_SERIALIZE_CBOR)
#include <cbor.h>
#endif


#define IOT_DUMP_MAIN(LVL, LOGID, arg) \
	IOT_DUMP(IOT_DEBUG_LEVEL_##LVL, IOT_DUMP_MAIN_##LOGID, __LINE__, arg)

#define IOT_DUMP_MAIN_ARG2(LVL, LOGID, arg1, arg2) \
	IOT_DUMP(IOT_DEBUG_LEVEL_##LVL, IOT_DUMP_MAIN_##LOGID, arg1, arg2)

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

static iot_error_t _check_prov_status(struct iot_context *ctx, bool cmd_only)
{
	iot_error_t err;
	ctx->iot_reg_data.new_reged = false;
	iot_state_t next_state;
	char *usr_id = NULL;
	size_t str_len;
	bool is_diff_dip;

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
			err = iot_nv_get_device_id(&usr_id, &str_len);
			if (err != IOT_ERROR_NONE) {
				IOT_WARN("There are no reged data in NV\n");
				ctx->iot_reg_data.new_reged = true;
				next_state = IOT_STATE_PROV_ENTER;
			} else {
				if (str_len > IOT_REG_UUID_STR_LEN) {
					IOT_WARN("Long deviceID in NV %s, use it insize\n", usr_id);
					memcpy(ctx->iot_reg_data.deviceId, usr_id, IOT_REG_UUID_STR_LEN);
					ctx->iot_reg_data.deviceId[IOT_REG_UUID_STR_LEN] = '\0';
				} else {
					memcpy(ctx->iot_reg_data.deviceId, usr_id, str_len);
					ctx->iot_reg_data.deviceId[str_len] = '\0';
					IOT_INFO("Current deviceID: %s (%d)\n", ctx->iot_reg_data.deviceId, str_len);
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
					next_state = IOT_STATE_PROV_DONE;
				} else {
					ctx->iot_reg_data.updated = true;
					next_state = IOT_STATE_CLOUD_DISCONNECTED;
				}

				free(usr_id);
			}
		}
	}

	if (cmd_only) {
		/* We don't need recovering for command only case */
		if (err != IOT_ERROR_NONE) {
			IOT_WARN("Internal WARN(%d) happened for command only", err);
		}

		return IOT_ERROR_NONE;
	} else {
		err = iot_state_update(ctx, next_state, IOT_STATE_OPT_NONE);
	}

	return err;
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
		iot_util_queue_delete(ctx->easysetup_req_queue);
		ctx->easysetup_req_queue = NULL;
	}
	if (ctx->easysetup_resp_queue) {
		iot_util_queue_delete(ctx->easysetup_resp_queue);
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
		ctx->easysetup_req_queue = iot_util_queue_create(sizeof(struct iot_easysetup_payload));
		if (!ctx->easysetup_req_queue) {
			IOT_ERROR("failed to create Queue for easysetup request\n");
			IOT_DUMP_MAIN(ERROR, BASE, 0xDEADBEEF);
			ret = IOT_ERROR_BAD_REQ;
			goto create_fail;
		}
	}

	if (!ctx->easysetup_resp_queue) {
		ctx->easysetup_resp_queue = iot_util_queue_create(sizeof(struct iot_easysetup_payload));
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




STATIC_FUNCTION
iot_error_t _delete_dev_card_by_usr(struct iot_context *ctx)
{
	iot_error_t iot_err = IOT_ERROR_NONE;
	unsigned char curr_events;
	st_mqtt_msg msg;
	int ret;

	if (!ctx) {
		return IOT_ERROR_INVALID_ARGS;
	}

	if ((!ctx->evt_mqttcli) || (ctx->curr_state != IOT_STATE_CLOUD_CONNECTED)) {
		IOT_WARN("not connected, so can't send device_card deleting msg");
		return IOT_ERROR_NONE;
	}

	iot_os_eventgroup_clear_bits(ctx->usr_events, IOT_USR_INTERACT_BIT_CMD_DONE);
	ctx->usr_delete_req = true;

	/* GreatGate wants to receive 'empty' payload */
	msg.payload = NULL;
	msg.payloadlen = 0;
	msg.qos = st_mqtt_qos1;
	msg.retained = false;
	msg.topic = IOT_PUB_TOPIC_DELETE;

	ret = st_mqtt_publish(ctx->evt_mqttcli, &msg);
	if (ret) {
		IOT_ERROR("error MQTTpub for %s(%d)", (char *)msg.topic, ret);
		ctx->usr_delete_req = false;
		iot_err = IOT_ERROR_BAD_REQ;
	} else {
		curr_events = iot_os_eventgroup_wait_bits(ctx->usr_events,
			IOT_USR_INTERACT_BIT_CMD_DONE, true, (NEXT_STATE_TIMEOUT_MS / 2));

		if (!(curr_events & IOT_USR_INTERACT_BIT_CMD_DONE)) {
			IOT_ERROR("Timeout happened for device_card deleting");
			ctx->usr_delete_req = false;
			iot_err = IOT_ERROR_TIMEOUT;
		}
	}

	return iot_err;
}

static void _get_device_preference(struct iot_context *ctx)
{
	st_mqtt_msg msg = {0};

	if (ctx->evt_mqttcli == NULL) {
		IOT_ERROR("Target has not connected to server yet!!");
		return;
	}

	msg.qos = st_mqtt_qos1;
	msg.retained = false;
	msg.topic = IOT_PUB_TOPIC_GET_PREFERENCES;

	IOT_INFO("Get device preference");

	st_mqtt_publish_async(ctx->evt_mqttcli, &msg);
}

static iot_error_t _do_state_updating(struct iot_context *ctx, iot_state_t new_state, int opt)
{
	iot_error_t iot_err = IOT_ERROR_NONE;
	enum iot_command_type iot_cmd;
	/* Timeout value for the state */
	unsigned int timeout_ms = 0;

	IOT_INFO("current state %d, new state %d", ctx->curr_state, new_state);

	switch (ctx->curr_state) {
	case IOT_STATE_INITIALIZED:
		if (new_state == IOT_STATE_PROV_ENTER) {
			iot_err = iot_wifi_ctrl_request(ctx, IOT_WIFI_MODE_SCAN);
			if (iot_err != IOT_ERROR_NONE) {
				IOT_ERROR("Can't control WIFI mode scan.(%d)", iot_err);
				return iot_err;
			}

#if defined(CONFIG_STDK_IOT_CORE_EASYSETUP_DISCOVERY_SSID)
			/*wifi soft-ap mode w/ ssid E4 format*/
			iot_err = iot_wifi_ctrl_request(ctx, IOT_WIFI_MODE_SOFTAP);
			if (iot_err != IOT_ERROR_NONE) {
				IOT_ERROR("Can't send WIFI mode softap.(%d)", iot_err);
				return iot_err;
			}
#endif
#if defined(CONFIG_STDK_IOT_CORE_EASYSETUP_BLE)
            iot_err = iot_ble_ctrl_request(ctx);
            if (iot_err != IOT_ERROR_NONE) {
				IOT_ERROR("Can't send BLE.(%d)", iot_err);
                IOT_DUMP_MAIN(ERROR, BASE, iot_err);
                break;
            }
#endif
			/* Update next state waiting time for Easy-setup process */
			timeout_ms = EASYSETUP_TIMEOUT_MS;
			IOT_MEM_CHECK("ES_PROV_ENTER DONE >>PT<<");
		} else if (new_state == IOT_STATE_PROV_DONE) {
			timeout_ms = REGISTRATION_TIMEOUT_MS;
			iot_cmd = IOT_COMMAND_CLOUD_REGISTERING;
			iot_err = iot_command_send(ctx, iot_cmd, NULL, 0);
		} else if (new_state == IOT_STATE_CLOUD_DISCONNECTED) {
			iot_cmd = IOT_COMMAND_CLOUD_CONNECTING;
			iot_err = iot_command_send(ctx, iot_cmd, NULL, 0);
		} else
			return IOT_ERROR_INVALID_ARGS;
		break;
	case IOT_STATE_PROV_ENTER:
		if (new_state == IOT_STATE_PROV_CONFIRM) {
		} else if (new_state == IOT_STATE_PROV_SLEEP) {
		} else
			return IOT_ERROR_INVALID_ARGS;
		break;
	case IOT_STATE_PROV_CONFIRM:
		if (new_state == IOT_STATE_PROV_DONE) {
			timeout_ms = REGISTRATION_TIMEOUT_MS;
			iot_cmd = IOT_COMMAND_CLOUD_REGISTERING;
			iot_err = iot_command_send(ctx, iot_cmd, NULL, 0);
		} else
			return IOT_ERROR_INVALID_ARGS;
		break;
	case IOT_STATE_PROV_DONE:
		if (new_state == IOT_STATE_CLOUD_DISCONNECTED) {
			iot_cmd = IOT_COMMAND_CLOUD_CONNECTING;
			iot_err = iot_command_send(ctx, iot_cmd, NULL, 0);
		} else if (new_state == IOT_STATE_PROV_ENTER) {
			iot_err = iot_wifi_ctrl_request(ctx, IOT_WIFI_MODE_SCAN);
			if (iot_err != IOT_ERROR_NONE) {
				IOT_ERROR("Can't control WIFI mode scan.(%d)", iot_err);
				return iot_err;
			}

#if defined(CONFIG_STDK_IOT_CORE_EASYSETUP_DISCOVERY_SSID)
			/*wifi soft-ap mode w/ ssid E4 format*/
			iot_err = iot_wifi_ctrl_request(ctx, IOT_WIFI_MODE_SOFTAP);
			if (iot_err != IOT_ERROR_NONE) {
				IOT_ERROR("Can't send WIFI mode softap.(%d)", iot_err);
				return iot_err;
			}
#endif
			/* Update next state waiting time for Easy-setup process */
			timeout_ms = EASYSETUP_TIMEOUT_MS;
			IOT_MEM_CHECK("ES_PROV_ENTER DONE >>PT<<");
		} else
			return IOT_ERROR_INVALID_ARGS;
		break;
	case IOT_STATE_CLOUD_DISCONNECTED:
		if (new_state == IOT_STATE_CLOUD_CONNECTED) {
			_get_device_preference(ctx);
		} else
			return IOT_ERROR_INVALID_ARGS;
		break;
	case IOT_STATE_CLOUD_CONNECTED:
		if (new_state == IOT_STATE_CLOUD_DISCONNECTED) {
			iot_cmd = IOT_COMMAND_CLOUD_CONNECTING;
			iot_err = iot_command_send(ctx, iot_cmd, NULL, 0);
		} else
			return IOT_ERROR_INVALID_ARGS;
		break;
	default:
		return IOT_ERROR_INVALID_ARGS;
		break;
	}

	if (timeout_ms) {
		IOT_INFO("Current timeout : %u for %d", timeout_ms, ctx->curr_state);
		iot_os_timer_count_ms(ctx->state_timer, timeout_ms);
	}

	ctx->curr_state = new_state;

	if (ctx->status_cb) {
		switch (new_state) {
		case IOT_STATE_INITIALIZED :
			break;
		case IOT_STATE_PROV_SLEEP :
			break;
		case IOT_STATE_PROV_ENTER :
			if (ctx->status_maps & IOT_STATUS_PROVISIONING) {
				ctx->status_cb(IOT_STATUS_PROVISIONING, IOT_STAT_LV_START, ctx->status_usr_data);
				ctx->reported_stat = IOT_STATUS_PROVISIONING | IOT_STAT_LV_START << 8;
			}
			break;
		case IOT_STATE_PROV_CONFIRM :
			break;
		case IOT_STATE_PROV_DONE :
			if (ctx->status_maps & IOT_STATUS_PROVISIONING) {
				ctx->status_cb(IOT_STATUS_PROVISIONING, IOT_STAT_LV_DONE, ctx->status_usr_data);
				ctx->reported_stat = IOT_STATUS_PROVISIONING | IOT_STAT_LV_DONE << 8;
			}
			break;
		case IOT_STATE_CLOUD_DISCONNECTED :
			if (ctx->status_maps & IOT_STATUS_IDLE) {
				ctx->status_cb(IOT_STATUS_IDLE, IOT_STAT_LV_STAY, ctx->status_usr_data);
				ctx->reported_stat = IOT_STATUS_IDLE | IOT_STAT_LV_STAY << 8;
			}
			break;
		case IOT_STATE_CLOUD_CONNECTED :
			iot_cap_call_init_cb(ctx->cap_handle_list);
			if (ctx->status_maps & IOT_STATUS_CONNECTING) {
				ctx->status_cb(IOT_STATUS_CONNECTING, IOT_STAT_LV_DONE, ctx->status_usr_data);
				ctx->reported_stat = IOT_STATUS_CONNECTING | IOT_STAT_LV_DONE << 8;
			}
			break;
		}
		IOT_INFO("Call usr status_cb with 0x%02x", ctx->reported_stat);
	}

	return iot_err;
}

static iot_error_t _do_iot_main_command(struct iot_context *ctx,
	struct iot_command *cmd)
{
	iot_error_t err = IOT_ERROR_NONE;
	iot_noti_data_t *noti = NULL;
	struct iot_state_data *state_data = NULL;

	IOT_INFO("curr_main_cmd:%d, curr_main_state:%d", cmd->cmd_type, ctx->curr_state);

	switch (cmd->cmd_type) {
		case IOT_COMMAND_STATE_UPDATE :
			state_data = (struct iot_state_data *)cmd->param;
			_do_state_updating(ctx, state_data->iot_state, state_data->opt);
			break;
		case IOT_COMMAND_CLOUD_REGISTERING:
			if (!ctx->is_wifi_station) {
				err = iot_wifi_ctrl_request(ctx, IOT_WIFI_MODE_STATION);
				if (err != IOT_ERROR_NONE) {
					IOT_ERROR("Can't send WIFI mode command(%d)", err);
					iot_command_send(ctx, IOT_COMMAND_CLOUD_REGISTERING, NULL, 0);
					break;
				}
			}

			/* if there is previous connection, disconnect it first. */
			if (ctx->reg_mqttcli != NULL) {
				IOT_INFO("There is active registering, disconnect it first.");
				iot_es_disconnect(ctx, IOT_CONNECT_TYPE_REGISTRATION);
			}

			err = iot_es_connect(ctx, IOT_CONNECT_TYPE_REGISTRATION);
			if (err == IOT_ERROR_MQTT_REJECT_CONNECT) {
				iot_state_update(ctx, IOT_STATE_PROV_ENTER, 0);
			} else if (err != IOT_ERROR_NONE) {
				IOT_ERROR("failed to iot_es_connect for registration");
				IOT_DUMP_MAIN(ERROR, BASE, err);

				if (err == IOT_ERROR_MQTT_CONNECT_TIMEOUT) {
					iot_set_st_ecode(ctx, IOT_ST_ECODE_CE12);
				} else {
					iot_set_st_ecode(ctx, IOT_ST_ECODE_CE11);
				}

				iot_command_send(ctx, IOT_COMMAND_CLOUD_REGISTERING, NULL, 0);
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
			iot_state_update(ctx, IOT_STATE_CLOUD_DISCONNECTED, 0);
			IOT_MEM_CHECK("CLOUD_REGISTERED DONE >>PT<<");
			break;
		case IOT_COMMAND_CLOUD_CONNECTING:
			if (!ctx->is_wifi_station) {
				err = iot_wifi_ctrl_request(ctx, IOT_WIFI_MODE_STATION);
				if (err != IOT_ERROR_NONE) {
					IOT_ERROR("Can't send WIFI mode command(%d)", err);
					iot_command_send(ctx, IOT_COMMAND_CLOUD_CONNECTING, NULL, 0);
					break;
				}
			}
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
				IOT_INFO("There is previous connecting, disconnect it first.");
				iot_es_disconnect(ctx, IOT_CONNECT_TYPE_COMMUNICATION);
			}

			err = iot_es_connect(ctx, IOT_CONNECT_TYPE_COMMUNICATION);
			if (err == IOT_ERROR_MQTT_REJECT_CONNECT) {
				IOT_WARN("Intended error case(reboot)");
				ctx->connection_retry_count = 0;
				IOT_DUMP_MAIN(WARN, BASE, err);
				iot_cleanup(ctx, true);
			} else if (err != IOT_ERROR_NONE) {
				unsigned int next_retry_time;
				ctx->connection_retry_count++;

				err = iot_os_timer_init(&ctx->next_connection_retry_timer);
				if (err != IOT_ERROR_NONE) {
					IOT_ERROR("failed to malloc for reconnection timer");
					break;
				}
				next_retry_time = iot_util_generator_backoff(ctx->connection_retry_count, 64);
				iot_os_timer_count_ms(ctx->next_connection_retry_timer, next_retry_time);

				IOT_ERROR("failed to iot_es_connect for communication try count %d next after %d ms",
						ctx->connection_retry_count, next_retry_time);

				if (err == IOT_ERROR_MQTT_CONNECT_TIMEOUT) {
					iot_set_st_ecode(ctx, IOT_ST_ECODE_CE21);
				} else {
					iot_set_st_ecode(ctx, IOT_ST_ECODE_CE20);
				}
			} else {
				ctx->connection_retry_count = 0;
				iot_state_update(ctx, IOT_STATE_CLOUD_CONNECTED, 0);
			}

			IOT_MEM_CHECK("CLOUD_CONNECTTING DONE >>PT<<");
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
				if (ctx->usr_delete_req) {
					IOT_INFO("Device-card deleting is done");
					IOT_DUMP_MAIN(WARN, BASE, 0xC1EAC1EB);

					ctx->usr_delete_req = false;
					iot_os_eventgroup_set_bits(ctx->usr_events,
						IOT_USR_INTERACT_BIT_CMD_DONE);
				} else {
					IOT_INFO("cleanup device");
					IOT_DUMP_MAIN(WARN, BASE, 0xC1EAC1EA);

					if (ctx->noti_cb)
						ctx->noti_cb(noti, ctx->noti_usr_data);

					iot_cleanup(ctx, true);
				}
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
			} else if (noti->type == (iot_noti_type_t)_IOT_NOTI_TYPE_PREFERENCE_UPDATED) {
				IOT_INFO("preference updated");

				if (ctx->noti_cb)
					ctx->noti_cb(noti, ctx->noti_usr_data);

				for (int i = 0; i < noti->raw.preferences.preferences_num; i++) {
					if (noti->raw.preferences.preferences_data[i].preference_data.type == IOT_CAP_VAL_TYPE_STRING)
						iot_os_free(noti->raw.preferences.preferences_data[i].preference_data.string);

					iot_os_free(noti->raw.preferences.preferences_data[i].preference_name);
				}
				iot_os_free(noti->raw.preferences.preferences_data);
			} else if (noti->type == (iot_noti_type_t)_IOT_NOTI_TYPE_SEND_FAILED) {
				IOT_INFO("send failed seq number : %d", noti->raw.send_fail.failed_sequence_num);

				if (ctx->noti_cb)
					ctx->noti_cb(noti, ctx->noti_usr_data);
			} else if (noti->type == (iot_noti_type_t)_IOT_NOTI_TYPE_JWT_EXPIRED) {
				iot_es_disconnect(ctx, IOT_CONNECT_TYPE_COMMUNICATION);
				if (iot_es_connect(ctx, IOT_CONNECT_TYPE_COMMUNICATION) != IOT_ERROR_NONE)
                                    IOT_ERROR("failed to iot_es_connect for communication");
			}

			break;
		default:
			IOT_ERROR("Unsupported command(%d)", cmd->cmd_type);
			err = IOT_ERROR_BAD_REQ;
			break;
	}

	return err;
}

static void _do_cmd_tout_check(struct iot_context *ctx)
{
	char is_expired;
	iot_error_t iot_err;

	switch (ctx->curr_state) {
	case IOT_STATE_INITIALIZED :
		break;
	case IOT_STATE_PROV_SLEEP :
		break;
	case IOT_STATE_PROV_ENTER :
		is_expired = iot_os_timer_isexpired(ctx->state_timer);
		if (is_expired) {
			IOT_INFO("Go into OOB sleep mode");
			iot_err = iot_wifi_ctrl_request(ctx, IOT_WIFI_MODE_OFF);
			if (iot_err != IOT_ERROR_NONE) {
				IOT_ERROR("Can't send WIFI off command(%d)", iot_err);
				IOT_DUMP_MAIN(ERROR, BASE, iot_err);
			}
			iot_state_update(ctx, IOT_STATE_PROV_SLEEP, 0);
		}
		break;
	case IOT_STATE_PROV_CONFIRM :
		break;
	case IOT_STATE_PROV_DONE :
		is_expired = iot_os_timer_isexpired(ctx->state_timer);
		if (is_expired) {
			IOT_INFO("Go back to SoftAP");
			iot_state_update(ctx, IOT_STATE_PROV_ENTER, 0);
		}
		break;
	case IOT_STATE_CLOUD_DISCONNECTED :
		if (ctx->next_connection_retry_timer) {
			is_expired = iot_os_timer_isexpired(ctx->next_connection_retry_timer);
			if (is_expired) {
				iot_os_timer_destroy(&ctx->next_connection_retry_timer);
				ctx->next_connection_retry_timer = NULL;
				iot_command_send(ctx, IOT_COMMAND_CLOUD_CONNECTING, NULL, 0);
			}
		}
		break;
	case IOT_STATE_CLOUD_CONNECTED :
		break;
	}
}

static void _throw_away_all_cmd_queue(struct iot_context *ctx)
{
	struct iot_command cmd;

	if (!ctx) {
		IOT_ERROR("There is no ctx!!");
		IOT_DUMP_MAIN(ERROR, BASE, 0xDEADBEEF);
		return;
	}

	cmd.param = NULL;
	while (iot_util_queue_receive(ctx->cmd_queue,
				&cmd) == IOT_ERROR_NONE) {
		if (cmd.param) {
			free(cmd.param);
			cmd.param = NULL;
		}
	}
}

static void _iot_main_task(struct iot_context *ctx)
{
	struct iot_command cmd;
	unsigned char curr_events;
	iot_error_t err = IOT_ERROR_NONE;
	struct iot_easysetup_payload easysetup_req;
#if !defined(STDK_MQTT_TASK)
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

			if (iot_os_mutex_lock(&ctx->iot_cmd_lock) != IOT_OS_TRUE)
				continue;

			if (iot_util_queue_receive(ctx->cmd_queue,
					&cmd) == IOT_ERROR_NONE) {

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
			if (iot_util_queue_receive(ctx->easysetup_req_queue,
					&easysetup_req) == IOT_ERROR_NONE) {
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
				err = iot_es_disconnect(ctx, IOT_CONNECT_TYPE_REGISTRATION);
				if (ctx->curr_state == IOT_STATE_PROV_DONE && !ctx->iot_reg_data.updated)
					iot_command_send(ctx, IOT_COMMAND_CLOUD_REGISTERING, NULL, 0);
			} else if (rc > 0) {
				task_cycle = 0;
			}
		} else if (ctx->evt_mqttcli) {
			int rc = st_mqtt_yield(ctx->evt_mqttcli, 0);
			if (rc < 0) {
				if (rc == E_ST_MQTT_PING_FAIL) {
					iot_set_st_ecode(ctx, IOT_ST_ECODE_CE32);
				} else if (rc == E_ST_MQTT_PING_TIMEOUT) {
					iot_set_st_ecode(ctx, IOT_ST_ECODE_CE33);
				}
				err = iot_es_disconnect(ctx, IOT_CONNECT_TYPE_COMMUNICATION);
				if (err == IOT_ERROR_NONE) {
					/* Quickly try to connect without user notification first */
					err = iot_es_connect(ctx, IOT_CONNECT_TYPE_COMMUNICATION);
					if (err != IOT_ERROR_NONE) {
						IOT_WARN("Report Disconnected..");
						err = iot_state_update(ctx, IOT_STATE_CLOUD_DISCONNECTED, 0);
						IOT_DUMP_MAIN(WARN, BASE, err);
					}
				} else {
					IOT_WARN("COMM disconnecting failed(%d) for mqtt_yield", err);
					IOT_DUMP_MAIN(WARN, BASE, err);
				}
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
    iot_err = iot_bsp_wifi_init();
    if (iot_err != IOT_ERROR_NONE) {
        IOT_ERROR("failed to init iot_bsp_wifi_init (%d)", iot_err);
        IOT_DUMP_MAIN(ERROR, BASE, iot_err);

        iot_api_device_info_mem_free(dev_info);
        goto error_main_load_device_info;
    }

	/* create queue */
	ctx->cmd_queue = iot_util_queue_create(sizeof(struct iot_command));

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
	iot_util_queue_delete(ctx->cmd_queue);

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
	iot_error_t iot_err;
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

	IOT_INFO("%s start (%s)", __func__, pin_num ? "pin" : "no-pin");
	IOT_DUMP_MAIN(INFO, BASE, (pin_num ? 1 : 0));

	if (ctx->curr_state != IOT_STATE_INITIALIZED) {
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

	ctx->add_justworks = false;

	if (status_cb) {
		SET_STATUS_CB(status_cb, maps, usr_data);
	}

	iot_err = _check_prov_status(ctx, false);

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

	IOT_INFO("%s done (%d)", __func__, iot_err);
	IOT_DUMP_MAIN(INFO, BASE, iot_err);

end_st_conn_start:
	iot_os_mutex_unlock(&ctx->st_conn_lock);
	return iot_err;
}

int st_conn_cleanup(IOT_CTX *iot_ctx, bool reboot)
{
	iot_error_t iot_err;
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
	if (iot_os_mutex_lock(&ctx->iot_cmd_lock) != IOT_OS_TRUE)
		return IOT_ERROR_BAD_REQ;

	_throw_away_all_cmd_queue(ctx);
	iot_os_mutex_unlock(&ctx->iot_cmd_lock);

	/* Try to delete device_card first, but it depends on connection-status */
	iot_err = _delete_dev_card_by_usr(ctx);
	if (iot_err != IOT_ERROR_NONE) {
		IOT_ERROR("failed to delete device_card(%d)", iot_err);
		IOT_DUMP_MAIN(ERROR, BASE, iot_err);
	}

	iot_cleanup(ctx, reboot);

	IOT_INFO("%s done (%d)", __func__, iot_err);
	IOT_DUMP_MAIN(INFO, BASE, iot_err);

	iot_os_mutex_unlock(&ctx->st_conn_lock);

	return iot_err;
}

int st_conn_start_ex(IOT_CTX *iot_ctx, iot_ext_args_t *ext_args)
{
	iot_error_t iot_err = IOT_ERROR_NONE;
	struct iot_context *ctx = (struct iot_context*)iot_ctx;
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

	if (ctx->curr_state != IOT_STATE_INITIALIZED) {
		IOT_WARN("iot-core is already working(%d), stop & remove all cmd first",
			ctx->curr_state);
		IOT_DUMP_MAIN(WARN, BASE, ctx->curr_state);

		/* remove all queued commands */
		iot_os_mutex_lock(&ctx->iot_cmd_lock);
		_throw_away_all_cmd_queue(ctx);
		iot_os_mutex_unlock(&ctx->iot_cmd_lock);

		iot_cleanup(ctx, false);
	}

	/* Forcely set iot_state by initialized */
	ctx->curr_state = IOT_STATE_INITIALIZED;

	if (ext_args->start_pt == IOT_STATUS_CONNECTING) {
		/* Check if STDK can try to connect to sever */
		iot_err = _check_prov_status(ctx, true);
		if (iot_err != IOT_ERROR_NONE) {
			IOT_ERROR("failed to send check_prov(%d)", iot_err);
			IOT_DUMP_MAIN(ERROR, BASE, iot_err);
			goto end_st_conn_start_ex;
		}

		if (ctx->iot_reg_data.new_reged) {
			IOT_ERROR("Can't support request to go to connecting");
			iot_err = IOT_ERROR_BAD_REQ;
			goto end_st_conn_start_ex;
		}

		iot_state_update(ctx, IOT_STATE_CLOUD_DISCONNECTED, 0);
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
		iot_state_update(ctx, IOT_STATE_PROV_ENTER, 0);

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

int st_change_device_name(IOT_CTX *iot_ctx, const char *new_name)
{
	int ret = IOT_ERROR_NONE;
	struct iot_context *ctx = (struct iot_context*)iot_ctx;
	st_mqtt_msg msg = {0};
	JSON_H *json_root = NULL;

	if (!ctx || !new_name) {
		IOT_ERROR("invalid input params");
		return IOT_ERROR_INVALID_ARGS;
	}

	if (ctx->curr_state != IOT_STATE_CLOUD_CONNECTED || ctx->evt_mqttcli == NULL) {
		IOT_ERROR("Target has not connected to server yet!!");
		return IOT_ERROR_BAD_REQ;
	}

	if (strlen(new_name) > IOT_DEVICE_NAME_MAX_LENGTH) {
		IOT_ERROR("new device name is over length(%d)", IOT_DEVICE_NAME_MAX_LENGTH);
		return IOT_ERROR_INVALID_ARGS;
	}

	json_root = JSON_CREATE_OBJECT();
	JSON_ADD_STRING_TO_OBJECT(json_root, "label", new_name);
#if defined(STDK_IOT_CORE_SERIALIZE_CBOR)
	iot_serialize_json2cbor(json_root, (uint8_t **)&msg.payload, (size_t *)&msg.payloadlen);
#else
	msg.payload = JSON_PRINT(json_root);
	if (msg.payload == NULL) {
		IOT_ERROR("Fail to make json string");
		ret = IOT_ERROR_BAD_REQ;
		goto exit;
	}
	msg.payloadlen = strlen(msg.payload);
#endif
	msg.qos = st_mqtt_qos1;
	msg.retained = false;
	msg.topic = IOT_PUB_TOPIC_DEVICES_UPDATE;

	IOT_INFO("change device name, topic : %s, payload :\n%s",
		(char *)msg.topic, (char *)msg.payload);

	ret = st_mqtt_publish(ctx->evt_mqttcli, &msg);
	if (ret) {
		ret = IOT_ERROR_MQTT_PUBLISH_FAIL;
		IOT_ERROR("Failt to publish change period packet");
		goto exit;
	}

exit:
	if (msg.payload)
		free(msg.payload);
	if (json_root)
		JSON_DELETE(json_root);

	return ret;
}

int st_change_health_period(IOT_CTX *iot_ctx, unsigned int new_period)
{
	int ret = IOT_ERROR_NONE;
	struct iot_context *ctx = (struct iot_context*)iot_ctx;
	st_mqtt_msg msg = {0};
	JSON_H *json_root = NULL;

	if (!ctx) {
		IOT_ERROR("ctx is null");
	    return IOT_ERROR_INVALID_ARGS;
	}

	if (ctx->curr_state != IOT_STATE_CLOUD_CONNECTED || ctx->evt_mqttcli == NULL) {
		IOT_ERROR("Target has not connected to server yet!!");
		return IOT_ERROR_BAD_REQ;
	}

	json_root = JSON_CREATE_OBJECT();
	JSON_ADD_STRING_TO_OBJECT(json_root, "status", "changePeriod");
	JSON_ADD_NUMBER_TO_OBJECT(json_root, "newPeriod", new_period);
#if defined(STDK_IOT_CORE_SERIALIZE_CBOR)
	iot_serialize_json2cbor(json_root, (uint8_t **)&msg.payload, (size_t *)&msg.payloadlen);
#else
	msg.payload = JSON_PRINT(json_root);
	if (msg.payload == NULL) {
		IOT_ERROR("Fail to make json string");
		ret = IOT_ERROR_BAD_REQ;
		goto exit;
	}
	msg.payloadlen = strlen(msg.payload);
#endif
	msg.qos = st_mqtt_qos1;
	msg.retained = false;
	msg.topic = ctx->mqtt_health_topic;

	IOT_INFO("publish event, topic : %s, payload :\n%s",
		ctx->mqtt_health_topic, (char *)msg.payload);

	ret = st_mqtt_publish(ctx->evt_mqttcli, &msg);
	if (ret) {
		ret = IOT_ERROR_MQTT_PUBLISH_FAIL;
		IOT_ERROR("Failt to publish change period packet");
		goto exit;
	}
	st_mqtt_change_ping_period(ctx->evt_mqttcli, new_period);

exit:
	if (msg.payload)
		free(msg.payload);
	if (json_root)
		JSON_DELETE(json_root);

	return ret;
}
