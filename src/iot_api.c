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
#include <sys/time.h>

#include "iot_main.h"
#include "iot_internal.h"
#include "iot_debug.h"
#include "iot_easysetup.h"
#include "iot_nv_data.h"
#include "iot_os_util.h"
#include "iot_util.h"
#include "iot_uuid.h"
#include "iot_bsp_wifi.h"
#include "security/iot_security_common.h"
#include "security/iot_security_helper.h"
#include "iot_bsp_system.h"

#include "JSON.h"
#define ONBOARDINGID_E4_MAX_LEN	13
#define ONBOARDINGID_E5_MAX_LEN	14
#define IOT_STATE_TIMEOUT_MAX_MS	(900000) /* 15 min */

iot_error_t iot_command_send(struct iot_context *ctx,
	enum iot_command_type new_cmd, const void *param, int param_size)
{
	struct iot_command cmd_data;
	iot_error_t err;

	if (param && (param_size > 0)) {
		cmd_data.param = malloc(param_size);
		if (!cmd_data.param) {
			IOT_ERROR("failed to malloc for iot_command param");
			return IOT_ERROR_MEM_ALLOC;
		}

		memcpy(cmd_data.param, param, param_size);
	} else {
		cmd_data.param = NULL;
	}

	cmd_data.cmd_type = new_cmd;

	err = iot_util_queue_send(ctx->cmd_queue, &cmd_data);
	if (err != IOT_ERROR_NONE) {
		IOT_ERROR("Cannot put the cmd into cmd_queue");
		if (cmd_data.param)
			free(cmd_data.param);
		err = IOT_ERROR_BAD_REQ;
	} else {
		iot_os_eventgroup_set_bits(ctx->iot_events,
			IOT_EVENT_BIT_COMMAND);
		err = IOT_ERROR_NONE;
	}

	return err;
}

iot_error_t iot_wifi_ctrl_request(struct iot_context *ctx,
		iot_wifi_mode_t wifi_mode)
{
	iot_error_t iot_err = IOT_ERROR_BAD_REQ;
	iot_wifi_conf wifi_conf;
	bool send_cmd = true;

	if (!ctx) {
		IOT_ERROR("There is no ctx\n");
		return IOT_ERROR_BAD_REQ;
	}

	memset(&wifi_conf, 0, sizeof(wifi_conf));
	wifi_conf.mode = wifi_mode;

	switch (wifi_mode) {
	case IOT_WIFI_MODE_OFF:
		/* fall through */
	case IOT_WIFI_MODE_STATION:
		/* easysetup resource deinit & free for both */
		if (ctx->es_http_ready) {
			ctx->es_http_ready = false;
			iot_easysetup_deinit(ctx);
		}

		if (ctx->scan_result) {
			free(ctx->scan_result);
			ctx->scan_result = NULL;
		}
		ctx->scan_num = 0;

		if (wifi_mode == IOT_WIFI_MODE_STATION) {
			memcpy(wifi_conf.ssid, ctx->prov_data.wifi.ssid,
				strlen(ctx->prov_data.wifi.ssid));
			memcpy(wifi_conf.pass, ctx->prov_data.wifi.password,
				strlen(ctx->prov_data.wifi.password));
			if (ctx->prov_data.wifi.mac_str[0] != '\0') {
				memcpy(wifi_conf.bssid, ctx->prov_data.wifi.bssid.addr,
					IOT_WIFI_MAX_BSSID_LEN);
			}
			wifi_conf.authmode = ctx->prov_data.wifi.security_type;
		} else {	/* For IOT_WIFI_MODE_OFF case */
			send_cmd = false;

			iot_err = iot_bsp_wifi_set_mode(&wifi_conf);
			if (iot_err != IOT_ERROR_NONE) {
				IOT_ERROR("failed to set wifi_set_mode for scan\n");
				return iot_err;
			}
		}
		break;

#if defined(CONFIG_STDK_IOT_CORE_EASYSETUP_DISCOVERY_SSID)
	case IOT_WIFI_MODE_SOFTAP:
		/*wifi soft-ap mode w/ ssid E4 format*/
		iot_err = iot_easysetup_create_ssid(&(ctx->devconf),
					wifi_conf.ssid, IOT_WIFI_MAX_SSID_LEN);
		if (iot_err != IOT_ERROR_NONE) {
			IOT_ERROR("Can't create ssid for easysetup.(%d)", iot_err);
			return iot_err;
		}

		snprintf(wifi_conf.pass, sizeof(wifi_conf.pass), "1111122222");
		wifi_conf.authmode = IOT_WIFI_AUTH_WPA_WPA2_PSK;
		break;
#endif
	case IOT_WIFI_MODE_SCAN:
		send_cmd = false;

		iot_err = iot_bsp_wifi_set_mode(&wifi_conf);
		if (iot_err != IOT_ERROR_NONE) {
			IOT_ERROR("failed to set wifi_set_mode for scan\n");
			return iot_err;
		}

		if (!ctx->scan_result) {
			ctx->scan_result = (iot_wifi_scan_result_t *)iot_os_malloc(IOT_WIFI_MAX_SCAN_RESULT * sizeof(iot_wifi_scan_result_t));
			if (!ctx->scan_result) {
				IOT_ERROR("failed to malloc for iot_wifi_scan_result_t\n");
				break;
			}
			memset(ctx->scan_result, 0x0, (IOT_WIFI_MAX_SCAN_RESULT * sizeof(iot_wifi_scan_result_t)));
		}

		ctx->scan_num = iot_bsp_wifi_get_scan_result(ctx->scan_result);
		break;

	default:
		IOT_ERROR("Unsupported wifi ctrl mode[%d]\n", wifi_mode);
		return IOT_ERROR_BAD_REQ;
	}

	if (send_cmd) {
		iot_err = iot_bsp_wifi_set_mode(&wifi_conf);
		if (iot_err < 0) {
			IOT_ERROR("failed to set wifi_set_mode %d", iot_err);
			iot_set_st_ecode_from_conn_error(ctx, iot_err);
			if (wifi_mode == IOT_WIFI_MODE_SOFTAP)
				iot_set_st_ecode(ctx, IOT_ST_ECODE_NE01);
			else if (wifi_mode == IOT_WIFI_MODE_STATION)
				iot_set_st_ecode(ctx, IOT_ST_ECODE_NE10);
			return iot_err;
		}

		switch (wifi_mode) {
		case IOT_WIFI_MODE_SOFTAP:
			iot_err = iot_easysetup_init(ctx);
			IOT_MEM_CHECK("ES_INIT DONE >>PT<<");

			if (iot_err != IOT_ERROR_NONE) {
				IOT_ERROR("failed to iot_easysetup_init(%d)", iot_err);
				return iot_err;
			} else {
				ctx->es_http_ready = true;
			}
			break;
		default:
			break;
		}
	}

	if (iot_err == IOT_ERROR_NONE) {
		if (wifi_mode == IOT_WIFI_MODE_STATION) {
			ctx->is_wifi_station = true;
		} else {
			ctx->is_wifi_station = false;
		}
	}

	return iot_err;
}

iot_error_t iot_ble_ctrl_request(struct iot_context *ctx)
{
    iot_error_t iot_err = IOT_ERROR_NONE;

    IOT_INFO("BLE onboarding start!!\n");

    if (!ctx) {
        IOT_ERROR("There is no ctx\n");
        return IOT_ERROR_BAD_REQ;
    }

    iot_err = iot_easysetup_init(ctx);
    IOT_MEM_CHECK("ES_INIT DONE >>PT<<");
    if (iot_err != IOT_ERROR_NONE) {
        IOT_ERROR("failed to iot_easysetup_init(%d)", iot_err);
    }
    return iot_err;
}

iot_error_t iot_easysetup_request(struct iot_context *ctx,
				enum iot_easysetup_step step, const void *payload)
{
	struct iot_easysetup_payload request;
	iot_error_t err;

	if (payload) {
		request.payload = (char *)payload;
	} else {
		request.payload = NULL;
	}

	request.step = step;

	if (ctx->easysetup_req_queue) {
		err = iot_util_queue_send(ctx->easysetup_req_queue, &request);
		if (err != IOT_ERROR_NONE) {
			IOT_ERROR("Cannot put the request into easysetup_req_queue");
			err = IOT_ERROR_EASYSETUP_QUEUE_SEND_ERROR;
		} else {
			iot_os_eventgroup_set_bits(ctx->iot_events,
				IOT_EVENT_BIT_EASYSETUP_REQ);
			err = IOT_ERROR_NONE;
		}
	} else {
		IOT_ERROR("easysetup_req_queue is deleted");
		err = IOT_ERROR_BAD_REQ;
	}

	return err;
}

iot_error_t iot_state_update(struct iot_context *ctx,
	iot_state_t new_state, int opt)
{
	struct iot_state_data state_data;
	iot_error_t err;

	if ((new_state == IOT_STATE_PROV_CONFIRM)
			&& (opt == IOT_STATE_OPT_NEED_INTERACT)) {
		IOT_INFO("Trigger PROV_CONFIRM");
		if ((ctx->status_maps & IOT_STATUS_NEED_INTERACT) && ctx->curr_otm_feature == OVF_BIT_BUTTON) {
			ctx->status_cb(IOT_STATUS_NEED_INTERACT, IOT_STAT_LV_STAY, ctx->status_usr_data);
			ctx->reported_stat = IOT_STATUS_NEED_INTERACT | IOT_STAT_LV_STAY << 8;
		}
	}

	state_data.iot_state = new_state;
	state_data.opt = opt;

	err = iot_command_send(ctx, IOT_COMMAND_STATE_UPDATE,
		                    &state_data, sizeof(struct iot_state_data));

	return err;
}

iot_error_t iot_state_timeout_change(struct iot_context *ctx, iot_state_t target_state,
	unsigned int new_timeout_ms)
{
	iot_error_t err;

	if (target_state <= IOT_STATE_INITIALIZED)
		return IOT_ERROR_INVALID_ARGS;

	if (new_timeout_ms > IOT_STATE_TIMEOUT_MAX_MS)
		return IOT_ERROR_INVALID_ARGS;

	if (ctx->curr_state != target_state) {
		IOT_INFO("Not current state(%d) target state %d", ctx->curr_state, target_state);
		return IOT_ERROR_INVALID_ARGS;
	}

	iot_os_timer_count_ms(ctx->state_timer, new_timeout_ms);

	return err;
}

void iot_api_onboarding_config_mem_free(struct iot_devconf_prov_data *devconf)
{
	if (!devconf)
		return;

	if (devconf->device_onboarding_id)
		iot_os_free(devconf->device_onboarding_id);
	if (devconf->mnid)
		iot_os_free(devconf->mnid);
	if (devconf->setupid)
		iot_os_free(devconf->setupid);
	if (devconf->vid)
		iot_os_free(devconf->vid);
	if (devconf->device_type)
		iot_os_free(devconf->device_type);
	if (devconf->dip)
		iot_os_free(devconf->dip);
}

static bool is_valid_onboarding_id_len(size_t len, unsigned char ssid_version)
{
	size_t max_len;

	max_len = (ssid_version == 4 ? ONBOARDINGID_E4_MAX_LEN : ONBOARDINGID_E5_MAX_LEN);
	if (len > max_len) {
		return false;
	}

	return true;
}

static bool is_valid_ssid_version(unsigned char version)
{
	if (version == 4 || version == 5) {
		return true;
	}
	return false;
}

static const char name_onboardingConfig[] = "onboardingConfig";
static const char name_deviceOnboardingId[] = "deviceOnboardingId";
static const char name_mnId[] = "mnId";
static const char name_setupId[] = "setupId";
static const char name_vid[] = "vid";
static const char name_deviceTypeId[] = "deviceTypeId";
static const char name_ownershipValidationTypes[] = "ownershipValidationTypes";
static const char name_identityType[] = "identityType";
static const char name_deviceIntegrationProfileId[] = "deviceIntegrationProfileKey";
static const char name_ssidVersion[] = "ssidVersion";

iot_error_t iot_api_onboarding_config_load(unsigned char *onboarding_config,
		unsigned int onboarding_config_len, struct iot_devconf_prov_data *devconf)
{
	iot_error_t iot_err = IOT_ERROR_NONE;
	JSON_H *root = NULL;
	JSON_H *config = NULL;
	JSON_H *dip = NULL;
	JSON_H *item = NULL;
	char *data = NULL;
	char *device_onboarding_id = NULL;
	char *mnid = NULL;
	char *setupid = NULL;
	char *vid = NULL;
	char *devicetypeid = NULL;
	unsigned char ssid_version;
	unsigned int ownership_validation_type = 0;
	iot_security_key_type_t pk_type;
	size_t str_len = 0;
	int i;
	struct iot_dip_data *new_dip = NULL;
#if defined(CONFIG_STDK_IOT_CORE_LOG_LEVEL_ERROR)
	char *current_name = NULL;
#endif

	if (!onboarding_config || !devconf || onboarding_config_len == 0)
		return IOT_ERROR_INVALID_ARGS;

	data = iot_os_malloc((size_t) onboarding_config_len + 1);
	if (!data) {
		return IOT_ERROR_MEM_ALLOC;
	}

	memcpy(data, onboarding_config, onboarding_config_len);
	data[onboarding_config_len] = '\0';

	root = JSON_PARSE((char *)data);
	config = JSON_GET_OBJECT_ITEM(root, name_onboardingConfig);
	if (!config) {
#if defined(CONFIG_STDK_IOT_CORE_LOG_LEVEL_ERROR)
		current_name = (char *)name_onboardingConfig;
#endif
		iot_err = IOT_ERROR_UNINITIALIZED;
		goto load_out;
	}

	/* SSID version, Optional */
	item = JSON_GET_OBJECT_ITEM(config, name_ssidVersion);
	if (item) {
		ssid_version = (unsigned char) JSON_GET_NUMBER_VALUE(item);
		if (!is_valid_ssid_version(ssid_version))
		{
#if defined(CONFIG_STDK_IOT_CORE_LOG_LEVEL_ERROR)
			current_name = (char *)name_ssidVersion;
#endif
			iot_err = IOT_ERROR_UNINITIALIZED;
			goto load_out;
		}
	} else {
		/* default version 4 */
		ssid_version = 4;
	}

	/* device_onboarding_id */
	item = JSON_GET_OBJECT_ITEM(config, name_deviceOnboardingId);
	if (item) {
		str_len = strlen(JSON_GET_STRING_VALUE(item));
	}
	if(!item || !is_valid_onboarding_id_len(str_len, ssid_version)) {
#if defined(CONFIG_STDK_IOT_CORE_LOG_LEVEL_ERROR)
		current_name = (char *)name_deviceOnboardingId;
#endif
		iot_err = IOT_ERROR_UNINITIALIZED;
		goto load_out;
	}

	device_onboarding_id = iot_os_malloc(str_len + 1);
	if (!device_onboarding_id) {
		iot_err = IOT_ERROR_MEM_ALLOC;
		goto load_out;
	}
	strncpy(device_onboarding_id, JSON_GET_STRING_VALUE(item), str_len);
	device_onboarding_id[str_len] = '\0';

	/* mnid */
	item = JSON_GET_OBJECT_ITEM(config, name_mnId);
	if (!item || !strcmp(JSON_GET_STRING_VALUE(item), "MNID")) {
#if defined(CONFIG_STDK_IOT_CORE_LOG_LEVEL_ERROR)
		current_name = (char *)name_mnId;
#endif
		iot_err = IOT_ERROR_UNINITIALIZED;
		goto load_out;
	}
	str_len = strlen(JSON_GET_STRING_VALUE(item));
	mnid = iot_os_malloc(str_len + 1);
	if (!mnid) {
		iot_err = IOT_ERROR_MEM_ALLOC;
		goto load_out;
	}
	strncpy(mnid, JSON_GET_STRING_VALUE(item), str_len);
	mnid[str_len] = '\0';

	/* setup_id */
	item = JSON_GET_OBJECT_ITEM(config, name_setupId);
	if (!item) {
#if defined(CONFIG_STDK_IOT_CORE_LOG_LEVEL_ERROR)
		current_name = (char *)name_setupId;
#endif
		iot_err = IOT_ERROR_UNINITIALIZED;
		goto load_out;
	}
	str_len = strlen(JSON_GET_STRING_VALUE(item));
	setupid = iot_os_malloc(str_len + 1);
	if (!setupid) {
		iot_err = IOT_ERROR_MEM_ALLOC;
		goto load_out;
	}
	strncpy(setupid, JSON_GET_STRING_VALUE(item), str_len);
	setupid[str_len] = '\0';

	/* vid */
	item = JSON_GET_OBJECT_ITEM(config, name_vid);
	if (!item) {
#if defined(CONFIG_STDK_IOT_CORE_LOG_LEVEL_ERROR)
		current_name = (char *)name_vid;
#endif
		iot_err = IOT_ERROR_UNINITIALIZED;
		goto load_out;
	}
	str_len = strlen(JSON_GET_STRING_VALUE(item));
	vid = iot_os_malloc(str_len + 1);
	if (!vid) {
		iot_err = IOT_ERROR_MEM_ALLOC;
		goto load_out;
	}
	strncpy(vid, JSON_GET_STRING_VALUE(item), str_len);
	vid[str_len] = '\0';

	/* device_type_id */
	item = JSON_GET_OBJECT_ITEM(config, name_deviceTypeId);
	if (!item || !strcmp(JSON_GET_STRING_VALUE(item), "TYPE")) {
#if defined(CONFIG_STDK_IOT_CORE_LOG_LEVEL_ERROR)
		current_name = (char *)name_deviceTypeId;
#endif
		iot_err = IOT_ERROR_UNINITIALIZED;
		goto load_out;
	}
	str_len = strlen(JSON_GET_STRING_VALUE(item));
	devicetypeid = iot_os_malloc(str_len + 1);
	if (!devicetypeid) {
		iot_err = IOT_ERROR_MEM_ALLOC;
		goto load_out;
	}
	strncpy(devicetypeid, JSON_GET_STRING_VALUE(item), str_len);
	devicetypeid[str_len] = '\0';

	/* ownership validation type */
	item = JSON_GET_OBJECT_ITEM(config, name_ownershipValidationTypes);
	if (!item) {
#if defined(CONFIG_STDK_IOT_CORE_LOG_LEVEL_ERROR)
		current_name = (char *)name_ownershipValidationTypes;
#endif
		iot_err = IOT_ERROR_UNINITIALIZED;
		goto load_out;
	}
	for (i = 0; i < JSON_GET_ARRAY_SIZE(item); i++) {
		JSON_H *ovf = JSON_GET_ARRAY_ITEM(item, i);
		if (ovf && JSON_IS_STRING(ovf)) {
			if (!strcmp(JSON_GET_STRING_VALUE(ovf), "JUSTWORKS"))
				ownership_validation_type |= (unsigned int) IOT_OVF_TYPE_JUSTWORKS;
			else if (!strcmp(JSON_GET_STRING_VALUE(ovf), "BUTTON"))
				ownership_validation_type |= (unsigned int) IOT_OVF_TYPE_BUTTON;
			else if (!strcmp(JSON_GET_STRING_VALUE(ovf), "PIN"))
				ownership_validation_type |= (unsigned int) IOT_OVF_TYPE_PIN;
			else if (!strcmp(JSON_GET_STRING_VALUE(ovf), "QR"))
				ownership_validation_type |= (unsigned int) IOT_OVF_TYPE_QR;
			else {
				IOT_ERROR("Unknown validation type: %s", JSON_GET_STRING_VALUE(ovf));
#if defined(CONFIG_STDK_IOT_CORE_LOG_LEVEL_ERROR)
				current_name = (char *)name_ownershipValidationTypes;
#endif
				iot_err = IOT_ERROR_UNINITIALIZED;
				goto load_out;
			}
		}
	}
	if (ownership_validation_type == 0)
	{
		IOT_ERROR("No ownership validation type selected");
#if defined(CONFIG_STDK_IOT_CORE_LOG_LEVEL_ERROR)
		current_name = (char *)name_ownershipValidationTypes;
#endif
		iot_err = IOT_ERROR_UNINITIALIZED;
		goto load_out;
	}

	/* device identity */
	item = JSON_GET_OBJECT_ITEM(config, name_identityType);
	if (!item || !strcmp(JSON_GET_STRING_VALUE(item), "ED25519")) {
		pk_type = IOT_SECURITY_KEY_TYPE_ED25519;
	} else if (!strcmp(JSON_GET_STRING_VALUE(item), "X509")) {
		pk_type = IOT_SECURITY_KEY_TYPE_ECCP256;
	} else {
#if defined(CONFIG_STDK_IOT_CORE_LOG_LEVEL_ERROR)
		current_name = (char *)name_identityType;
#endif
		iot_err = IOT_ERROR_UNINITIALIZED;
		goto load_out;
	}

	/* Device Integration Profile, optional */
	dip = JSON_GET_OBJECT_ITEM(config, name_deviceIntegrationProfileId);
	if (dip) {
#if defined(CONFIG_STDK_IOT_CORE_LOG_LEVEL_ERROR)
		current_name = (char *)name_deviceIntegrationProfileId;
#endif
		new_dip = iot_os_malloc(sizeof(struct iot_dip_data));
		if (!new_dip) {
			iot_err = IOT_ERROR_MEM_ALLOC;
			goto load_out;
		}
		memset(new_dip, 0, sizeof(struct iot_dip_data));

		item = JSON_GET_OBJECT_ITEM(dip, "id");
		if (!item) {
			IOT_ERROR("Can't get id (NULL)");
			iot_err = IOT_ERROR_UNINITIALIZED;
			goto load_out;
		}

		iot_err = iot_util_convert_str_uuid(JSON_GET_STRING_VALUE(item),
						&new_dip->dip_id);
		if (iot_err != IOT_ERROR_NONE) {
			IOT_ERROR("Can't convert uuid for dip_id(%d)", iot_err);
			goto load_out;
		}

		item = JSON_GET_OBJECT_ITEM(dip, "majorVersion");
		if (!item) {
			IOT_ERROR("Can't get majorVersion (NULL)");
			iot_err = IOT_ERROR_UNINITIALIZED;
			goto load_out;
		}
		new_dip->dip_major_version = item->valueint;

		/* minorVersion is optional, default 0 */
		item = JSON_GET_OBJECT_ITEM(dip, "minorVersion");
		if (item) {
			new_dip->dip_minor_version = item->valueint;
		}
	}

	devconf->device_onboarding_id = device_onboarding_id;
	devconf->mnid = mnid;
	devconf->setupid = setupid;
	devconf->vid = vid;
	devconf->device_type = devicetypeid;
	devconf->ownership_validation_type = ownership_validation_type;
	devconf->pk_type = pk_type;
	if (new_dip) {
		devconf->dip = new_dip;
	}
	devconf->ssid_version = ssid_version;

	if (root)
		JSON_DELETE(root);

	iot_os_free(data);

	return iot_err;

load_out:
	if (iot_err == IOT_ERROR_UNINITIALIZED) {
		if (item && JSON_IS_STRING(item)) {
			IOT_ERROR("[%s] wrong onboarding config value detected: %s",
					current_name, JSON_GET_STRING_VALUE(item));
		}
		else {
			IOT_ERROR("[%s] wrong onboarding config value detected", current_name);
		}
	}
	if (device_onboarding_id) {
		iot_os_free(device_onboarding_id);
	}
	if (mnid) {
		iot_os_free(mnid);
	}
	if (setupid) {
		iot_os_free(setupid);
	}
	if (vid) {
		iot_os_free(vid);
	}
	if (devicetypeid) {
		iot_os_free(devicetypeid);
	}
	if (root) {
		JSON_DELETE(root);
	}
	if (data) {
		iot_os_free(data);
	}
	if (new_dip) {
		iot_os_free(new_dip);
	}

	return iot_err;
}

iot_error_t iot_get_time_in_sec(char *buf, size_t buf_len)
{
	struct timeval tv_now;

	if (!buf) {
		IOT_ERROR("buffer for time is NULL");
		return IOT_ERROR_INVALID_ARGS;
	}

	gettimeofday(&tv_now, NULL);
	snprintf(buf, buf_len, "%ld", tv_now.tv_sec);

	return IOT_ERROR_NONE;
}

iot_error_t iot_get_time_in_sec_by_long(long *sec)
{
	struct timeval tv_now;

	if (!sec) {
		IOT_ERROR("buffer for time is NULL");
		return IOT_ERROR_INVALID_ARGS;
	}

	gettimeofday(&tv_now, NULL);
	*sec = tv_now.tv_sec;

	return IOT_ERROR_NONE;
}

iot_error_t iot_get_time_in_ms(char *buf, size_t buf_len)
{
	struct timeval tv_now;

	if (!buf) {
		IOT_ERROR("buffer for time is NULL");
		return IOT_ERROR_INVALID_ARGS;
	}

	gettimeofday(&tv_now, NULL);
	snprintf(buf, buf_len, "%ld%03ld",
		tv_now.tv_sec, (tv_now.tv_usec / 1000));

	return IOT_ERROR_NONE;
}

void iot_api_device_info_mem_free(struct iot_device_info *device_info)
{
	if (!device_info)
		return;

	device_info->opt_info = 0;

	if (device_info->firmware_version) {
		iot_os_free(device_info->firmware_version);
		device_info->firmware_version = NULL;
	}

	if (device_info->model_number) {
		iot_os_free(device_info->model_number);
		device_info->model_number = NULL;
	}

	if (device_info->marketing_name) {
		iot_os_free(device_info->marketing_name);
		device_info->marketing_name = NULL;
	}

	if (device_info->manufacturer_name) {
		iot_os_free(device_info->manufacturer_name);
		device_info->manufacturer_name = NULL;
	}

	if (device_info->manufacturer_code) {
		iot_os_free(device_info->manufacturer_code);
		device_info->manufacturer_code = NULL;
	}
}

static void _dump_device_info(struct iot_device_info *info)
{
	if (!info)
		return;

	IOT_INFO("firmware_version: %s", info->firmware_version);
}

static const char name_deviceInfo[] = "deviceInfo";
static const char name_version[] = "firmwareVersion";
static const char name_model_number[] = "modelNumber";
static const char name_marketing[] = "marketingName";
static const char name_manufacturer[] = "manufacturerName";
static const char name_manufacturer_code[] = "manufacturerCode";

iot_error_t iot_api_device_info_load(unsigned char *device_info,
		unsigned int device_info_len, struct iot_device_info *info)
{
	iot_error_t iot_err = IOT_ERROR_NONE;
	JSON_H *root = NULL;
	JSON_H *profile = NULL;
	JSON_H *item = NULL;
	char *firmware_version = NULL;
	char *model_number = NULL;
	char *marketing_name = NULL;
	char *manufacturer_name = NULL;
	char *manufacturer_code = NULL;
	char *data = NULL;
	size_t str_len = 0;
#if defined(CONFIG_STDK_IOT_CORE_LOG_LEVEL_ERROR)
	char *current_name = NULL;
#endif

	if (!device_info || !info || device_info_len == 0)
		return IOT_ERROR_INVALID_ARGS;

	data = iot_os_malloc((size_t) device_info_len + 1);
	if (!data) {
		return IOT_ERROR_MEM_ALLOC;
	}

	memcpy(data, device_info, device_info_len);
	data[device_info_len] = '\0';

	root = JSON_PARSE((char *)data);
	profile = JSON_GET_OBJECT_ITEM(root, name_deviceInfo);
	if (!profile) {
#if defined(CONFIG_STDK_IOT_CORE_LOG_LEVEL_ERROR)
		current_name = (char *)name_deviceInfo;
#endif
		iot_err = IOT_ERROR_UNINITIALIZED;
		goto load_out;
	}

	/* version */
	item = JSON_GET_OBJECT_ITEM(profile, name_version);
	if (!item) {
#if defined(CONFIG_STDK_IOT_CORE_LOG_LEVEL_ERROR)
		current_name = (char *)name_version;
#endif
		iot_err = IOT_ERROR_UNINITIALIZED;
		goto load_out;
	}
	str_len = strlen(JSON_GET_STRING_VALUE(item));
	firmware_version = iot_os_malloc(str_len + 1);
	if (!firmware_version) {
		iot_err = IOT_ERROR_MEM_ALLOC;
		goto load_out;
	}
	strncpy(firmware_version, JSON_GET_STRING_VALUE(item), str_len);
	firmware_version[str_len] = '\0';

	info->firmware_version = firmware_version;
	info->opt_info = 0;

	/* name_model_number */
	item = JSON_GET_OBJECT_ITEM(profile, name_model_number);
	if (item) {
		str_len = strlen(JSON_GET_STRING_VALUE(item));
		model_number = iot_os_malloc(str_len + 1);
		if (!model_number) {
			iot_err = IOT_ERROR_MEM_ALLOC;
			goto load_out;
		}
		strncpy(model_number, JSON_GET_STRING_VALUE(item), str_len);
		model_number[str_len] = '\0';
		info->model_number = model_number;
		info->opt_info++;
	} else {
		info->model_number = NULL;
	}

	/* name_marketing */
	item = JSON_GET_OBJECT_ITEM(profile, name_marketing);
	if (item) {
		str_len = strlen(JSON_GET_STRING_VALUE(item));
		marketing_name = iot_os_malloc(str_len + 1);
		if (!marketing_name) {
			iot_err = IOT_ERROR_MEM_ALLOC;
			goto load_out;
		}
		strncpy(marketing_name, JSON_GET_STRING_VALUE(item), str_len);
		marketing_name[str_len] = '\0';

		info->marketing_name = marketing_name;
		info->opt_info++;
	} else {
		info->marketing_name = NULL;
	}

	/* name_manufacturer */
	item = JSON_GET_OBJECT_ITEM(profile, name_manufacturer);
	if (item) {
		str_len = strlen(JSON_GET_STRING_VALUE(item));
		manufacturer_name = iot_os_malloc(str_len + 1);
		if (!manufacturer_name) {
			iot_err = IOT_ERROR_MEM_ALLOC;
			goto load_out;
		}
		strncpy(manufacturer_name, JSON_GET_STRING_VALUE(item), str_len);
		manufacturer_name[str_len] = '\0';

		info->manufacturer_name = manufacturer_name;
		info->opt_info++;
	} else {
		info->manufacturer_name = NULL;
	}

	/* manufacturerCode */
	item = JSON_GET_OBJECT_ITEM(profile, name_manufacturer_code);
	if (item) {
		str_len = strlen(JSON_GET_STRING_VALUE(item));
		manufacturer_code = iot_os_malloc(str_len + 1);
		if (!manufacturer_code) {
			iot_err = IOT_ERROR_MEM_ALLOC;
			goto load_out;
		}
		strncpy(manufacturer_code, JSON_GET_STRING_VALUE(item), str_len);
		manufacturer_code[str_len] = '\0';

		info->manufacturer_code = manufacturer_code;
		info->opt_info++;
	} else {
		info->manufacturer_code = NULL;
	}

	if (root)
		JSON_DELETE(root);

	iot_os_free(data);

	_dump_device_info(info);

	return iot_err;

load_out:
#if defined(CONFIG_STDK_IOT_CORE_LOG_LEVEL_ERROR)
	if (iot_err == IOT_ERROR_UNINITIALIZED) {
		IOT_ERROR("[%s] wrong device info value detected", current_name);
	}
#endif

	if (firmware_version)
		iot_os_free(firmware_version);
	if (marketing_name)
		iot_os_free(marketing_name);
	if (model_number)
		iot_os_free(model_number);
	if (manufacturer_name)
		iot_os_free(manufacturer_name);

	if (root)
		JSON_DELETE(root);
	if (data)
		iot_os_free(data);

	return iot_err;
}

void iot_api_prov_data_mem_free(struct iot_device_prov_data *prov)
{
	if (!prov)
		return;

	if (prov->cloud.broker_url)
		iot_os_free(prov->cloud.broker_url);

	if (prov->cloud.label)
		iot_os_free(prov->cloud.label);
}

#if !defined(CONFIG_STDK_IOT_CORE_SUPPORT_STNV_PARTITION)
iot_error_t iot_api_read_device_identity(unsigned char* nv_prof,
		unsigned int nv_prof_len, const char* object, char** nv_data)
{
	iot_error_t iot_err = IOT_ERROR_NONE;
	JSON_H *root = NULL;
	JSON_H *profile = NULL;
	JSON_H *item = NULL;
	char *data = NULL;
	char *object_data = NULL;
	size_t str_len = 0;
#if defined(CONFIG_STDK_IOT_CORE_LOG_LEVEL_ERROR)
	char *current_name = NULL;
#endif

	if (!nv_prof || !nv_data || nv_prof_len == 0)
		return IOT_ERROR_INVALID_ARGS;

	data = iot_os_malloc((size_t) nv_prof_len + 1);
	if (!data) {
		return IOT_ERROR_MEM_ALLOC;
	}

	memcpy(data, nv_prof, nv_prof_len);
	data[nv_prof_len] = '\0';

	root = JSON_PARSE((char *)data);
	profile = JSON_GET_OBJECT_ITEM(root, name_deviceInfo);
	if (!profile) {
#if defined(CONFIG_STDK_IOT_CORE_LOG_LEVEL_ERROR)
		current_name = (char*)name_deviceInfo;
#endif
		iot_err = IOT_ERROR_UNINITIALIZED;
		goto load_out;
	}

	item = JSON_GET_OBJECT_ITEM(profile, object);
	if (!item || !strcmp(JSON_GET_STRING_VALUE(item), object)) {
#if defined(CONFIG_STDK_IOT_CORE_LOG_LEVEL_ERROR)
		current_name = (char *)object;
#endif
		iot_err = IOT_ERROR_UNINITIALIZED;
		goto load_out;
	}

	str_len = strlen(JSON_GET_STRING_VALUE(item));
	object_data = iot_os_malloc(str_len + 1);
	if (!object_data) {
		iot_err = IOT_ERROR_MEM_ALLOC;
		goto load_out;
	}

	strncpy(object_data, JSON_GET_STRING_VALUE(item), str_len);
	object_data[str_len] = '\0';

	*nv_data = object_data;

	if (root)
		JSON_DELETE(root);

	iot_os_free(data);

	return iot_err;

load_out:
	if (iot_err == IOT_ERROR_UNINITIALIZED) {
		if (item && JSON_IS_STRING(item)) {
			IOT_ERROR("[%s] wrong nv profile value detected: %s",
					current_name, JSON_GET_STRING_VALUE(item));
		}
		else {
			IOT_ERROR("[%s] wrong nv profile value detected", current_name);
		}
	}

	if (root) {
		JSON_DELETE(root);
	}
	if (data) {
		iot_os_free(data);
	}

	return iot_err;
}
#endif

iot_error_t iot_device_cleanup(struct iot_context *ctx)
{
	iot_error_t iot_err = IOT_ERROR_NONE;
	iot_wifi_conf config;

	IOT_INFO("start to erase device information");

	memset(&config, 0x0, sizeof(iot_wifi_conf));

	iot_api_prov_data_mem_free(&(ctx->prov_data));
	memset(&(ctx->prov_data), 0x0, sizeof(ctx->prov_data));

	iot_err = iot_nv_erase_prov_data();
	if ((iot_err != IOT_ERROR_NONE) && (iot_err != IOT_ERROR_NV_DATA_NOT_EXIST)) {
		IOT_ERROR("%s: failed to erase provisioning data: %d", __func__, iot_err);
	}

	iot_err = iot_nv_erase(IOT_NVD_DEVICE_ID);
	if ((iot_err != IOT_ERROR_NONE) && (iot_err != IOT_ERROR_NV_DATA_NOT_EXIST)) {
		IOT_ERROR("%s: failed to erase device ID: %d", __func__, iot_err);
	}

	/* if there is previous connection, disconnect it first. */
	if (ctx->evt_mqttcli != NULL) {
		IOT_INFO("There is previous connecting, disconnect it first.\n");
		iot_err = iot_es_disconnect(ctx, IOT_CONNECT_TYPE_COMMUNICATION);
		if (iot_err != IOT_ERROR_NONE) {
			IOT_ERROR("%s: evt_mqtt disconnect failed %d", __func__, iot_err);
		}
	}

	if (ctx->reg_mqttcli != NULL) {
		IOT_INFO("There is active registering, disconnect it first.\n");
		iot_err = iot_es_disconnect(ctx, IOT_CONNECT_TYPE_REGISTRATION);
		if (iot_err != IOT_ERROR_NONE) {
			IOT_ERROR("%s: reg_mqtt disconnect failed %d", __func__, iot_err);
		}
	}

	if(ctx->lookup_id) {
		free(ctx->lookup_id);
		ctx->lookup_id = NULL;
	}

	return iot_err;
}

static iot_error_t _get_dip_from_json(JSON_H *json, struct iot_dip_data *dip)
{
	struct iot_dip_data curr_dip;
	JSON_H *sub_item = NULL;
	JSON_H *item = NULL;
	iot_error_t iot_err;

	sub_item = JSON_GET_OBJECT_ITEM(json, "dip");
	if (sub_item == NULL) {
		IOT_ERROR("There is no dip in misc_info");
		return IOT_ERROR_BAD_REQ;
	}

	item = JSON_GET_OBJECT_ITEM(sub_item, "id");
	if (item == NULL) {
		IOT_ERROR("There is no id in dip");
		return IOT_ERROR_BAD_REQ;
	}

	iot_err = iot_util_convert_str_uuid(JSON_GET_STRING_VALUE(item),
				&curr_dip.dip_id);
	if (iot_err != IOT_ERROR_NONE) {
		IOT_ERROR("Can't convert str to uuid(%d)", iot_err);
		return iot_err;
	}

	item = JSON_GET_OBJECT_ITEM(sub_item, "maj");
	if (item == NULL) {
		IOT_ERROR("There is no major-version in dip");
		return IOT_ERROR_BAD_REQ;
	}
	curr_dip.dip_major_version = item->valueint;

	item = JSON_GET_OBJECT_ITEM(sub_item, "min");
	if (item == NULL) {
		curr_dip.dip_minor_version = 0;
	} else {
		curr_dip.dip_minor_version = item->valueint;
	}

	memcpy(dip, &curr_dip, sizeof(curr_dip));
	return iot_err;
}

static iot_error_t _get_location_from_json(JSON_H *json, struct iot_uuid *uuid)
{
	struct iot_uuid curr_uuid;
	JSON_H *item = NULL;
	iot_error_t iot_err;

	item = JSON_GET_OBJECT_ITEM(json, "loId");
	if (item == NULL) {
		IOT_ERROR("There is no locationId in misc_info");
		return IOT_ERROR_BAD_REQ;
	}

	iot_err = iot_util_convert_str_uuid(JSON_GET_STRING_VALUE(item),
				&curr_uuid);
	if (iot_err != IOT_ERROR_NONE) {
		IOT_ERROR("Can't convert str to uuid(%d)", iot_err);
		return iot_err;
	}

	memcpy(uuid, &curr_uuid, sizeof(curr_uuid));
	return IOT_ERROR_NONE;
}

static iot_error_t _get_preverr_from_json(JSON_H *json, char *prev_err)
{
	JSON_H *item = NULL;

	item = JSON_GET_OBJECT_ITEM(json, "prevErr");
	if (item == NULL) {
		IOT_ERROR("There is no prevErr in misc_info");
		return IOT_ERROR_BAD_REQ;
	}

	memcpy(prev_err, item->valuestring, strlen(item->valuestring));
	return IOT_ERROR_NONE;
}

iot_error_t iot_misc_info_load(iot_misc_info_t type, void *out_data)
{
	char *misc_info = NULL;
	size_t misc_info_len = 0;
	JSON_H *json = NULL;
	iot_error_t iot_err = IOT_ERROR_NONE;

	if (!out_data) {
		iot_err = IOT_ERROR_INVALID_ARGS;
		goto misc_info_load_out;
	}

	iot_err = iot_nv_get_misc_info(&misc_info, &misc_info_len);
	if (iot_err != IOT_ERROR_NONE) {
		IOT_ERROR("Can't get misc_info from NV(%d)", iot_err);
		goto misc_info_load_out;
	}

	IOT_DEBUG("Load raw misc_info str:%s", misc_info);

	json = JSON_PARSE(misc_info);
	if (json == NULL) {
		IOT_ERROR("misc_info(%s) parsing failed", misc_info);
		iot_err = IOT_ERROR_BAD_REQ;
		goto misc_info_load_out;
	}

	switch (type) {
	case IOT_MISC_INFO_DIP:
		iot_err = _get_dip_from_json(json, (struct iot_dip_data *)out_data);
		break;

	case IOT_MISC_INFO_LOCATION:
		iot_err = _get_location_from_json(json, (struct iot_uuid *)out_data);
		break;

	case IOT_MISC_PREV_ERR:
		iot_err = _get_preverr_from_json(json, (char *)out_data);
		break;

	default:
		IOT_ERROR("Unsupported type(%d)", type);
		iot_err = IOT_ERROR_BAD_REQ;
		break;
	}

misc_info_load_out:
	if (misc_info)
		iot_os_free(misc_info);

	if (json)
		JSON_DELETE(json);

	return iot_err;
}

static iot_error_t _set_dip_to_json(JSON_H *json, struct iot_dip_data *new_dip)
{
	JSON_H *sub_item = NULL;
	JSON_H *item = NULL;
	iot_error_t iot_err;
	char dip_id_str[40];

	sub_item = JSON_CREATE_OBJECT();
	if (sub_item == NULL) {
		IOT_ERROR("Can't make new obj for dip");
		return IOT_ERROR_MEM_ALLOC;
	}

	iot_err = iot_util_convert_uuid_str(&new_dip->dip_id,
				dip_id_str, sizeof(dip_id_str));
	if (iot_err != IOT_ERROR_NONE) {
		IOT_ERROR("Can't convert uuid to str(%d)", iot_err);
		JSON_DELETE(sub_item);
		return iot_err;
	}

	item = JSON_CREATE_STRING(dip_id_str);
	if (item == NULL) {
		IOT_ERROR("Can't make new string for dip's id");
		JSON_DELETE(sub_item);
		return IOT_ERROR_MEM_ALLOC;
	}
	JSON_ADD_ITEM_TO_OBJECT(sub_item, "id", item);

	item = JSON_CREATE_NUMBER(new_dip->dip_major_version);
	if (item == NULL) {
		IOT_ERROR("Can't make new item for dip's major version");
		JSON_DELETE(sub_item);
		return IOT_ERROR_MEM_ALLOC;
	}
	JSON_ADD_ITEM_TO_OBJECT(sub_item, "maj", item);

	if (new_dip->dip_minor_version != 0) {
		item = JSON_CREATE_NUMBER(new_dip->dip_minor_version);
		if (item == NULL) {
			IOT_ERROR("Can't make new item for dip's minor version");
			JSON_DELETE(sub_item);
			return IOT_ERROR_MEM_ALLOC;
		}
		JSON_ADD_ITEM_TO_OBJECT(sub_item, "min", item);
	}

	if (JSON_GET_OBJECT_ITEM(json, "dip") == NULL) {
		IOT_DEBUG("There is no dip in misc_info");
		JSON_ADD_ITEM_TO_OBJECT(json, "dip", sub_item);
	} else {
		JSON_REPLACE_ITEM_IN_OBJ_CASESENS(json, "dip", sub_item);
	}

	return iot_err;
}

static iot_error_t _set_location_to_json(JSON_H *json, struct iot_uuid *uuid)
{
	JSON_H *item = NULL;
	char location_id[IOT_REG_UUID_STR_LEN + 1];
	iot_error_t iot_err;

	iot_err = iot_util_convert_uuid_str(uuid,
				location_id, sizeof(location_id));
	if (iot_err != IOT_ERROR_NONE) {
		IOT_ERROR("Can't convert uuid to str(%d)", iot_err);
		return iot_err;
	}

	item = JSON_CREATE_STRING(location_id);
	if (item == NULL) {
		IOT_ERROR("Can't make new string for locationId");
		return IOT_ERROR_MEM_ALLOC;
	}

	if (JSON_GET_OBJECT_ITEM(json, "loId") == NULL) {
		IOT_DEBUG("There is no locatinoId in misc_info");
		JSON_ADD_ITEM_TO_OBJECT(json, "loId", item);
	} else {
		JSON_REPLACE_ITEM_IN_OBJ_CASESENS(json, "loId", item);
	}

	return IOT_ERROR_NONE;
}

static iot_error_t _set_preverr_to_json(JSON_H *json, char *prev_err)
{
	JSON_H *item = NULL;

	item = JSON_CREATE_STRING(prev_err);
	if (item == NULL) {
		IOT_ERROR("Can't make new string for prev_err");
		return IOT_ERROR_MEM_ALLOC;
	}

	if (JSON_GET_OBJECT_ITEM(json, "prevErr") == NULL) {
		IOT_DEBUG("There is no prevErr in misc_info");
		JSON_ADD_ITEM_TO_OBJECT(json, "prevErr", item);
	} else {
		JSON_REPLACE_ITEM_IN_OBJ_CASESENS(json, "prevErr", item);
	}

	return IOT_ERROR_NONE;
}

iot_error_t iot_misc_info_store(iot_misc_info_t type, const void *in_data)
{
	char *old_misc_info = NULL;
	size_t old_misc_info_len = 0;
	char *new_misc_info = NULL;
	JSON_H *json = NULL;
	iot_error_t iot_err = IOT_ERROR_NONE;
	unsigned char old_hash[IOT_SECURITY_SHA256_LEN] = {0,};
	unsigned char new_hash[IOT_SECURITY_SHA256_LEN] = {0,};
	bool hash_chk = false;
	bool old_misc_avail = false;

	if (!in_data) {
		iot_err = IOT_ERROR_INVALID_ARGS;
		goto misc_info_store_out;
	}

	iot_err = iot_nv_get_misc_info(&old_misc_info, &old_misc_info_len);
	if (iot_err != IOT_ERROR_NONE) {
		IOT_INFO("There is no old misc_info in NV");
		json = JSON_CREATE_OBJECT();
	} else {
		json = JSON_PARSE(old_misc_info);
		if (json == NULL) {
			IOT_WARN("old misc_info(%s/%u) parsing failed",
				old_misc_info, (unsigned int)old_misc_info_len);
			json = JSON_CREATE_OBJECT();
		} else {
			old_misc_avail = true;
		}
	}

	if (old_misc_avail) {
		iot_err = iot_security_sha256((const unsigned char *)old_misc_info,
				old_misc_info_len, old_hash, sizeof(old_hash));
		if (iot_err != IOT_ERROR_NONE) {
			IOT_WARN("Can't make hash for old_misc_info!!");
		} else {
			hash_chk = true;
		}
	}

	if (old_misc_info) {
		iot_os_free(old_misc_info);
		old_misc_info = NULL;
	}

	switch (type) {
	case IOT_MISC_INFO_DIP:
		iot_err = _set_dip_to_json(json, (struct iot_dip_data *)in_data);
		break;

	case IOT_MISC_INFO_LOCATION:
		iot_err = _set_location_to_json(json, (struct iot_uuid *)in_data);
		break;

	case IOT_MISC_PREV_ERR:
		iot_err = _set_preverr_to_json(json, (char *)in_data);
		break;

	default:
		IOT_ERROR("Unsupported type(%d)", type);
		iot_err = IOT_ERROR_BAD_REQ;
		break;
	}

	if (iot_err != IOT_ERROR_NONE)
		goto misc_info_store_out;

	new_misc_info = JSON_PRINT(json);
	IOT_DEBUG("Store raw msic_info str : %s", new_misc_info);

	if (hash_chk) {
		iot_err = iot_security_sha256((const unsigned char *)new_misc_info,
				strlen(new_misc_info), new_hash, sizeof(new_hash));
		if (iot_err != IOT_ERROR_NONE) {
			IOT_WARN("Can't make hash for new_misc_info!!");
		} else {
			if (!memcmp(old_hash, new_hash, IOT_SECURITY_SHA256_LEN)) {
				IOT_DEBUG("Same misc_info, skip NV update");
				goto misc_info_store_out;
			}
		}
	}

	iot_err = iot_nv_set_misc_info(new_misc_info);
	if (iot_err != IOT_ERROR_NONE) {
		IOT_ERROR("Can't set new misc_info into NV : %s", new_misc_info);
	}

misc_info_store_out:
	if (new_misc_info)
		iot_os_free(new_misc_info);

	if (json)
		JSON_DELETE(json);

	return iot_err;
}

iot_error_t iot_get_random_id_str(char *str, size_t max_sz)
{
	iot_error_t err = IOT_ERROR_NONE;
	struct iot_uuid uuid;

	if (str == NULL) {
		IOT_ERROR("There is no string arg");
		return IOT_ERROR_INVALID_ARGS;
	}

	err = iot_get_random_uuid_from_mac(&uuid);
	if (err != IOT_ERROR_NONE) {
		IOT_ERROR("To get uuid is failed (%d)", err);
		return err;
	}

	err = iot_util_convert_uuid_str(&uuid, str, max_sz);
	if (err != IOT_ERROR_NONE) {
		IOT_ERROR("Failed to convert uuid to str (%d)", err);
	}

	return err;
}

static iot_error_t iot_ecodeType_to_string(iot_st_ecode_t ecode_type, struct iot_st_ecode *st_ecode)
{
	switch(ecode_type)
	{
		case IOT_ST_ECODE_NONE:
			strncpy(st_ecode->ecode, "\0", sizeof(st_ecode->ecode));
			break;
		case IOT_ST_ECODE_EE01:
			strncpy(st_ecode->ecode, "EE01", sizeof(st_ecode->ecode));
			break;
		case IOT_ST_ECODE_NE01:
			strncpy(st_ecode->ecode, "NE01", sizeof(st_ecode->ecode));
			break;
		case IOT_ST_ECODE_NE02:
			strncpy(st_ecode->ecode, "NE02", sizeof(st_ecode->ecode));
			break;
		case IOT_ST_ECODE_NE03:
			strncpy(st_ecode->ecode, "NE03", sizeof(st_ecode->ecode));
			break;
		case IOT_ST_ECODE_NE04:
			strncpy(st_ecode->ecode, "NE04", sizeof(st_ecode->ecode));
			break;
		case IOT_ST_ECODE_NE10:
			strncpy(st_ecode->ecode, "NE10", sizeof(st_ecode->ecode));
			break;
		case IOT_ST_ECODE_NE11:
			strncpy(st_ecode->ecode, "NE11", sizeof(st_ecode->ecode));
			break;
		case IOT_ST_ECODE_NE12:
			strncpy(st_ecode->ecode, "NE12", sizeof(st_ecode->ecode));
			break;
		case IOT_ST_ECODE_NE13:
			strncpy(st_ecode->ecode, "NE13", sizeof(st_ecode->ecode));
			break;
		case IOT_ST_ECODE_NE14:
			strncpy(st_ecode->ecode, "NE14", sizeof(st_ecode->ecode));
			break;
		case IOT_ST_ECODE_NE15:
			strncpy(st_ecode->ecode, "NE15", sizeof(st_ecode->ecode));
			break;
		case IOT_ST_ECODE_NE16:
			strncpy(st_ecode->ecode, "NE16", sizeof(st_ecode->ecode));
			break;
		case IOT_ST_ECODE_NE17:
			strncpy(st_ecode->ecode, "NE17", sizeof(st_ecode->ecode));
			break;
		case IOT_ST_ECODE_CE11:
			strncpy(st_ecode->ecode, "CE11", sizeof(st_ecode->ecode));
			break;
		case IOT_ST_ECODE_CE12:
			strncpy(st_ecode->ecode, "CE12", sizeof(st_ecode->ecode));
			break;
		case IOT_ST_ECODE_CE20:
			strncpy(st_ecode->ecode, "CE20", sizeof(st_ecode->ecode));
			break;
		case IOT_ST_ECODE_CE21:
			strncpy(st_ecode->ecode, "CE21", sizeof(st_ecode->ecode));
			break;
		case IOT_ST_ECODE_CE30:
			strncpy(st_ecode->ecode, "CE30", sizeof(st_ecode->ecode));
			break;
		case IOT_ST_ECODE_CE31:
			strncpy(st_ecode->ecode, "CE31", sizeof(st_ecode->ecode));
			break;
		case IOT_ST_ECODE_CE32:
			strncpy(st_ecode->ecode, "CE32", sizeof(st_ecode->ecode));
			break;
		case IOT_ST_ECODE_CE33:
			strncpy(st_ecode->ecode, "CE33", sizeof(st_ecode->ecode));
			break;
		case IOT_ST_ECODE_CE40:
			strncpy(st_ecode->ecode, "CE40", sizeof(st_ecode->ecode));
			break;
		case IOT_ST_ECODE_CE41:
			strncpy(st_ecode->ecode, "CE41", sizeof(st_ecode->ecode));
			break;
		case IOT_ST_ECODE_CE50:
			strncpy(st_ecode->ecode, "CE50", sizeof(st_ecode->ecode));
			break;
		case IOT_ST_ECODE_CE51:
			strncpy(st_ecode->ecode, "CE51", sizeof(st_ecode->ecode));
			break;
		case IOT_ST_ECODE_CE60:
			strncpy(st_ecode->ecode, "CE60", sizeof(st_ecode->ecode));
			break;
		default:
			break;
	}
	return IOT_ERROR_NONE;
}

iot_error_t iot_set_st_ecode_from_conn_error(struct iot_context *ctx, iot_error_t conn_error)
{
	iot_st_ecode_t ecode;

	switch (conn_error)
	{
		case IOT_ERROR_CONN_SOFTAP_CONF_FAIL:
			ecode = IOT_ST_ECODE_NE01;
			break;
		case IOT_ERROR_CONN_SOFTAP_CONN_FAIL:
			ecode = IOT_ST_ECODE_NE02;
			break;
		case IOT_ERROR_CONN_SOFTAP_DHCP_FAIL:
			ecode = IOT_ST_ECODE_NE03;
			break;
		case IOT_ERROR_CONN_SOFTAP_AUTH_FAIL:
			ecode = IOT_ST_ECODE_NE04;
			break;
		case IOT_ERROR_CONN_STA_CONF_FAIL:
			ecode = IOT_ST_ECODE_NE10;
			break;
		case IOT_ERROR_CONN_STA_CONN_FAIL:
			ecode = IOT_ST_ECODE_NE11;
			break;
		case IOT_ERROR_CONN_STA_DHCP_FAIL:
			ecode = IOT_ST_ECODE_NE12;
			break;
		case IOT_ERROR_CONN_STA_AP_NOT_FOUND:
			ecode = IOT_ST_ECODE_NE13;
			break;
		case IOT_ERROR_CONN_STA_ASSOC_FAIL:
			ecode = IOT_ST_ECODE_NE14;
			break;
		case IOT_ERROR_CONN_STA_AUTH_FAIL:
			ecode = IOT_ST_ECODE_NE15;
			break;
		case IOT_ERROR_CONN_STA_NO_INTERNET:
			ecode = IOT_ST_ECODE_NE16;
			break;
		case IOT_ERROR_CONN_DNS_QUERY_FAIL:
			ecode = IOT_ST_ECODE_NE17;
			break;
		default:
			return IOT_ERROR_INVALID_ARGS;
	}
	return iot_set_st_ecode(ctx, ecode);
}

iot_error_t iot_get_st_ecode(struct iot_context *ctx, struct iot_st_ecode *st_ecode)
{
	if ((ctx == NULL) || (st_ecode == NULL)) {
		IOT_ERROR("There is no ctx or st_ecode arg");
		return IOT_ERROR_INVALID_ARGS;
	}

	memcpy(st_ecode, &(ctx->last_st_ecode), sizeof(struct iot_st_ecode));

	return IOT_ERROR_NONE;
}

iot_error_t iot_set_st_ecode(struct iot_context *ctx, iot_st_ecode_t ecode_type)
{
	iot_error_t err = IOT_ERROR_NONE;

	if (ctx == NULL) {
		IOT_ERROR("There is no ctx");
		return IOT_ERROR_INVALID_ARGS;
	}

	if ((ecode_type != ctx->last_st_ecode.ecode_type) || (ecode_type == IOT_ST_ECODE_NONE)) {
		memset(ctx->last_st_ecode.ecode, 0, sizeof(ctx->last_st_ecode.ecode));
		iot_ecodeType_to_string(ecode_type, &ctx->last_st_ecode);
		err = iot_misc_info_store(IOT_MISC_PREV_ERR, (void *)ctx->last_st_ecode.ecode);
	}

	return err;
}

iot_error_t iot_cleanup(struct iot_context *ctx, bool reboot)
{
	if (ctx->es_http_ready) {
		ctx->es_http_ready = false;
		iot_easysetup_deinit(ctx);
	}

	iot_device_cleanup(ctx);

	if (reboot) {
		IOT_REBOOT();
	}

	return IOT_ERROR_NONE;
}

/**************************************************************
*                       Synchronous Call                      *
**************************************************************/
