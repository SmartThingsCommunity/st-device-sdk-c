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
#include "iot_crypto.h"
#include "iot_nv_data.h"
#include "iot_os_util.h"
#include "iot_util.h"

#include "JSON.h"

static void _set_cmd_status(struct iot_context *ctx, enum iot_command_type cmd_type)
{
	if ((cmd_type) != IOT_COMMNAD_STATE_UPDATE) {
		ctx->cmd_status |= (1u << (cmd_type));
		ctx->cmd_count[(cmd_type)]++;
	}
}

iot_error_t iot_command_send(struct iot_context *ctx,
	enum iot_command_type new_cmd, const void *param, int param_size)
{
	struct iot_command cmd_data;
	int ret;
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

	ret = iot_os_queue_send(ctx->cmd_queue, &cmd_data, 0);
	if (ret != IOT_OS_TRUE) {
		IOT_ERROR("Cannot put the cmd into cmd_queue");
		if (cmd_data.param)
			free(cmd_data.param);
		err = IOT_ERROR_BAD_REQ;
	} else {
		_set_cmd_status(ctx, new_cmd);

		iot_os_eventgroup_set_bits(ctx->iot_events,
			IOT_EVENT_BIT_COMMAND);
		err = IOT_ERROR_NONE;
	}

	return err;
}

iot_error_t iot_wifi_ctrl_request(struct iot_context *ctx,
		iot_wifi_mode_t wifi_mode)
{
	iot_error_t iot_err;
	iot_wifi_conf wifi_conf;

	if (!ctx) {
		IOT_ERROR("There is no ctx\n");
		return IOT_ERROR_BAD_REQ;
	}

	memset(&wifi_conf, 0, sizeof(wifi_conf));
	wifi_conf.mode = wifi_mode;

	switch (wifi_mode) {
	case IOT_WIFI_MODE_STATION:
		memcpy(wifi_conf.ssid, ctx->prov_data.wifi.ssid,
			strlen(ctx->prov_data.wifi.ssid));
		memcpy(wifi_conf.pass, ctx->prov_data.wifi.password,
			strlen(ctx->prov_data.wifi.password));
		break;

	case IOT_WIFI_MODE_SOFTAP:
		/*wifi soft-ap mode w/ ssid E4 format*/
		iot_err = iot_easysetup_create_ssid(&(ctx->devconf),
					wifi_conf.ssid, IOT_WIFI_MAX_SSID_LEN);
		if (iot_err != IOT_ERROR_NONE) {
			IOT_ERROR("Can't create ssid for easysetup.(%d)", iot_err);
			return iot_err;
		}

		snprintf(wifi_conf.pass, sizeof(wifi_conf.pass), "1111122222");
		break;

	case IOT_WIFI_MODE_SCAN:
		/* fall through */
	case IOT_WIFI_MODE_OFF:
		IOT_DEBUG("No need more settings for [%d] mode\n", wifi_mode);
		break;

	default:
		IOT_ERROR("Unsupported wifi ctrl mode[%d]\n", wifi_mode);
		return IOT_ERROR_BAD_REQ;
	}

	iot_err = iot_command_send(ctx,
				IOT_COMMAND_NETWORK_MODE,
					&wifi_conf, sizeof(wifi_conf));

	return iot_err;
}


iot_error_t iot_easysetup_request(struct iot_context *ctx,
				enum iot_easysetup_step step, const void *payload)
{
	struct iot_easysetup_payload request;
	int ret;
	iot_error_t err;

	if (payload) {
		request.payload = (char *)payload;
	} else {
		request.payload = NULL;
	}

	request.step = step;

	if (ctx->easysetup_req_queue) {
		ret = iot_os_queue_send(ctx->easysetup_req_queue, &request, 0);
		if (ret != IOT_OS_TRUE) {
			IOT_ERROR("Cannot put the request into easysetup_req_queue");
			err = IOT_ERROR_BAD_REQ;
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
		IOT_INFO("Trigger user_event with 0x%0x",
				(1u << (unsigned)IOT_STATE_PROV_CONFIRM));
		iot_os_eventgroup_set_bits(ctx->usr_events,
				(1u << (unsigned)IOT_STATE_PROV_CONFIRM));
	}

	state_data.iot_state = new_state;
	state_data.opt = opt;

	err = iot_command_send(ctx, IOT_COMMNAD_STATE_UPDATE,
                           &state_data, sizeof(struct iot_state_data));

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

static const char name_onboardingConfig[] = "onboardingConfig";
static const char name_deviceOnboardingId[] = "deviceOnboardingId";
static const char name_mnId[] = "mnId";
static const char name_setupId[] = "setupId";
static const char name_vid[] = "vid";
static const char name_deviceTypeId[] = "deviceTypeId";
static const char name_ownershipValidationTypes[] = "ownershipValidationTypes";
static const char name_identityType[] = "identityType";
static const char name_deviceIntegrationProfileId[] = "deviceIntegrationProfileKey";

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
	unsigned int ownership_validation_type = 0;
	iot_crypto_pk_type_t pk_type;
	size_t str_len = 0;
	int i;
	char *current_name = NULL;
	struct iot_dip_data *new_dip = NULL;

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
		current_name = (char *)name_onboardingConfig;
		iot_err = IOT_ERROR_UNINITIALIZED;
		goto load_out;
	}

	/* device_onboarding_id */
	item = JSON_GET_OBJECT_ITEM(config, name_deviceOnboardingId);
	if (!item) {
		current_name = (char *)name_deviceOnboardingId;
		iot_err = IOT_ERROR_UNINITIALIZED;
		goto load_out;
	}
	str_len = strlen(JSON_GET_STRING_VALUE(item));
	if (str_len > 13) {
		current_name = (char *)name_deviceOnboardingId;
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
		current_name = (char *)name_mnId;
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
		current_name = (char *)name_setupId;
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
		current_name = (char *)name_vid;
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
		current_name = (char *)name_deviceTypeId;
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
		current_name = (char *)name_ownershipValidationTypes;
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
				current_name = (char *)name_ownershipValidationTypes;
				iot_err = IOT_ERROR_UNINITIALIZED;
				goto load_out;
			}
		}
	}
	if (ownership_validation_type == 0)
	{
		IOT_ERROR("No ownership validation type selected");
		current_name = (char *)name_ownershipValidationTypes;
		iot_err = IOT_ERROR_UNINITIALIZED;
		goto load_out;
	}

	/* device identity */
	item = JSON_GET_OBJECT_ITEM(config, name_identityType);
	if (!item || !strcmp(JSON_GET_STRING_VALUE(item), "ED25519")) {
		pk_type = IOT_CRYPTO_PK_ED25519;
	} else if (!strcmp(JSON_GET_STRING_VALUE(item), "CERTIFICATE")) {
		pk_type = IOT_CRYPTO_PK_RSA;
	} else {
		current_name = (char *)name_identityType;
		iot_err = IOT_ERROR_UNINITIALIZED;
		goto load_out;
	}

	/* Device Integration Profile, optional */
	dip = JSON_GET_OBJECT_ITEM(config, name_deviceIntegrationProfileId);
	if (dip) {
		current_name = (char *)name_deviceIntegrationProfileId;
		new_dip = iot_os_malloc(sizeof(struct iot_dip_data));
		if (!new_dip) {
			iot_err = IOT_ERROR_MEM_ALLOC;
			goto load_out;
		}

		item = JSON_GET_OBJECT_ITEM(dip, "id");
		if (!item) {
			IOT_ERROR("Can't get id (NULL)");
			iot_err = IOT_ERROR_UNINITIALIZED;
			goto load_out;
		}

		iot_err = iot_util_convert_str_uuid(JSON_GET_STRING_VALUE(item),
						&new_dip->dip_id);
		if (iot_err != IOT_ERROR_NONE) {
			IOT_ERROR("Can't convert uuid (str:%s)", JSON_GET_STRING_VALUE(item));
			goto load_out;
		}

		item = JSON_GET_OBJECT_ITEM(dip, "majorVersion");
		if (!item) {
			IOT_ERROR("Can't get majorVersion (NULL)");
			iot_err = IOT_ERROR_UNINITIALIZED;
			goto load_out;
		}
		new_dip->dip_major_version = item->valueint;

		item = JSON_GET_OBJECT_ITEM(dip, "minorVersion");
		if (!item) {
			IOT_ERROR("Can't get minorVersion (NULL)");
			iot_err = IOT_ERROR_UNINITIALIZED;
			goto load_out;
		}
		new_dip->dip_minor_version = item->valueint;
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

	if (device_info->firmware_version) {
		iot_os_free(device_info->firmware_version);
		device_info->firmware_version = NULL;
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

iot_error_t iot_api_device_info_load(unsigned char *device_info,
		unsigned int device_info_len, struct iot_device_info *info)
{
	iot_error_t iot_err = IOT_ERROR_NONE;
	JSON_H *root = NULL;
	JSON_H *profile = NULL;
	JSON_H *item = NULL;
	char *firmware_version = NULL;
	char *data = NULL;
	size_t str_len = 0;
	char *current_name = NULL;


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
		current_name = (char *)name_deviceInfo;
		iot_err = IOT_ERROR_UNINITIALIZED;
		goto load_out;
	}

	/* version */
	item = JSON_GET_OBJECT_ITEM(profile, name_version);
	if (!item) {
		current_name = (char *)name_version;
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

	if (root)
		JSON_DELETE(root);

	iot_os_free(data);

	_dump_device_info(info);

	return iot_err;

load_out:
	if (iot_err == IOT_ERROR_UNINITIALIZED) {
		if (item && JSON_IS_STRING(item)) {
			IOT_ERROR("[%s] wrong device info value detected: %s",
					current_name, JSON_GET_STRING_VALUE(item));
		}
		else {
			IOT_ERROR("[%s] wrong device info value detected", current_name);
		}
	}
	if (iot_err == IOT_ERROR_INVALID_ARGS) {
		if (item && JSON_IS_NUMBER(item)) {
			IOT_ERROR("invalid device info value: %d", item->valueint);
		}
	}
	if (firmware_version)
		iot_os_free(firmware_version);
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
	char *current_name = NULL;

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
		current_name = (char*)name_deviceInfo;
		iot_err = IOT_ERROR_UNINITIALIZED;
		goto load_out;
	}

	item = JSON_GET_OBJECT_ITEM(profile, object);
	if (!item || !strcmp(JSON_GET_STRING_VALUE(item), object)) {
		current_name = (char *)object;
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

	if (root)
		JSON_DELETE(root);
	if (data)
		free(data);

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

	if ((iot_err = iot_nv_erase_prov_data()) != IOT_ERROR_NONE) {
		IOT_ERROR("%s: failed to erase provisioning data: %d", __func__, iot_err);
	}

	if ((iot_err = iot_nv_erase(IOT_NVD_DEVICE_ID)) != IOT_ERROR_NONE) {
		IOT_ERROR("%s: failed to erase device ID: %d", __func__, iot_err);
	}

	if((iot_err = iot_es_disconnect(ctx, IOT_CONNECT_TYPE_COMMUNICATION)) != IOT_ERROR_NONE) {
		IOT_ERROR("%s: mqtt disconnect failed %d", __func__, iot_err);
	}

	config.mode = IOT_WIFI_MODE_OFF;
	iot_bsp_wifi_set_mode(&config);

	if(ctx->lookup_id) {
		free(ctx->lookup_id);
		ctx->lookup_id = NULL;
	}

	ctx->curr_state = ctx->req_state = IOT_STATE_UNKNOWN;

	return iot_err;
}

iot_error_t iot_misc_info_load(iot_misc_info_t type, void *out_data)
{
	char *misc_info = NULL;
	size_t misc_info_len = 0;
	JSON_H *json = NULL;
	JSON_H *item = NULL;
	JSON_H *sub_item = NULL;
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
	{
		struct iot_dip_data old_dip;

		sub_item = JSON_GET_OBJECT_ITEM(json, "dip");
		if (sub_item == NULL) {
			IOT_ERROR("There is no dip in misc_info");
			iot_err = IOT_ERROR_BAD_REQ;
			break;
		}

		item = JSON_GET_OBJECT_ITEM(sub_item, "id");
		if (item == NULL) {
			IOT_ERROR("There is no id in dip");
			iot_err = IOT_ERROR_BAD_REQ;
			break;
		}

		iot_err = iot_util_convert_str_uuid(JSON_GET_STRING_VALUE(item),
					&old_dip.dip_id);
		if (iot_err != IOT_ERROR_NONE) {
			IOT_ERROR("Can't convert str to uuid(%d)", iot_err);
			break;
		}

		item = JSON_GET_OBJECT_ITEM(sub_item, "maj");
		if (item == NULL) {
			IOT_ERROR("There is no major-version in dip");
			iot_err = IOT_ERROR_BAD_REQ;
			break;
		}
		old_dip.dip_major_version = item->valueint;

		item = JSON_GET_OBJECT_ITEM(sub_item, "min");
		if (item == NULL) {
			old_dip.dip_minor_version = 0;
		} else {
			old_dip.dip_minor_version = item->valueint;
		}

		memcpy(out_data, &old_dip, sizeof(old_dip));
		break;
	}

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

iot_error_t iot_misc_info_store(iot_misc_info_t type, const void *in_data)
{
	char *old_misc_info = NULL;
	size_t old_misc_info_len = 0;
	char *new_misc_info = NULL;
	JSON_H *json = NULL;
	JSON_H *item = NULL;
	JSON_H *new_item = NULL;
	JSON_H *sub_item = NULL;
	iot_error_t iot_err = IOT_ERROR_NONE;

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
			IOT_ERROR("old misc_info(%s) parsing failed", old_misc_info);
			iot_err = IOT_ERROR_BAD_REQ;
			goto misc_info_store_out;
		}
	}

	iot_os_free(old_misc_info);
	old_misc_info = NULL;

	switch (type) {
	case IOT_MISC_INFO_DIP:
	{
		struct iot_dip_data *new_dip;
		char dip_id_str[40];

		new_dip = (struct iot_dip_data *)in_data;
		sub_item = JSON_GET_OBJECT_ITEM(json, "dip");
		if (sub_item == NULL) {
			IOT_DEBUG("There is no dip in misc_info");
			sub_item = JSON_CREATE_OBJECT();
			if (sub_item == NULL) {
				IOT_ERROR("Can't make new obj for dip");
				iot_err = IOT_ERROR_MEM_ALLOC;
				break;
			}
			JSON_ADD_ITEM_TO_OBJECT(json, "dip", sub_item);
		}

		iot_err = iot_util_convert_uuid_str(&new_dip->dip_id,
					dip_id_str, sizeof(dip_id_str));
		if (iot_err != IOT_ERROR_NONE) {
			IOT_ERROR("Can't convert uuid to str(%d)", iot_err);
			break;
		}

		new_item = JSON_CREATE_STRING(dip_id_str);
		if (new_item == NULL) {
			IOT_ERROR("Can't make new string for dip's id");
			iot_err = IOT_ERROR_MEM_ALLOC;
			break;
		}

		item = JSON_GET_OBJECT_ITEM(sub_item, "id");
		if (item == NULL) {
			IOT_DEBUG("There is no ids in dip");
			JSON_ADD_ITEM_TO_OBJECT(sub_item, "id", new_item);
		} else {
			JSON_REPLACE_ITEM_IN_OBJ_CASESENS(sub_item, "id", new_item);
		}

		new_item = JSON_CREATE_NUMBER(new_dip->dip_major_version);
		if (new_item == NULL) {
			IOT_ERROR("Can't make new item for dip's major version");
			iot_err = IOT_ERROR_MEM_ALLOC;
			break;
		}

		item = JSON_GET_OBJECT_ITEM(sub_item, "maj");
		if (item == NULL) {
			IOT_DEBUG("There is no major version in dip");
			JSON_ADD_ITEM_TO_OBJECT(sub_item, "maj", new_item);
		} else {
			JSON_REPLACE_ITEM_IN_OBJ_CASESENS(sub_item, "maj", new_item);
		}

		new_item = NULL;
		if (new_dip->dip_minor_version != 0) {
			new_item = JSON_CREATE_NUMBER(new_dip->dip_minor_version);
			if (new_item == NULL) {
				IOT_ERROR("Can't make new item for dip's minor version");
				iot_err = IOT_ERROR_MEM_ALLOC;
				break;
			}
		}

		/* minor version value is optional */
		item = JSON_GET_OBJECT_ITEM(sub_item, "min");
		if ((item == NULL) && (new_item != NULL)) {
			/* Old is 0 but new has value, add new */
			IOT_INFO("There is no minor version in dip");
			JSON_ADD_ITEM_TO_OBJECT(sub_item, "min", new_item);
		} else if ((item != NULL) && (new_item != NULL)) {
			/* Old had value and new also has, update new */
			JSON_REPLACE_ITEM_IN_OBJ_CASESENS(sub_item, "min", new_item);
		} else if ((item != NULL) && (new_item == NULL)) {
			/* Old had value but new is 0, just remove old */
			JSON_DELETE(item);
		}

		break;
	}

	default:
		IOT_ERROR("Unsupported type(%d)", type);
		iot_err = IOT_ERROR_BAD_REQ;
		break;
	}

	if (iot_err != IOT_ERROR_NONE)
		goto misc_info_store_out;

	new_misc_info = JSON_PRINT(json);
	IOT_DEBUG("Store raw msic_info str : %s", new_misc_info);

	iot_err = iot_nv_set_misc_info(new_misc_info);
	if (iot_err != IOT_ERROR_NONE) {
		IOT_ERROR("Can't set new misc_info into NV : %s", new_misc_info);
	}

misc_info_store_out:
	if (new_misc_info)
		iot_os_free(new_misc_info);

	if (old_misc_info)
		iot_os_free(old_misc_info);

	if (json)
		JSON_DELETE(json);

	return iot_err;
}

/**************************************************************
*                       Synchronous Call                      *
**************************************************************/
