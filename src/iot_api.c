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
#include <sys/time.h>

#include "iot_main.h"
#include "iot_internal.h"
#include "iot_debug.h"
#include "iot_easysetup.h"
#include "iot_crypto.h"
#include "iot_nv_data.h"
#include "iot_os_util.h"

#include "cJSON.h"

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
		if (new_cmd != IOT_CMD_STATE_HANDLE) {
			ctx->cmd_status |= (1 << new_cmd);
			ctx->cmd_count[new_cmd]++;
		}

		iot_os_eventgroup_set_bits(ctx->iot_events,
			IOT_EVENT_BIT_COMMAND);
		err = IOT_ERROR_NONE;
	}

	return err;
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

	switch (new_state) {
	case IOT_STATE_PROV_CONFIRMING:
		if (opt == IOT_STATE_OPT_NEED_INTERACT) {
			IOT_INFO("Trigger user_event with 0x%0x",
				(1 << new_state));
			iot_os_eventgroup_set_bits(ctx->usr_events,
				(1 << new_state));
		}
		break;

	default:
		break;
	}

	state_data.iot_state = new_state;
	state_data.opt = opt;

	err = iot_command_send(ctx, IOT_CMD_STATE_HANDLE,
			&state_data, sizeof(struct iot_state_data));

	return err;
}

void iot_api_onboarding_config_mem_free(struct iot_devconf_prov_data *devconf)
{
	if (!devconf)
		return;

	if (devconf->device_onboarding_id)
		free(devconf->device_onboarding_id);
	if (devconf->mnid)
		free(devconf->mnid);
	if (devconf->setupid)
		free(devconf->setupid);
	if (devconf->vid)
		free(devconf->vid);
	if (devconf->device_type)
		free(devconf->device_type);
}

static const char name_onboardingConfig[] = "onboardingConfig";
static const char name_deviceOnboardingId[] = "deviceOnboardingId";
static const char name_mnId[] = "mnId";
static const char name_setupId[] = "setupId";
static const char name_vid[] = "vid";
static const char name_deviceTypeId[] = "deviceTypeId";
static const char name_ownershipValidationTypes[] = "ownershipValidationTypes";
static const char name_identityType[] = "identityType";

iot_error_t iot_api_onboarding_config_load(unsigned char *onboarding_config,
		unsigned int onboarding_config_len, struct iot_devconf_prov_data *devconf)
{
	iot_error_t iot_err = IOT_ERROR_NONE;
	cJSON *root = NULL;
	cJSON *config = NULL;
	cJSON *item = NULL;
	char *data = NULL;
	char *device_onboarding_id = NULL;
	char *mnid = NULL;
	char *setupid = NULL;
	char *vid = NULL;
	char *devicetypeid = NULL;
	int ownership_validation_type = 0;
	iot_crypto_pk_type_t pk_type;
	int str_len = 0;
	int i;
	char *current_name = NULL;

	if (!onboarding_config || !devconf || onboarding_config_len == 0)
		return IOT_ERROR_INVALID_ARGS;

	data = malloc((size_t) onboarding_config_len + 1);
	if (!data)
		return IOT_ERROR_MEM_ALLOC;
	memcpy(data, onboarding_config, onboarding_config_len);
	data[onboarding_config_len] = '\0';

	root = cJSON_Parse((char *)data);
	config = cJSON_GetObjectItem(root, name_onboardingConfig);
	if (!config) {
		current_name = (char *)name_onboardingConfig;
		iot_err = IOT_ERROR_UNINITIALIZED;
		goto load_out;
	}

	/* device_onboarding_id */
	item = cJSON_GetObjectItem(config, name_deviceOnboardingId);
	if (!item) {
		current_name = (char *)name_deviceOnboardingId;
		iot_err = IOT_ERROR_UNINITIALIZED;
		goto load_out;
	}
	str_len = strlen(cJSON_GetStringValue(item));
	if (str_len > 13) {
		current_name = (char *)name_deviceOnboardingId;
		iot_err = IOT_ERROR_UNINITIALIZED;
		goto load_out;
	}
	device_onboarding_id = malloc(str_len + 1);
	if (!device_onboarding_id) {
		iot_err = IOT_ERROR_MEM_ALLOC;
		goto load_out;
	}
	strncpy(device_onboarding_id, cJSON_GetStringValue(item), str_len);
	device_onboarding_id[str_len] = '\0';

	/* mnid */
	item = cJSON_GetObjectItem(config, name_mnId);
	if (!item || !strcmp(cJSON_GetStringValue(item), "MNID")) {
		current_name = (char *)name_mnId;
		iot_err = IOT_ERROR_UNINITIALIZED;
		goto load_out;
	}
	str_len = strlen(cJSON_GetStringValue(item));
	mnid = malloc(str_len + 1);
	if (!mnid) {
		iot_err = IOT_ERROR_MEM_ALLOC;
		goto load_out;
	}
	strncpy(mnid, cJSON_GetStringValue(item), str_len);
	mnid[str_len] = '\0';

	/* setup_id */
	item = cJSON_GetObjectItem(config, name_setupId);
	if (!item) {
		current_name = (char *)name_setupId;
		iot_err = IOT_ERROR_UNINITIALIZED;
		goto load_out;
	}
	str_len = strlen(cJSON_GetStringValue(item));
	setupid = malloc(str_len + 1);
	if (!setupid) {
		iot_err = IOT_ERROR_MEM_ALLOC;
		goto load_out;
	}
	strncpy(setupid, cJSON_GetStringValue(item), str_len);
	setupid[str_len] = '\0';

	/* vid */
	item = cJSON_GetObjectItem(config, name_vid);
	if (!item) {
		current_name = (char *)name_vid;
		iot_err = IOT_ERROR_UNINITIALIZED;
		goto load_out;
	}
	str_len = strlen(cJSON_GetStringValue(item));
	vid = malloc(str_len + 1);
	if (!vid) {
		iot_err = IOT_ERROR_MEM_ALLOC;
		goto load_out;
	}
	strncpy(vid, cJSON_GetStringValue(item), str_len);
	vid[str_len] = '\0';

	/* device_type_id */
	item = cJSON_GetObjectItem(config, name_deviceTypeId);
	if (!item || !strcmp(cJSON_GetStringValue(item), "TYPE")) {
		current_name = (char *)name_deviceTypeId;
		iot_err = IOT_ERROR_UNINITIALIZED;
		goto load_out;
	}
	str_len = strlen(cJSON_GetStringValue(item));
	devicetypeid = malloc(str_len + 1);
	if (!devicetypeid) {
		iot_err = IOT_ERROR_MEM_ALLOC;
		goto load_out;
	}
	strncpy(devicetypeid, cJSON_GetStringValue(item), str_len);
	devicetypeid[str_len] = '\0';

	/* ownership validation type */
	item = cJSON_GetObjectItem(config, name_ownershipValidationTypes);
	if (!item) {
		current_name = (char *)name_ownershipValidationTypes;
		iot_err = IOT_ERROR_UNINITIALIZED;
		goto load_out;
	}
	for (i = 0; i < cJSON_GetArraySize(item); i++) {
		cJSON *ovf = cJSON_GetArrayItem(item, i);
		if (ovf && cJSON_IsString(ovf)) {
			if (!strcmp(cJSON_GetStringValue(ovf), "JUSTWORKS"))
				ownership_validation_type |= (unsigned int) IOT_OVF_TYPE_JUSTWORKS;
			else if (!strcmp(cJSON_GetStringValue(ovf), "BUTTON"))
				ownership_validation_type |= (unsigned int) IOT_OVF_TYPE_BUTTON;
			else if (!strcmp(cJSON_GetStringValue(ovf), "PIN"))
				ownership_validation_type |= (unsigned int) IOT_OVF_TYPE_PIN;
			else if (!strcmp(cJSON_GetStringValue(ovf), "QR"))
				ownership_validation_type |= (unsigned int) IOT_OVF_TYPE_QR;
			else {
				IOT_ERROR("Unknown validation type: %s", cJSON_GetStringValue(ovf));
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
	item = cJSON_GetObjectItem(config, name_identityType);
	if (!item || !strcmp(cJSON_GetStringValue(item), "ED25519")) {
		pk_type = IOT_CRYPTO_PK_ED25519;
	} else if (!strcmp(cJSON_GetStringValue(item), "CERTIFICATE")) {
		pk_type = IOT_CRYPTO_PK_RSA;
	} else {
		current_name = (char *)name_identityType;
		iot_err = IOT_ERROR_UNINITIALIZED;
		goto load_out;
	}

	devconf->device_onboarding_id = device_onboarding_id;
	devconf->mnid = mnid;
	devconf->setupid = setupid;
	devconf->vid = vid;
	devconf->device_type = devicetypeid;
	devconf->ownership_validation_type = ownership_validation_type;
	devconf->pk_type = pk_type;

	if (root)
		cJSON_Delete(root);
	if (data)
		free(data);

	return iot_err;

load_out:
	if (iot_err == IOT_ERROR_UNINITIALIZED) {
		if (item && cJSON_IsString(item)) {
			IOT_ERROR("[%s] wrong onboarding config value detected: %s",
					current_name, cJSON_GetStringValue(item));
		}
		else {
			IOT_ERROR("[%s] wrong onboarding config value detected", current_name);
		}
	}
	if (device_onboarding_id)
		free(device_onboarding_id);
	if (mnid)
		free(mnid);
	if (setupid)
		free(setupid);
	if (vid)
		free(vid);
	if (devicetypeid)
		free(devicetypeid);
	if (root)
		cJSON_Delete(root);
	if (data)
		free(data);

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
		free(device_info->firmware_version);
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
	cJSON *root = NULL;
	cJSON *profile = NULL;
	cJSON *item = NULL;
	char *firmware_version = NULL;
	char *data = NULL;
	size_t str_len = 0;
	char *current_name = NULL;


	if (!device_info || !info || device_info_len == 0)
		return IOT_ERROR_INVALID_ARGS;

	data = malloc((size_t) device_info_len + 1);
	if (!data)
		return IOT_ERROR_MEM_ALLOC;
	memcpy(data, device_info, device_info_len);
	data[device_info_len] = '\0';

	root = cJSON_Parse((char *)data);
	profile = cJSON_GetObjectItem(root, name_deviceInfo);
	if (!profile) {
		current_name = (char *)name_deviceInfo;
		iot_err = IOT_ERROR_UNINITIALIZED;
		goto load_out;
	}

	/* version */
	item = cJSON_GetObjectItem(profile, name_version);
	if (!item) {
		current_name = (char *)name_version;
		iot_err = IOT_ERROR_UNINITIALIZED;
		goto load_out;
	}
	str_len = strlen(cJSON_GetStringValue(item));
	firmware_version = malloc(str_len + 1);
	if (!firmware_version) {
		iot_err = IOT_ERROR_MEM_ALLOC;
		goto load_out;
	}
	strncpy(firmware_version, cJSON_GetStringValue(item), str_len);
	firmware_version[str_len] = '\0';

	info->firmware_version = firmware_version;

	if (root)
		cJSON_Delete(root);
	if (data)
		free(data);

	_dump_device_info(info);

	return iot_err;

load_out:
	if (iot_err == IOT_ERROR_UNINITIALIZED) {
		if (item && cJSON_IsString(item)) {
			IOT_ERROR("[%s] wrong device info value detected: %s",
					current_name, cJSON_GetStringValue(item));
		}
		else {
			IOT_ERROR("[%s] wrong device info value detected", current_name);
		}
	}
	if (iot_err == IOT_ERROR_INVALID_ARGS) {
		if (item && cJSON_IsNumber(item)) {
			IOT_ERROR("invalid device info value: %d", item->valueint);
		}
	}
	if (firmware_version)
		free(firmware_version);
	if (root)
		cJSON_Delete(root);
	if (data)
		free(data);

	return iot_err;
}

void iot_api_prov_data_mem_free(struct iot_device_prov_data *prov)
{
	if (!prov)
		return;

	if (prov->cloud.broker_url)
		free(prov->cloud.broker_url);

	if (prov->cloud.label)
		free(prov->cloud.label);

	return;
}

#if !defined(CONFIG_STDK_IOT_CORE_SUPPORT_STNV_PARTITION)
iot_error_t iot_api_read_device_identity(unsigned char* nv_prof,
		unsigned int nv_prof_len, const char* object, char** nv_data)
{
	iot_error_t iot_err = IOT_ERROR_NONE;
	cJSON *root = NULL;
	cJSON *profile = NULL;
	cJSON *item = NULL;
	char *data = NULL;
	char *object_data = NULL;
	int str_len = 0;
	char *current_name = NULL;

	if (!nv_prof || !nv_data || nv_prof_len == 0)
		return IOT_ERROR_INVALID_ARGS;

	data = malloc((size_t) nv_prof_len + 1);
	if (!data)
		return IOT_ERROR_MEM_ALLOC;
	memcpy(data, nv_prof, nv_prof_len);
	data[nv_prof_len] = '\0';

	root = cJSON_Parse((char *)data);
	profile = cJSON_GetObjectItem(root, name_deviceInfo);
	if (!profile) {
		current_name = (char*)name_deviceInfo;
		iot_err = IOT_ERROR_UNINITIALIZED;
		goto load_out;
	}

	item = cJSON_GetObjectItem(profile, object);
	if (!item || !strcmp(cJSON_GetStringValue(item), object)) {
		current_name = (char *)object;
		iot_err = IOT_ERROR_UNINITIALIZED;
		goto load_out;
	}

	str_len = strlen(cJSON_GetStringValue(item));
	object_data = malloc(str_len + 1);
	if (!object_data) {
		iot_err = IOT_ERROR_MEM_ALLOC;
		goto load_out;
	}

	strncpy(object_data, cJSON_GetStringValue(item), str_len);
	object_data[str_len] = '\0';

	*nv_data = object_data;

	if (root)
		cJSON_Delete(root);
	if (data)
		free(data);

	return iot_err;

load_out:
	if (iot_err == IOT_ERROR_UNINITIALIZED) {
		if (item && cJSON_IsString(item)) {
			IOT_ERROR("[%s] wrong nv profile value detected: %s",
					current_name, cJSON_GetStringValue(item));
		}
		else {
			IOT_ERROR("[%s] wrong nv profile value detected", current_name);
		}
	}

	if (root)
		cJSON_Delete(root);
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

	if ((iot_err = iot_nv_erase_prov_data()) != IOT_ERROR_NONE)
		IOT_ERROR("%s: failed to erase provisioning data: %d", __func__, iot_err);

	if ((iot_err = iot_nv_erase(IOT_NVD_DEVICE_ID)) != IOT_ERROR_NONE)
		IOT_ERROR("%s: failed to erase device ID: %d", __func__, iot_err);

	if((iot_err = iot_es_disconnect(ctx, IOT_CONNECT_TYPE_COMMUNICATION)) != IOT_ERROR_NONE)
		IOT_ERROR("%s: mqtt disconnect failed %d", __func__, iot_err);

	config.mode = IOT_WIFI_MODE_OFF;
	iot_bsp_wifi_set_mode(&config);

	if(ctx->lookup_id) {
		free(ctx->lookup_id);
		ctx->lookup_id = NULL;
	}

	ctx->curr_state = ctx->req_state = IOT_STATE_UNKNOWN;

	return iot_err;
}
/**************************************************************
*                       Synchronous Call                      *
**************************************************************/
