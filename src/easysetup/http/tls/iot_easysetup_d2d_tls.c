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

#include <string.h>
#include <time.h>
#include "JSON.h"
#include "iot_main.h"
#include "iot_bsp_random.h"
#include "iot_bsp_system.h"
#include "iot_easysetup.h"
#include "iot_internal.h"
#include "iot_nv_data.h"
#include "iot_util.h"
#include "iot_debug.h"
#include "security/iot_security_helper.h"

#define PIN_SIZE	8
#define MAC_ADDR_BUFFER_SIZE	20
#define URL_BUFFER_SIZE 	64
#define WIFIINFO_BUFFER_SIZE	20
#define ES_CONFIRM_MAX_DELAY	100000
#define ES_CONFIRM_FAIL_TIMEOUT (10000)

void st_conn_ownership_confirm(IOT_CTX *iot_ctx, bool confirm)
{
	struct iot_context *ctx = (struct iot_context*)iot_ctx;

	if (ctx->curr_otm_feature == OVF_BIT_BUTTON) {
		if (confirm == true) {
			IOT_INFO("To confirm is reported!!");
			IOT_ES_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_EASYSETUP_GET_OWNER_CONFIRM, 0);
			iot_os_eventgroup_set_bits(ctx->iot_events, IOT_EVENT_BIT_EASYSETUP_CONFIRM);
		}
	}
}

STATIC_FUNCTION
char *_es_json_parse_string(JSON_H *json, const char *name)
{
	char *buf = NULL;
	JSON_H *recv = NULL;
	unsigned int buf_len;

	if (!json || !name) {
		IOT_ERROR("invalid args");
		return NULL;
	}

	if ((recv = JSON_GET_OBJECT_ITEM(json, name)) == NULL) {
		IOT_INFO("failed to find '%s'", name);
		return NULL;
	}
	buf_len = (strlen(recv->valuestring) + 1);

	IOT_DEBUG("'%s' (%d): %s",
			name, buf_len, recv->valuestring);

	if ((buf = (char *)iot_os_malloc(buf_len)) == NULL) {
		IOT_ERROR("failed to malloc for buf");
		return NULL;
	}
	memset(buf, 0, buf_len);
	memcpy(buf, recv->valuestring, strlen(recv->valuestring));

	return buf;
}

STATIC_FUNCTION
iot_error_t _es_time_set(unsigned char *time)
{
	char time_str[11] = {0,};
	iot_error_t err = IOT_ERROR_NONE;
	struct tm tm = { 0 };
	time_t now = 0;

	if (sscanf((char *)time, "%4d-%2d-%2dT%2d.%2d.%2d", &tm.tm_year, &tm.tm_mon, &tm.tm_mday, &tm.tm_hour, &tm.tm_min, &tm.tm_sec) != 6) {
		IOT_ERROR("Invalid UTC time!!");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_TIME, 0);
		err = IOT_ERROR_EASYSETUP_INVALID_TIME;
		return err;
	}

	/*
	This code is applied by the Year 2038 problem.
	The Year 2038 problem relates to representing time in many digital systems
	as the number of seconds passed since 00:00:00 UTC on 1 January 1970 and storing it as a signed 32-bit integer.
	Such implementations cannot encode times after 03:14:07 UTC on 19 January 2038.
	The Year 2038 problem is caused by insufficient capacity used to represent time.
	If it meet the problem, the time info will be updated by SNTP.
	*/
	if (sizeof(time_t) == 4) {
		if (tm.tm_year >= 2038) {
			IOT_ERROR("Not support time by year 2038 problem(Y2038 Problem)");
			IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_TIME, 0);
			return err;
		}
	}

	tm.tm_year -= 1900;
	tm.tm_mon -= 1;

	now = mktime(&tm);
	snprintf(time_str, sizeof(time_str), "%ld", now);

	err = iot_bsp_system_set_time_in_sec(time_str);
	if (err) {
		IOT_ERROR("Time set error!!");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_TIME, err);
		err = IOT_ERROR_EASYSETUP_INVALID_TIME;
	}
	return err;
}

STATIC_FUNCTION
iot_error_t _es_deviceinfo_handler(struct iot_context *ctx, char **out_payload)
{
	char *output_ptr = NULL;
	JSON_H *root = NULL;
	iot_error_t err = IOT_ERROR_NONE;

	if (!ctx) {
		IOT_ERROR("invalid iot_context!!");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INTERNAL_SERVER_ERROR, 0);
		err = IOT_ERROR_EASYSETUP_INTERNAL_SERVER_ERROR;
		return err;
	}

	root = JSON_CREATE_OBJECT();
	if (!root) {
		IOT_ERROR("json create failed");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_JSON_CREATE_ERROR, 0);
		err = IOT_ERROR_EASYSETUP_JSON_CREATE_ERROR;
		return err;
	}
	JSON_ADD_ITEM_TO_OBJECT(root, "protocolVersion", JSON_CREATE_STRING(STDK_D2D_PROTOCOL_VERSION));
	JSON_ADD_ITEM_TO_OBJECT(root, "firmwareVersion", JSON_CREATE_STRING(ctx->device_info.firmware_version));
	JSON_ADD_ITEM_TO_OBJECT(root, "hashedSn", JSON_CREATE_STRING((char *)ctx->devconf.hashed_sn));
	JSON_ADD_NUMBER_TO_OBJECT(root, "wifiSupportFrequency", (double) iot_bsp_wifi_get_freq());
	err = iot_misc_info_load(IOT_MISC_PREV_ERR, (char *)ctx->last_st_ecode.ecode);
	if (!err) {
		JSON_ADD_ITEM_TO_OBJECT(root, "prevErrorCode", JSON_CREATE_STRING((char *)ctx->last_st_ecode.ecode));
	}

	output_ptr = JSON_PRINT(root);

	*out_payload = output_ptr;
	IOT_DEBUG("payload: %s", *out_payload);

	if (root)
		JSON_DELETE(root);
	return err;
}

STATIC_FUNCTION
iot_error_t _es_keyinfo_handler(struct iot_context *ctx, char *in_payload, char **out_payload)
{
	char *final_msg = NULL;
	JSON_H *recv = NULL;
	JSON_H *root = NULL;
	JSON_H *array = NULL;
	unsigned int i;
	iot_error_t err = IOT_ERROR_NONE;
	unsigned char *p_datetime_str = NULL;
	unsigned char *p_regionaldatetime_str = NULL;
	unsigned char *p_timezoneid_str = NULL;

	root = JSON_PARSE(in_payload);
	if (!root) {
		IOT_ERROR("Invalid json format of payload");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_REQUEST, 0);
		err = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto exit;
	}

	if ((recv = JSON_GET_OBJECT_ITEM(root, "datetime")) == NULL) {
		IOT_INFO("no datetime info");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_REQUEST, 0);
		err  = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto skip_time_set;
	}
	p_datetime_str = (unsigned char *)JSON_GET_STRING_VALUE(recv);

	err = _es_time_set(p_datetime_str);
	if (err) {
		goto exit_secret;
	}

	if ((recv = JSON_GET_OBJECT_ITEM(root, "regionaldatetime")) == NULL) {
		IOT_INFO("no regionaldatetime info");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_REQUEST, 0);
		err  = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto exit_secret;
	}
	p_regionaldatetime_str = (unsigned char *)JSON_GET_STRING_VALUE(recv);

	IOT_DEBUG("regionaldatetime = %s", p_regionaldatetime_str);

	if ((recv = JSON_GET_OBJECT_ITEM(root, "timezoneid")) == NULL) {
		IOT_INFO("no timezoneid info");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_REQUEST, 0);
		err  = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto exit_secret;
	}
	p_timezoneid_str = (unsigned char *)JSON_GET_STRING_VALUE(recv);

	IOT_DEBUG("timezoneid = %s", p_timezoneid_str); // TODO: where to store

skip_time_set:

	JSON_DELETE(root);

	root = JSON_CREATE_OBJECT();
	if (!root) {
		IOT_ERROR("json create failed");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_MEM_ALLOC_ERROR, 0);
		err = IOT_ERROR_EASYSETUP_MEM_ALLOC_ERROR;
		goto exit_secret;
	}

	array = JSON_CREATE_ARRAY();
	if (!array) {
		IOT_ERROR("json create failed");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_MEM_ALLOC_ERROR, 0);
		err = IOT_ERROR_EASYSETUP_MEM_ALLOC_ERROR;
		goto exit_secret;
	}

	for (i = OVF_BIT_JUSTWORKS; i < OVF_BIT_MAX_FEATURE; i++) {
		if ((i == OVF_BIT_JUSTWORKS) && ctx->add_justworks) {
			JSON_ADD_ITEM_TO_ARRAY(array, JSON_CREATE_NUMBER(i));
		} else if (ctx->devconf.ownership_validation_type & (unsigned)(1 << i)) {
			JSON_ADD_ITEM_TO_ARRAY(array, JSON_CREATE_NUMBER(i));
		}
	}
	JSON_ADD_ITEM_TO_OBJECT(root, "otmSupportFeatures", array);
	
	final_msg = JSON_PRINT(root);

	*out_payload = final_msg;
exit_secret:
exit:
	if (root) {
		JSON_DELETE(root);
	}
	return err;
}

STATIC_FUNCTION
iot_error_t _es_confirm_check_manager(struct iot_context *ctx, enum ownership_validation_feature confirm_feature, char *sn)
{
	char *dev_sn = NULL;
	unsigned char curr_event = 0;
	size_t devsn_len;
	iot_error_t err = IOT_ERROR_NONE;

	iot_os_eventgroup_clear_bits(ctx->iot_events, IOT_EVENT_BIT_EASYSETUP_CONFIRM);
	ctx->curr_otm_feature = confirm_feature;

	IOT_REMARK("IOT_STATE_PROV_CONFIRMING");

	err = iot_state_update(ctx, IOT_STATE_PROV_CONFIRM,
			IOT_STATE_OPT_NEED_INTERACT);
	if (err != IOT_ERROR_NONE) {
		IOT_ERROR("failed handle cmd (%d): %d", IOT_STATE_PROV_CONFIRM, err);
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INTERNAL_SERVER_ERROR, err);
		err = IOT_ERROR_EASYSETUP_INTERNAL_SERVER_ERROR;
		goto out;
	}

	switch (confirm_feature)
	{
		case OVF_BIT_JUSTWORKS:
			IOT_INFO("There is no confirmation request. The check is skipped");
			IOT_ES_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_EASYSETUP_OTMTYPE_JUSTWORK, 0);
			break;
		case OVF_BIT_QR:
			IOT_INFO("The QR code confirmation is requested\n");
			IOT_ES_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_EASYSETUP_OTMTYPE_QR, 0);
			if (sn == NULL) {
				IOT_ERROR("to get invalid QR serial num\n");
				IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_QR, 0);
				err = IOT_ERROR_EASYSETUP_INVALID_QR;
				goto out;
			}

			err = iot_nv_get_serial_number(&dev_sn, &devsn_len);
			if (err != IOT_ERROR_NONE) {
				IOT_ERROR("failed to get serial num\n");
				IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_SERIAL_NOT_FOUND, err);
				err = IOT_ERROR_EASYSETUP_SERIAL_NOT_FOUND;
				goto out;
			}

			if (!strcmp(sn, dev_sn)) {
				IOT_INFO("confirm");
				IOT_ES_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_EASYSETUP_GET_OWNER_CONFIRM, 0);
			} else {
				IOT_ERROR("confirm fail");
				IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_SERIAL_NUMBER, 0);
				err = IOT_ERROR_EASYSETUP_INVALID_SERIAL_NUMBER;
				goto out;
			}
			break;
		case OVF_BIT_BUTTON:
			IOT_INFO("The button confirmation is requested");
			IOT_ES_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_EASYSETUP_OTMTYPE_BUTTON, 0);

			curr_event = iot_os_eventgroup_wait_bits(ctx->iot_events, IOT_EVENT_BIT_EASYSETUP_CONFIRM, false, ES_CONFIRM_MAX_DELAY);
			IOT_DEBUG("curr_event = 0x%x", curr_event);

			if (curr_event & IOT_EVENT_BIT_EASYSETUP_CONFIRM) {
				IOT_INFO("confirm");
				IOT_ES_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_EASYSETUP_GET_OWNER_CONFIRM, 0);
			} else {
				IOT_ERROR("confirm failed");
				IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_CONFIRM_DENIED, 0);
				iot_set_st_ecode(ctx, IOT_ST_ECODE_EE01);

				/* To report confirm failure to user, try to change iot-state timeout value shortly */
				if (iot_state_timeout_change(ctx, IOT_STATE_PROV_CONFIRM, ES_CONFIRM_FAIL_TIMEOUT) != IOT_ERROR_NONE) {
					IOT_ERROR("Can't update prov_confirm state timeout");
				}

				err = IOT_ERROR_EASYSETUP_CONFIRM_DENIED;
				goto out;
			}
			break;
		case OVF_BIT_PIN:
			IOT_INFO("The pin number confirmation is requested");
			IOT_ES_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_EASYSETUP_OTMTYPE_PIN, 0);
			return err;
		default:
			IOT_INFO("Not Supported confirmation type is requested");
			IOT_ES_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_EASYSETUP_OTMTYPE_NOT_SUPPORTED, 0);
			return err;
	}

out:
	if (dev_sn)
		free(dev_sn);
	return err;
}

STATIC_FUNCTION
iot_error_t _es_confirminfo_handler(struct iot_context *ctx, char *in_payload, char **out_payload)
{
	char *final_msg = NULL;
	JSON_H *recv = NULL;
	JSON_H *root = NULL;
	iot_error_t err = IOT_ERROR_NONE;

	if (!ctx || !in_payload) {
		IOT_ERROR("Invalid data is reported");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INTERNAL_SERVER_ERROR, 0);
		err = IOT_ERROR_EASYSETUP_INTERNAL_SERVER_ERROR;
		return err;
	}

	root = JSON_PARSE(in_payload);
	if (!root) {
		IOT_ERROR("Invalid args");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_REQUEST, 0);
		err = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto out;
	}

	if ((recv = JSON_GET_OBJECT_ITEM(root, "otmSupportFeature")) == NULL) {
		IOT_ERROR("no otmsupportfeature info");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_REQUEST, 0);
		err = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto out;
	}

	IOT_INFO("otmSupportFeature = %d", recv->valueint);
	IOT_ES_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_EASYSETUP_REPORTED_OTMTYPE, recv->valueint);

	if ((recv->valueint >= OVF_BIT_JUSTWORKS) && (recv->valueint < OVF_BIT_MAX_FEATURE)) {
		char *sn = NULL;

		if (recv->valueint == OVF_BIT_QR)
			sn = _es_json_parse_string(root, "sn");

		err = _es_confirm_check_manager(ctx, recv->valueint, sn);

		if (sn) {
			free(sn);
		}
		if (err != IOT_ERROR_NONE)
			goto out;
	} else {
		IOT_ERROR("Not supported otmsupportfeature : %d", recv->valueint);
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_CONFIRM_NOT_SUPPORT, recv->valueint);
		err = IOT_ERROR_EASYSETUP_CONFIRM_NOT_SUPPORT ;
		goto out;
	}
	JSON_DELETE(root);


	root = JSON_CREATE_OBJECT();
	if (!root) {
		IOT_ERROR("json create failed");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_JSON_CREATE_ERROR, 0);
		err = IOT_ERROR_EASYSETUP_JSON_CREATE_ERROR;
		goto out;
	}
	
	final_msg = JSON_PRINT(root);

	*out_payload = final_msg;
out:
	if (root) {
		JSON_DELETE(root);
	}
	return err;
}

STATIC_FUNCTION
iot_error_t _es_confirm_handler(struct iot_context *ctx, char *in_payload, char **out_payload)
{
	bool validation = true;
	char pin[PIN_SIZE + 1];
	char *final_msg = NULL;
	JSON_H *recv = NULL;
	JSON_H *root = NULL;
	int i;
	iot_error_t err = IOT_ERROR_NONE;

	if (!ctx || !ctx->pin) {
		IOT_ERROR("no pin from device app");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_PIN_NOT_FOUND, 0);
		err = IOT_ERROR_EASYSETUP_PIN_NOT_FOUND;
		return err;
	}

	if (ctx->curr_otm_feature != OVF_BIT_PIN) {
		IOT_ERROR("otm is not pin.");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_CMD, 0);
		err = IOT_ERROR_EASYSETUP_INVALID_CMD;
		return err;
	}

	root = JSON_PARSE(in_payload);
	if (!root) {
		IOT_ERROR("Invalid args");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_REQUEST, 0);
		err = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto out;
	}

	if ((recv = JSON_GET_OBJECT_ITEM(root, "pin")) == NULL) {
		IOT_ERROR("no pin info");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_REQUEST, 0);
		err = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto out;
	}

	if (strlen(JSON_GET_STRING_VALUE(recv)) != PIN_SIZE) {
		IOT_ERROR("pin size mistmatch");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_PIN, 0);
		err = IOT_ERROR_EASYSETUP_INVALID_PIN;
		goto out;
	}

	strncpy(pin, recv->valuestring, sizeof(pin) - 1);
	pin[PIN_SIZE] = '\0';
	IOT_INFO("pin = %s", pin);
	for (i = 0; i < PIN_SIZE; i++) {
		if (pin[i] > '9' || pin[i] < '0') {
			IOT_ERROR("invalid pin number from application");
			validation = false;
			break;
		}
	}

	if (!validation) {
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_PIN, 0);
		err = IOT_ERROR_EASYSETUP_INVALID_PIN;
		goto out;
	}

	for (i = 0; i < PIN_SIZE; i++) {
		if (ctx->pin->pin[i] != pin[i]) {
			IOT_ERROR("the reported pin number is not matched[%d]", i);
			validation = false;
			break;
		}
	}

	if (!validation) {
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_PIN_NOT_MATCHED, 0);
		err = IOT_ERROR_EASYSETUP_PIN_NOT_MATCHED;
		goto out;
	}
	JSON_DELETE(root);

	/*
	 * output payload
	 */
	root = JSON_CREATE_OBJECT();
	if (!root) {
		IOT_ERROR("json create failed");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_JSON_CREATE_ERROR, 0);
		err = IOT_ERROR_EASYSETUP_JSON_CREATE_ERROR;
		goto out;
	}
	final_msg = JSON_PRINT(root);

	*out_payload = final_msg;

out:
	if (root) {
		JSON_DELETE(root);
	}
	return err;
}

STATIC_FUNCTION
iot_error_t _es_wifiscaninfo_handler(struct iot_context *ctx, char **out_payload)
{
	char *final_msg = NULL;
	char wifi_bssid[WIFIINFO_BUFFER_SIZE] = {0, };
	JSON_H *root = NULL;
	JSON_H *array = NULL;
	JSON_H *array_obj = NULL;
	int i;
	iot_error_t err = IOT_ERROR_NONE;

	if (!ctx) {
		IOT_ERROR("invalid iot_context!!");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INTERNAL_SERVER_ERROR, 0);
		err = IOT_ERROR_EASYSETUP_INTERNAL_SERVER_ERROR;
		return err;
	}

	//optional : some chipsets don't support wifi scan mode during working AP mode
	err = iot_wifi_ctrl_request(ctx, IOT_WIFI_MODE_SCAN);
	if (err != IOT_ERROR_NONE) {
		IOT_INFO("Can't control WIFI mode scan.(%d)", err);
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_EASYSETUP_WIFI_SCAN_NOT_FOUND, err);
	}

	if (!ctx->scan_num) {
		IOT_ERROR("wifi AP isn't found!!");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_WIFI_SCAN_NOT_FOUND, ctx->scan_num);
		err = IOT_ERROR_EASYSETUP_WIFI_SCAN_NOT_FOUND;
		return err;
	}

	array = JSON_CREATE_ARRAY();
	if (!array) {
		IOT_ERROR("json_array create failed");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_JSON_CREATE_ERROR, 0);
		err = IOT_ERROR_EASYSETUP_JSON_CREATE_ERROR;
		return err;
	}

	for(i = 0; i < ctx->scan_num; i++) {
		if ((ctx->scan_result[i].authmode <  IOT_WIFI_AUTH_OPEN) ||
			(ctx->scan_result[i].authmode >= IOT_WIFI_AUTH_WPA2_ENTERPRISE)) {
			IOT_DEBUG("Unsupported authType %d, %s", ctx->scan_result[i].authmode,
								(char *)ctx->scan_result[i].ssid);
			continue;
		}
		snprintf(wifi_bssid, sizeof(wifi_bssid), "%02X:%02X:%02X:%02X:%02X:%02X",
						ctx->scan_result[i].bssid[0], ctx->scan_result[i].bssid[1],
						ctx->scan_result[i].bssid[2], ctx->scan_result[i].bssid[3],
						ctx->scan_result[i].bssid[4], ctx->scan_result[i].bssid[5]);

		array_obj = JSON_CREATE_OBJECT();
		if (!array_obj) {
			IOT_ERROR("json create failed");
			if (array) {
				JSON_DELETE(array);
			}
			IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_JSON_CREATE_ERROR, 0);
			err = IOT_ERROR_EASYSETUP_JSON_CREATE_ERROR;
			goto out;
		}
		JSON_ADD_ITEM_TO_OBJECT(array_obj, "bssid", JSON_CREATE_STRING(wifi_bssid));
		JSON_ADD_ITEM_TO_OBJECT(array_obj, "ssid", JSON_CREATE_STRING((char*)ctx->scan_result[i].ssid));
		JSON_ADD_NUMBER_TO_OBJECT(array_obj, "rssi", (double) ctx->scan_result[i].rssi);
		JSON_ADD_NUMBER_TO_OBJECT(array_obj, "frequency", (double) ctx->scan_result[i].freq);
		JSON_ADD_NUMBER_TO_OBJECT(array_obj, "authType", ctx->scan_result[i].authmode);
		JSON_ADD_ITEM_TO_ARRAY(array, array_obj);
	}

	root = JSON_CREATE_OBJECT();
	if (!root) {
		IOT_ERROR("json create failed");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_JSON_CREATE_ERROR, 0);
		err = IOT_ERROR_EASYSETUP_JSON_CREATE_ERROR;
		if (array) {
			JSON_DELETE(array);
		}
		goto out;
	}
	JSON_ADD_ITEM_TO_OBJECT(root, "wifiScanInfo", array);

	final_msg = JSON_PRINT(root);

	*out_payload = final_msg;
out:
	if (root) {
		JSON_DELETE(root);
	}
	return err;
}

STATIC_FUNCTION
iot_wifi_auth_mode_t _decide_wifi_auth_mode(const JSON_H *item, struct iot_wifi_prov_data *wifi_prov, const struct iot_context *ctx)
{
	iot_wifi_auth_mode_t auth_mode = IOT_WIFI_AUTH_WPA_WPA2_PSK;
	int i;

	if (!ctx || !wifi_prov) {
		return IOT_WIFI_AUTH_WPA_WPA2_PSK;
	}

	if (item == NULL) {
		IOT_INFO("no authType");
		for (i = 0; i < ctx->scan_num; i++) {
			if (!strcmp(wifi_prov->ssid, (char *)ctx->scan_result[i].ssid)) {
				auth_mode = ctx->scan_result[i].authmode;
				IOT_DEBUG("%s is type %d", wifi_prov->ssid, auth_mode);
				break;
			}
		}
		if (i == ctx->scan_num) {
			if (strlen(wifi_prov->password) == 0) {
				IOT_DEBUG("%s doesn't exist in scan list. So assume it as Open", wifi_prov->ssid);
				auth_mode = IOT_WIFI_AUTH_OPEN;
			} else {
				IOT_DEBUG("%s doesn't exist in scan list. So assume it as WPA", wifi_prov->ssid);
				auth_mode = IOT_WIFI_AUTH_WPA_WPA2_PSK;
			}
		}
	} else {
		for (i = 0; i < ctx->scan_num; i++) {
			if (!strcmp(wifi_prov->ssid, (char *)ctx->scan_result[i].ssid)) {
				if (item->valueint == ctx->scan_result[i].authmode) {
					auth_mode = item->valueint;
				} else {
					auth_mode = ctx->scan_result[i].authmode;
				}
				break;
			}
		}
		if (i == ctx->scan_num) {
			auth_mode = item->valueint;
		}
		IOT_DEBUG("%s is type %d", wifi_prov->ssid, auth_mode);
	}

	return auth_mode;
}

STATIC_FUNCTION
iot_error_t _es_wifi_prov_parse(struct iot_context *ctx, char *in_payload)
{
	struct iot_wifi_prov_data *wifi_prov = NULL;
	JSON_H *item = NULL;
	JSON_H *root = NULL;
	JSON_H *wifi_credential = NULL;
	iot_error_t err = IOT_ERROR_NONE;

	root = JSON_PARSE(in_payload);
	if (!root) {
		IOT_ERROR("Invalid args");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_REQUEST, 0);
		err = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto wifi_parse_out;
	}

	if ((wifi_credential = JSON_GET_OBJECT_ITEM(root, "wifiCredential")) == NULL) {
		IOT_ERROR("failed to find wifiCredential");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_REQUEST, 0);
		err = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto wifi_parse_out;
	}

	if ((wifi_prov = (struct iot_wifi_prov_data *)malloc(sizeof(struct iot_wifi_prov_data))) == NULL) {
		IOT_ERROR("failed to malloc for wifi_prov_data");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_MEM_ALLOC_ERROR, 0);
		err = IOT_ERROR_EASYSETUP_MEM_ALLOC_ERROR;
		goto wifi_parse_out;
	}

	memset(wifi_prov, 0, sizeof(struct iot_wifi_prov_data));

	if ((item = JSON_GET_OBJECT_ITEM(wifi_credential, "ssid")) == NULL) {
		IOT_ERROR("failed to find ssid");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_REQUEST, 0);
		err = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto wifi_parse_out;
	}
	strncpy(wifi_prov->ssid, JSON_GET_STRING_VALUE(item), sizeof(wifi_prov->ssid) - 1);

	// password is optional.
	if ((item = JSON_GET_OBJECT_ITEM(wifi_credential, "password")) == NULL)
		IOT_INFO("No wifi password");
	else
		strncpy(wifi_prov->password, JSON_GET_STRING_VALUE(item), sizeof(wifi_prov->password) - 1);

	if ((item = JSON_GET_OBJECT_ITEM(wifi_credential, "macAddress")) == NULL) {
		IOT_INFO("no macAddress");
	} else {
		strncpy(wifi_prov->mac_str, JSON_GET_STRING_VALUE(item), sizeof(wifi_prov->mac_str));
		err = iot_util_convert_str_mac(wifi_prov->mac_str, &wifi_prov->bssid);
		if (err) {
			IOT_ERROR("Failed to convert str to mac address (error : %d) : %s", err, wifi_prov->mac_str);
			IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_MAC, err);
			err = IOT_ERROR_EASYSETUP_INVALID_MAC;
			goto wifi_parse_out;
		}
	}

	wifi_prov->security_type =
		_decide_wifi_auth_mode(JSON_GET_OBJECT_ITEM(wifi_credential, "authType"), wifi_prov, ctx);

	err = iot_nv_set_wifi_prov_data(wifi_prov);
	if (err) {
		IOT_ERROR("failed to set the cloud prov data");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_WIFI_DATA_WRITE_FAIL, err);
		err = IOT_ERROR_EASYSETUP_WIFI_DATA_WRITE_FAIL;
		goto wifi_parse_out;
	}

	IOT_INFO("ssid: %s", wifi_prov->ssid);
	IOT_DEBUG("password: %s", wifi_prov->password);
	IOT_INFO("mac addr: %s", wifi_prov->mac_str);

wifi_parse_out:
	if (wifi_prov)
		free(wifi_prov);
	if (root)
		JSON_DELETE(root);
	return err;
}

STATIC_FUNCTION
iot_error_t _es_cloud_prov_parse(struct iot_context *ctx, char *in_payload)
{
	struct iot_cloud_prov_data *cloud_prov = NULL;
	char *full_url = NULL;
	JSON_H *root = NULL;
	iot_error_t err = IOT_ERROR_NONE;
	url_parse_t url = { .protocol = NULL, .domain = NULL, .port = 0};

	root = JSON_PARSE(in_payload);
	if (!root) {
		IOT_ERROR("Invalid payload json format");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_REQUEST, 0);
		err = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto cloud_parse_out;
	}

	if ((cloud_prov = (struct iot_cloud_prov_data *)malloc(sizeof(struct iot_cloud_prov_data))) == NULL) {
		IOT_ERROR("failed to alloc mem");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_MEM_ALLOC_ERROR, 0);
		err = IOT_ERROR_EASYSETUP_MEM_ALLOC_ERROR;
		goto cloud_parse_out;
	}

	memset(cloud_prov, 0, sizeof(struct iot_cloud_prov_data));

	if ((full_url = _es_json_parse_string(root, "brokerUrl")) == NULL) {
		IOT_ERROR("failed to find brokerUrl");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_REQUEST, 0);
		err = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto cloud_parse_out;
	}

	err = iot_util_url_parse(full_url, &url);
	if (err) {
		IOT_ERROR("failed to parse broker url");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_BROKER_URL, err);
		err = IOT_ERROR_EASYSETUP_INVALID_BROKER_URL;
		goto cloud_parse_out;
	}

	if ((cloud_prov->label = _es_json_parse_string(root, "deviceName")) == NULL) {
		IOT_INFO("No deviceName");
	}

	cloud_prov->broker_url = url.domain;
	cloud_prov->broker_port = url.port;

	err = iot_nv_set_cloud_prov_data(cloud_prov);
	if (err) {
		IOT_ERROR("failed to set the cloud prov data");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_CLOUD_DATA_WRITE_FAIL, err);
		cloud_prov->broker_port = 0;
		err = IOT_ERROR_EASYSETUP_CLOUD_DATA_WRITE_FAIL;
		goto cloud_prov_data_fail;
	}

	IOT_INFO("brokerUrl: %s:%d", cloud_prov->broker_url, cloud_prov->broker_port);
	IOT_INFO("deviceName : %s", cloud_prov->label);

cloud_prov_data_fail:
	if (cloud_prov->label) {
		iot_os_free(cloud_prov->label);
	}
cloud_parse_out:
	if (url.domain) {
		iot_os_free(url.domain);
	}
	if (url.protocol) {
		iot_os_free(url.protocol);
	}
	if (full_url) {
		iot_os_free(full_url);
	}
	if (cloud_prov) {
		iot_os_free(cloud_prov);
	}
	if (root) {
		JSON_DELETE(root);
	}
	return err;
}

STATIC_FUNCTION
iot_error_t _es_wifiprovisioninginfo_handler(struct iot_context *ctx, char *in_payload, char **out_payload)
{
	char *final_msg = NULL;
	char *recv_msg = NULL;
	JSON_H *root = NULL;
	iot_error_t err = IOT_ERROR_NONE;
	char *serial = NULL;
	size_t serial_len;

	root = JSON_PARSE(in_payload);
	if (!root) {
		IOT_ERROR("Invalid args");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INVALID_REQUEST, 0);
		err = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto out;
	}

	recv_msg = JSON_PRINT(root);

	err = _es_wifi_prov_parse(ctx, (char *)recv_msg);
	if (err) {
		IOT_ERROR("failed to parse wifi_prov");
		goto out;
	}

	err = _es_cloud_prov_parse(ctx, (char *)recv_msg);
	if (err) {
		IOT_ERROR("failed to parse cloud_prov");
		goto out;
	}

	if (ctx->lookup_id == NULL) {
		ctx->lookup_id = iot_os_malloc(IOT_REG_UUID_STR_LEN + 1);
	}

	err = iot_get_random_id_str(ctx->lookup_id,
			(IOT_REG_UUID_STR_LEN + 1));
	if (err != IOT_ERROR_NONE) {
		IOT_ERROR("failed to get new lookup_id(%d)", err);
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_LOOKUPID_GENERATE_FAIL, err);
		err = IOT_ERROR_EASYSETUP_LOOKUPID_GENERATE_FAIL;
		goto out;
	}

	IOT_DEBUG("lookupid = %s", ctx->lookup_id);

	JSON_DELETE(root);

	root = JSON_CREATE_OBJECT();
	if (!root) {
		IOT_ERROR("json create failed");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_JSON_CREATE_ERROR, 0);
		err = IOT_ERROR_EASYSETUP_JSON_CREATE_ERROR;
		goto out;
	}

	JSON_ADD_ITEM_TO_OBJECT(root, "lookupId", JSON_CREATE_STRING(ctx->lookup_id));

	err = iot_nv_get_serial_number(&serial, &serial_len);
	if (err != IOT_ERROR_NONE) {
		IOT_ERROR("Failed to get serial number (%d)", err);
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_SERIAL_NUMBER_GET_FAIL, err);
		err = IOT_ERROR_EASYSETUP_SERIAL_NUMBER_GET_FAIL;
		goto out;
	}
	JSON_ADD_ITEM_TO_OBJECT(root, "sn", JSON_CREATE_STRING(serial));

	final_msg = JSON_PRINT(root);

	*out_payload = final_msg;

	/* Now we allow D2D process reentrant and prov_data could be loaded
	 * at the init state or previous D2D, so free it first to avoid memory-leak
	 */
	iot_api_prov_data_mem_free(&ctx->prov_data);
	err = iot_nv_get_prov_data(&ctx->prov_data);
	if (err) {
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_WIFI_DATA_READ_FAIL, err);
		err = IOT_ERROR_EASYSETUP_WIFI_DATA_READ_FAIL;
		IOT_WARN("No provisining from nv");
	} else {
		IOT_INFO("provisioning success");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_EASYSETUP_PROVISIONING_SUCCESS, 0);
	}
out:
	if (recv_msg) {
		free(recv_msg);
	}
	if (root) {
		JSON_DELETE(root);
	}
	return err;
}

STATIC_FUNCTION
iot_error_t _es_setupcomplete_handler(struct iot_context *ctx, char *in_payload, char **out_payload)
{
	char *final_msg = NULL;
	JSON_H *root = NULL;
	iot_error_t err = IOT_ERROR_NONE;

	root = JSON_CREATE_OBJECT();
	if (!root) {
		IOT_ERROR("json create failed");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_JSON_CREATE_ERROR, 0);
		err = IOT_ERROR_EASYSETUP_JSON_CREATE_ERROR;
		goto out;
	}

	final_msg = JSON_PRINT(root);

	*out_payload = final_msg;
out:
	if (root) {
		JSON_DELETE(root);
	}
	return err;
}

static iot_error_t _es_log_systeminfo_handler(struct iot_context *ctx, char **out_payload)
{
	char *output_ptr = NULL;
	JSON_H *root = NULL;
	iot_error_t err = IOT_ERROR_NONE;

	root = JSON_CREATE_OBJECT();
	if (!root) {
		IOT_ERROR("json create failed");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_JSON_CREATE_ERROR, 0);
		err = IOT_ERROR_EASYSETUP_JSON_CREATE_ERROR;
		goto out;
	}

	JSON_ADD_ITEM_TO_OBJECT(root, "version", JSON_CREATE_STRING("1.0"));

	output_ptr = JSON_PRINT(root);

	*out_payload = output_ptr;

out:
	if (root)
		JSON_DELETE(root);
	return err;
}

static iot_error_t _es_log_create_dump_handler(struct iot_context *ctx, char *in_payload, char **out_payload)
{
	char *output_ptr = NULL;
	JSON_H *root = NULL;
	iot_error_t err = IOT_ERROR_NONE;

	root = JSON_CREATE_OBJECT();
	if (!root) {
		IOT_ERROR("json create failed");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_JSON_CREATE_ERROR, 0);
		err = IOT_ERROR_EASYSETUP_JSON_CREATE_ERROR;
		goto out;
	}

	output_ptr = JSON_PRINT(root);

	*out_payload = output_ptr;

out:
	if (root)
		JSON_DELETE(root);
	return err;
}

static iot_error_t _es_log_get_dump_handler(struct iot_context *ctx, char **out_payload)
{
	char *log_dump = NULL;
	char *output_ptr = NULL;
	JSON_H *item = NULL;
	JSON_H *root = NULL;
	iot_error_t err = IOT_ERROR_NONE;
#if !defined(CONFIG_STDK_IOT_CORE_EASYSETUP_LOG_SUPPORT_NO_USE_LOGFILE)
	char *sumo_dump = NULL;
	size_t log_dump_size = 2048;
	size_t sumo_dump_size = 200;
	size_t written_size = 0;
#endif

	item = JSON_CREATE_OBJECT();
	if (!item) {
		IOT_ERROR("json create failed");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_JSON_CREATE_ERROR, 0);
		err = IOT_ERROR_EASYSETUP_JSON_CREATE_ERROR;
		goto out;
	}

#if defined(CONFIG_STDK_IOT_CORE_EASYSETUP_LOG_SUPPORT_NO_USE_LOGFILE)
	log_dump = iot_debug_get_log();
#else
	err = st_create_log_dump((IOT_CTX *)ctx, &log_dump, log_dump_size, &written_size, IOT_DUMP_MODE_NEED_BASE64 | IOT_DUMP_MODE_NEED_DUMP_STATE);
	if (err < 0) {
		IOT_ERROR("Fail to get log dump!\n");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_CREATE_LOGDUMP_FAIL, 0);
		goto out;
	}
	err = st_create_log_dump((IOT_CTX *)ctx, &sumo_dump, sumo_dump_size, &written_size, IOT_DUMP_MODE_NEED_BASE64);
	if (err < 0) {
		IOT_ERROR("Fail to get sumo dump!\n");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_CREATE_SUMODUMP_FAIL, 0);
		goto out;
	}
#endif

	JSON_ADD_NUMBER_TO_OBJECT(item, "code", 1);
	JSON_ADD_ITEM_TO_OBJECT(item, "message", JSON_CREATE_STRING(log_dump));
#if !defined(CONFIG_STDK_IOT_CORE_EASYSETUP_LOG_SUPPORT_NO_USE_LOGFILE)
	JSON_ADD_ITEM_TO_OBJECT(item, "sumomessage", JSON_CREATE_STRING(sumo_dump));
#endif

	root = JSON_CREATE_OBJECT();
	if (!root) {
		IOT_ERROR("json create failed");
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_JSON_CREATE_ERROR, 0);
		err = IOT_ERROR_EASYSETUP_MEM_ALLOC_ERROR;
		if (item) {
			JSON_DELETE(item);
		}
		goto out;
	}

	JSON_ADD_ITEM_TO_OBJECT(root, "error", item);

	output_ptr = JSON_PRINT(root);

	*out_payload = output_ptr;
out:
#if !defined(CONFIG_STDK_IOT_CORE_EASYSETUP_LOG_SUPPORT_NO_USE_LOGFILE)
		if (log_dump)
			free(log_dump);
		if (sumo_dump)
			free(sumo_dump);
#endif
	if (root)
		JSON_DELETE(root);
	return err;
}

iot_error_t iot_easysetup_request_handler(struct iot_context *ctx, struct iot_easysetup_payload request)
{
	iot_error_t err = IOT_ERROR_NONE;
	struct iot_easysetup_payload response;

	if (!ctx)
		return IOT_ERROR_EASYSETUP_INTERNAL_SERVER_ERROR;

	response.step = request.step;
	response.payload = NULL;

	switch (request.step) {
	case IOT_EASYSETUP_STEP_DEVICEINFO:
		err = _es_deviceinfo_handler(ctx, &response.payload);
		break;
	case IOT_EASYSETUP_STEP_WIFISCANINFO:
		err = _es_wifiscaninfo_handler(ctx, &response.payload);
		break;
	case IOT_EASYSETUP_STEP_KEYINFO:
		err = _es_keyinfo_handler(ctx, request.payload, &response.payload);
		break;
	case IOT_EASYSETUP_STEP_CONFIRMINFO:
		err = _es_confirminfo_handler(ctx, request.payload, &response.payload);
		break;
	case IOT_EASYSETUP_STEP_CONFIRM:
		err = _es_confirm_handler(ctx, request.payload, &response.payload);
		break;
	case IOT_EASYSETUP_STEP_WIFIPROVIONINGINFO:
		err = _es_wifiprovisioninginfo_handler(ctx, request.payload, &response.payload);
		break;
	case IOT_EASYSETUP_STEP_SETUPCOMPLETE:
		err = _es_setupcomplete_handler(ctx, request.payload, &response.payload);
		break;
	case IOT_EASYSETUP_STEP_LOG_SYSTEMINFO:
		err = _es_log_systeminfo_handler(ctx, &response.payload);
		break;
	case IOT_EASYSETUP_STEP_LOG_CREATE_DUMP:
		err = _es_log_create_dump_handler(ctx, request.payload, &response.payload);
	break;
	case IOT_EASYSETUP_STEP_LOG_GET_DUMP:
		err = _es_log_get_dump_handler(ctx, &response.payload);
		break;
	default:
		err = IOT_ERROR_EASYSETUP_INTERNAL_SERVER_ERROR;
		break;
	}
	if (err) {
		IOT_ERROR("failed to handle step %d (%d)", request.step, err);
	}

	response.err = err;

	if (ctx->easysetup_resp_queue) {
		err = iot_util_queue_send(ctx->easysetup_resp_queue, &response);
		if (err != IOT_ERROR_NONE) {
			IOT_ERROR("Cannot put the response into easysetup_resp_queue");
			err = IOT_ERROR_EASYSETUP_QUEUE_SEND_ERROR;
		} else {
			iot_os_eventgroup_set_bits(ctx->iot_events,
				IOT_EVENT_BIT_EASYSETUP_RESP);
			err = IOT_ERROR_NONE;
		}
	} else {
		IOT_ERROR("easysetup_resp_queue is deleted");
		err = IOT_ERROR_EASYSETUP_INTERNAL_SERVER_ERROR;
	}

	return err;
}
