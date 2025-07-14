/* ***************************************************************************
 *
 * Copyright (c) 2019-2022 Samsung Electronics All Rights Reserved.
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
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "FreeRTOS.h"
#include "event_groups.h"
#include "wifi.h"
#include <wifi_v2.h>
#include <generated/lmac_wifi_adapter.h>
#include "wifi_types.h"
#include "bk_wifi_types.h"
#include <modules/wifi.h>
#include <components/netif.h>
#include <components/event.h>
#include "iot_debug.h"
#include "iot_bsp_wifi.h"
#include "iot_os_util.h"
#include "iot_util.h"
#include "lwip/apps/sntp.h"
#include "lwip/inet.h"

#define TAG "BK_WiFi"
#define BK_STR_NULL_IP "0.0.0.0"

const int WIFI_STA_CONNECT_BIT = 1 << 0;
const int WIFI_STA_DISCONNECT_BIT = 1 << 1;
const int WIFI_SCAN_DONE_BIT = 1 << 2;

const int WIFI_EVENT_BIT_ALL = WIFI_STA_CONNECT_BIT | WIFI_STA_DISCONNECT_BIT | WIFI_SCAN_DONE_BIT;

static int WIFI_INITIALIZED = false;
static EventGroupHandle_t wifi_event_group;
static iot_bsp_wifi_event_cb_t wifi_event_cb;
static bool s_wifi_connect_timeout = false;
static iot_error_t s_latest_disconnect_reason;
static bool gotIP = false;

static bk_err_t bk_wifi_event_post_to_user(void *arg, event_module_t event_module, int event_id, void *event_data)
{
	wifi_event_sta_disconnected_t *sta_disconnected;
	wifi_event_sta_connected_t *sta_connected;
	wifi_event_ap_disconnected_t *ap_disconnected;
	wifi_event_ap_connected_t *ap_connected;

	switch (event_id) {
	case EVENT_WIFI_SCAN_DONE:
		IOT_INFO("Complete scanning");
		xEventGroupSetBits(wifi_event_group, WIFI_SCAN_DONE_BIT);
		break;
	case EVENT_WIFI_STA_CONNECTED:
		sta_connected = (wifi_event_sta_connected_t *)event_data;
		IOT_INFO("STA connected to %s", sta_connected->ssid);
		break;
	case EVENT_WIFI_STA_DISCONNECTED:
		gotIP = false;
		sta_disconnected = (wifi_event_sta_disconnected_t *)event_data;
		IOT_INFO("STA disconnected, reason(%d)",sta_disconnected->disconnect_reason);
		xEventGroupSetBits(wifi_event_group, WIFI_STA_DISCONNECT_BIT);
		xEventGroupClearBits(wifi_event_group, WIFI_STA_CONNECT_BIT);
		switch (sta_disconnected->disconnect_reason)
		{
			case WIFI_REASON_NO_AP_FOUND:
				s_latest_disconnect_reason = IOT_ERROR_CONN_STA_AP_NOT_FOUND;
				break;
			case WIFI_REASON_IEEE_802_1X_AUTH_FAILED:
				s_latest_disconnect_reason = IOT_ERROR_CONN_STA_AUTH_FAIL;
				break;
			case WIFI_REASON_STA_REQ_ASSOC_WITHOUT_AUTH:
				s_latest_disconnect_reason = IOT_ERROR_CONN_STA_ASSOC_FAIL;
				break;
			case WIFI_REASON_DISCONNECT_BY_APP:
				s_latest_disconnect_reason = IOT_ERROR_CONN_STA_CONN_FAIL;
				break;
		}
		break;
	case EVENT_WIFI_AP_CONNECTED:
		ap_connected = (wifi_event_ap_connected_t *)event_data;
		BK_LOGI(TAG, BK_MAC_FORMAT " connected to AP\n", BK_MAC_STR(ap_connected->mac));
		if (wifi_event_cb) {
			IOT_DEBUG("0x%p called", wifi_event_cb);
			(*wifi_event_cb)(IOT_WIFI_EVENT_SOFTAP_STA_JOIN, IOT_ERROR_NONE);
		}
		break;
	case EVENT_WIFI_AP_DISCONNECTED:
		ap_disconnected = (wifi_event_ap_disconnected_t *)event_data;
		IOT_INFO(BK_MAC_FORMAT " disconnected from AP\n", BK_MAC_STR(ap_disconnected->mac));
		break;
	default:
		BK_LOGI(TAG, "rx event <%d %d>\n", event_module, event_id);
		break;
	}
	return BK_OK;
}

static bk_err_t bk_ip_event_post_to_user(void *arg, event_module_t event_module,
					   int event_id, void *event_data)
{
	netif_event_got_ip4_t *got_ip;

	switch (event_id) {
	case EVENT_NETIF_GOT_IP4:
		got_ip = (netif_event_got_ip4_t *)event_data;
		s_wifi_connect_timeout = false;
		gotIP = true;
		xEventGroupSetBits(wifi_event_group, WIFI_STA_CONNECT_BIT);
		xEventGroupClearBits(wifi_event_group, WIFI_STA_DISCONNECT_BIT);
		BK_LOGI(TAG, "%s got ip\n", got_ip->netif_if == NETIF_IF_STA ? "STA" : "unknown netif");
		break;
	default:
		BK_LOGI(TAG, "rx event <%d %d>\n", event_module, event_id);
		break;
	}

	return BK_OK;
}

static bk_err_t bk_event_handler_init(void)
{
	bk_err_t ret = BK_OK;
	ret = bk_event_register_cb(EVENT_MOD_WIFI, EVENT_ID_ALL, bk_wifi_event_post_to_user, NULL);
	if (ret != BK_OK) {
		IOT_ERROR("Failed to register bk wifi event callback");
		return ret;
	}
	ret = bk_event_register_cb(EVENT_MOD_NETIF, EVENT_ID_ALL, bk_ip_event_post_to_user, NULL);
	if (ret != BK_OK) {
		IOT_ERROR("Failed to register bk ip event callback");
		return ret;
	}
	return ret;
}

iot_error_t iot_bsp_wifi_init()
{
	bk_err_t bk_ret;
	EventBits_t uxBits = 0;
	IOT_INFO("[bk7236] iot_bsp_wifi_init");
	
	if (WIFI_INITIALIZED)
		return IOT_ERROR_NONE;
	wifi_event_group = xEventGroupCreate();
	bk_ret = bk_event_handler_init();
	if (bk_ret != BK_OK) {
		IOT_ERROR("bk_event_handler_init failed err=[%d]", bk_ret);
		IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_BSP_WIFI_INIT_FAIL, bk_ret, __LINE__);
		return IOT_ERROR_INIT_FAIL;
	}

	WIFI_INITIALIZED = true;
	IOT_INFO("[bk7236] iot_bsp_wifi_init done");
	IOT_DUMP(IOT_DEBUG_LEVEL_DEBUG, IOT_DUMP_BSP_WIFI_INIT_SUCCESS, 0, 0);

	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_wifi_set_mode(iot_wifi_conf *conf)
{
	bk_err_t bk_ret;
	int str_len = 0;
	EventBits_t uxBits = 0;

	IOT_INFO("iot_bsp_wifi_set_mode = %d", conf->mode);
	IOT_DUMP(IOT_DEBUG_LEVEL_DEBUG, IOT_DUMP_BSP_WIFI_SETMODE, conf->mode, 0);

	switch (conf->mode)
	{
	case IOT_WIFI_MODE_OFF:
		if (wifi_sta_is_started()) {
			bk_ret = bk_wifi_sta_stop();
			if (bk_ret != BK_OK) {
				IOT_ERROR("bk_wifi_sta_stop failed err=[%d]", bk_ret);
				IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_BSP_WIFI_SETMODE_FAIL, conf->mode, bk_ret);
				return IOT_ERROR_CONN_OPERATE_FAIL;
			}
		}
		if (wifi_ap_is_started()) {
			bk_ret = bk_wifi_ap_stop();
			if (bk_ret != BK_OK) {
				IOT_ERROR("bk_wifi_ap_stop failed err=[%d]", bk_ret);
				IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_BSP_WIFI_SETMODE_FAIL, conf->mode, bk_ret);
				return IOT_ERROR_CONN_OPERATE_FAIL;
			}
		}
		break;
	case IOT_WIFI_MODE_SCAN:
		/* Handles scan request when device connecting to AP has timed out. Waits for
		 * disconnect or connect event before start scan to prevent scan rejection.
		 */
		if (s_wifi_connect_timeout == true) {
			xEventGroupClearBits(wifi_event_group, WIFI_STA_CONNECT_BIT | WIFI_STA_DISCONNECT_BIT);

			uxBits = xEventGroupWaitBits(wifi_event_group,
				WIFI_STA_DISCONNECT_BIT | WIFI_STA_CONNECT_BIT,
				true, false, IOT_WIFI_CMD_TIMEOUT);

			if (uxBits & (WIFI_STA_DISCONNECT_BIT | WIFI_STA_CONNECT_BIT)) {
				IOT_INFO("Ready for wifi scan");
			} else {
				IOT_ERROR("Device is busy connecting to AP");
				IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_BSP_WIFI_TIMEOUT, mode, __LINE__);
				return IOT_ERROR_CONN_OPERATE_FAIL;
			}
		}
		break;
	case IOT_WIFI_MODE_STATION:
		if (wifi_ap_is_started()) {
			bk_ret = bk_wifi_ap_stop();
			if (bk_ret != BK_OK) {
				IOT_ERROR("bk_wifi_ap_stop failed err=[%d]", bk_ret);
				IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_BSP_WIFI_SETMODE_FAIL, conf->mode, bk_ret);
				return IOT_ERROR_CONN_OPERATE_FAIL;
			}
		}
		wifi_sta_config_t sta_config = {0};
		memcpy(sta_config.ssid, conf->ssid, strlen(conf->ssid));
		memcpy(sta_config.password, conf->pass, strlen(conf->pass));
		memcpy(sta_config.bssid, conf->bssid, sizeof(conf->bssid));

		BK_LOG_ON_ERR(bk_wifi_sta_set_config(&sta_config));
		BK_LOG_ON_ERR(bk_wifi_sta_start());

		IOT_INFO("connect to ap SSID:%s", sta_config.ssid);

		uxBits = xEventGroupWaitBits(wifi_event_group, WIFI_STA_CONNECT_BIT,
									 true, false, IOT_WIFI_CMD_TIMEOUT);

		if((uxBits & WIFI_STA_CONNECT_BIT)) {
			IOT_INFO("AP Connected");
			s_latest_disconnect_reason = IOT_ERROR_NONE;
			IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_BSP_WIFI_CONNECT_SUCCESS, 0, 0);
		}
		else {
			IOT_ERROR("WIFI_STA_CONNECT_BIT event Timeout %d", s_latest_disconnect_reason);
			IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_BSP_WIFI_CONNECT_FAIL, IOT_WIFI_CMD_TIMEOUT,
				s_latest_disconnect_reason);

			s_wifi_connect_timeout = true;
			return IOT_ERROR_CONN_OPERATE_FAIL;
		}
		break;
	case IOT_WIFI_MODE_SOFTAP:
		str_len = strlen(conf->ssid);
		wifi_ap_config_t ap_config = {0};
		netif_ip4_config_t ip4_config = {0};
		strncpy(ip4_config.ip, WLAN_DEFAULT_IP, NETIF_IP4_STR_LEN);
		strncpy(ip4_config.mask, WLAN_DEFAULT_MASK, NETIF_IP4_STR_LEN);
		strncpy(ip4_config.gateway, WLAN_DEFAULT_GW, NETIF_IP4_STR_LEN);
		strncpy(ip4_config.dns, WLAN_DEFAULT_GW, NETIF_IP4_STR_LEN);
		BK_RETURN_ON_ERR(bk_netif_set_ip4_config(NETIF_IF_AP, &ip4_config));
		memcpy(ap_config.ssid, conf->ssid, (str_len > IOT_WIFI_MAX_SSID_LEN) ? IOT_WIFI_MAX_SSID_LEN : str_len);

		str_len =  strlen(conf->pass);
		memcpy(ap_config.password, conf->pass, (str_len > IOT_WIFI_MAX_PASS_LEN) ? IOT_WIFI_MAX_PASS_LEN : str_len);

		ap_config.acs = 0;
		ap_config.channel = IOT_SOFT_AP_CHANNEL;
		ap_config.max_con = 1;
		ap_config.hidden = 0;

		if(strlen(conf->pass) == 0){
			ap_config.security = WIFI_SECURITY_NONE;
		}
		else{
			ap_config.security = WIFI_SECURITY_TYPE_WAPI_PSK;
		}

		BK_LOG_ON_ERR(bk_wifi_ap_set_config(&ap_config));
		BK_LOG_ON_ERR(bk_wifi_ap_start());

		IOT_DEBUG("wifi_init_softap finished.SSID:%s password:%s",
				ap_config.ssid, ap_config.password);

		if (wifi_ap_is_started()) {
			IOT_INFO("AP Mode Started");
			xEventGroupClearBits(wifi_event_group, WIFI_EVENT_BIT_ALL);
		}
		else
		{
			IOT_ERROR("Failed to start AP Mode");
			IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_BSP_WIFI_ERROR, conf->mode, __LINE__);
			return IOT_ERROR_CONN_OPERATE_FAIL;
		}
		break;
	default:
		IOT_ERROR("bk7236 cannot support this mode = %d", conf->mode);
		IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_BSP_WIFI_ERROR, conf->mode, __LINE__);
		return IOT_ERROR_CONN_OPERATE_FAIL;
	}
	return IOT_ERROR_NONE;
}

static iot_wifi_auth_mode_t bk_transfer_authmode(wifi_security_t authmod)
{
	iot_wifi_auth_mode_bits_t iot_auth;
	switch (authmod)
	{
	case WIFI_SECURITY_NONE:
		iot_auth = IOT_WIFI_AUTH_OPEN;
		break;
	case WIFI_SECURITY_WEP:
		iot_auth = IOT_WIFI_AUTH_WEP;
		break;
	case WIFI_SECURITY_WPA_TKIP:
	case WIFI_SECURITY_WPA_AES:
		iot_auth = IOT_WIFI_AUTH_WPA_PSK;
		break;
	case WIFI_SECURITY_WPA_MIXED:
	case WIFI_SECURITY_WPA2_MIXED:
		iot_auth = IOT_WIFI_AUTH_WPA_WPA2_PSK;
		break;
	case WIFI_SECURITY_WPA2_TKIP:
	case WIFI_SECURITY_WPA2_AES:
		iot_auth = IOT_WIFI_AUTH_WPA2_PSK;
		break;
	case WIFI_SECURITY_WPA3_SAE:
		iot_auth = IOT_WIFI_AUTH_WPA3_PERSONAL;
		break;
	case WIFI_SECURITY_WPA3_WPA2_MIXED:
		iot_auth = IOT_WIFI_AUTH_WPA3_PERSONAL;
		break;
	case WIFI_SECURITY_EAP:
		iot_auth = IOT_WIFI_AUTH_WPA2_ENTERPRISE;
		break;
	
	default:
		iot_auth = IOT_WIFI_AUTH_UNKNOWN;
		break;
	}
	return iot_auth;
}

uint16_t iot_bsp_wifi_get_scan_result(iot_wifi_scan_result_t *scan_result)
{
	uint16_t ap_num = 0;
	ScanResult_adv result;
	wifi_scan_result_t bk_scan_result = {0};
	bk_err_t ret;
	EventBits_t uxBits = 0;

	memset(&result, 0x0, sizeof(result));

	bk_wifi_scan_start(NULL);
	uxBits = xEventGroupWaitBits(wifi_event_group, WIFI_SCAN_DONE_BIT,
								 true, false, IOT_WIFI_CMD_TIMEOUT);
	if (!(uxBits & WIFI_SCAN_DONE_BIT))
	{
		IOT_ERROR("Scan timeout");
		return ap_num;
	}

	ret = bk_wifi_scan_get_result(&bk_scan_result);
	if (ret != BK_OK) {
		IOT_ERROR("Failed to get scan result");
		return ap_num;
	}
	xEventGroupClearBits(wifi_event_group, WIFI_SCAN_DONE_BIT);
	ap_num = (bk_scan_result.ap_num > IOT_WIFI_MAX_SCAN_RESULT) ? IOT_WIFI_MAX_SCAN_RESULT : bk_scan_result.ap_num;
	/*need to initialize the scan buffer before updating*/
	memset(scan_result, 0x0, (IOT_WIFI_MAX_SCAN_RESULT * sizeof(iot_wifi_scan_result_t)));

	for (int i= 0; i < ap_num; i++) {
		iot_wifi_auth_mode_t conv_auth_mode;
		memcpy(scan_result[i].ssid, bk_scan_result.aps[i].ssid, strlen(bk_scan_result.aps[i].ssid));
		memcpy(scan_result[i].bssid, bk_scan_result.aps[i].bssid, sizeof(bk_scan_result.aps[i].bssid));
		scan_result[i].rssi = bk_scan_result.aps[i].rssi;
		scan_result[i].freq = iot_util_convert_channel_freq(bk_scan_result.aps[i].channel);
		conv_auth_mode = bk_transfer_authmode(bk_scan_result.aps[i].security);
		scan_result[i].authmode = conv_auth_mode;
		IOT_DEBUG("scan result ssid=%s, mac=%02X:%02X:%02X:%02X:%02X:%02X, rssi=%d, freq=%d, authmode=%d chan=%d",
							scan_result[i].ssid,
							scan_result[i].bssid[0], scan_result[i].bssid[1], scan_result[i].bssid[2],
							scan_result[i].bssid[3], scan_result[i].bssid[4], scan_result[i].bssid[5], scan_result[i].rssi,
							scan_result[i].freq, scan_result[i].authmode, bk_scan_result.aps[i].channel);
	}

	return ap_num;
}

iot_error_t iot_bsp_wifi_get_mac(struct iot_mac *wifi_mac)
{
	bk_err_t bk_ret;
	bk_ret = bk_wifi_sta_get_mac((uint8_t*)wifi_mac->addr);
	if (bk_ret != BK_OK)
	{
		IOT_ERROR("failed to read wifi mac address : %d", bk_ret);
		IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_BSP_WIFI_ERROR, 0, __LINE__);
		return IOT_ERROR_CONN_OPERATE_FAIL;
	}

	return IOT_ERROR_NONE;
}

iot_wifi_freq_t iot_bsp_wifi_get_freq(void)
{
	return IOT_WIFI_FREQ_2_4G_ONLY;
}

iot_error_t iot_bsp_wifi_register_event_cb(iot_bsp_wifi_event_cb_t cb)
{
	if (cb == NULL)
	{
		return IOT_ERROR_INVALID_ARGS;
	}

	wifi_event_cb = cb;
	return IOT_ERROR_NONE;
}

void iot_bsp_wifi_clear_event_cb(void)
{
	wifi_event_cb = NULL;
}

iot_wifi_auth_mode_bits_t iot_bsp_wifi_get_auth_mode(void)
{
	iot_wifi_auth_mode_bits_t supported_mode_bits = IOT_WIFI_AUTH_MODE_BIT_ALL;
	supported_mode_bits ^= IOT_WIFI_AUTH_MODE_BIT(IOT_WIFI_AUTH_WPA2_ENTERPRISE);

	return supported_mode_bits;
}

bool iot_bsp_wifi_is_dhcp_success()
{
	return gotIP ? true : false;
}

iot_error_t iot_bsp_wifi_get_status(void)
{
    return s_latest_disconnect_reason;
}
