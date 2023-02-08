/* ***************************************************************************
 *
 * Copyright 2020-2021 Samsung Electronics All Rights Reserved.
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

#include "iot_bsp_wifi.h"
#include "iot_debug.h"
#include "mico.h"
#include "iot_os_util.h"
#include "mico_socket.h"


#define DHCP_SERVER_IP		"192.168.4.1"

const int WIFI_STA_START_BIT        = 0x0001;
const int WIFI_STA_CONNECT_BIT      = 0x0002;
const int WIFI_STA_DISCONNECT_BIT   = 0x0004;
const int WIFI_STA_SCAN_BIT         = 0x0008;
const int WIFI_DNS_FOUND_BIT        = 0x0010;
const int WIFI_TIME_SET_BIT         = 0x0020;

const int WIFI_EVENT_BIT_ALL = 0x01 | 0x02 | 0x04 | 0x08 | 0x10;

static int WIFI_INITIALIZED = false;
static iot_os_eventgroup *wifi_event_group;

struct bsp_scan_result_s {
	iot_wifi_scan_result_t *buff;
	uint16_t                num;
};
static struct bsp_scan_result_s g_scan_result;

static void _time_synced_cb(void)
{
	IOT_INFO("time is updated to system.");
	iot_os_eventgroup_set_bits(wifi_event_group, WIFI_TIME_SET_BIT);
}

static void _set_sntp_server(int index, const char* server)
{
	struct hostent* host;

	host = gethostbyname(server);
	if (host) {
		IOT_INFO("Find ip %0x for server %s", ((struct in_addr *)host->h_addr)->s_addr, server);
		sntp_set_server_ip_address(index, *((struct in_addr *)host->h_addr));
	}
}

static void _obtain_time(void)
{
	int index = 0;
	unsigned int ux_bits = 0;
	time_t now;
	struct tm *timeinfo;

	_set_sntp_server(index++, "time1.google.com");
	_set_sntp_server(index, "pool.ntp.org");

	sntp_start_auto_time_sync(1000, _time_synced_cb);
	ux_bits = iot_os_eventgroup_wait_bits(wifi_event_group, WIFI_TIME_SET_BIT, true, 4 * IOT_WIFI_CMD_TIMEOUT);
	if ((ux_bits & WIFI_TIME_SET_BIT) == 0) {
		IOT_ERROR("Can't sync time from sntp.");
		return;
	}

	sntp_stop_auto_time_sync();
	time(&now);
	timeinfo = localtime(&now);
	if (timeinfo) {
		IOT_INFO("after sync, time is %d-%d-%d %d-%d",
				(1900 + timeinfo->tm_year), (timeinfo->tm_mon + 1),
				timeinfo->tm_mday, timeinfo->tm_hour, timeinfo->tm_min);
	} else {
		IOT_ERROR("failed to get localtime!");
	}
}

iot_error_t iot_bsp_wifi_init(void)
{
	OSStatus err = kNoErr;

	if(WIFI_INITIALIZED)
		return IOT_ERROR_NONE;

	wifi_event_group = iot_os_eventgroup_create();

	MicoInit();

	WIFI_INITIALIZED = true;
	IOT_INFO("[emw3080] iot_bsp_wifi_init done");
	return IOT_ERROR_NONE;
}

static iot_error_t _iot_wifi_set_softap(iot_wifi_conf *conf)
{
	OSStatus err = kNoErr;
	network_InitTypeDef_st net_config;

	if ((strlen(conf->ssid) >= sizeof(net_config.wifi_ssid)) || (strlen(conf->pass) >= sizeof(net_config.wifi_key))) {
		IOT_ERROR("too long ssid or password to set driver");
		return IOT_ERROR_CONN_OPERATE_FAIL;
	}

	memset(&net_config, 0x0, sizeof(network_InitTypeDef_st));

	strcpy((char*)net_config.wifi_ssid, conf->ssid);
	strcpy((char*)net_config.wifi_key, conf->pass);
	net_config.wifi_mode = Soft_AP;
	net_config.dhcpMode = DHCP_Server;
	net_config.wifi_retry_interval = 100;
	strcpy((char*)net_config.local_ip_addr, DHCP_SERVER_IP);
	strcpy((char*)net_config.net_mask, "255.255.255.0");
	strcpy((char*)net_config.dnsServer_ip_addr, DHCP_SERVER_IP);

	IOT_INFO("ssid:%s  key:%s", net_config.wifi_ssid, net_config.wifi_key);
	err = micoWlanStart(&net_config);
	IOT_ERROR_CHECK(err != kNoErr, IOT_ERROR_CONN_OPERATE_FAIL, "set softap failed, err %d", err);

	return IOT_ERROR_NONE;
}

static void _connect_failed_handler(OSStatus err, void* inContext)
{
	IOT_INFO("join Wlan failed Err: %d", err);
}

static void _wifi_status_handler(WiFiEvent event,  void* inContext)
{
	switch (event) {
		case NOTIFY_STATION_UP:
			IOT_INFO("Station up");
			iot_os_eventgroup_set_bits(wifi_event_group, WIFI_STA_START_BIT);
			break;
		case NOTIFY_STATION_DOWN:
			IOT_INFO("Station down");
			break;
		default:
			break;
	}
}

static void _wifi_get_ip_handler(IPStatusTypedef *pnet, void* arg)
{
	IOT_INFO("DHCP got ip. %s", pnet->ip);
	iot_os_eventgroup_set_bits(wifi_event_group, WIFI_STA_CONNECT_BIT);
}

static iot_error_t _iot_wifi_set_station(iot_wifi_conf *conf)
{
	OSStatus err = kNoErr;
	network_InitTypeDef_st net_config;

	if ((strlen(conf->ssid) >= sizeof(net_config.wifi_ssid)) || (strlen(conf->pass) >= sizeof(net_config.wifi_key))) {
		IOT_ERROR("too long ssid or password to set driver");
		return IOT_ERROR_CONN_OPERATE_FAIL;
	}

	/* Register user function when wlan connection status is changed */
	err = mico_system_notify_register( mico_notify_WIFI_STATUS_CHANGED, (void *)_wifi_status_handler, NULL );
	IOT_ERROR_CHECK(err != kNoErr, IOT_ERROR_CONN_OPERATE_FAIL,"register wifi status fail");

	/* Register user function when wlan connection is failed in one attempt */
	err = mico_system_notify_register( mico_notify_WIFI_CONNECT_FAILED, (void *)_connect_failed_handler, NULL );
	IOT_ERROR_CHECK(err != kNoErr, IOT_ERROR_CONN_OPERATE_FAIL,"register wifi connect fail");

	/* Register user function when DHCP get ip from server */
	err = mico_system_notify_register( mico_notify_DHCP_COMPLETED, (void *)_wifi_get_ip_handler, NULL );
	IOT_ERROR_CHECK(err != kNoErr, IOT_ERROR_CONN_OPERATE_FAIL,"register wifi got ip fail");

	memset(&net_config, 0x0, sizeof(network_InitTypeDef_st));

	strcpy((char*)net_config.wifi_ssid, conf->ssid);
	strcpy((char*)net_config.wifi_key, conf->pass);

	net_config.wifi_mode = Station;
	net_config.dhcpMode = DHCP_Client;
	net_config.wifi_retry_interval = 100;

	/* Connect Now! , micoWlanStart return immediately in station mode*/
	IOT_INFO("connecting to %s...", net_config.wifi_ssid);
	err = micoWlanStart(&net_config);
	IOT_ERROR_CHECK(err != kNoErr, IOT_ERROR_CONN_CONNECT_FAIL,"set station failed, err %d", err);

	return IOT_ERROR_NONE;
}

static iot_error_t _iot_wifi_set_scan(void)
{
	IOT_INFO("currently we do nothing for set_scan.");
	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_wifi_set_mode(iot_wifi_conf *conf)
{
	time_t now;
	struct tm *timeinfo;
	unsigned int ux_bits = 0;
	iot_error_t ret = IOT_ERROR_NONE;

	IOT_ERROR_CHECK(conf == NULL, IOT_ERROR_INVALID_ARGS, "param null");
	IOT_INFO("iot_bsp_wifi_set_mode = %d", conf->mode);

	switch(conf->mode) {
	case IOT_WIFI_MODE_OFF:
		micoWlanSuspend();

		break;

	case IOT_WIFI_MODE_SCAN:
		_iot_wifi_set_scan();

		break;

	case IOT_WIFI_MODE_STATION:
		ret = _iot_wifi_set_station(conf);
		if (ret != IOT_ERROR_NONE) {
			return ret;
		}

		ux_bits = iot_os_eventgroup_wait_bits(wifi_event_group, WIFI_STA_CONNECT_BIT, true, 2 * IOT_WIFI_CMD_TIMEOUT);
		if ((ux_bits & WIFI_STA_CONNECT_BIT)) {
			IOT_INFO("AP Connected");
		} else {
			IOT_ERROR("WIFI_STA_CONNECT_BIT event Timeout");
			return IOT_ERROR_TIMEOUT;
		}

		time(&now);
		timeinfo = localtime(&now);

		if (timeinfo && timeinfo->tm_year < (2016 - 1900)) {
			IOT_INFO("Time is not set yet. Connecting to WiFi and getting time over NTP.");
			_obtain_time();
		}

		break;

	case IOT_WIFI_MODE_SOFTAP:
		ret = _iot_wifi_set_softap(conf);
		if(ret == IOT_ERROR_NONE) {
			IOT_INFO("AP Mode Started");
		}

		break;

	default:
		IOT_ERROR("bsp cannot support this mode = %d", conf->mode);
		break;
	}

	return ret;
}

static void _ap_list_callback(ScanResult *ap_list, void *arg)
{
	int i = 0;

	if (!ap_list || !g_scan_result.buff) {
		IOT_ERROR("ap_list 0x%x, or Scan buffer has been cleared.", ap_list);
		return;
	}

	IOT_INFO("Got %d AP", ap_list->ApNum);
	for (i = 0; i < ap_list->ApNum; i++) {
		if (i >= IOT_WIFI_MAX_SCAN_RESULT)
			break;

		IOT_INFO("AP %d: Name = %s  | Strength=%ddbm", i, ap_list->ApList[i].ssid, ap_list->ApList[i].rssi);

		strncpy(g_scan_result.buff[i].ssid, ap_list->ApList[i].ssid, (sizeof(g_scan_result.buff[i].ssid) - 1));
		g_scan_result.buff[i].rssi = ap_list->ApList[i].rssi;
	}

	g_scan_result.num = i;
	iot_os_eventgroup_set_bits(wifi_event_group, WIFI_STA_SCAN_BIT);

}

uint16_t iot_bsp_wifi_get_scan_result(iot_wifi_scan_result_t *scan_result)
{
	unsigned int ux_bits = 0;
	g_scan_result.num = 0;
	g_scan_result.buff = scan_result;

	/* Register user function when wlan scan is completed */
	mico_system_notify_register(mico_notify_WIFI_SCAN_COMPLETED, (void *)_ap_list_callback, NULL);

	IOT_INFO("start scan mode, please wait...");
	micoWlanStartScan( );

	ux_bits = iot_os_eventgroup_wait_bits(wifi_event_group, WIFI_STA_SCAN_BIT,
				true, IOT_WIFI_CMD_TIMEOUT);

	g_scan_result.buff = NULL; //reset the buffer pointer for callback
	if (ux_bits & WIFI_STA_SCAN_BIT) {
		IOT_INFO("Wifi scan finished, ap number is %d", g_scan_result.num);
	} else {
		IOT_ERROR("WIFI_STA_SCAN_BIT event Timeout");
		return 0;
	}

	return g_scan_result.num;
}

iot_error_t iot_bsp_wifi_get_mac(struct iot_mac *wifi_mac)
{
	IOT_ERROR_CHECK(wifi_mac == NULL, IOT_ERROR_INVALID_ARGS, "param null");

	mico_wlan_get_mac_address((uint8_t*)wifi_mac->addr);
	return IOT_ERROR_NONE;
}

iot_wifi_freq_t iot_bsp_wifi_get_freq(void)
{
	return IOT_WIFI_FREQ_2_4G_ONLY;
}

iot_error_t iot_bsp_wifi_register_event_cb(iot_bsp_wifi_event_cb_t cb)
{
	return IOT_ERROR_BAD_REQ;
}

void iot_bsp_wifi_clear_event_cb(void)
{
}

iot_wifi_auth_mode_bits_t iot_bsp_wifi_get_auth_mode(void)
{
	iot_wifi_auth_mode_bits_t supported_mode_bits = IOT_WIFI_AUTH_MODE_BIT_ALL;
	supported_mode_bits ^= IOT_WIFI_AUTH_MODE_BIT(IOT_WIFI_AUTH_WPA2_ENTERPRISE);
	supported_mode_bits ^= IOT_WIFI_AUTH_MODE_BIT(IOT_WIFI_AUTH_WPA3_PERSONAL);

	return supported_mode_bits;
}