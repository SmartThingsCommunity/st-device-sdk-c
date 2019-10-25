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

#include <string.h>
#include <time.h>

#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "rom/ets_sys.h"
#include "esp_wifi.h"
#include "esp_event_loop.h"
#include "esp_log.h"

#include "iot_debug.h"
#include "iot_bsp_wifi.h"
#include "iot_os_util.h"
#include "iot_util.h"

#include "lwip/apps/sntp.h"

const int WIFI_STA_START_BIT 		= BIT0;
const int WIFI_STA_CONNECT_BIT		= BIT1;
const int WIFI_STA_DISCONNECT_BIT	= BIT2;
const int WIFI_AP_START_BIT 			= BIT3;
const int WIFI_AP_STOP_BIT 			= BIT4;

const int WIFI_EVENT_BIT_ALL = BIT0|BIT1|BIT2|BIT3|BIT4;

static int WIFI_INITIALIZED = false;
static EventGroupHandle_t wifi_event_group;

static void _initialize_sntp(void)
{
	IOT_INFO("Initializing SNTP");
	sntp_setoperatingmode(SNTP_OPMODE_POLL);
	sntp_setservername(0, "pool.ntp.org");
	sntp_setservername(1, "1.kr.pool.ntp.org");
	sntp_setservername(2, "1.asia.pool.ntp.org");
	sntp_setservername(3, "us.pool.ntp.org");
	sntp_setservername(4, "1.cn.pool.ntp.org");
	sntp_setservername(5, "1.hk.pool.ntp.org");
	sntp_setservername(6, "europe.pool.ntp.org");
	sntp_setservername(7, "time1.google.com");

	sntp_init();
}

static void _obtain_time(void)
{
	time_t now = 0;
	struct tm timeinfo = { 0 };
	int retry = 0;
	const int retry_count = 10;

	_initialize_sntp();

	while (timeinfo.tm_year < (2016 - 1900) && ++retry < retry_count) {
		IOT_INFO("Waiting for system time to be set... (%d/%d)", retry, retry_count);
		IOT_DELAY(2000);
		time(&now);
		localtime_r(&now, &timeinfo);
	}

	if (retry < 10) {
		IOT_INFO("[WIFI] system time updated by %ld", now);
	}
}

static esp_err_t event_handler(void *ctx, system_event_t *event)
{
	switch(event->event_id) {
	case SYSTEM_EVENT_STA_START:
		xEventGroupSetBits(wifi_event_group, WIFI_STA_START_BIT);
		esp_wifi_connect();
		break;

	case SYSTEM_EVENT_STA_STOP:
		IOT_INFO("SYSTEM_EVENT_STA_STOP");
		xEventGroupClearBits(wifi_event_group, WIFI_EVENT_BIT_ALL);
		break;

	case SYSTEM_EVENT_STA_DISCONNECTED:
		IOT_WARN("Disconnect reason : %d", event->event_info.disconnected.reason);
		xEventGroupSetBits(wifi_event_group, WIFI_STA_DISCONNECT_BIT);
		esp_wifi_connect();
		xEventGroupClearBits(wifi_event_group, WIFI_STA_CONNECT_BIT);
		break;

	case SYSTEM_EVENT_STA_GOT_IP:
		IOT_INFO("got ip:%s",
				ip4addr_ntoa(&event->event_info.got_ip.ip_info.ip));
		xEventGroupSetBits(wifi_event_group, WIFI_STA_CONNECT_BIT);
		xEventGroupClearBits(wifi_event_group, WIFI_STA_DISCONNECT_BIT);
		break;

	case SYSTEM_EVENT_AP_START:
		xEventGroupClearBits(wifi_event_group, WIFI_EVENT_BIT_ALL);
		IOT_INFO("SYSTEM_EVENT_AP_START");
		xEventGroupSetBits(wifi_event_group, WIFI_AP_START_BIT);
		break;

	case SYSTEM_EVENT_AP_STOP:
		IOT_INFO("SYSTEM_EVENT_AP_STOP");
		xEventGroupSetBits(wifi_event_group, WIFI_AP_STOP_BIT);
		break;

	case SYSTEM_EVENT_AP_STACONNECTED:
		IOT_INFO("station:"MACSTR" join, AID=%d",
				MAC2STR(event->event_info.sta_connected.mac),
				event->event_info.sta_connected.aid);
		break;

	case SYSTEM_EVENT_AP_STADISCONNECTED:
		IOT_INFO("station:"MACSTR"leave, AID=%d",
				MAC2STR(event->event_info.sta_disconnected.mac),
				event->event_info.sta_disconnected.aid);

		xEventGroupSetBits(wifi_event_group, WIFI_AP_STOP_BIT);
		break;

	default:
		IOT_INFO("event_handler = %d", event->event_id);
		break;
	}

	return ESP_OK;
}

iot_error_t iot_bsp_wifi_init()
{
	IOT_INFO("[esp8266] iot_bsp_wifi_init");

	if(WIFI_INITIALIZED)
		return IOT_ERROR_NONE;

	wifi_event_group = xEventGroupCreate();

	tcpip_adapter_init();
	ESP_ERROR_CHECK(esp_event_loop_init(event_handler, NULL));

	wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
	ESP_ERROR_CHECK(esp_wifi_init(&cfg));
	ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
	ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));

	WIFI_INITIALIZED = true;
	IOT_INFO("[esp8266] iot_bsp_wifi_init done");

	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_wifi_set_mode(iot_wifi_conf *conf)
{
	int str_len = 0;
	wifi_config_t wifi_config;
	time_t now;
	struct tm timeinfo;
	wifi_mode_t mode = WIFI_MODE_NULL;
	EventBits_t uxBits = 0;

	memset(&wifi_config, 0x0, sizeof(wifi_config_t));

	IOT_INFO("iot_bsp_wifi_set_mode = %d", conf->mode);

	switch(conf->mode) {
	case IOT_WIFI_MODE_OFF:
		ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
		break;

	case IOT_WIFI_MODE_SCAN:

		ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA) );
		ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config));
		ESP_ERROR_CHECK(esp_wifi_start() );

		uxBits = xEventGroupWaitBits(wifi_event_group, WIFI_STA_START_BIT,
			true, false, IOT_WIFI_CMD_TIMEOUT);

		if(uxBits & WIFI_STA_START_BIT) {
			IOT_INFO("WiFi Station Started");
		}
		else {
			IOT_ERROR("WIFI_STA_START_BIT event timeout");
			return IOT_ERROR_TIMEOUT;
		}

		break;

	case IOT_WIFI_MODE_STATION:

		esp_wifi_get_mode(&mode);

		if(mode == WIFI_MODE_AP) {
			IOT_INFO("[esp8266] current mode=%d need to call esp_wifi_stop", mode);
			ESP_ERROR_CHECK(esp_wifi_stop() );

			uxBits = xEventGroupWaitBits(wifi_event_group, WIFI_AP_STOP_BIT,
					true, false, IOT_WIFI_CMD_TIMEOUT);

			if(uxBits & WIFI_AP_STOP_BIT) {
				IOT_INFO("AP Mode stopped");
				IOT_DELAY(500);
			}
			else {
				IOT_ERROR("WIFI_AP_STOP_BIT event Timeout");
				return IOT_ERROR_TIMEOUT;
			}
		}

		str_len = strlen(conf->ssid);
		if(str_len) {
			memcpy(wifi_config.sta.ssid, conf->ssid, str_len);
			if (str_len < IOT_WIFI_MAX_SSID_LEN)
				wifi_config.sta.ssid[str_len] = '\0';
		}

		str_len = strlen(conf->pass);
		if(str_len) {
			memcpy(wifi_config.sta.password, conf->pass, str_len);
			if (str_len < IOT_WIFI_MAX_PASS_LEN)
				wifi_config.sta.password[str_len] = '\0';
		}

		str_len = strlen((char *)conf->bssid);
		if(str_len){
			memcpy(wifi_config.sta.bssid, conf->bssid, IOT_WIFI_MAX_BSSID_LEN);
			wifi_config.sta.bssid_set = true;

			IOT_DEBUG("target mac=%2X:%2X:%2X:%2X:%2X:%2X",
					wifi_config.sta.bssid[0], wifi_config.sta.bssid[1], wifi_config.sta.bssid[2],
					wifi_config.sta.bssid[3], wifi_config.sta.bssid[4], wifi_config.sta.bssid[5]);
		}

		ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA) );
		ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config) );
		ESP_ERROR_CHECK(esp_wifi_start() );

		IOT_INFO("connect to ap SSID:%s", wifi_config.sta.ssid);

		uxBits = xEventGroupWaitBits(wifi_event_group, WIFI_STA_CONNECT_BIT,
				true, false, IOT_WIFI_CMD_TIMEOUT);
		if((uxBits & WIFI_STA_CONNECT_BIT)) {
			IOT_INFO("AP Connected");
		}
		else {
				IOT_ERROR("WIFI_STA_CONNECT_BIT event Timeout");
				esp_wifi_stop();
				return IOT_ERROR_TIMEOUT;
		}

		time(&now);
		localtime_r(&now, &timeinfo);

		if (timeinfo.tm_year < (2016 - 1900)) {
			IOT_INFO("Time is not set yet. Connecting to WiFi and getting time over NTP.");
			_obtain_time();
		}

		break;

	case IOT_WIFI_MODE_SOFTAP:

		str_len = strlen(conf->ssid);
		memcpy(wifi_config.ap.ssid, conf->ssid, str_len);
		if (str_len < IOT_WIFI_MAX_SSID_LEN)
			wifi_config.sta.ssid[str_len] = '\0';

		str_len =  strlen(conf->pass);
		memcpy(wifi_config.ap.password, conf->pass, str_len);
		if (str_len < IOT_WIFI_MAX_PASS_LEN)
			wifi_config.sta.password[str_len] = '\0';

		wifi_config.ap.ssid_len = strlen(conf->ssid);
		wifi_config.ap.max_connection = 1;
		wifi_config.ap.channel = 1;
		wifi_config.ap.beacon_interval = 100;
		wifi_config.ap.ssid_hidden = false;

		if(strlen(conf->pass) == 0){
			wifi_config.ap.authmode = WIFI_AUTH_OPEN;
		}
		else{
			wifi_config.ap.authmode = WIFI_AUTH_WPA_WPA2_PSK;
		}
		ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
		ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_AP, &wifi_config));
		ESP_ERROR_CHECK(esp_wifi_start());

		IOT_DEBUG("wifi_init_softap finished.SSID:%s password:%s",
				wifi_config.ap.ssid, wifi_config.ap.password);

		uxBits=xEventGroupWaitBits(wifi_event_group, WIFI_AP_START_BIT,
				true, false, IOT_WIFI_CMD_TIMEOUT);

		if(uxBits & WIFI_AP_START_BIT) {
			IOT_INFO("AP Mode Started");
		}
		else {
				IOT_ERROR("WIFI_AP_START_BIT event Timeout");
				return IOT_ERROR_TIMEOUT;
		}

		break;

	default:
		IOT_ERROR("esp8266 cannot support this mode = %d", conf->mode);
		return IOT_ERROR_BAD_REQ;
	}

	return IOT_ERROR_NONE;
}

uint16_t iot_bsp_wifi_get_scan_result(iot_wifi_scan_result_t *scan_result)
{
	uint16_t ap_num = 0;
	uint16_t i;
	wifi_scan_config_t config;
	wifi_ap_record_t *ap_list = NULL;

	memset(&config, 0x0, sizeof(config));

	esp_wifi_scan_start(&config, true);
	if(esp_wifi_scan_get_ap_num(&ap_num) == ESP_OK) {
		ap_num = (ap_num > IOT_WIFI_MAX_SCAN_RESULT) ?
				IOT_WIFI_MAX_SCAN_RESULT : ap_num;

		if(ap_num > 0) {
			ap_list = (wifi_ap_record_t *) malloc(ap_num * sizeof(wifi_ap_record_t));
			if(!ap_list){
				IOT_ERROR("failed to malloc for wifi_ap_record_t");
				return 0;
			}

			if(esp_wifi_scan_get_ap_records(&ap_num, ap_list) == ESP_OK){
				for(i=0; i<ap_num; i++)	{
					memcpy(scan_result[i].ssid, ap_list[i].ssid, strlen((char *)ap_list[i].ssid));
					memcpy(scan_result[i].bssid, ap_list[i].bssid, IOT_WIFI_MAX_BSSID_LEN);

					scan_result[i].rssi = ap_list[i].rssi;
					scan_result[i].freq = iot_util_convert_channel_freq(ap_list[i].primary);
					scan_result[i].authmode = ap_list[i].authmode;

					IOT_DEBUG("esp8266 ssid=%s, mac=%02X:%02X:%02X:%02X:%02X:%02X, rssi=%d, freq=%d, authmode=%d chan=%d",
							scan_result[i].ssid,
							scan_result[i].bssid[0], scan_result[i].bssid[1], scan_result[i].bssid[2],
							scan_result[i].bssid[3], scan_result[i].bssid[4], scan_result[i].bssid[5], scan_result[i].rssi,
							scan_result[i].freq, scan_result[i].authmode, ap_list[i].primary);
				}
			}
			free(ap_list);
		}
	} else {
		IOT_INFO("failed to get esp_wifi_scan_get_ap_num");
		ap_num = 0;
		scan_result = NULL;
	}

	return ap_num;
}

iot_error_t iot_bsp_wifi_get_mac(struct iot_mac *wifi_mac)
{
	iot_error_t ret;

	ret = esp_wifi_get_mac(ESP_IF_WIFI_STA, wifi_mac->addr);

	if(ret != ESP_OK){
		IOT_ERROR("failed to read wifi mac address : %d", ret);
		return IOT_ERROR_READ_FAIL;
	}

	return IOT_ERROR_NONE;
}

iot_wifi_freq_t iot_bsp_wifi_get_freq(void)
{
	return IOT_WIFI_FREQ_2_4G_ONLY;
}
