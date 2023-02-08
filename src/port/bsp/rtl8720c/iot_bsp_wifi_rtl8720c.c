/******************************************************************
 *
 * Copyright (c) 2019-2021 Samsung Electronics All Rights Reserved.
 *
 *
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************/
#include <lwip_netconf.h>
#include <wifi_constants.h>
#include <wifi_structures.h>
#include <iot_bsp_wifi.h>
#include "iot_os_util.h"
#include "freertos_service.h"
#include "wifi_conf.h"
#include "lwip/ip_addr.h"
#include "iot_debug.h"
#include "apps/sntp.h"

struct wifi_scan_result {
	iot_wifi_scan_result_t *scan_result;
	int len;
	_sema scan_sema;
};

enum e_wifi_init_status {
	e_wifi_uninit = 0,
	e_wifi_init,
};

static enum e_wifi_init_status wifi_init_status = e_wifi_uninit;
static rtw_mode_t rtw_mode = RTW_MODE_NONE;
static rtw_result_t app_scan_result_handler(rtw_scan_handler_result_t *malloced_scan_result);
extern struct netif xnetif[NET_IF_NUM];

static int _iot_bsp_wifi_on(iot_wifi_mode_t mode)
{
	rtw_mode_t iot_wifi_rtw_mode_map[] = {
		[IOT_WIFI_MODE_OFF] = RTW_MODE_NONE,
		[IOT_WIFI_MODE_SCAN] = RTW_MODE_STA,
		[IOT_WIFI_MODE_STATION] = RTW_MODE_STA,
		[IOT_WIFI_MODE_SOFTAP] = RTW_MODE_AP,
		[IOT_WIFI_MODE_P2P]  = RTW_MODE_P2P,
	};
	rtw_mode = iot_wifi_rtw_mode_map[mode];
	return wifi_on(rtw_mode);
}

static int _iot_bsp_wifi_off()
{
	return wifi_off();
}

static void _initialize_sntp(void)
{
	IOT_INFO("Initializing SNTP");
	if (sntp_enabled()) {
		IOT_INFO("SNTP is already working, STOP it first");
		sntp_stop();
	}

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

	sntp_stop();

	if (retry < 10) {
		IOT_INFO("[WIFI] system time updated by %ld", now);
	}
}

iot_error_t iot_bsp_wifi_init()
{
	if (wifi_init_status == e_wifi_init) {
		IOT_INFO("wifi is already initialized, returning");
		return IOT_ERROR_NONE;
	}
#if CONFIG_INIT_NET
#if CONFIG_LWIP_LAYER
	/* Initilaize the LwIP stack */
	LwIP_Init();//it will set the ip auto
#endif
#endif
#if CONFIG_WIFI_IND_USE_THREAD
	wifi_manager_init();
#endif
	if (_iot_bsp_wifi_on(IOT_WIFI_MODE_STATION) < 0) {
		IOT_ERROR("wifi_on failed");
		return IOT_ERROR_INIT_FAIL;
	}
	wifi_set_autoreconnect(1);

	wifi_init_status = e_wifi_init;
	return IOT_ERROR_NONE;
}

/*These code copy from at comand sample**/
static int _find_ap_from_scan_buf(char *buf, int buflen, char *target_ssid, void *user_data)
{
	rtw_wifi_setting_t *pwifi = (rtw_wifi_setting_t *)user_data;
	int plen = 0;

	IOT_DEBUG("ssid %s buflen %d target_ssid %s", target_ssid, buflen, target_ssid);
	while (plen < buflen) {
		u8 len, ssid_len, security_mode;
		char *ssid;

		// len offset = 0
		len = (int)*(buf + plen);
		// check end
		if (len == 0) break;
		// ssid offset = 14
		ssid_len = len - 14;
		ssid = buf + plen + 14;
		IOT_DEBUG("ssid_len %d target_ssidlen %d len %d ssid %s, :%c-%c-%c", ssid_len, strlen(target_ssid), len, ssid, ssid[0], ssid[13], ssid[14]);
		IOT_DEBUG("ssid_len %d target_ssidlen %d len %d ssid %s, :%c-%c-%c", ssid_len, strlen(target_ssid), len, target_ssid, target_ssid[0], target_ssid[13], target_ssid[14]);
		if ((ssid_len == strlen(target_ssid))
			&& (!memcmp(ssid, target_ssid, ssid_len))) {
				strcpy((char*)pwifi->ssid, target_ssid);
				// channel offset = 13
				pwifi->channel = *(buf + plen + 13);
				// security_mode offset = 11
				security_mode = (u8)*(buf + plen + 11);
				if(security_mode == IW_ENCODE_ALG_NONE)
					pwifi->security_type = RTW_SECURITY_OPEN;
				else if(security_mode == IW_ENCODE_ALG_WEP)
					pwifi->security_type = RTW_SECURITY_WEP_PSK;
				else if(security_mode == IW_ENCODE_ALG_CCMP)
					pwifi->security_type = RTW_SECURITY_WPA2_AES_PSK;
				IOT_DEBUG("ssid %s security_mode %0x", target_ssid, pwifi->security_type);
				strcpy((char*)pwifi->ssid, target_ssid);
				break;
		}
		plen += len;
	}
	return 0;
}

static int _get_ap_security_mode(IN char *ssid, OUT rtw_security_t *security_mode, OUT u8 *channel)
{
	rtw_wifi_setting_t wifi;
	u32 scan_buflen = 1000;

	memset(&wifi, 0, sizeof(wifi));

	IOT_INFO("_get_ap_security_mode");
	if (wifi_scan_networks_with_ssid(_find_ap_from_scan_buf, (void*)&wifi, scan_buflen, ssid, strlen(ssid)) != RTW_SUCCESS) {
		IOT_ERROR("Wifi scan failed!");
		return 0;
	}

	if (strcmp(wifi.ssid, ssid) == 0) {
		*security_mode = wifi.security_type;
		*channel = wifi.channel;
		IOT_INFO("Wifi scan secruity mode %d channel %d\n", wifi.security_type, wifi.channel);
		return 1;
	}
	IOT_INFO("Wifi scan could not search the ap with ssid %s, target ssid is: wifi.ssid %s!", ssid, wifi.ssid);

	return 0;
}

iot_error_t iot_bsp_wifi_set_mode(iot_wifi_conf *conf)
{
	int str_len = 0;
	int timeout = 20;
	iot_error_t ret = IOT_ERROR_NONE;
	time_t now;
	struct tm timeinfo;
	struct ip_addr ipaddr;
	struct ip_addr netmask;
	struct ip_addr gw;
	struct netif *pnetif = &xnetif[0];

	rtw_network_info_t wifi_config = {0};

	str_len = strlen(conf->ssid);
	memcpy(wifi_config.ssid.val, conf->ssid, str_len);
	if (str_len < IOT_WIFI_MAX_SSID_LEN)
		wifi_config.ssid.val[str_len] = '\0';

	str_len =  strlen(conf->pass);

	wifi_config.ssid.len = strlen(conf->ssid);
	rtw_security_t security_type = RTW_SECURITY_WPA2_AES_PSK;
	if (str_len == 0) {
		security_type = RTW_SECURITY_OPEN;
	} else {
		wifi_config.password = (char *) malloc(sizeof(char) * str_len + 1);
		memcpy(wifi_config.password, conf->pass, str_len);
		if (str_len < IOT_WIFI_MAX_PASS_LEN)
			wifi_config.password[str_len] = '\0';
	}
	wifi_config.security_type = security_type;

	switch (conf->mode) {
	case IOT_WIFI_MODE_OFF:
		if (rtw_mode != RTW_MODE_NONE) {
			if (RTW_ERROR == _iot_bsp_wifi_off()) {
				ret = IOT_ERROR_CONN_OPERATE_FAIL;
				goto out;
			}
			vTaskDelay(20);
		}
		if (RTW_ERROR == _iot_bsp_wifi_on(IOT_WIFI_MODE_OFF)) {
			ret = IOT_ERROR_CONN_OPERATE_FAIL;
			goto out;
		}
		wifi_set_autoreconnect(0);
	break;
	case IOT_WIFI_MODE_SCAN:
		if (rtw_mode == RTW_MODE_NONE) {
			IOT_ERROR("Scan could perform on both STA or SOFTAP mode, but current mode is NONE.");
			ret = IOT_ERROR_CONN_OPERATE_FAIL;
			goto out;
		}
	break;
	case IOT_WIFI_MODE_STATION:
		if (rtw_mode != RTW_MODE_STA) {
			if (RTW_ERROR == _iot_bsp_wifi_off()) {
				ret = IOT_ERROR_CONN_OPERATE_FAIL;
				goto out;
			}
			vTaskDelay(20);
		}

		if (RTW_ERROR == _iot_bsp_wifi_on(IOT_WIFI_MODE_STATION)) {
				ret = IOT_ERROR_CONN_OPERATE_FAIL;
				goto out;
		}

		wifi_set_autoreconnect(0);

		u8 ap_channel = 0;
		for (int i = 0; i < 5; i++) {
			if(0 !=	_get_ap_security_mode(wifi_config.ssid.val, &(wifi_config.security_type), &ap_channel))
				break;
			IOT_INFO("Connect failed, No. %d try!", i);
		}

		wifi_set_autoreconnect(1);
		int keyindex = 0;
		/*NOTE: keyindex is for web auth mode, in other mode keyindex will not take effect*/
		/*Known issue: We checked in our AP, if keyindex >0,
				DHCP will failed, and we check with android phone and our pc, they are
				are same issue.*/
		for (keyindex = 0; keyindex < 4; keyindex++) {
			wifi_config.key_id = keyindex;
			if (wifi_connect(wifi_config.ssid.val, wifi_config.security_type,
				wifi_config.password, strlen(wifi_config.ssid.val),
				strlen(wifi_config.password), wifi_config.key_id, NULL) == RTW_SUCCESS) {
					LwIP_DHCP(0, DHCP_START);
					int rssi = 0;
					wifi_get_rssi(&rssi);
					IOT_INFO("The RSSI: %d", rssi);
					break;
			} else {
				if (RTW_SECURITY_WEP_PSK == wifi_config.security_type
					|| RTW_SECURITY_WEP_SHARED == wifi_config.security_type) {
					IOT_INFO("keyindex %d wifi connect to ap %s failed, ap secruity mode: %d",
						keyindex,
						wifi_config.ssid.val, wifi_config.security_type);
				} else {
					IOT_ERROR("keyindex %d wifi connect to ap %s failed, ap secruity mode: %d",
						keyindex,
						wifi_config.ssid.val, wifi_config.security_type);
					break;
				}
			}
		}

		time(&now);
		localtime_r(&now, &timeinfo);

		if (timeinfo.tm_year < (2016 - 1900)) {
			IOT_INFO("Time is not set yet. Connecting to WiFi and getting time over NTP.");
			_obtain_time();
		}

	break;
	case IOT_WIFI_MODE_SOFTAP:
		dhcps_deinit();
		IP4_ADDR(&ipaddr, 192, 168, 4, 1);
		IP4_ADDR(&netmask, 255, 255 , 255, 0);
		IP4_ADDR(&gw, 192, 168, 4, 1);
		netif_set_addr(pnetif, &ipaddr, &netmask, &gw);
#ifdef CONFIG_DONT_CARE_TP
		pnetif->flags |= NETIF_FLAG_IPSWITCH;
#endif
		///enable wifi ap mode
		if (RTW_ERROR == _iot_bsp_wifi_off()) {
			ret = IOT_ERROR_CONN_OPERATE_FAIL;
			goto out;
		}
		vTaskDelay(20);
		if(_iot_bsp_wifi_on(IOT_WIFI_MODE_SOFTAP) < 0) {
			IOT_ERROR("wifi_on failed");
			ret = IOT_ERROR_CONN_OPERATE_FAIL;
			goto out;
		}

		wifi_set_autoreconnect(0);
		int channel = 6;	//#define SOFTAP_CHANNEL 6
		if (wifi_start_ap(wifi_config.ssid.val, wifi_config.security_type, wifi_config.password, strlen(wifi_config.ssid.val), strlen(wifi_config.password), channel) < 0) {
			IOT_ERROR("[WLAN_SCENARIO_EXAMPLE] ERROR: wifi_start_ap failed");
			ret = IOT_ERROR_CONN_OPERATE_FAIL;
			goto out;
		}
		while (1) {
			char essid[33];

			if (wext_get_ssid(WLAN0_NAME, (unsigned char *)essid) > 0) {
				if (strcmp((const char *)essid, (const char *)wifi_config.ssid.val) == 0) {
					IOT_INFO("%s started", wifi_config.ssid.val);
					break;
				}
			}

			if (timeout == 0) {
				IOT_ERROR("ERROR: Start AP timeout!");
				ret = IOT_ERROR_CONN_OPERATE_FAIL;
				break;
			}

			vTaskDelay(1 * configTICK_RATE_HZ);
			timeout --;
		}
		dhcps_init(pnetif);
		break;
	default:
		break;
	}
out:
	if (wifi_config.password) {
		free(wifi_config.password);
		wifi_config.password = NULL;
	}
	return ret;
}

#define CONFIG_INIC_CMD_RSP 1

static rtw_result_t app_scan_result_handler(rtw_scan_handler_result_t *malloced_scan_result)
{
	IOT_DEBUG("++++++++++++++++++++++++++");
	if (malloced_scan_result->scan_complete != RTW_TRUE) {
		rtw_scan_result_t* record = &malloced_scan_result->ap_details;
		record->SSID.val[record->SSID.len] = 0; /* Ensure the SSID is null terminated */
#if CONFIG_INIC_CMD_RSP
		if (malloced_scan_result->user_data) {
			struct wifi_scan_result *wifi_scan_result = (struct wifi_scan_result *)malloced_scan_result->user_data;
			iot_wifi_scan_result_t *scan_result = (iot_wifi_scan_result_t *)wifi_scan_result->scan_result;

			if (wifi_scan_result->len >= IOT_WIFI_MAX_SCAN_RESULT) {
				//NOTE: if preallocation is exceed the IOT_WIFI_MAX_SCAN_RESULT, just print the ap info, do not add to scan list
				IOT_DEBUG("exceed the max scan, do not add to scan list, just print here:find ap:%s", record->SSID.val);
				goto out;
			}
			wifi_scan_result->len++;
			int i = wifi_scan_result->len - 1;
			memcpy(scan_result[i].ssid, record->SSID.val, strlen((char *)record->SSID.val));
			memcpy(scan_result[i].bssid, record->BSSID.octet, IOT_WIFI_MAX_BSSID_LEN);
			scan_result[i].rssi = record->signal_strength;
			scan_result[i].freq = iot_util_convert_channel_freq(record->channel);

			switch(record->security){
			case RTW_SECURITY_OPEN:
				scan_result[i].authmode = IOT_WIFI_AUTH_OPEN;
				break;
			case RTW_SECURITY_WEP_PSK:
			case RTW_SECURITY_WEP_SHARED:
				scan_result[i].authmode = IOT_WIFI_AUTH_WEP;
				break;
			case RTW_SECURITY_WPA_TKIP_PSK:
			case RTW_SECURITY_WPA_AES_PSK:
				scan_result[i].authmode = IOT_WIFI_AUTH_WPA_PSK;
				break;
			case RTW_SECURITY_WPA2_AES_PSK:
			case RTW_SECURITY_WPA2_TKIP_PSK:
			case RTW_SECURITY_WPA2_MIXED_PSK:
				scan_result[i].authmode = IOT_WIFI_AUTH_WPA2_PSK;
				break;
			case RTW_SECURITY_WPA_WPA2_MIXED:
				scan_result[i].authmode = IOT_WIFI_AUTH_WPA_WPA2_PSK;
				break;
			default:
				IOT_DEBUG("%s auto not map origin sec mode record->security:%d : iot authmode: %d", scan_result[i].ssid, record->security, scan_result[i].authmode);
				break;
			}
			IOT_DEBUG("%s auto map origin sec mode record->security:%d : iot authmode: %d", scan_result[i].ssid, record->security, scan_result[i].authmode);
		}
#endif
	} else {
#if CONFIG_INIC_CMD_RSP
		if(malloced_scan_result->user_data) {
			struct wifi_scan_result *wifi_scan_result = (struct wifi_scan_result *)malloced_scan_result->user_data;
			rtw_up_sema(&wifi_scan_result->scan_sema);
		}
#endif

	}
out:
	IOT_DEBUG("------------------------------");
	return RTW_SUCCESS;
}


uint16_t iot_bsp_wifi_get_scan_result(iot_wifi_scan_result_t *scan_result)
{
	int len = 0;
	int ret = 0;

	struct wifi_scan_result inic_scan_buf;
	rtw_init_sema(&(inic_scan_buf.scan_sema), 0);
	if(inic_scan_buf.scan_sema == NULL)
		return RTW_ERROR;

	inic_scan_buf.scan_result = scan_result;
	inic_scan_buf.len = 0;

	if ((ret = wifi_scan_networks(app_scan_result_handler, &inic_scan_buf)) != RTW_SUCCESS) {
		return IOT_ERROR_CONNECT_FAIL;
	}
	if (rtw_down_timeout_sema(&inic_scan_buf.scan_sema, SCAN_LONGEST_WAIT_TIME) == RTW_FALSE) {
		IOT_INFO("WPS scan done early!");
	}
	len = inic_scan_buf.len;
	return len;
}


/*Note: sample: '0' -> 0x0, '1' -> 0x1, ...'a'->0xa,  'E' -> 0xE, 'F' -> 0xF*/
static int transfer_ascii_to_hex(char c)
{
	if ((c >= '0') && (c <= '9')) {
		return c - '0';
	} else if ((c >= 'a') && (c <= 'f')) {
		return c - 'a' + 0xa;
	} else if ((c >= 'A') && (c <= 'F')) {
		return c - 'A' + 0xa;
	}
}

iot_error_t iot_bsp_wifi_get_mac(struct iot_mac *wifi_mac)
{
	iot_error_t ret;
	char mac_addr[32];
	ret = wifi_get_mac_address(mac_addr);
	if (ret != RTW_SUCCESS) {
		IOT_ERROR("failed to read wifi mac address : %d", ret);
		return IOT_ERROR_CONN_OPERATE_FAIL;
	}

	int i = 0;
	for (i = 0; i < 6; i++) {
		int j = i * 3;
		wifi_mac->addr[i] = transfer_ascii_to_hex(mac_addr[j]) * 0x10 + transfer_ascii_to_hex(mac_addr[j + 1]);
	}
	IOT_DEBUG("MAC:%02X-%02X-%02X-%02X-%02X-%02X",
		wifi_mac->addr[0], wifi_mac->addr[1], wifi_mac->addr[2], wifi_mac->addr[3], wifi_mac->addr[4], wifi_mac->addr[5]);
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