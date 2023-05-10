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

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <bits/ioctls.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>

#include <netinet/in.h>
#include <net/route.h>
#include <sys/types.h>
#include <pwd.h>

#include "iot_os_util.h"
#include "iot_util.h"
#include "iot_debug.h"
#include "iot_bsp_wifi.h"
#include "wifi_supplicant.h"

/* Few linux machines set default time to 1 APR 2020 */
#define NTP_REFERENCE_TIME_YEAR (2020 - 1900)
#define NTP_REFERENCE_TIME_MONTH 3
#define NTP_REFERENCE_TIME_MDAY 1

static int _create_socket(void)
{
	int sockfd = 0;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd == -1) {
		IOT_ERROR("Can't get socket (%d, %s)", errno, strerror(errno));
		return -errno;
	}

	return sockfd;
}

static int _is_time_updated(void)
{
	time_t now = 0;
	struct tm timeinfo = { 0 };

	time(&now);
	localtime_r(&now, &timeinfo);

	if (timeinfo.tm_year < NTP_REFERENCE_TIME_YEAR ||
	    (timeinfo.tm_year == NTP_REFERENCE_TIME_YEAR &&
	    timeinfo.tm_mon == NTP_REFERENCE_TIME_MONTH &&
	    timeinfo.tm_mday == NTP_REFERENCE_TIME_MDAY)) {
		return 0;
	}

	return 1;
}

static void _update_time(void)
{
	time_t now = 0;
	int retry = 0;
	const int retry_count = 10;

	supplicant_activate_ntpd();

	while (_is_time_updated() == 0 && ++retry < retry_count) {
		IOT_INFO("Waiting for system time to be set... (%d/%d)", retry, retry_count);
		IOT_DELAY(2000);
	}

	if (retry < 10) {
		time(&now);
		IOT_INFO("[WIFI] system time updated by %ld", now);
	}
}

iot_error_t iot_bsp_wifi_init(void)
{
	supplicant_initialise_wifi();
	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_wifi_set_mode(iot_wifi_conf *conf)
{
	char ssid[IOT_WIFI_MAX_SSID_LEN + 1];
	char pass[IOT_WIFI_MAX_PASS_LEN + 1];
	int ret;

	IOT_INFO("iot_bsp_wifi_set_mode = %d", conf->mode);

	switch(conf->mode) {
	case IOT_WIFI_MODE_OFF:
		/* TODO: set wifi mode off */
		break;

	case IOT_WIFI_MODE_SCAN:
		if (!supplicant_is_scan_mode()) {
			ret = supplicant_start_station();
			if (ret < 0)
				return IOT_ERROR_CONN_OPERATE_FAIL;
		}
		break;

	case IOT_WIFI_MODE_STATION:
		strncpy(ssid, conf->ssid, IOT_WIFI_MAX_SSID_LEN);
		ssid[IOT_WIFI_MAX_SSID_LEN] = 0;
		strncpy(pass, conf->pass, IOT_WIFI_MAX_PASS_LEN);
		pass[IOT_WIFI_MAX_PASS_LEN] = 0;

		ret = supplicant_start_station();
		if (ret < 0)
			return IOT_ERROR_CONN_OPERATE_FAIL;
		ret = supplicant_join_network(ssid, pass);
		if (ret < 0)
			return IOT_ERROR_CONN_OPERATE_FAIL;
		ret = supplicant_start_dhcp_client();
		if (ret < 0)
			return IOT_ERROR_CONN_OPERATE_FAIL;
		if (_is_time_updated() == 0) {
			IOT_INFO("Time is not set yet. Connecting to WiFi and getting time over NTP.");
			_update_time();
		}

		break;

	case IOT_WIFI_MODE_SOFTAP:
		strncpy(ssid, conf->ssid, IOT_WIFI_MAX_SSID_LEN);
		ssid[IOT_WIFI_MAX_SSID_LEN] = 0;
		strncpy(pass, conf->pass, IOT_WIFI_MAX_PASS_LEN);
		pass[IOT_WIFI_MAX_PASS_LEN] = 0;

		ret = supplicant_start_softap(ssid, pass);
		if (ret < 0)
			return IOT_ERROR_CONN_OPERATE_FAIL;
		ret = supplicant_start_dhcp_server();
		if (ret < 0)
			return IOT_ERROR_CONN_OPERATE_FAIL;
		IOT_DEBUG("wifi_init_softap finished. SSID:%s password:%s", ssid, pass);
		break;

	default:
		IOT_ERROR("Linux cannot support this mode = %d", conf->mode);
		return IOT_ERROR_BAD_REQ;
	}

	return IOT_ERROR_NONE;
}

uint16_t iot_bsp_wifi_get_scan_result(iot_wifi_scan_result_t *scan_result)
{
	uint16_t ap_num;
	int i;
	iot_wifi_scan_result_t *ap_list;
	int ret;

	ret = supplicant_start_scan();
	if (ret != 0) {
		IOT_ERROR("failed to scan for APs");
		scan_result = NULL;
		return 0;
	}

	ap_list = (iot_wifi_scan_result_t *)calloc(IOT_WIFI_MAX_SCAN_RESULT, sizeof(iot_wifi_scan_result_t));
	ap_num = supplicant_get_scanned_ap_list(ap_list);
	if (ap_num == 0)
		IOT_INFO("No APs found!");

	for(i = 0; i < ap_num; i++)	{
		memcpy(scan_result[i].ssid, ap_list[i].ssid, strlen((char *)ap_list[i].ssid));
		memcpy(scan_result[i].bssid, ap_list[i].bssid, IOT_WIFI_MAX_BSSID_LEN);

		scan_result[i].rssi = ap_list[i].rssi;
		scan_result[i].freq = ap_list[i].freq;
		scan_result[i].authmode = ap_list[i].authmode;

		IOT_DEBUG("Linux AP[%d]: ssid=%s, mac=%02X:%02X:%02X:%02X:%02X:%02X, rssi=%d, freq=%d, authmode=%d",
				i + 1, scan_result[i].ssid,
				scan_result[i].bssid[0], scan_result[i].bssid[1], scan_result[i].bssid[2],
				scan_result[i].bssid[3], scan_result[i].bssid[4], scan_result[i].bssid[5],
				scan_result[i].rssi, scan_result[i].freq, scan_result[i].authmode);
	}

	free(ap_list);
	return ap_num;
}

iot_error_t iot_bsp_wifi_get_mac(struct iot_mac *wifi_mac)
{
	struct ifreq ifr;
	int sockfd = 0;
	char *ctrl_ifname;
	iot_error_t err = IOT_ERROR_NONE;

	sockfd = _create_socket();
	if (sockfd < 0)
		return IOT_ERROR_READ_FAIL;

	err = supplicant_get_wireless_interface(&ctrl_ifname);
	if (err) {
		IOT_ERROR("unable to fetch wireless interface name (%d)", err);
		goto mac_out;
	}

	strncpy(ifr.ifr_name, ctrl_ifname, IF_NAMESIZE);
	if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
		IOT_ERROR("ioctl(%d, %s): 0x%x", errno, strerror(errno), SIOCGIFHWADDR);
		err = IOT_ERROR_READ_FAIL;
		goto mac_out;
	}
	memcpy(wifi_mac->addr, ifr.ifr_hwaddr.sa_data, sizeof(wifi_mac->addr));

mac_out:
	close(sockfd);
	return err;
}

iot_wifi_freq_t iot_bsp_wifi_get_freq(void)
{
	if (supplicant_get_freq_support() == 0)
		return IOT_WIFI_FREQ_2_4G_ONLY;

	return IOT_WIFI_FREQ_2_4G_5G_BOTH;
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
