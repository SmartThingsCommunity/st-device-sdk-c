/* ***************************************************************************
 *
 * Copyright 2020 Samsung Electronics All Rights Reserved.
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
#ifndef _IOT_BSP_WIFI_SUPPLICANT_H_
#define _IOT_BSP_WIFI_SUPPLICANT_H_

#include "iot_bsp_wifi.h"

#define IOT_WIFI_MAX_SSID_LEN	(32)
#define IOT_WIFI_MAX_PASS_LEN	(64)

struct wpa_ssid
{
	char ssid[IOT_WIFI_MAX_SSID_LEN + 1];
	char pswd[IOT_WIFI_MAX_PASS_LEN + 1];
	enum wpas_mode
	{
		WPAS_MODE_INFRA = 0,
		WPAS_MODE_IBSS = 1,
		WPAS_MODE_AP = 2,
	} mode;
	char *key_mgmt;
};

	int supplicant_get_wireless_interface(char **ctrl_ifname);
	static int supplicant_remove_network(char *iface);

	int supplicant_turn_wifi_off(void);
	int supplicant_turn_wifi_on(void);
	void supplicant_initialise_wifi(void);

	int supplicant_is_scan_mode(void);
	int supplicant_start_scan(void);
	uint16_t supplicant_get_scanned_ap_list(iot_wifi_scan_result_t *ap_list);

	int supplicant_start_station(void);
	int supplicant_stop_station(void);
	int supplicant_join_network(char *ssid_key, char *password);
	int supplicant_leave_network(void);

	int supplicant_start_softap(char *ssid_name, char *pswd);
	int supplicant_stop_softap(void);

	int supplicant_start_dhcp_client(void);
	void supplicant_stop_dhcp_client(void);
	int supplicant_start_dhcp_server(void);
	void supplicant_stop_dhcp_server(void);

	int supplicant_get_freq_support(void);

	int supplicant_activate_ntpd(void);
#endif
