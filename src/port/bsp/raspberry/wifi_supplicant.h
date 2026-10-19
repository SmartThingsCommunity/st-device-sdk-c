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

#define IOT_WIFI_MAX_SSID_LEN (32)
#define IOT_WIFI_MAX_PASS_LEN (64)

struct wpa_ssid {
    char ssid[IOT_WIFI_MAX_SSID_LEN + 1];
    char pswd[IOT_WIFI_MAX_PASS_LEN + 1];
    enum wpas_mode {
        WPAS_MODE_INFRA = 0,
        WPAS_MODE_IBSS = 1,
        WPAS_MODE_AP = 2,
    } mode;
    char *key_mgmt;
    int hidden;
    /* PMF (802.11w) mode: 0 = disabled, 1 = optional, 2 = required.
     * Only applied when key_mgmt includes SAE. */
    int ieee80211w;
};

/* IEEE 802.11 reason codes reported via the wpa_supplicant DisconnectReason
 * property. A negative property value means a locally generated disconnect. */
#define WLAN_REASON_PREV_AUTH_NOT_VALID 2
#define WLAN_REASON_DEAUTH_LEAVING 3
#define WLAN_REASON_DISASSOC_AP_BUSY 5
#define WLAN_REASON_4WAY_HANDSHAKE_TIMEOUT 15
#define WLAN_REASON_GROUP_KEY_UPDATE_TIMEOUT 16
#define WLAN_REASON_IEEE_802_1X_AUTH_FAILED 23

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
int supplicant_join_network(char *ssid_key, char *password, iot_wifi_auth_mode_t authmode, int hidden);
int supplicant_leave_network(void);

int supplicant_start_softap(char *ssid_name, char *pswd);
int supplicant_stop_softap(void);

int supplicant_get_freq_support(void);

int supplicant_get_current_ap(iot_wifi_scan_result_t *ap_record);
int supplicant_is_station_active(void);

#endif
