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

#include <string.h>
#include <time.h>

#include <aos/kernel.h>
#include <aos/yloop.h>
#include <event_device.h>
#include <bl_efuse.h>
#include <hal_wifi.h>
#include <wifi_mgmr_ext.h>
#include <bl60x_wifi_driver/wifi_mgmr.h>
#include <bl60x_wifi_driver/bl_main.h>
#include <lwip/tcpip.h>
#include <lwip/sockets.h>
#include <lwip/netdb.h>
#include <lwip/tcp.h>
#include <lwip/err.h>
//#include <netif.h>
#include "bl60x_fw_api.h"

#include "FreeRTOS.h"
#include "event_groups.h"

#include "iot_debug.h"
#include "iot_bsp_wifi.h"
#include "iot_os_util.h"
#include "iot_util.h"

#include "lwip/apps/sntp.h"
#include "lwip/inet.h"

#define IOT_WIFI_CMD_TIMEOUT_BL602 10000

#define BIT5    0x00000020
#define BIT4    0x00000010
#define BIT3    0x00000008
#define BIT2    0x00000004
#define BIT1    0x00000002
#define BIT0    0x00000001

const int WIFI_INIT_BIT      		= BIT0;
const int WIFI_STA_CONNECT_BIT		= BIT1;
const int WIFI_STA_DISCONNECT_BIT	= BIT2;
const int WIFI_AP_START_BIT 		= BIT3;
const int WIFI_AP_STOP_BIT 			= BIT4;
const int WIFI_SCAN_DONE_BIT        = BIT5;

const int WIFI_EVENT_BIT_ALL = BIT0|BIT1|BIT2|BIT3|BIT4|BIT5;

static int WIFI_INITIALIZED = false;
static iot_error_t s_latest_disconnect_reason;
static EventGroupHandle_t wifi_event_group;
static iot_bsp_wifi_event_cb_t wifi_event_cb;
static bool s_wifi_connect_timeout = false;
static wifi_conf_t wifi_conf =
{
    .country_code = "CN",
};
/*
static void bl_ap_sta_get_mac(uint8_t index, uint8_t *mac)
{
    struct wifi_sta_basic_info sta_info;
    wifi_mgmr_ap_sta_info_get(&sta_info, index);
    strncpy(mac, sta_info.sta_mac, sizeof(sta_info.sta_mac) - 1);
}
*/
static void set_disconnect_reason(uint16_t id)
{
    if (id == WLAN_FW_DEAUTH_BY_AP_WHEN_NOT_CONNECTION || id == WLAN_FW_DEAUTH_BY_AP_WHEN_CONNECTION) {
        s_latest_disconnect_reason = IOT_ERROR_CONN_STA_CONN_FAIL;
    }else if (id == WLAN_FW_SCAN_NO_BSSID_AND_CHANNEL) {
        s_latest_disconnect_reason = IOT_ERROR_CONN_STA_AP_NOT_FOUND;
    }else if (id == WLAN_FW_ASSOCIATE_FAIILURE || id == WLAN_FW_TX_ASSOC_FRAME_ALLOCATE_FAIILURE) {
        s_latest_disconnect_reason = IOT_ERROR_CONN_STA_ASSOC_FAIL;
    }else if (id == WLAN_FW_TX_AUTH_FRAME_ALLOCATE_FAIILURE || id == WLAN_FW_AUTHENTICATION_FAIILURE ||
        id == WLAN_FW_AUTH_ALGO_FAIILURE) {
        s_latest_disconnect_reason = IOT_ERROR_CONN_STA_AUTH_FAIL;
    }
}

static void event_cb_wifi_event(input_event_t *event, void *private_data)
{
    //static char *ssid;
    //static char *password;
    struct sm_connect_tlv_desc* ele = NULL;

    switch (event->code) {
        case CODE_WIFI_ON_MGMR_DONE:
        {
            xEventGroupSetBits(wifi_event_group, WIFI_INIT_BIT);
        }
        break;

        case CODE_WIFI_ON_CONNECTED:
        {
            IOT_INFO("Wifi Connected");
        }
        break;

        case CODE_WIFI_ON_DISCONNECT:
        {
            IOT_INFO("Disconnect reason : %s", wifi_mgmr_status_code_str(event->value));
		    IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_BSP_WIFI_EVENT_DEAUTH, wifi_mgmr_status_code_str(event->value), 0);
            xEventGroupSetBits(wifi_event_group, WIFI_STA_DISCONNECT_BIT);
            set_disconnect_reason((uint16_t)event->value);
            /*
            if (s_wifi_connect_timeout == false) {
                esp_wifi_connect();
            } else {
                s_wifi_connect_timeout = false;
            }
            */
            xEventGroupClearBits(wifi_event_group, WIFI_STA_CONNECT_BIT);
            IOT_ERROR("clean bit: WIFI_STA_CONNECT_BIT");
        }
        break;

        case CODE_WIFI_ON_GOT_IP:
        {
            uint32_t ip;
            ip = netif_ip4_addr(&wifiMgmr.wlan_sta.netif)->addr;
            IOT_INFO("got ip:%s", ip4addr_ntoa(&ip));
            s_wifi_connect_timeout = false;
            xEventGroupSetBits(wifi_event_group, WIFI_STA_CONNECT_BIT);
        }

        case CODE_WIFI_ON_AP_STARTED:
        {
            int state = WIFI_STATE_UNKNOWN;
            wifi_mgmr_state_get(&state);
            if (state == WIFI_STATE_CONNECTED_IP_GOT) {
                //do not need do anything
            } else {
                xEventGroupClearBits(wifi_event_group, WIFI_EVENT_BIT_ALL);
                IOT_INFO("SYSTEM_EVENT_AP_START");
                xEventGroupSetBits(wifi_event_group, WIFI_AP_START_BIT);
            }
        }
        break;

        case CODE_WIFI_ON_AP_STOPPED:
        {
            IOT_INFO("SYSTEM_EVENT_AP_STOP");
            xEventGroupSetBits(wifi_event_group, WIFI_AP_STOP_BIT);
        }
        break;

        case CODE_WIFI_ON_AP_STA_ADD:
        {   /*
            uint8_t mac[6];
            memset(mac, 0, sizeof(mac));
            bl_ap_sta_get_mac((uint8_t)event->value, mac);
            IOT_INFO("station: %02x:%02x:%02x:%02x:%02x:%02x join",
				mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);*/
            struct wifi_sta_basic_info sta_info;
            wifi_mgmr_ap_sta_info_get(&sta_info, (uint8_t)event->value);
            IOT_INFO("station: %02x:%02x:%02x:%02x:%02x:%02x join\r\n",
            sta_info.sta_mac[0],sta_info.sta_mac[1],sta_info.sta_mac[2],sta_info.sta_mac[3],sta_info.sta_mac[4],sta_info.sta_mac[5]);
            if (wifi_event_cb) {
			    IOT_DEBUG("0x%p called", wifi_event_cb);
			    (*wifi_event_cb)(IOT_WIFI_EVENT_SOFTAP_STA_JOIN, IOT_ERROR_NONE);
		    }
        }
        break;

        case CODE_WIFI_ON_AP_STA_DEL:
        {   /*
            uint8_t mac[6];
            memset(mac, 0, sizeof(mac));
            bl_ap_sta_get_mac((uint8_t)event->value, mac);
            IOT_INFO("station: %02x:%02x:%02x:%02x:%02x:%02x join",
				mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);*/
            struct wifi_sta_basic_info sta_info;
            wifi_mgmr_ap_sta_info_get(&sta_info, (uint8_t)event->value);
            IOT_INFO("station: %02x:%02x:%02x:%02x:%02x:%02x left\r\n",
            sta_info.sta_mac[0],sta_info.sta_mac[1],sta_info.sta_mac[2],sta_info.sta_mac[3],sta_info.sta_mac[4],sta_info.sta_mac[5]);
            if (wifi_event_cb) {
			    IOT_DEBUG("0x%p called", wifi_event_cb);
			    (*wifi_event_cb)(IOT_WIFI_EVENT_SOFTAP_STA_LEAVE, IOT_ERROR_NONE);
		    }
        }
        break;

        case CODE_WIFI_ON_SCAN_DONE:
        {
            IOT_INFO("Complete scanning");
            xEventGroupSetBits(wifi_event_group, WIFI_SCAN_DONE_BIT);
        }
        break;
        default:
        {
            printf("[APP] [EVT] Unknown code %u, %lld\r\n", event->code, aos_now_ms());
            /*nothing*/
        }
    }
}

iot_error_t iot_bsp_wifi_init ()
{
    EventBits_t uxBits = 0;

	IOT_INFO("[bl602] iot_bsp_wifi_init");

    if(WIFI_INITIALIZED)
		return IOT_ERROR_NONE;

    wifi_event_group = xEventGroupCreate();
    aos_register_event_filter(EV_WIFI, event_cb_wifi_event, NULL);
    tcpip_init(NULL, NULL);
    hal_wifi_start_firmware_task();
    wifi_mgmr_start_background(&wifi_conf);

    uxBits=xEventGroupWaitBits(wifi_event_group, WIFI_INIT_BIT,
				true, false, IOT_WIFI_CMD_TIMEOUT_BL602);

    if(uxBits & WIFI_INIT_BIT) {
        WIFI_INITIALIZED = true;
        IOT_INFO("[bl602] iot_bsp_wifi_init done");
        IOT_DUMP(IOT_DEBUG_LEVEL_DEBUG, IOT_DUMP_BSP_WIFI_INIT_SUCCESS, 0, 0);
        return IOT_ERROR_NONE;
    }
    return IOT_ERROR_INIT_FAIL;
}

static bool is_sta_busy(int status)
{
    return ((status) & WIFI_STATE_CONNECTING || (status) & WIFI_STATE_CONNECTED_IP_GETTING || (status) & WIFI_STATE_CONNECTED_IP_GOT);
}

static bool is_ap_started(int status)
{
    return WIFI_STATE_AP_IS_ENABLED(status);
}

static void stop_sta()
{
    wifi_mgmr_sta_disconnect();
    /*XXX Must make sure sta is already disconnect, otherwise sta disable won't work*/
    bl_os_msleep(WIFI_MGMR_STA_DISCONNECT_DELAY);
    wifi_mgmr_sta_disable(NULL);
}

static void stop_ap()
{
    wifi_mgmr_ap_stop(NULL);
}

static unsigned char char_to_hex(char asccode)
{
    unsigned char ret;

    if('0'<=asccode && asccode<='9')
        ret=asccode-'0';
    else if('a'<=asccode && asccode<='f')
        ret=asccode-'a'+10;
    else if('A'<=asccode && asccode<='F')
        ret=asccode-'A'+10;
    else
        ret=0;

    return ret;
}

static void bssid_str_to_mac(uint8_t *hex, char *bssid, int len)
{
   unsigned char l4,h4;
   int i,lenstr;
   lenstr = len;

   if(lenstr%2) {
       lenstr -= (lenstr%2);
   }

   if(lenstr==0){
       return;
   }

   for(i=0; i < lenstr; i+=2) {
       h4=char_to_hex(bssid[i]);
       l4=char_to_hex(bssid[i+1]);
       hex[i/2]=(h4<<4)+l4;
   }
}

iot_error_t iot_bsp_wifi_set_mode(iot_wifi_conf *conf)
{
    int str_len = 0;
	time_t now;
	struct tm timeinfo;
    int state = WIFI_STATE_UNKNOWN;
	EventBits_t uxBits = 0;
    char ssid[33], password[66];
    char bssid[32];
    uint8_t mac[6];
    char ap_ssid[33], ap_password[66];
    int ap_channel, ap_max_connection;
    uint8_t ap_hidden_ssid;
    wifi_interface_t wifi_interface;

    

	IOT_INFO("iot_bsp_wifi_set_mode = %d", conf->mode);
	IOT_DUMP(IOT_DEBUG_LEVEL_DEBUG, IOT_DUMP_BSP_WIFI_SETMODE, conf->mode, 0);

    switch(conf->mode) {
    case IOT_WIFI_MODE_OFF:
        wifi_mgmr_state_get(&state);
        if (is_sta_busy(state)) {
            stop_sta();
            //wait disconect done event
            uxBits=xEventGroupWaitBits(wifi_event_group, WIFI_STA_DISCONNECT_BIT,
				true, false, IOT_WIFI_CMD_TIMEOUT_BL602);

            if(uxBits & WIFI_STA_DISCONNECT_BIT) {
                IOT_INFO("wifi disconnected");
            }
            else {
				IOT_ERROR("WIFI_STA_DISCONNECT_BIT event Timeout");
				IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_BSP_WIFI_TIMEOUT, mode, __LINE__);
				return IOT_ERROR_CONN_OPERATE_FAIL;
			}
        }
        if (is_ap_started(state)) {
            stop_ap();
            //wait ap stop done event
            uxBits=xEventGroupWaitBits(wifi_event_group, WIFI_AP_STOP_BIT,
				true, false, IOT_WIFI_CMD_TIMEOUT_BL602);

            if(uxBits & WIFI_AP_STOP_BIT) {
                IOT_INFO("AP mode stopped");
            }
            else {
				IOT_ERROR("WIFI_AP_STOP_BIT event Timeout");
				IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_BSP_WIFI_TIMEOUT, conf->mode, __LINE__);
				return IOT_ERROR_CONN_OPERATE_FAIL;
			}
        }
        break;
    case IOT_WIFI_MODE_SCAN:
        //don't need do anything
        if (s_wifi_connect_timeout == true) {
			xEventGroupClearBits(wifi_event_group, WIFI_STA_CONNECT_BIT | WIFI_STA_DISCONNECT_BIT);
            IOT_ERROR("clean bit: WIFI_STA_CONNECT_BIT");
			uxBits = xEventGroupWaitBits(wifi_event_group,
				WIFI_STA_DISCONNECT_BIT | WIFI_STA_CONNECT_BIT,
				true, false, IOT_WIFI_CMD_TIMEOUT_BL602);

			if (uxBits & (WIFI_STA_DISCONNECT_BIT | WIFI_STA_CONNECT_BIT)) {
				IOT_INFO("Ready for wifi scan");
			} else {
				IOT_ERROR("Device is busy connecting to AP");
				IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_BSP_WIFI_TIMEOUT, conf->mode, __LINE__);
				return IOT_ERROR_CONN_OPERATE_FAIL;
			}
		}
        break;
    case IOT_WIFI_MODE_STATION:
        memset(ssid, 0, sizeof(ssid));
        memset(password, 0, sizeof(password));
        memset(bssid, 0, sizeof(bssid));
        memset(mac, 0, sizeof(mac));
        //if in ap mode, stop ap mode
        wifi_mgmr_state_get(&state);
        if (is_ap_started(state)) {
            stop_ap();
            //wait ap stop done event
            uxBits=xEventGroupWaitBits(wifi_event_group, WIFI_AP_STOP_BIT,
				true, false, IOT_WIFI_CMD_TIMEOUT_BL602);

            if(uxBits & WIFI_AP_STOP_BIT) {
                IOT_INFO("AP mode stopped");
            }
            else {
				IOT_ERROR("WIFI_AP_STOP_BIT event Timeout");
				IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_BSP_WIFI_TIMEOUT, conf->mode, __LINE__);
				return IOT_ERROR_CONN_OPERATE_FAIL;
			}
        }
        wifi_interface = wifi_mgmr_sta_enable();
        strncpy(ssid, conf->ssid, sizeof(ssid) - 1);
        strncpy(password, conf->pass, sizeof(password) - 1);
        strncpy(bssid, (const char *)conf->bssid, sizeof(bssid) - 1);
        bssid_str_to_mac(mac, bssid, strlen(bssid));
        if (wifi_mgmr_sta_connect_mid(wifi_interface, ssid, password, NULL, mac, 0, 0, 1, WIFI_CONNECT_PMF_CAPABLE) == -1) {
            IOT_ERROR("Failed to connect");
            return IOT_ERROR_CONN_OPERATE_FAIL;
        }
        uxBits = xEventGroupWaitBits(wifi_event_group, WIFI_STA_CONNECT_BIT,
				true, false, IOT_WIFI_CMD_TIMEOUT_BL602);
		if((uxBits & WIFI_STA_CONNECT_BIT)) {
            wifi_mgmr_state_get(&state);
			IOT_INFO("AP Connected");
			IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_BSP_WIFI_CONNECT_SUCCESS, 0, 0);
		}
		else {
			IOT_ERROR("WIFI_STA_CONNECT_BIT event Timeout %d", s_latest_disconnect_reason);
			IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_BSP_WIFI_CONNECT_FAIL, IOT_WIFI_CMD_TIMEOUT_BL602,
				s_latest_disconnect_reason);

			s_wifi_connect_timeout = true;
			return IOT_ERROR_CONN_OPERATE_FAIL;
		}
        break;
    case IOT_WIFI_MODE_SOFTAP:
        memset(ssid, 0, sizeof(ssid));
        memset(password, 0, sizeof(password));
        strncpy(ap_ssid, conf->ssid, sizeof(ap_ssid) - 1);
        strncpy(ap_password, conf->pass, sizeof(ap_password) - 1);
        ap_channel = IOT_SOFT_AP_CHANNEL;
        ap_hidden_ssid = 0;
        ap_max_connection = 1;
        wifi_interface = wifi_mgmr_ap_enable();

        wifi_mgmr_ap_start_atcmd(wifi_interface, ap_ssid, ap_hidden_ssid, ap_password, ap_channel, ap_max_connection);
        IOT_INFO("wifi_init_softap finished.SSID:%s password:%s",
				ap_ssid, ap_password);

        uxBits=xEventGroupWaitBits(wifi_event_group, WIFI_AP_START_BIT,
				true, false, IOT_WIFI_CMD_TIMEOUT_BL602);

		if(uxBits & WIFI_AP_START_BIT) {
			IOT_INFO("AP Mode Started");
		}
		else {
				IOT_ERROR("WIFI_AP_START_BIT event Timeout");
				IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_BSP_WIFI_TIMEOUT, conf->mode, __LINE__);
				return IOT_ERROR_CONN_SOFTAP_CONF_FAIL;
		}

        break;
    default:
		IOT_ERROR("bl602 cannot support this mode = %d", conf->mode);
		IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_BSP_WIFI_ERROR, conf->mode, __LINE__);
		return IOT_ERROR_CONN_OPERATE_FAIL;
    }
    return IOT_ERROR_NONE;
}

static iot_wifi_auth_mode_t bl_transfer_auth_mode(uint8_t auth)
{
    iot_wifi_auth_mode_t conv_auth_mode;
    if (auth == WIFI_EVENT_BEACON_IND_AUTH_WPA3_SAE || auth == WIFI_EVENT_BEACON_IND_AUTH_WPA2_PSK_WPA3_SAE) {
        conv_auth_mode = IOT_WIFI_AUTH_WPA3_PERSONAL;
    } else if (auth == WIFI_EVENT_BEACON_IND_AUTH_UNKNOWN) {
        conv_auth_mode = IOT_WIFI_AUTH_UNKNOWN;
    } else {
        conv_auth_mode = auth;
    }
    return conv_auth_mode;
}

uint16_t iot_bsp_wifi_get_scan_result(iot_wifi_scan_result_t *scan_result)
{
    uint16_t ap_num = 0;
    uint16_t i;
    uint8_t bssid[6];
    uint8_t scan_mode = 1;
    int channel_num = 0;
    EventBits_t uxBits = 0;
    uint32_t duration = 0;
    memset(bssid, 255, sizeof(bssid));

    wifi_mgmr_scan_adv(NULL, NULL, NULL, channel_num, bssid, NULL, scan_mode, duration);
    uxBits=xEventGroupWaitBits(wifi_event_group, WIFI_SCAN_DONE_BIT,
				true, false, IOT_WIFI_CMD_TIMEOUT_BL602);

    if(!(uxBits & WIFI_SCAN_DONE_BIT)) {
        IOT_INFO("failed to get esp_wifi_scan_get_ap_num");
		IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_BSP_WIFI_ERROR, 0, __LINE__);
		ap_num = 0;
    }
    //ap_num = wifi_mgmr_sta_scanlist_nums_get();
    /*need to initialize the scan buffer before updating*/
	memset(scan_result, 0x0, (IOT_WIFI_MAX_SCAN_RESULT * sizeof(iot_wifi_scan_result_t)));
    
    for(i = 0; i < sizeof(wifiMgmr.scan_items)/sizeof(wifiMgmr.scan_items[0]); i++) {
        if (wifiMgmr.scan_items[i].is_used && (!wifi_mgmr_scan_item_is_timeout(&wifiMgmr, &wifiMgmr.scan_items[i]))) {
            iot_wifi_auth_mode_t conv_auth_mode;
            conv_auth_mode = bl_transfer_auth_mode(wifiMgmr.scan_items[i].auth);

            memcpy(scan_result[ap_num].ssid, wifiMgmr.scan_items[i].ssid, strlen(wifiMgmr.scan_items[i].ssid));
			memcpy(scan_result[ap_num].bssid, wifiMgmr.scan_items[i].bssid, IOT_WIFI_MAX_BSSID_LEN);
            scan_result[ap_num].rssi = wifiMgmr.scan_items[i].rssi;
			scan_result[ap_num].freq = iot_util_convert_channel_freq(wifiMgmr.scan_items[i].channel);
			scan_result[ap_num].authmode = conv_auth_mode;
            ap_num++;
        }
    }
    return ap_num;
}

iot_error_t iot_bsp_wifi_get_mac(struct iot_mac *wifi_mac)
{
    if (wifi_mgmr_sta_mac_get(wifi_mac->addr) != 0) {
        IOT_ERROR("failed to read wifi mac address");
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
	if (cb == NULL) {
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
    uint32_t ip = 0;
    int state = WIFI_STATE_UNKNOWN;
    wifi_mgmr_state_get(&state);
    if (state == WIFI_STATE_CONNECTED_IP_GOT) {
        ip = netif_ip4_addr(&wifiMgmr.wlan_sta.netif)->addr;
        //IOT_DEBUG("Wifi station IP Address :" IPSTR ", ", ip4addr_ntoa(&ip));
        return true;
    }
    return false;
}

iot_error_t iot_bsp_wifi_get_status(void)
{
    iot_error_t ret = IOT_ERROR_NONE;

	ret = s_latest_disconnect_reason;
	return ret;
}
