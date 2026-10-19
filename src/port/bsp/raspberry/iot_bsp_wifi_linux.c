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

#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/route.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "iot_bsp_wifi.h"
#include "iot_debug.h"
#include "iot_os_util.h"
#include "iot_util.h"
#include "wifi_supplicant.h"

bool g_scanning = false;
iot_wifi_status g_wifi_status = IOT_WIFI_STATUS_UNKNOWN;
iot_wifi_disconnected_reason g_last_disconnected_reason = IOT_WIFI_DISCONNECTED_REASON_UNKNOWN;

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

iot_error_t iot_bsp_wifi_init(void)
{
    supplicant_initialise_wifi();
    return IOT_ERROR_NONE;
}

static void _fill_ip_status(iot_wifi_info *wifi_info)
{
    struct ifreq ifr;
    int sockfd;
    char *ctrl_ifname = NULL;

    if (supplicant_get_wireless_interface(&ctrl_ifname)) {
        IOT_ERROR("unable to fetch wireless interface name");
        return; /* ip_status stays IOT_IP_STATUS_UNKNOWN */
    }

    sockfd = _create_socket();
    if (sockfd < 0) {
        free(ctrl_ifname);
        return;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ctrl_ifname, IF_NAMESIZE - 1);
    if (ioctl(sockfd, SIOCGIFADDR, &ifr) == 0) {
        wifi_info->ip = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
        wifi_info->ip_status = IOT_IP_STATUS_ASSIGNED;
    } else if (errno == EADDRNOTAVAIL) {
        /* interface is up without an IPv4 address (e.g. DHCP in progress) */
        wifi_info->ip_status = IOT_IP_STATUS_NOT_ASSIGNED;
    } else {
        IOT_ERROR("ioctl(%d, %s): 0x%x", errno, strerror(errno), SIOCGIFADDR);
    }

    close(sockfd);
    free(ctrl_ifname);
}

void iot_bsp_wifi_get_status(iot_wifi_info *wifi_info)
{
    memset(wifi_info, 0, sizeof(iot_wifi_info));

    if (!supplicant_is_station_active()) {
        wifi_info->wifi_status = IOT_WIFI_STATUS_IDLE;
        return;
    }

    IOT_DEBUG("wifi status: %d", g_wifi_status);
    wifi_info->wifi_status = g_wifi_status;
    wifi_info->last_disconnected_reason = g_last_disconnected_reason;
    if (wifi_info->wifi_status == IOT_WIFI_STATUS_CONNECTED) {
        iot_wifi_scan_result_t ap = {0};

        if (supplicant_get_current_ap(&ap) == 0) {
            memcpy(wifi_info->ap_ssid, ap.ssid, ap.ssid_len);
            memcpy(wifi_info->bssid.addr, ap.bssid, IOT_WIFI_MAX_BSSID_LEN);
            wifi_info->rssi = ap.rssi;
        }
        _fill_ip_status(wifi_info);
    }
}

iot_error_t iot_bsp_wifi_set_mode(iot_wifi_conf *conf)
{
    char ssid[IOT_WIFI_MAX_SSID_LEN + 1];
    char pass[IOT_WIFI_MAX_PASS_LEN + 1];
    int ret;

    IOT_INFO("iot_bsp_wifi_set_mode = %d", conf->mode);

    switch (conf->mode) {
        case IOT_WIFI_MODE_OFF:
            /* TODO: set wifi mode off */
            break;

        case IOT_WIFI_MODE_SCAN:
            if (!supplicant_is_scan_mode()) {
                ret = supplicant_start_station();
                if (ret < 0)
                    return IOT_ERROR_CONN_OPERATE_FAIL;
            }
            if (!g_scanning) {
                supplicant_start_scan();
                g_scanning = true;
            }
            break;

        case IOT_WIFI_MODE_STATION:
            strncpy(ssid, conf->ssid, IOT_WIFI_MAX_SSID_LEN);
            ssid[IOT_WIFI_MAX_SSID_LEN] = 0;
            strncpy(pass, conf->pass, IOT_WIFI_MAX_PASS_LEN);
            pass[IOT_WIFI_MAX_PASS_LEN] = 0;

            if (!supplicant_is_station_active()) {
                ret = supplicant_start_station();
                if (ret < 0) {
                    IOT_ERROR("failed to start station mode (%d)", ret);
                    return IOT_ERROR_CONN_STA_CONF_FAIL;
                }
            }
            ret = supplicant_join_network(ssid, pass, conf->authmode, conf->hidden);
            if (ret < 0) {
                IOT_ERROR("failed to join network (%d)", ret);
                return IOT_ERROR_CONN_STA_CONF_FAIL;
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
            IOT_DEBUG("wifi_init_softap finished. SSID:%s password:%s", ssid, pass);
            break;

        default:
            IOT_ERROR("Linux cannot support this mode = %d", conf->mode);
            return IOT_ERROR_BAD_REQ;
    }

    return IOT_ERROR_NONE;
}

#define SCAN_COMPLETE_POLL_INTERVAL_MS 500
#define SCAN_COMPLETE_MAX_POLL 20 /* up to 10 seconds */

static void _wait_scan_complete(void)
{
    int i;

    /* the Scanning property flips to true shortly after the trigger */
    IOT_DELAY(SCAN_COMPLETE_POLL_INTERVAL_MS);
    for (i = 0; i < SCAN_COMPLETE_MAX_POLL; i++) {
        if (!g_scanning)
            return;
        IOT_DELAY(SCAN_COMPLETE_POLL_INTERVAL_MS);
    }
    IOT_WARN("scan did not complete within timeout");
}

uint16_t iot_bsp_wifi_get_scan_result(iot_wifi_scan_result_t *scan_result)
{
    uint16_t ap_num = 0;
    int i;
    iot_wifi_scan_result_t *ap_list;
    int ret;

    _wait_scan_complete();

    ap_list = (iot_wifi_scan_result_t *)calloc(IOT_WIFI_MAX_SCAN_RESULT, sizeof(iot_wifi_scan_result_t));
    if (!ap_list) {
        IOT_ERROR("failed to malloc for ap_list");
        return 0;
    }
    ap_num = supplicant_get_scanned_ap_list(ap_list);
    if (ap_num == 0)
        IOT_INFO("No APs found!");

    memset(scan_result, 0x0, (IOT_WIFI_MAX_SCAN_RESULT * sizeof(iot_wifi_scan_result_t)));
    for (i = 0; i < ap_num; i++) {
        memcpy(scan_result[i].ssid, ap_list[i].ssid, ap_list[i].ssid_len);
        memcpy(scan_result[i].bssid, ap_list[i].bssid, IOT_WIFI_MAX_BSSID_LEN);

        scan_result[i].ssid_len = ap_list[i].ssid_len;
        scan_result[i].hexssid_needed = ap_list[i].hexssid_needed;
        scan_result[i].rssi = ap_list[i].rssi;
        scan_result[i].freq = ap_list[i].freq;
        scan_result[i].authmode = ap_list[i].authmode;

        IOT_DEBUG("Linux AP[%d]: ssid=%s, mac=%02X:%02X:%02X:%02X:%02X:%02X, rssi=%d, freq=%d, authmode=%d", i + 1,
                  scan_result[i].ssid, scan_result[i].bssid[0], scan_result[i].bssid[1], scan_result[i].bssid[2],
                  scan_result[i].bssid[3], scan_result[i].bssid[4], scan_result[i].bssid[5], scan_result[i].rssi,
                  scan_result[i].freq, scan_result[i].authmode);
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

    return supported_mode_bits;
}
