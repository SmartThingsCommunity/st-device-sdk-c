/* ***************************************************************************
 *
 * Copyright (c) 2020 Samsung Electronics All Rights Reserved.
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
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <iot_error.h>
#include <iot_bsp_wifi.h>

iot_error_t __wrap_iot_bsp_wifi_get_mac(struct iot_mac *wifi_mac)
{
    unsigned char *mock_mac;
    if (wifi_mac == NULL) {
        return IOT_ERROR_INVALID_ARGS;
    }

    mock_mac = mock_ptr_type(unsigned char *);
    if (mock_mac != NULL) {
        memcpy(wifi_mac->addr, mock_mac, IOT_WIFI_MAX_BSSID_LEN);
    }
    return mock_type(iot_error_t);
}

const iot_wifi_scan_result_t mock_wifi_scan_result[IOT_WIFI_MAX_SCAN_RESULT] = {
        { { 0xe1, 0xf2, 0x03, 0x14, 0x25, 0x36 },"fakeSsid_01_XXXXXXXXXX",-60,2412,IOT_WIFI_AUTH_WPA_WPA2_PSK},
        { { 0xf1, 0x02, 0x13, 0x24, 0x35, 0x46 },"fakeSsid_02_XXXXXXXXX",-61,2417,IOT_WIFI_AUTH_WPA2_PSK},
        { { 0x01, 0x12, 0x23, 0x34, 0x45, 0x56 },"fakeSsid_03_XXXXXXXX",-62,2422,IOT_WIFI_AUTH_WPA_WPA2_PSK},
        { { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 },"fakeSsid_04_XXXXXXX",-63,2427,IOT_WIFI_AUTH_OPEN},
        { { 0x21, 0x32, 0x43, 0x54, 0x65, 0x76 },"fakeSsid_05_XXXXXX",-64,2432,IOT_WIFI_AUTH_WPA_WPA2_PSK},
        { { 0x31, 0x42, 0x53, 0x64, 0x75, 0x86 },"fakeSsid_06_XXXXX",-65,2442,IOT_WIFI_AUTH_WPA_PSK},
        { { 0x41, 0x52, 0x63, 0x74, 0x85, 0x96 },"fakeSsid_07_XXXX",-66,2447,IOT_WIFI_AUTH_WPA_WPA2_PSK},
        { { 0x51, 0x62, 0x73, 0x84, 0x95, 0xa6 },"fakeSsid_08_XXX",-67,2452,IOT_WIFI_AUTH_WPA2_PSK},
        { { 0x61, 0x72, 0x83, 0x94, 0xa5, 0xb6 },"fakeSsid_09_XX",-68,2457,IOT_WIFI_AUTH_WPA_WPA2_PSK},
        { { 0x71, 0x82, 0x93, 0xa4, 0xb5, 0xc6 },"fakeSsid_10_X",-68,2462,IOT_WIFI_AUTH_WEP},
        { { 0x81, 0x92, 0xa3, 0xb4, 0xc5, 0xd6 },"fakeSsid_11",-69,2467,IOT_WIFI_AUTH_WPA2_PSK},
        { { 0x91, 0xa2, 0xb3, 0xc4, 0xd5, 0xe6 },"fakeSsid_12_X",-60,2472,IOT_WIFI_AUTH_WPA_PSK},
        { { 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6 },"fakeSsid_13_XX",-61,2484,IOT_WIFI_AUTH_WPA_PSK},
        { { 0xb1, 0xc2, 0xd3, 0xe4, 0xf5, 0x16 },"fakeSsid_14_XXX",-62,2412,IOT_WIFI_AUTH_WPA_WPA2_PSK},
        { { 0xc1, 0xd2, 0xe3, 0xf4, 0x05, 0x26 },"fakeSsid_15_XXXXX",-63,2417,IOT_WIFI_AUTH_WPA_WPA2_PSK},
        { { 0xd1, 0xe2, 0xf3, 0x04, 0x15, 0x37 },"fakeSsid_16_XXXXXX",-64,2422,IOT_WIFI_AUTH_WPA2_PSK},
        { { 0xe2, 0xf3, 0x04, 0x15, 0x26, 0x48 },"fakeSsid_17_XXXXXXX",-65,2427,IOT_WIFI_AUTH_WPA_WPA2_PSK},
        { { 0xf2, 0x03, 0x14, 0x25, 0x36, 0x59 },"fakeSsid_18_XXXXXXXX",-66,2432,IOT_WIFI_AUTH_WPA_WPA2_PSK},
        { { 0x02, 0x13, 0x24, 0x35, 0x46, 0x6a },"fakeSsid_19_XXXXXXXXX",-67,2437,IOT_WIFI_AUTH_OPEN},
        { { 0x12, 0x23, 0x34, 0x45, 0x56, 0x7b },"fakeSsid_20_XXXXXXXXXX",-68,2442,IOT_WIFI_AUTH_WPA2_ENTERPRISE},
};

uint16_t __wrap_iot_bsp_wifi_get_scan_result(iot_wifi_scan_result_t *scan_result)
{
    if (scan_result == NULL) {
        return IOT_ERROR_INVALID_ARGS;
    }

    uint16_t mock_scan_num = mock_type(uint16_t);
    for (int i = 0; i < mock_scan_num; i++)
    {
        memcpy(scan_result[i].bssid, mock_wifi_scan_result[i].bssid, IOT_WIFI_MAX_BSSID_LEN);
        strncpy(scan_result[i].ssid, mock_wifi_scan_result[i].ssid, IOT_WIFI_MAX_SSID_LEN);
        scan_result[i].rssi = mock_wifi_scan_result[i].rssi;
        scan_result[i].freq = mock_wifi_scan_result[i].freq;
        scan_result[i].authmode = mock_wifi_scan_result[i].authmode;
    }
    return mock_scan_num;
}

iot_error_t __wrap_iot_bsp_system_set_time_in_sec(const char* time_in_sec)
{
    check_expected(time_in_sec);
    return IOT_ERROR_NONE;
}

iot_error_t __wrap_iot_bsp_wifi_set_mode(iot_wifi_conf *conf)
{
    check_expected(conf->mode);
    return (int)mock();
}