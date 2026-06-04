/* ***************************************************************************
 *
 * Copyright 2026 Samsung Electronics All Rights Reserved.
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

#ifndef _IOT_CAPS_HELPER_WIFI_INFORMATION_
#define _IOT_CAPS_HELPER_WIFI_INFORMATION_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_WIFIINFORMATION_SUPPORTEDWIFIAUTHTYPES_VALUE_OPEN,
    CAP_ENUM_WIFIINFORMATION_SUPPORTEDWIFIAUTHTYPES_VALUE_WEP,
    CAP_ENUM_WIFIINFORMATION_SUPPORTEDWIFIAUTHTYPES_VALUE_WPA_PSK,
    CAP_ENUM_WIFIINFORMATION_SUPPORTEDWIFIAUTHTYPES_VALUE_WPA2_PSK,
    CAP_ENUM_WIFIINFORMATION_SUPPORTEDWIFIAUTHTYPES_VALUE_EAP,
    CAP_ENUM_WIFIINFORMATION_SUPPORTEDWIFIAUTHTYPES_VALUE_SAE,
    CAP_ENUM_WIFIINFORMATION_SUPPORTEDWIFIAUTHTYPES_VALUE_OWE,
    CAP_ENUM_WIFIINFORMATION_SUPPORTEDWIFIAUTHTYPES_VALUE_FT_PSK,
    CAP_ENUM_WIFIINFORMATION_SUPPORTEDWIFIAUTHTYPES_VALUE_MAX
};

enum {
    CAP_ENUM_WIFIINFORMATION_SUPPORTEDWIFIFREQUENCIES_VALUE__2_4G,
    CAP_ENUM_WIFIINFORMATION_SUPPORTEDWIFIFREQUENCIES_VALUE__5G,
    CAP_ENUM_WIFIINFORMATION_SUPPORTEDWIFIFREQUENCIES_VALUE__6G,
    CAP_ENUM_WIFIINFORMATION_SUPPORTEDWIFIFREQUENCIES_VALUE_MAX
};

const static struct iot_caps_wifiInformation {
    const char *id;
    const struct wifiInformation_attr_ssid {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
    } attr_ssid;
    const struct wifiInformation_attr_supportedWiFiAuthTypes {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_WIFIINFORMATION_SUPPORTEDWIFIAUTHTYPES_VALUE_MAX];
        const char *value_OPEN;
        const char *value_WEP;
        const char *value_WPA_PSK;
        const char *value_WPA2_PSK;
        const char *value_EAP;
        const char *value_SAE;
        const char *value_OWE;
        const char *value_FT_PSK;
    } attr_supportedWiFiAuthTypes;
    const struct wifiInformation_attr_supportedWiFiFrequencies {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_WIFIINFORMATION_SUPPORTEDWIFIFREQUENCIES_VALUE_MAX];
        const char *value__2_4G;
        const char *value__5G;
        const char *value__6G;
    } attr_supportedWiFiFrequencies;
} caps_helper_wifiInformation = {
    .id = "wifiInformation",
    .attr_ssid =
        {
            .name = "ssid",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
        },
    .attr_supportedWiFiAuthTypes =
        {
            .name = "supportedWiFiAuthTypes",
            .property = ATTR_SET_VALUE_ARRAY,
            .valueType = VALUE_TYPE_STRING,
            .values = {"OPEN", "WEP", "WPA-PSK", "WPA2-PSK", "EAP", "SAE", "OWE", "FT-PSK"},
            .value_OPEN = "OPEN",
            .value_WEP = "WEP",
            .value_WPA_PSK = "WPA-PSK",
            .value_WPA2_PSK = "WPA2-PSK",
            .value_EAP = "EAP",
            .value_SAE = "SAE",
            .value_OWE = "OWE",
            .value_FT_PSK = "FT-PSK",
        },
    .attr_supportedWiFiFrequencies =
        {
            .name = "supportedWiFiFrequencies",
            .property = ATTR_SET_VALUE_ARRAY,
            .valueType = VALUE_TYPE_STRING,
            .values = {"2.4G", "5G", "6G"},
            .value__2_4G = "2.4G",
            .value__5G = "5G",
            .value__6G = "6G",
        },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_WIFI_INFORMATION_ */
