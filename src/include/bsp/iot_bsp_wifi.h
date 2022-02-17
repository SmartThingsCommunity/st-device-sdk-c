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

#ifndef _IOT_WIFI_H_
#define _IOT_WIFI_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "iot_error.h"

#define IOT_WIFI_MAX_SSID_LEN	(32)
#define IOT_WIFI_MAX_PASS_LEN	(64)
#define IOT_WIFI_MAX_BSSID_LEN (6)
#define IOT_WIFI_MAX_SCAN_RESULT (20)
#define IOT_SOFT_AP_CHANNEL (1)
#define IOT_WIFI_CMD_TIMEOUT	5000

typedef enum {
	IOT_WIFI_MODE_OFF = 0,
	IOT_WIFI_MODE_SCAN,
	IOT_WIFI_MODE_STATION,
	IOT_WIFI_MODE_SOFTAP,
	IOT_WIFI_MODE_P2P,

	IOT_WIFI_MODE_UNDEFINED = 0x20,
} iot_wifi_mode_t;

typedef enum {
	IOT_WIFI_FREQ_2_4G_ONLY = 0,
	IOT_WIFI_FREQ_5G_ONLY,
	IOT_WIFI_FREQ_2_4G_5G_BOTH,
} iot_wifi_freq_t;

typedef enum {
	IOT_WIFI_AUTH_OPEN = 0,
	IOT_WIFI_AUTH_WEP,
	IOT_WIFI_AUTH_WPA_PSK,
	IOT_WIFI_AUTH_WPA2_PSK,
	IOT_WIFI_AUTH_WPA_WPA2_PSK,
	IOT_WIFI_AUTH_WPA2_ENTERPRISE,
	IOT_WIFI_AUTH_WPA3_PERSONAL,
	IOT_WIFI_AUTH_UNKNOWN,
	IOT_WIFI_AUTH_MAX
} iot_wifi_auth_mode_t;

typedef enum {
	IOT_WIFI_EVENT_SOFTAP_STA_JOIN,
	IOT_WIFI_EVENT_SOFTAP_STA_LEAVE,
	IOT_WIFI_EVENT_SOFTAP_STA_FAIL,
} iot_wifi_event_t;

typedef uint32_t iot_wifi_auth_mode_bits_t;

static inline uint32_t _iot_wifi_auth_mode_bit(iot_wifi_auth_mode_t auth_mode) {
	return (1u << auth_mode);
}
#define IOT_WIFI_AUTH_MODE_BIT(_auth_mode)	_iot_wifi_auth_mode_bit(_auth_mode)

#define IOT_WIFI_AUTH_MODE_BIT_ALL	(	\
			IOT_WIFI_AUTH_MODE_BIT(IOT_WIFI_AUTH_OPEN) | \
			IOT_WIFI_AUTH_MODE_BIT(IOT_WIFI_AUTH_WEP) | \
			IOT_WIFI_AUTH_MODE_BIT(IOT_WIFI_AUTH_WPA_PSK) | \
			IOT_WIFI_AUTH_MODE_BIT(IOT_WIFI_AUTH_WPA2_PSK) | \
			IOT_WIFI_AUTH_MODE_BIT(IOT_WIFI_AUTH_WPA_WPA2_PSK) | \
			IOT_WIFI_AUTH_MODE_BIT(IOT_WIFI_AUTH_WPA2_ENTERPRISE) | \
			IOT_WIFI_AUTH_MODE_BIT(IOT_WIFI_AUTH_WPA3_PERSONAL)	)

/**
 * @brief Contains a "wifi stack configuration" data
 */
typedef struct {
	iot_wifi_mode_t mode;					/**< @brief wifi operation mode */
	char ssid[IOT_WIFI_MAX_SSID_LEN+1];		/**< @brief wifi SSID string */
	char pass[IOT_WIFI_MAX_PASS_LEN+1];		/**< @brief wifi password string */
	uint8_t bssid[IOT_WIFI_MAX_BSSID_LEN];	/**< @brief wifi mac address */
	iot_wifi_auth_mode_t authmode;			/**< @brief wifi authentication mode for station and softap*/
} iot_wifi_conf;

/**
 * @brief Contains a "wifi scan" data
 */
typedef struct {
	uint8_t bssid[IOT_WIFI_MAX_BSSID_LEN];	/**< @brief wifi mac address */
	uint8_t ssid[IOT_WIFI_MAX_SSID_LEN+1];	/**< @brief wifi SSID string */
	int8_t  rssi;							/**< @brief wifi signal strength */
	uint16_t freq;							/**< @brief wifi operation channel */
	iot_wifi_auth_mode_t authmode;			/**< @brief wifi authentication mode */
} iot_wifi_scan_result_t;

/**
 * @brief Contains "wifi mac" data
 */
struct iot_mac {
	unsigned char addr[IOT_WIFI_MAX_BSSID_LEN];	/**< @brief wifi mac address */
};

/**
 * @brief  Initialize Wi-Fi function
 *
 * This function initializes Wi-Fi
 *
 * @return
 *  IOT_ERROR_NONE : succeed
 */

iot_error_t iot_bsp_wifi_init();

/**
 * @brief  Set the Wi-Fi mode
 *
 * This function set the wifi operating mode as scan, station and softap
 *
 * @param[in] mode			Wi-Fi operation mode
 * @return
 *   IOT_ERROR_NONE : succeed
 */
iot_error_t iot_bsp_wifi_set_mode(iot_wifi_conf *conf);

/**
 * @brief  Get the AP scan result
 *
 * This function get the scan result
 *
 * @param[out] iot_wifi_scan_result_t array to save AP list
 * @return
 *   number of APs found
 */
uint16_t iot_bsp_wifi_get_scan_result(iot_wifi_scan_result_t *scan_result);

/**
 * @brief  Get the Wi-Fi MAC
 *
 * This function get the Wi-Fi MAC
 *
 * @param[out] iot_mac array to save Wi-Fi MAC
 * @return
 * IOT_ERROR_NONE : Success
 * IOT_ERROR_READ_FAIL
 */
iot_error_t iot_bsp_wifi_get_mac(struct iot_mac *wifi_mac);


/**
 * @brief  Get the Wi-Fi Frequency band
 *
 * This function get the Wi-Fi Frequency band
 *
 * @return
 * IOT_WIFI_FREQ_2_4G_ONLY : 2.4GHz only supported
 * IOT_WIFI_FREQ_5G_ONLY : 5GHz only supported
 * IOT_WIFI_FREQ_2_4G_5G_BOTH : 2.4GHz and 5GHz both supported
 */
iot_wifi_freq_t iot_bsp_wifi_get_freq(void);

/**
 * @brief  Wi-Fi event callback function type
 */
typedef void (*iot_bsp_wifi_event_cb_t)(iot_wifi_event_t event, iot_error_t error);

/**
 * @brief  Register Wi-Fi event callback
 * @param[in] cb event callback function pointer
 * @return
 * IOT_ERROR_NONE : Success
 * IOT_ERROR_BAD_REQ : Not supported
 * IOT_ERROR_INVALID_ARGS : Callback function is null
 */
iot_error_t iot_bsp_wifi_register_event_cb(iot_bsp_wifi_event_cb_t cb);

/**
 * @brief  Clear Wi-Fi event callback
 */
void iot_bsp_wifi_clear_event_cb(void);

/**
 * @brief  Get Wi-Fi module's supported Authentication/Encryption modes
 *
 * This function get Wi-Fi module's Authentication/Encryption modes
 *
 * @return IOT_WIFI_AUTH_MODE_BIT() based bits
 */
iot_wifi_auth_mode_bits_t iot_bsp_wifi_get_auth_mode(void);

#ifdef __cplusplus
}
#endif

#endif /* _IOT_WIFI_H_ */
