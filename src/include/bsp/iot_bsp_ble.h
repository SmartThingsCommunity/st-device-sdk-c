/* ***************************************************************************
 *
 * Copyright 2022 Samsung Electronics All Rights Reserved.
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

#ifndef _IOT_BSP_BLE_H_
#define _IOT_BSP_BLE_H_

#if defined(__cplusplus)
extern "C" {
#endif

#include "iot_error.h"

#if !defined(CONFIG_STDK_IOT_CORE_EASYSETUP_X509)
#define HASH_SERIAL_NUMBER_HYBRID_PORTION 4
#define PLAIN_SERIAL_NUMBER_HYBRID_PORTION 4
#define HYBRID_SERIAL_NUMBER_SIZE (HASH_SERIAL_NUMBER_HYBRID_PORTION + PLAIN_SERIAL_NUMBER_HYBRID_PORTION)
#endif

typedef enum {
       IOT_BLE_EVENT_GATT_JOIN,
       IOT_BLE_EVENT_GATT_LEAVE,
       IOT_BLE_EVENT_GATT_FAIL,
} iot_ble_event_t;

typedef bool (*CharWriteCallback)(uint8_t *buf, uint32_t len);
typedef void (*iot_bsp_ble_event_cb_t)(iot_ble_event_t event, iot_error_t error);

/**
 * @brief  Initialize BLE function.
 *
 * This function initializes BLE function
 *
 * @param[in] cb event callback function pointer
 */
void iot_bsp_ble_init(CharWriteCallback cb);

/**
 * @brief  Deinitizlize BLE function.
 *
 * This function deinitalizes BLE function
 */
void iot_bsp_ble_deinit(void);

/**
 * @brief  Get BLE MTU.
 *
 * This function gets BLE MTU.
 *
 * @return
 *   BLE MTU size
 */
uint32_t iot_bsp_ble_get_mtu(void);

/**
 * @brief  Initialize GATT.
 *
 * This function initializes GATT.
 *
 * @param[in] Wi-Fi update support 
 */
void iot_bsp_gatt_init(bool wifi_update_enabled);

/**
 * @brief  Set onboarding completion.
 *
 * @param[in] Onboarding complete status
 */
void iot_bsp_ble_set_onboarding_completion(bool onboarding_complete);

/**
 * @brief  Create advertise packet
 *
 * This function creates advertise packet
 *
 * @param[in] Manufacturer ID
 * @param[in] Setup ID
 * @param[in] Serial number
 */
void iot_create_advertise_packet(char *mnid, char *setupid, char *serial);

/**
 * @brief  Create response packet
 *
 * This function creates response packet
 *
 * @param[in] Device onboarding name
 * @param[in] Serial number
 */
void iot_create_scan_response_packet(char *device_onboarding_id, char *serial);

/**
 * @brief  Send indication
 *
 * This function sends the indication
 *
 * @param[in] Indication message
 * @param[in] Message length
 *
 * @return
 *   0 : Send Success
 *   1 : Send Fail
 */
int iot_send_indication(uint8_t *buf, uint32_t len);

/**
 * @brief  Register BLE event callback
 * This function must be support for BLE onboarding
 * @param[in] cb event callback function pointer
 * @return
 * IOT_ERROR_NONE : Success
 * IOT_ERROR_BAD_REQ : Not supported
 * IOT_ERROR_INVALID_ARGS : Callback function is null
 */
iot_error_t iot_bsp_ble_register_event_cb(iot_bsp_ble_event_cb_t cb);

/**
 * @brief  Clear BLE event callback
 */
void iot_bsp_ble_clear_event_cb(void);

#if defined(__cplusplus)
}
#endif

#endif /* _IOT_BSP_BLE_H_ */
