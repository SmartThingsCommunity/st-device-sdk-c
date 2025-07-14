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
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#if !defined(CONFIG_STDK_IOT_CORE_EASYSETUP_X509)
#define HASH_SERIAL_NUMBER_HYBRID_PORTION 4
#define PLAIN_SERIAL_NUMBER_HYBRID_PORTION 4
#define HYBRID_SERIAL_NUMBER_SIZE (HASH_SERIAL_NUMBER_HYBRID_PORTION + PLAIN_SERIAL_NUMBER_HYBRID_PORTION)
#endif

/**
 * @brief Enums for BLE connection events.
 */
typedef enum {
    IOT_BLE_CONNECTION_EVENT_CONNECTED,         /**< @brief Event for BLE connection */
    IOT_BLE_CONNECTION_EVENT_DISCONNECTED,      /**< @brief Event for BLE disconnection */
} iot_ble_conn_evt_t;

/**
 * @brief Callback definition for BLE connection events.
 *
 * @param[in] evt Event for BLE connection.
 */
typedef void (*iot_bsp_ble_connection_cb_t)(iot_ble_conn_evt_t evt);

/**
 * @brief Callback definition for BLE GATT write event.
 *
 * @param[in] buf received data for write event
 * @param[in] len data length
 */
typedef bool (*iot_bsp_ble_write_cb_t)(uint8_t *buf, uint32_t len);

/**
 * @brief Callback functions for BLE port layer
 */
typedef struct {
    iot_bsp_ble_connection_cb_t conn_cb;
    iot_bsp_ble_write_cb_t write_cb;
} iot_ble_cbs_t;

/**
 * @brief  Initialize BLE function.
 *
 * This function initializes BLE function
 *
 * @param[in] ble_cbs BLE callbacks
 */
iot_error_t iot_bsp_ble_init(iot_ble_cbs_t *ble_cbs);

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
 * @brief  Start BLE advertisement
 *
 * @param[in] mn_code 2 bytes manufacturer code for manufacturer data in advertisement
 * @param[in] mn_data manufacturer data in advertisement
 * @param[in] mn_data_len mn_data length
 * @param[in] local_name local name in advertisement
 *
 * @return
 *   0 : Send Success
 *   1 : Send Fail
 */
int iot_bsp_ble_start_adv(uint16_t mn_code, uint8_t *mn_data, size_t mn_data_len, char *local_name);

/**
 * @brief  Get BLE MAC address
 *
 * @param[out] mac_address 6 btyes mac address
 *
 * @return
 *   0 : Send Success
 *   1 : Send Fail
 */
int iot_bsp_ble_get_mac_address(uint8_t mac_address[6]);

#if defined(__cplusplus)
}
#endif

#endif /* _IOT_BSP_BLE_H_ */
