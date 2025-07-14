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

#include "iot_bsp_ble.h"

#include <stdint.h>
#include <string.h>

#include "bluez/advertisement.h"
#include "bluez/bluez_device.h"
#include "bluez/gatt_service.h"
#include "gdbus/gdbus_util.h"

iot_ble_cbs_t *g_ble_cbs;

iot_error_t iot_bsp_ble_init(iot_ble_cbs_t *ble_cbs)
{
    g_ble_cbs = ble_cbs;
    gdbus_init_loop();
    start_advertisement_server();
    start_gatt_service();
    register_gatt_application();
    init_bluez_device();

    return IOT_ERROR_NONE;
}

void iot_bsp_ble_deinit(void)
{
}

int iot_bsp_ble_start_adv(uint16_t mn_code, uint8_t *mn_data, size_t mn_data_len, char *local_name)
{
	stop_advertisement();
	set_advertisement_data(mn_code, mn_data, mn_data_len, local_name);
	start_advertisement();
	return 0;
}

int iot_bsp_ble_stop_adv(void)
{
	stop_advertisement();
	return 0;
}

int iot_send_indication(uint8_t *buf, uint32_t len)
{
	send_data_over_gatt(buf, len);
	return 0;
}

uint32_t iot_bsp_ble_get_mtu(void)
{
	return get_mtu();
}

int iot_bsp_ble_get_mac_address(uint8_t mac_address[6])
{
	return get_bt_dev_address(mac_address);
}

int iot_bsp_ble_disconnect(void)
{
	disconnect_bluez_device();
	return 0;
}
