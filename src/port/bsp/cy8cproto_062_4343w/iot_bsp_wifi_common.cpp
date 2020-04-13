/* ***************************************************************************
 *
 * Copyright 2019-2020 Samsung Electronics All Rights Reserved.
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

#include "iot_debug.h"
#include "iot_bsp_wifi.h"
#include "iot_os_util.h"
#include "iot_util.h"

iot_error_t iot_bsp_wifi_init()
{
	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_wifi_set_mode(iot_wifi_conf *conf)
{
	int str_len = 0;

	switch(conf->mode) {
	case IOT_WIFI_MODE_OFF: {
		// TODO: Turn off WiFi
		break;
	}
	case IOT_WIFI_MODE_SCAN: {
		//TODO: ensure AP is turned off and scan
		break;
	}
	case IOT_WIFI_MODE_STATION: {
		//TODO: ensure AP is turned off and STA is turned on

		break;
	}
	case IOT_WIFI_MODE_SOFTAP: {
		//TODO: ensure AP is turned on
		break;
	}
	default:
		IOT_ERROR("iot bsp wifi can't support this mode = %d", conf->mode);
		return IOT_ERROR_INIT_FAIL;
	}

	return IOT_ERROR_NONE;
}

uint16_t iot_bsp_wifi_get_scan_result(iot_wifi_scan_result_t *scan_result)
{
	return 0;
}

//TODO: get correct MAC address
iot_error_t iot_bsp_wifi_get_mac(struct iot_mac *wifi_mac)
{
	return IOT_ERROR_NONE;
}

iot_wifi_freq_t iot_bsp_wifi_get_freq(void)
{
	return IOT_WIFI_FREQ_2_4G_ONLY;
}
