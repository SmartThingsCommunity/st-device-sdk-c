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

#include "iot_bsp_nv_data.h"
#include "iot_debug.h"

const char* iot_bsp_nv_get_data_path(iot_nvd_t nv_type) {
	HIT();
	IOT_WARN_CHECK((nv_type < 0 || nv_type > IOT_NVD_MAX), NULL,
			"Invalid args");

	switch (nv_type) {

	/* wifi prov data */
	case IOT_NVD_WIFI_PROV_STATUS:
		return "/fs/WifiProvStatus";
	case IOT_NVD_AP_SSID:
		return "/fs/IotAPSSID";
	case IOT_NVD_AP_PASS:
		return "/fs/IotAPPASS";
	case IOT_NVD_AP_BSSID:
		return "/fs/IotAPBSSID";
	case IOT_NVD_AP_AUTH_TYPE:
		return "/fs/IotAPAuthType";

	/* cloud prov data */
	case IOT_NVD_CLOUD_PROV_STATUS:
		return "/fs/CloudProvStatus";
	case IOT_NVD_SERVER_URL:
		return "/fs/ServerURL";
	case IOT_NVD_SERVER_PORT:
		return "/fs/ServerPort";
	case IOT_NVD_LOCATION_ID:
		return "/fs/LocationID";
	case IOT_NVD_ROOM_ID:
		return "/fs/RoomID";
	case IOT_NVD_LABEL:
		return "/fs/Label";
	case IOT_NVD_DEVICE_ID:
		return "/fs/DeviceID";

	/* TODO: Get Manufacturer data */
	/* stored in stnv partition (manufacturer data) */
	case IOT_NVD_PRIVATE_KEY:
		return "/rom/PrivateKey";
	case IOT_NVD_PUBLIC_KEY:
		return "/rom/PublicKey";
	case IOT_NVD_CA_CERT:
		return "/rom/CACert";
	case IOT_NVD_SUB_CERT:
		return "/rom/SubCert";
	case IOT_NVD_SERIAL_NUM:
		return "/rom/SerialNum";

	default:
		return NULL;
	}
}
