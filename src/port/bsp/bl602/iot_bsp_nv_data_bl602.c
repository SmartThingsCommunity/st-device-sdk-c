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


#include "iot_bsp_nv_data.h"
#include "iot_debug.h"

const char* iot_bsp_nv_get_data_path(iot_nvd_t nv_type)
{
	HIT();
	IOT_WARN_CHECK((nv_type < 0 || nv_type > IOT_NVD_MAX), NULL, "Invalid args");

	switch (nv_type) {

	/* wifi prov data */
	case IOT_NVD_WIFI_PROV_STATUS:
		return "WifiProvStatus";
	case IOT_NVD_AP_SSID:
		return "IotAPSSID";
	case IOT_NVD_AP_PASS:
		return "IotAPPASS";
	case IOT_NVD_AP_BSSID:
		return "IotAPBSSID";
	case IOT_NVD_AP_AUTH_TYPE:
		return "IotAPAuthType";
	/* wifi prov data */

	/* cloud prov data */
	case IOT_NVD_CLOUD_PROV_STATUS:
		return "CloudProvStatus";
	case IOT_NVD_SERVER_URL:
		return "ServerURL";
	case IOT_NVD_SERVER_PORT:
		return "ServerPort";
	case IOT_NVD_LABEL:
		return "Label";
	/* cloud prov data */

	case IOT_NVD_DEVICE_ID:
		return "DeviceID";
	case IOT_NVD_MISC_INFO:
		return "MiscInfo";

	/* stored in stnv partition (manufacturer data) */
	case IOT_NVD_PRIVATE_KEY:
		return "PrivateKey";
	case IOT_NVD_PUBLIC_KEY:
		return "PublicKey";
	case IOT_NVD_ROOT_CA_CERT:
		return "RootCert";
	case IOT_NVD_SUB_CA_CERT:
		return "SubCert";
	case IOT_NVD_DEVICE_CERT:
		return "DeviceCert";
	case IOT_NVD_SERIAL_NUM:
		return "SerialNum";
	/* stored in stnv partition (manufacturer data) */

	default:
		return NULL;
	}
}
