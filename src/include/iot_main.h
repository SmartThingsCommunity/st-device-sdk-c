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

#ifndef _IOT_MAIN_H_
#define _IOT_MAIN_H_

#include "st_dev.h"
#include "iot_mqtt_client.h"
#include "iot_error.h"
#include "iot_bsp_wifi.h"
#include "iot_os_util.h"
#include "iot_crypto.h"
#include "iot_os_net.h"

#define IOT_WIFI_PROV_SSID_LEN		(31 + 1)
#define IOT_WIFI_PROV_PASSWORD_LEN 	(63 + 1)

#define IOT_BUF_TX_SIZE 3500
#define IOT_BUF_RX_SIZE 512

#define IOT_EVENT_BIT_COMMAND		(1 << 0)
#define IOT_EVENT_BIT_CAPABILITY	(1 << 1)
#define IOT_EVENT_BIT_EASYSETUP_REQ	(1 << 2)
#define IOT_EVENT_BIT_EASYSETUP_RESP	(1 << 3)
#define IOT_EVENT_BIT_EASYSETUP_CONFIRM	(1 << 4)
#define IOT_EVENT_BIT_ALL	(IOT_EVENT_BIT_COMMAND | IOT_EVENT_BIT_CAPABILITY | IOT_EVENT_BIT_EASYSETUP_REQ)

enum _iot_noti_type {
	/* Common notifications */
	_IOT_NOTI_TYPE_UNKNOWN = IOT_NOTI_TYPE_UNKNOWN,

	_IOT_NOTI_TYPE_DEV_DELETED = IOT_NOTI_TYPE_DEV_DELETED,
	_IOT_NOTI_TYPE_RATE_LIMIT = IOT_NOTI_TYPE_RATE_LIMIT,
	_IOT_NOTI_TYPE_QUOTA_REACHED = IOT_NOTI_TYPE_QUOTA_REACHED,

	/* Internal only notifications */
	_IOT_NOTI_TYPE_JWT_EXPIRED,
};

enum iot_command_type {
	IOT_COMMAND_READY_TO_CTL,

	IOT_COMMAND_NETWORK_MODE,
	IOT_COMMAND_CHECK_PROV_STATUS,
	IOT_COMMAND_SELF_CLEANUP,

	IOT_COMMAND_CHECK_CLOUD_STATE,
	IOT_COMMAND_CLOUD_REGISTERING,
	IOT_COMMAND_CLOUD_REGISTERED,
	IOT_COMMAND_CLOUD_CONNECTING,

	IOT_COMMAND_NOTIFICATION_RECEIVED,

	IOT_COMMAND_TYPE_MAX, /* MAX : under 32 */
	IOT_CMD_STATE_HANDLE,
};

enum iot_easysetup_step {
	IOT_EASYSETUP_STEP_DEVICEINFO,
	IOT_EASYSETUP_STEP_KEYINFO,
	IOT_EASYSETUP_STEP_CONFIRMINFO,
	IOT_EASYSETUP_STEP_CONFIRM,
	IOT_EASYSETUP_STEP_WIFISCANINFO,
	IOT_EASYSETUP_STEP_WIFIPROVIONINGINFO,
	IOT_EASYSETUP_STEP_SETUPCOMPLETE,
	IOT_EASYSETUP_STEP_LOG_SYSTEMINFO,
	IOT_EASYSETUP_STEP_LOG_CREATE_DUMP,
	IOT_EASYSETUP_STEP_LOG_GET_DUMP,
};

enum iot_connect_type {
	IOT_CONNECT_TYPE_REGISTRATION,
	IOT_CONNECT_TYPE_COMMUNICATION,
};

typedef enum iot_state_type {
	IOT_STATE_CHANGE_FAILED = -2,
	IOT_STATE_UNKNOWN = -1,

	IOT_STATE_INITIALIZED = 0,

	IOT_STATE_PROV_ENTER,
	IOT_STATE_PROV_CONFIRMING,
	IOT_STATE_PROV_DONE,

	IOT_STATE_CLOUD_DISCONNECTED,
	IOT_STATE_CLOUD_REGISTERING,

	IOT_STATE_CLOUD_CONNECTING,
	IOT_STATE_CLOUD_CONNECTED,
} iot_state_t;

enum iot_state_opt {
	IOT_STATE_OPT_NONE,
	IOT_STATE_OPT_NEED_INTERACT,
};

/**
 * @brief Contains "uuid" data
 */
struct iot_uuid {
	unsigned char id[16];	/**< @brief actual uuid values, 16 octet */
};

/**
 * @brief Contains "wifi provisioning" data
 */
struct iot_wifi_prov_data {
	char ssid[IOT_WIFI_PROV_SSID_LEN];			/**< @brief wifi SSID string */
	char password[IOT_WIFI_PROV_PASSWORD_LEN];	/**< @brief wifi password string */
	struct iot_mac bssid;						/**< @brief wifi mac addresss struct */
	iot_wifi_auth_mode_t security_type;			/**< @brief wifi security type such as WEP, PSK2.. */
};

/**
 * @brief Contains "cloud provisioning" data
 */
struct iot_cloud_prov_data {
	char *broker_url;				/**< @brief broker url for mqtt */
	int  broker_port;				/**< @brief broker port num for mqtt */
	struct iot_uuid location_id;	/**< @brief location id for ST(server) management */
	struct iot_uuid room_id;		/**< @brief room id for ST(server) management */
	char *label;					/**< @brief device name, got from the mobile */
};

/**
 * @brief Contains "device configuration" data
 */
struct iot_devconf_prov_data {
	char *device_onboarding_id;		/**< @brief onboarding id, determined in devworks */
	char *mnid;						/**< @brief mnid, determined in devworks */
	char *setupid;					/**< @brief setupid, determined in devworks */
	char *device_type;				/**< @brief device_type, determined in devworks */
	char *vid;						/**< @brief vid, determined in devworks */
	int ownership_validation_type;	/**< @brief onboarding process validation type, JUSTWORKS, BUTTON, PIN, QR */
	iot_crypto_pk_type_t pk_type;	/**< @brief Authentication type, determined in devworks */
	char *hashed_sn;				/**< @brief hashed serial, self-generating values during onboarding process */
};

/**
 * @brief Contains "all device's provisioning" data
 */
struct iot_device_prov_data {
	struct iot_wifi_prov_data wifi;		/**< @brief wifi provisionig data, refer to iot_wifi_prov_data struct */
	struct iot_cloud_prov_data cloud;	/**< @brief cloud provisionig data, refer to iot_cloud_prov_data struct */
};

/**
 * @brief Contains "internal command" data
 */
struct iot_command {
	enum iot_command_type cmd_type;		/**< @brief command type to handle device */
	void *param;						/**< @brief additional inform for each command */
};

/**
 * @brief Contains "easy-setup payload" data
 */
struct iot_easysetup_payload {
	enum iot_easysetup_step	step;		/**< @brief reflect easy-setup process step */
	iot_error_t err;					/**< @brief error status for each step */
	char *payload;						/**< @brief actual payload for each step */
};

#define IOT_REG_UUID_STR_LEN		(36)

/**
 * @brief Contains "registration message" data
 */
struct iot_registered_data {
	char deviceId[IOT_REG_UUID_STR_LEN + 1];	/**< @brief device Id, allocated from server */
	bool updated;								/**< @brief reflect getting device id */
	bool new_reged;								/**< @brief reflect that it is new registration process or not */
};

/**
 * @brief Contains "mqtt handling context" data
 */
struct iot_mqtt_ctx {
	iot_net_socket net;		/**< @brief network management handle for mqtt */
	MQTTClient cli;			/**< @brief mqtt client handle for iot_core */
	bool mqtt_connected;	/**< @brief mqtt connected status */

#if !defined(CONFIG_STDK_MQTT_DYNAMIC_BUFFER)
	unsigned char buf[IOT_BUF_TX_SIZE];			/**< @brief mqtt buffer for sending */
	unsigned char readbuf[IOT_BUF_RX_SIZE];		/**< @brief mqtt buffer for receiving */
#endif

	const char *cmd_filter;		/**< @brief mqtt command topic filter string */
	const char *noti_filter;	/**< @brief mqtt notification topic filter string */

	void *iot_ctx;				/**< @brief iot main context ref. used for mqtt message callback */
};

/**
 * @brief Contains "device's information" data
 */
struct iot_device_info {
	char *firmware_version;		/**< @brief device's binary/firmware version */
};

/**
 * @brief Contains "iot core's main state" data
 */
struct iot_state_data {
	iot_state_t iot_state;		/**< @brief current iot core's state */
	int opt;					/**< @brief additional option for each state */
};

typedef struct iot_cap_handle_list iot_cap_handle_list_t;

/**
 * @brief Contains "iot core's main context" data
 */
struct iot_context {
	iot_os_queue *cmd_queue;			/**< @brief iot core's internal command queue */
	iot_os_queue *pub_queue;			/**< @brief iot core's event publish queue */
	iot_os_queue *easysetup_req_queue;	/**< @brief request queue for easy-setup process */
	iot_os_queue *easysetup_resp_queue;	/**< @brief response queue for easy-setup process */

	iot_state_t curr_state;			/**< @brief reflect current iot_state */
	iot_state_t req_state;			/**< @brief reflect requested iot_state */
	iot_os_timer state_timer;		/**< @brief state checking timer for each iot_state */

	iot_os_eventgroup *usr_events;		/**< @brief User level handling events */
	iot_os_eventgroup *iot_events;		/**< @brief Internal handling events */

	iot_cap_handle_list_t *cap_handle_list;		/**< @brief allocated capability handle lists */

	struct iot_mqtt_ctx *client_ctx;	/**< @brief mqtt context ref. for registration */
	struct iot_mqtt_ctx *reged_cli;		/**< @brief mqtt context ref. for connection */

	struct iot_device_prov_data prov_data;	/**< @brief allocated device provisioning data */
	struct iot_devconf_prov_data devconf;	/**< @brief allocated device configuration data */
	struct iot_device_info device_info;		/**< @brief allocated device information data */

	iot_crypto_cipher_info_t *es_crypto_cipher_info;	/**< @brief cipher context ref. for easy-setup process */

	struct iot_registered_data iot_reg_data;	/**< @brief allocated registration data from server */
	void *es_httpd_handle;						/**< @brief httpd handler for easy-setup process */

	uint16_t scan_num;						/**< @brief number of wifi ap scan result */
	iot_wifi_scan_result_t *scan_result;	/**< @brief actual data lists of each wifi ap scan result */
	char *lookup_id;						/**< @brief device's lookup id for server & mobile side notification */

	st_cap_noti_cb noti_cb;		/**< @brief notification handling callback for each capability */
	void *noti_usr_data;		/**< @brief notification handling callback data for user */

	st_status_cb status_cb;		/**< @brief iot core status handling callback for user */
	iot_status_t status_maps;	/**< @brief iot status callback maps to check it call or not */
	unsigned int reported_stat;	/**< @brief iot status callback checking flag to check it reported or not */
	void *status_usr_data;		/**< @brief iot core status handling callback data for user */

	int curr_otm_feature;	/**< @brief current device's supported onboarding process validation type */
	iot_pin_t *pin;			/**< @brief current device's PIN values for PIN type otm */

	unsigned int cmd_err;						/**< @brief current command handling error checking value */
	unsigned int cmd_status;					/**< @brief current command status */
	uint16_t cmd_count[IOT_COMMAND_TYPE_MAX];	/**< @brief current queued command counts */
};

#endif /* _IOT_MAIN_H_ */
