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
#include "iot_error.h"
#include "iot_bsp_wifi.h"
#include "iot_os_util.h"
#include "iot_net.h"
#include "iot_mqtt.h"
#include "security/iot_security_crypto.h"
#include "iot_util.h"

#define IOT_WIFI_PROV_SSID_STR_LEN		(32)
#define IOT_WIFI_PROV_PASSWORD_STR_LEN 	(64)
#define IOT_WIFI_PROV_MAC_STR_LEN 	(17)

#define IOT_EVENT_BIT_COMMAND		(1u << 0u)
#define IOT_EVENT_BIT_CAPABILITY	(1u << 1u)
#define IOT_EVENT_BIT_EASYSETUP_REQ	(1u << 2u)
#define IOT_EVENT_BIT_EASYSETUP_RESP	(1u << 3u)
#define IOT_EVENT_BIT_EASYSETUP_CONFIRM	(1u << 4u)
#define IOT_EVENT_BIT_EASYSETUP_CONFIRM_DENY	(1u << 5u)
#define IOT_EVENT_BIT_ALL	(IOT_EVENT_BIT_COMMAND | IOT_EVENT_BIT_CAPABILITY | IOT_EVENT_BIT_EASYSETUP_REQ)

#define IOT_USR_INTERACT_BIT_CMD_DONE		(1u << 4u)

#define IOT_MAIN_TASK_DEFAULT_CYCLE			100		/* in ms */
#define IOT_MQTT_CONNECT_CRITICAL_REJECT_MAX	3
#define IOT_RATE_LIMIT_BREAK_TIME		60000
#define IOT_PREVERR_LEN     5

#define IOT_DEVICE_NAME_MAX_LENGTH		20

#define NEXT_STATE_TIMEOUT_MS	(100000)
#define EASYSETUP_TIMEOUT_MS	(300000) /* 5 min */
#define REGISTRATION_TIMEOUT_MS	(900000) /* 15 min */

#define GG_CONNECTION_RESPONSE_TIMEOUT_MS	(5000)

enum _iot_noti_type {
	/* Common notifications */
	_IOT_NOTI_TYPE_UNKNOWN = IOT_NOTI_TYPE_UNKNOWN,

	_IOT_NOTI_TYPE_DEV_DELETED = IOT_NOTI_TYPE_DEV_DELETED,
	_IOT_NOTI_TYPE_RATE_LIMIT = IOT_NOTI_TYPE_RATE_LIMIT,
	_IOT_NOTI_TYPE_QUOTA_REACHED = IOT_NOTI_TYPE_QUOTA_REACHED,
	_IOT_NOTI_TYPE_SEND_FAILED = IOT_NOTI_TYPE_SEND_FAILED,
	_IOT_NOTI_TYPE_PREFERENCE_UPDATED = IOT_NOTI_TYPE_PREFERENCE_UPDATED,

	/* Internal only notifications */
	_IOT_NOTI_TYPE_JWT_EXPIRED,
};

enum iot_command_type {
	IOT_COMMAND_STATE_UPDATE,
	IOT_COMMAND_CLOUD_REGISTERING,
	IOT_COMMAND_CLOUD_REGISTERED,
	IOT_COMMAND_CLOUD_CONNECTING,
	IOT_COMMAND_NOTIFICATION_RECEIVED,
	IOT_COMMAND_TYPE_MAX = IOT_COMMAND_NOTIFICATION_RECEIVED, /* MAX : under 32 */
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
	IOT_EASYSETUP_INVALID_STEP,
};

enum iot_connect_type {
	IOT_CONNECT_TYPE_REGISTRATION,
	IOT_CONNECT_TYPE_COMMUNICATION,
};

typedef enum iot_state_type {
	IOT_STATE_INITIALIZED = 0,

	IOT_STATE_PROV_SLEEP,
	IOT_STATE_PROV_ENTER,
	IOT_STATE_PROV_CONFIRM,
	IOT_STATE_PROV_DONE,

	IOT_STATE_CLOUD_DISCONNECTED,
	IOT_STATE_CLOUD_CONNECTED,
} iot_state_t;

enum iot_state_opt {
	IOT_STATE_OPT_NONE,
	IOT_STATE_OPT_NEED_INTERACT,
	IOT_STATE_OPT_CLEANUP,
};

typedef enum iot_st_ecode_type {
	IOT_ST_ECODE_NONE,
	IOT_ST_ECODE_EE01,
	IOT_ST_ECODE_NE01,
	IOT_ST_ECODE_NE02,
	IOT_ST_ECODE_NE03,
	IOT_ST_ECODE_NE04,
	IOT_ST_ECODE_NE10,
	IOT_ST_ECODE_NE11,
	IOT_ST_ECODE_NE12,
	IOT_ST_ECODE_NE13,
	IOT_ST_ECODE_NE14,
	IOT_ST_ECODE_NE15,
	IOT_ST_ECODE_NE16,
	IOT_ST_ECODE_NE17,
	IOT_ST_ECODE_CE11,
	IOT_ST_ECODE_CE12,
	IOT_ST_ECODE_CE20,
	IOT_ST_ECODE_CE21,
	IOT_ST_ECODE_CE30,
	IOT_ST_ECODE_CE31,
	IOT_ST_ECODE_CE32,
	IOT_ST_ECODE_CE33,
	IOT_ST_ECODE_CE40,
	IOT_ST_ECODE_CE41,
	IOT_ST_ECODE_CE50,
	IOT_ST_ECODE_CE51,
	IOT_ST_ECODE_CE60,
}iot_st_ecode_t;


/**
 * @brief Contains "wifi provisioning" data
 */
struct iot_wifi_prov_data {
	char ssid[IOT_WIFI_PROV_SSID_STR_LEN + 1];			/**< @brief wifi SSID string */
	char password[IOT_WIFI_PROV_PASSWORD_STR_LEN + 1];	/**< @brief wifi password string */
	char mac_str[IOT_WIFI_PROV_MAC_STR_LEN + 1];/**< @brief wifi mac address string */
	struct iot_mac bssid;						/**< @brief wifi bssid raw value */
	iot_wifi_auth_mode_t security_type;			/**< @brief wifi security type such as WEP, PSK2.. */
};

/**
 * @brief Contains "cloud provisioning" data
 */
struct iot_cloud_prov_data {
	char *broker_url;				/**< @brief broker url for mqtt */
	int  broker_port;				/**< @brief broker port num for mqtt */
	char *location;
	char *room;
	char *label;					/**< @brief device name, got from the mobile */
};

/**
 * @brief Contains "Device Integration Profile" data
 */
struct iot_dip_data {
	struct iot_uuid dip_id;		/**< @brief Device Integration Profile ID */
	int dip_major_version;		/**< @brief DIP's major version */
	int dip_minor_version;		/**< @brief DIP's minor version */
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
	unsigned int ownership_validation_type;	/**< @brief onboarding process validation type, JUSTWORKS, BUTTON, PIN, QR */
	iot_security_key_type_t pk_type;	/**< @brief Authentication type, determined in devworks */
	char *hashed_sn;				/**< @brief hashed serial, self-generating values during onboarding process */
	unsigned char ssid_version;		/**< @brief ssid version */
	struct iot_dip_data *dip;		/**< @brief Device Integration Profile data, determined in devworks, optional */
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
	struct iot_dip_data *dip;					/**< @brief Registered Device Integration Profile data */
	struct iot_uuid *locationId;				/**< @brief location Id, allocated from server */
	char deviceId[IOT_REG_UUID_STR_LEN + 1];	/**< @brief device Id, allocated from server */
	bool updated;								/**< @brief reflect getting device id */
	bool new_reged;								/**< @brief reflect that it is new registration process or not */
	bool self_reged;							/**< @brief reflect that it is self registration process or not */
};

/**
 * @brief Contains "device's information" data
 */
struct iot_device_info {
	char *firmware_version;		/**< @brief device's binary/firmware version */
	char *model_number;			/**< @brief device's model number */
	char *marketing_name;			/**< @brief device's marketing name */
	char *manufacturer_name;		/**< @brief device's manaufacturer name */
	char *manufacturer_code;		/**< @brief device's manaufacturer code */
	unsigned char opt_info;			/**< @brief to check optional information */
};

/**
 * @brief Contains "iot core's main state" data
 */
struct iot_state_data {
	iot_state_t iot_state;		/**< @brief current iot core's state */
	int opt;					/**< @brief additional option for each state */
};

/**
 * @brief Contains "iot core's main state" data
 */
typedef struct iot_cap_handle_list iot_cap_handle_list_t;

#define IOT_ST_ECODE_STR_LEN	(4)

struct iot_st_ecode {
	iot_st_ecode_t ecode_type;
	char ecode[IOT_ST_ECODE_STR_LEN + 1];
};

typedef enum {
	GG_CONNECTION_REQUEST_STATUS_NOT_INITIALIZED,
	GG_CONNECTION_REQUEST_STATUS_WAITING,
	GG_CONNECTION_REQUEST_STATUS_SUCCESS,
	GG_CONNECTION_REQUEST_STATUS_FAIL,
} gg_connection_request_status;

/**
 * @brief Contains "iot core's main context" data
 */
struct iot_context {
	iot_util_queue_t *cmd_queue;			/**< @brief iot core's internal command queue */
	iot_util_queue_t *easysetup_req_queue;	/**< @brief request queue for easy-setup process */
	iot_util_queue_t *easysetup_resp_queue;	/**< @brief response queue for easy-setup process */
	bool es_res_created;				/**< @brief to check easy-setup resources are created or not */
	bool es_http_ready;					/**< @brief to check easy-setup-httpd is initialized or not */

	iot_state_t curr_state;			/**< @brief reflect current iot_state */
	iot_os_timer state_timer;		/**< @brief state checking timer for each iot_state */

	iot_os_eventgroup *usr_events;		/**< @brief User level handling events */
	iot_os_eventgroup *iot_events;		/**< @brief Internal handling events */

	iot_cap_handle_list_t *cap_handle_list;		/**< @brief allocated capability handle lists */

	st_mqtt_client evt_mqttcli;			/**< @brief SmartThings MQTT Client for event & commands */
	gg_connection_request_status sign_in_connection_request_status;	/**< @brief Sign-in connection request status */
	st_mqtt_client reg_mqttcli;			/**< @brief SmartThings MQTT Client for registration */
	unsigned int mqtt_connect_critical_reject_count;		/**< @brief MQTT connect critical reject count */
	gg_connection_request_status sign_up_connection_request_status;	/**< @brief Sign-up connection request status */
	char *mqtt_event_topic;				/**< @brief mqtt topic for event publish */
	char *mqtt_health_topic;				/**< @brief mqtt topic for health publish */

	struct iot_device_prov_data prov_data;	/**< @brief allocated device provisioning data */
	struct iot_devconf_prov_data devconf;	/**< @brief allocated device configuration data */
	struct iot_device_info device_info;		/**< @brief allocated device information data */

	iot_security_context_t *easysetup_security_context;	/**< @brief security context ref. for easy-setup process */

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

	iot_os_thread main_thread; /**< @brief iot main task thread */
	iot_os_mutex st_conn_lock; /**< @brief User level control API lock */
	iot_os_mutex iot_cmd_lock; /**< @brief iot-core's command handling lock*/

	bool add_justworks; 	/**< @brief to skip user-confirm using JUSTWORKS bit */

	int event_sequence_num;	/**< @brief Last event's sequence number */

	bool rate_limit; 	/**< @brief whether rate limit occurs */
	iot_os_timer rate_limit_timeout;	/**< @brief timeout for rate limit penalty */

	unsigned int mqtt_connection_success_count; /**< @brief MQTT connection success count */
	unsigned int mqtt_connection_try_count; /**< @brief MQTT connection try count */
	bool usr_delete_req;	/**< @brief whether self-device-card-deleting requested from usr */

	struct iot_st_ecode last_st_ecode;	/**< @brief last happended device error code to send SmartThings App */

	bool is_wifi_station;		/**< @brief indicator if wifi is station mode or not */

	unsigned int connection_retry_count; 	/**< @brief MQTT server connection retry count */
	iot_os_timer next_connection_retry_timer;	/**< @brief timer for next connection retry count */
};

#endif /* _IOT_MAIN_H_ */
