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

#ifndef _IOT_CAPABILITY_H_
#define _IOT_CAPABILITY_H_

#include "iot_main.h"

#define SERVER_NOTI_TYPE_DEVICE_DELETED "device.deleted"
#define SERVER_NOTI_TYPE_EXPIRED_JWT "expired.jwt"
#define SERVER_NOTI_TYPE_RATE_LIMIT_REACHED "rate.limit.reached"
#define SERVER_NOTI_TYPE_QUOTA_REACHED "quota.reached"
#define SERVER_NOTI_TYPE_PREFERENCE_UPDATED "device.preferences"

enum iot_cap_unit_type {
	IOT_CAP_UNIT_TYPE_UNUSED,
	IOT_CAP_UNIT_TYPE_STRING,
};

/**
 * @brief Contains a "unit" data.
 */
typedef struct {
	uint8_t type;	/**< @brief Unused or string */
	char *string;	/**< @brief NULL-terminated string. */
} iot_cap_unit_t;

/**
 * @brief Contains data for "deviceEvent" payload.
 */
typedef struct iot_cap_evt_data_t {
	/**
	 * @brief Capability reference for this event.
	 *
	 */
	struct iot_cap_handle *ref_cap;
	/**
	 * @brief NULL-terminated string, which is name of `attributes`.
	 *
	 */
	const char *evt_type;

	/**
	 * @brief 'value' data for deviceEvent.
	 *
	 */
	iot_cap_val_t evt_value;

	/**
	 * @brief 'unit' data for deviceEvent.
	 *
	 */
	iot_cap_unit_t evt_unit;

	/**
	 * @brief 'data' data for deviceEvent.
	 *
	 */
	char *evt_value_data;

	/**
	 * @brief option for deviceEvent.
	 *
	 */
	iot_cap_attr_option_t options;
} iot_cap_evt_data_t;

/**
 * @brief Contains user command callback function data.
 */
typedef struct iot_cap_cmd_set {
	/**
	 * @brief NULL-terminated string, which is name of `commands`.
	 */
	char *cmd_type;

	st_cap_cmd_cb cmd_cb;	/**< @brief User callback function. */
	void *usr_data;		/**< @brief User data for cmd_cb. */
} iot_cap_cmd_set_t;

/**
 * @brief linked list for command callback function data
 */
typedef struct iot_cap_cmd_set_list {
	/**
	 * @brief a pointer to a command data
	 */
	struct iot_cap_cmd_set *command;
	/**
	 * @brief a pointer to a next list
	 */
	struct iot_cap_cmd_set_list *next;
} iot_cap_cmd_set_list_t;

/**
 * @brief Contains data for capability handle.
 */
struct iot_cap_handle {
	/**
	 * @brief NULL-terminated string, which is name of `capability`.
	 *
	 * Use capability id for this variable. e.g. "switchLevel"
	 *
	 */
	const char *capability;

	/**
	 * @brief NULL-terminated string, which is name of `component`.
	 */
	const char *component;

	struct iot_cap_cmd_set_list *cmd_list;	/**< @brief List of command data. */

	st_cap_init_cb init_cb;	/**< @brief User callback function for init device state. */
	void *init_usr_data;	/**< @brief User data for init_cb. */

	struct iot_context *ctx;	/**< @brief ctx */
};

/**
 * @brief linked list for capability handle
 */
struct iot_cap_handle_list {
	/**
	 * @brief a pointer to a capability handle
	 */
	struct iot_cap_handle *handle;
	/**
	 * @brief a pointer to a next list
	 */
	struct iot_cap_handle_list *next;
};

/**
 * @brief Contains data for final message handling.
 */
typedef struct iot_cap_msg {
	char *msg;	/**< @brief final message for network handling layer such as MQTT */
	int msglen; /**< @brief final message length */
} iot_cap_msg_t;

#endif /* _IOT_CAPABILITY_H_ */
