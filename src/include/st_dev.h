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

#ifndef _ST_DEV_H_
#define _ST_DEV_H_

#include <stdint.h>
#include <stdbool.h>

#include "st_dev_version.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Contains a enumeration values for types of iot_status.
 */
typedef enum iot_status {
	IOT_STATUS_IDLE = (1 << 0),				/**< @brief For idle status, not connected. supports IOT_STAT_LV_STAY */
	IOT_STATUS_PROVISIONING = (1 << 1),		/**< @brief For provisioning status. do onboarding process. supports IOT_STAT_LV_START/CONN/DONE/FAIL */
	IOT_STATUS_NEED_INTERACT = (1 << 2),	/**< @brief For user interation status. need to interact with user. only supports IOT_STAT_LV_STAY/FAIL */
	IOT_STATUS_CONNECTING = (1 << 3),		/**< @brief For server connecting status. do connecting server. supports IOT_STAT_LV_START/DONE/FAIL */

	IOT_STATUS_ALL = (IOT_STATUS_IDLE | IOT_STATUS_PROVISIONING
				| IOT_STATUS_NEED_INTERACT | IOT_STATUS_CONNECTING),
} iot_status_t;

/**
 * @brief Contains a enumeration values for types of iot_status level.
 */
typedef enum iot_stat_lv {
	IOT_STAT_LV_STAY = 0,		/**< @brief meanings for staying level with each status */
	IOT_STAT_LV_START = 1,		/**< @brief meanings for start level with each status  */
	IOT_STAT_LV_DONE = 2,		/**< @brief meanings for done level with each status */
	IOT_STAT_LV_FAIL = 3,		/**< @brief meanings for fail level with each status */
	IOT_STAT_LV_CONN = 4,		/**< @brief meanings for connection with mobile */
	IOT_STAT_LV_SIGN_UP = IOT_STAT_LV_START,	/**< @brief meanings for trying to sign-up process */
	IOT_STAT_LV_SIGN_IN = 6,	/**< @brief meanings for trying to sign-in process */
} iot_stat_lv_t;


typedef void *IOT_CTX;
typedef void *IOT_CAP_HANDLE;
typedef void *IOT_EVENT;

/**
 * @brief Contains a pin values for pin type onboarding process.
 */
typedef struct iot_pin_t {
	unsigned char pin[8];	/**< @brief actual pin values */
} iot_pin_t;

/**
 * @brief Contains a enumeration values for types of capability.
 */
typedef enum iot_cap_val_type {
	IOT_CAP_VAL_TYPE_UNKNOWN = -1,	/**< @brief For undefined type. */
	IOT_CAP_VAL_TYPE_INTEGER,		/**< @brief For integer. */
	IOT_CAP_VAL_TYPE_NUMBER,		/**< @brief For float number. */
	IOT_CAP_VAL_TYPE_INT_OR_NUM,	/**< @brief For integer or float number. */
	IOT_CAP_VAL_TYPE_STRING,		/**< @brief For NULL-terminated string. */
	IOT_CAP_VAL_TYPE_STR_ARRAY,		/**< @brief For array of NULL-terminated strings. */
	IOT_CAP_VAL_TYPE_JSON_OBJECT,	/**< @brief For json object. */
	IOT_CAP_VAL_TYPE_BOOLEAN		/**< @brief For boolean. */
} iot_cap_val_type_t;

/**
 * @brief Contains a various type of data which can be int, double, string and string array.
 */
typedef struct {
	/**
	 * @brief Data type to notify valid data.
	 *
	 * @note Even though there are 4 different type of data
	 * (integer, number, string, strings) in this structure,
	 * only one type of data is used.
	 */
	iot_cap_val_type_t type; /**< @brief Type of capability's data. */

	uint8_t str_num; /**< @brief Number of stings. Only used for sting array. */
	int	integer;	/**< @brief Integer. */

	union {
		double number;	/**< @brief Float number. */
		char *string;	/**< @brief NULL-terminated string. */
		char **strings; /**< @brief Array of NULL-terminated strings. */
		char *json_object; /**< @brief Json object payload strings */
		bool boolean; /**< @brief boolean */
	};
} iot_cap_val_t;


#define MAX_CAP_ARG (5)

/**
 * @brief Contains data for "command" payload.
 */
typedef struct {
	/**
	 * @brief Number of arguments.
	 *
	 * @note Usally 1, but if commands type is 'json object',
	 * it could be more than 1. (See colorControl capability.)
	 */
	uint8_t num_args;

	/**
	 * @brief Name of each argument.
	 *
	 * @note This is used only if there is more than one argument.
	 */
	char *args_str[MAX_CAP_ARG];

	iot_cap_val_t cmd_data[MAX_CAP_ARG];	/**< @brief Value of each arguments. */

	int total_commands_num;		/**< @brief Total number of commands in a bunch of commands */
	int order_of_command;		/**< @brief Order of this command in a bunch of commands */
} iot_cap_cmd_data_t;

/**
 * @brief Contains a enumeration values for types of notification.
 */
typedef enum iot_noti_type {
	IOT_NOTI_TYPE_UNKNOWN = -1,		/**< @brief For undefined type. */

	IOT_NOTI_TYPE_DEV_DELETED,		/**< @brief For device deleted event. */
	IOT_NOTI_TYPE_RATE_LIMIT,		/**< @brief For rate limit event. */
	IOT_NOTI_TYPE_QUOTA_REACHED		/**< @brief For data quota reached event. */
} iot_noti_type_t;


/**
 * @brief Contains data for raw data of each notification.
 */
typedef union {
	/* rate limit case */
	struct _rate_limit {
		int count;			/**< @brief Current rate limit count. */
		int threshold;		/**< @brief Current rate limit threshold. */
		int remainingTime;	/**< @brief How much time remains for rate limit releasing. */
		int sequenceNumber;	/**< @brief Sequence number of event that triggered rate limit */
	} rate_limit;
	/* quota reached case */
	struct _quota {
		int used;			/**< @brief Current used data usage in bytes. */
		int limit;			/**< @brief Current data limit in bytes. */
	} quota;
} noti_data_raw_t;

/**
 * @brief Contains data for notification data.
 */
typedef struct {
	iot_noti_type_t type;	/**< @brief Type of notification's data. */
	noti_data_raw_t raw;	/**< @brief Raw data of each notification. */
} iot_noti_data_t;

/* For user(apps) callback */
typedef void (*st_status_cb)(iot_status_t iot_status, iot_stat_lv_t stat_lv, void *usr_data);
typedef void (*st_cap_init_cb)(IOT_CAP_HANDLE *cap_handle, void *init_usr_data);
typedef void (*st_cap_noti_cb)(iot_noti_data_t *noti_data, void *noti_usr_data);
typedef void (*st_cap_cmd_cb)(IOT_CAP_HANDLE *cap_handle,
	iot_cap_cmd_data_t *cmd_data, void *usr_data);

/**
 * @brief Contains data for extension options.
 */
typedef struct {
	st_status_cb status_cb;	/**< @brief user callback function to receive status of st-iot-core */
	iot_status_t maps;		/**< @brief status of st-iot-core interested to receive through status_cb */
	void *usr_data;			/**< @brief user data(a pointer) to use in status_cb */
	iot_pin_t *pin_num;		/**< @brief if PIN ownership validation type used, valid 8 digit pin should be set. otherwise set null. */

	iot_status_t start_pt;	/**< @brief starting connection point, support only IOT_STATUS_PROVISIONING & IOT_STATUS_CONNECTING cases */
	bool skip_usr_confirm;	/**< @brief set true to skip user-confirm, else false. */
} iot_ext_args_t;

/**
 * @brief Contains a enumeration values for types of notification.
 */
typedef enum iot_info_type {
	IOT_INFO_TYPE_IOT_STATUS_AND_STAT,		/**< @brief to get current st_status. */
	IOT_INFO_TYPE_IOT_PROVISIONED,			/**< @brief to get provision state, provisioned or not */
} iot_info_type_t;

/**
 * @brief Contains data for iot-core information.
 */
typedef union {
	/* to get current iot_status case */
	struct _st_status {
		iot_status_t iot_status;	/**< @brief current reported status of st-iot-core. */
		iot_stat_lv_t stat_lv;		/**< @brief current reported iot_status's level. */
	} st_status;
	/* to get provisioned state case */
	bool provisioned;				/**< @brief to check provisoned or not */
} iot_info_data_t;

//////////////////////////////////////////////////////////////

/**
 * @brief Create IOT_EVENT data with integer `value`.
 *
 * @details This function creates a new IOT_EVENT data with input parameters.
 * Once it returns, user has full responsibility for deallocating event data
 * by using [st_cap_attr_free](@ref st_cap_attr_free).
 *
 * @param[in] attribute The attribute string of IOT_EVENT data.
 * @param[in] integer The integer to add to IOT_EVENT data.
 * @param[in] unit The unit string if needed. Otherwise NULL.
 *
 * @return Pointer of `IOT_EVENT` which is used to publish device status.
 *
 * @warning Must call [st_cap_attr_free](@ref st_cap_attr_free)
 * to free IOT_EVENT data after using it.
 *
 * @see @ref st_cap_attr_send
 */
IOT_EVENT* st_cap_attr_create_int(const char *attribute, int integer, const char *unit);

/**
 * @brief Create IOT_EVENT data with real number(double) `value`.
 *
 * @details This function creates a new IOT_EVENT data with input parameters.
 * Once it returns, user has full responsibility for deallocating event data
 * by using [st_cap_attr_free](@ref st_cap_attr_free).
 *
 * @param[in] attribute The attribute string of IOT_EVENT data.
 * @param[in] number The double number to add to IOT_EVENT data.
 * @param[in] unit The unit string if needed. Otherwise NULL.
 *
 * @return Pointer of `IOT_EVENT` which is used to publish device status.
 *
 * @warning Must call [st_cap_attr_free](@ref st_cap_attr_free)
 * to free IOT_EVENT data after using it.
 *
 * @see @ref st_cap_attr_send
 */
IOT_EVENT* st_cap_attr_create_number(const char *attribute, double number, const char *unit);

/**
 * @brief Create IOT_EVENT data with string `value`.
 *
 * @details This function creates a new IOT_EVENT data with input parameters.
 * Once it returns, user has full responsibility for deallocating event data
 * by using [st_cap_attr_free](@ref st_cap_attr_free).
 *
 * @param[in] attribute The attribute string of IOT_EVENT data.
 * @param[in] string The string to add to IOT_EVENT data.
 * @param[in] unit The unit string if needed. Otherwise NULL.
 *
 * @return Pointer of `IOT_EVENT` which is used to publish device status.
 *
 * @warning Must call [st_cap_attr_free](@ref st_cap_attr_free)
 * to free IOT_EVENT data after using it.
 *
 * @see @ref st_cap_attr_send
 */
IOT_EVENT* st_cap_attr_create_string(const char *attribute, char *string, const char *unit);

/**
 * @brief Create IOT_EVENT data with string array `value`.
 *
 * @details This function creates a new IOT_EVENT data with input parameters.
 * Once it returns, user has full responsibility for deallocating event data
 * by using [st_cap_attr_free](@ref st_cap_attr_free).
 *
 * @param[in] attribute The attribute string of IOT_EVENT data.
 * @param[in] str_num The number of strings in the string_array.
 * @param[in] string_array The pointer of string array to add to IOT_EVENT data.
 * @param[in] unit The unit string if needed. Otherwise NULL.
 *
 * @return Pointer of `IOT_EVENT` which is used to publish device status.
 *
 * @warning Must call [st_cap_attr_free](@ref st_cap_attr_free)
 * to free IOT_EVENT data after using it.
 *
 * @see @ref st_cap_attr_send
 */
IOT_EVENT* st_cap_attr_create_string_array(const char *attribute,
		uint8_t str_num, char *string_array[], const char *unit);

/**
 * @brief Create IOT_EVENT data.
 *
 * @details This function creates a new IOT_EVENT data with input parameters.
 * Once it returns, user has full responsibility for deallocating event data
 * by using [st_cap_attr_free](@ref st_cap_attr_free).
 *
 * @param[in] attribute The attribute string of IOT_EVENT data.
 * @param[in] value The value to add to IOT_EVENT data.
 * @param[in] unit The unit string if needed. Otherwise NULL.
 * @param[in] data The data json object if needed. Otherwise NULL.
 *
 * @return Pointer of `IOT_EVENT` which is used to publish device status.
 *
 * @warning Must call [st_cap_attr_free](@ref st_cap_attr_free)
 * to free IOT_EVENT data after using it.
 *
 * @see @ref st_cap_attr_send
 */
IOT_EVENT* st_cap_attr_create(const char *attribute,
			iot_cap_val_t *value, const char *unit, const char *data);

/**
 * @brief Free IOT_EVENT data.
 *
 * @details This function frees IOT_EVENT data.
 *
 * @param[in] event The IOT_EVENT data to free.
 */
void st_cap_attr_free(IOT_EVENT* event);

/**
 * @brief Request to publish deviceEvent.
 *
 * @details This function creates a deviceEvent with the list of IOT_EVENT data,
 * and requests to publish it.
 * When there is no error, this function returns sequence number,
 * which is unique value to identify the deviceEvent message.
 *
 * @param[in] cap_handle The IOT_CAP_HANDLE to publish a deviceEvent.
 * @param[in] evt_num The number of IOT_EVENT data in the event.
 * @param[in] event The IOT_EVENT data list to create the deviceEvent.
 *
 * @return return `sequence number`(which is positive integer) if successful,
 * negative integer for error case.
 */
int st_cap_attr_send(IOT_CAP_HANDLE *cap_handle,
		uint8_t evt_num, IOT_EVENT *event[]);

/**
 * @brief Create and initialize a capability handle.
 *
 * @details This function creates a capability handle, and initializes it with input args.
 *
 * @param[in] iot_ctx The iot context.
 * @param[in] component Component string. Default component name is "main".
 * @param[in] capability Capability string. This should be matched with "id" value of capability definition json format.
 * @param[in] init_cb The function which is called to initialize device state.
 * @param[in] init_usr_data User data for init_cb.
 *
 * @return Pointer of created capability handle.
 */
IOT_CAP_HANDLE *st_cap_handle_init(IOT_CTX *iot_ctx, const char *component,
		const char *capability, st_cap_init_cb init_cb, void *init_usr_data);

/**
 * @brief Register callback function for notification event.
 *
 * @details This function registers user callback function which will be called when
 * notification event occurs(such as `rate limit`, `delete device`).
 *
 * @param[in] iot_ctx The iot context.
 * @param[in] noti_cb The callback function which will be called when notification event occurs.
 * @param[in] noti_usr_data User data for noti_cb.
 *
 * @return return `(0)` if it works successfully, non-zero for error case.
 *
 * @warning User callback must return because MQTT works after user callback has ended
 */
int st_conn_set_noti_cb(IOT_CTX *iot_ctx,
		st_cap_noti_cb noti_cb, void *noti_usr_data);

/**
 * @brief Register callback function for command message.
 *
 * @details This function registers user callback for command message from ST server.
 * If the `capability`(used to create handle) and `cmd_type` of command message are same with
 * input arguments, the callback function will be called.
 *
 * @param[in] cap_handle The capability handle to register cb function.
 * @param[in] cmd_type The commands interested to process.
 * @param[in] cmd_cb The callback function invoked when command is received.
 * @param[in] usr_data User data for cmd_cb.
 *
 * @return return `(0)` if it works successfully, non-zero for error case.
 *
 * @warning User callback must return because MQTT works after user callback has ended.
 */
int st_cap_cmd_set_cb(IOT_CAP_HANDLE *cap_handle, const char *cmd_type,
		st_cap_cmd_cb cmd_cb, void *usr_data);

/**
 * @brief	st-iot-core initialize function
 * @details	This function initializes st-iot-core for target
 * @param[in]	onboarding_config	starting pointer of onboarding_config.json contents
 * @param[in]	onboarding_config_len	size of onboarding_config.json contents
 * @param[in]	device_info		starting pointer of device_info.json contents
 * @param[in]	device_info_len		size of device_info.json contents
 * @return		return IOT_CTX handle(a pointer) if it succeeds, or NULL if it fails
 */
IOT_CTX* st_conn_init(unsigned char *onboarding_config, unsigned int onboarding_config_len,
		unsigned char* device_info, unsigned int device_info_len);

/**
* @brief	st-iot-core server connection function
* @details	This function tries to connect server
* @param[in]	iot_ctx		iot_context handle generated by iot_main_init()
* @param[in]	status_cb	user callback function to receive status of st-iot-core
* @param[in]	maps		status of st-iot-core interested to receive through status_cb
* @param[in]	usr_data	user data(a pointer) to use in status_cb
* @param[in]	pin_num		if PIN ownership validation type used, valid 8 digit pin should be set. otherwise set null.
* @return 		return `(0)` if it works successfully, non-zero for error case.
*/
int st_conn_start(IOT_CTX *iot_ctx, st_status_cb status_cb,
		iot_status_t maps, void *usr_data, iot_pin_t *pin_num);

/**
* @brief	st-iot-core device clean-up function
* @details	This function cleans-up all DATA including provisioning & registered data
* @param[in]	iot_ctx		iot_context handle generated by iot_main_init()
* @param[in]	reboot		boolean set true for auto-reboot of system, else false.
* @return 		return `(0)` if it works successfully, non-zero for error case.
*/
int st_conn_cleanup(IOT_CTX *iot_ctx, bool reboot);

/**
* @brief	easysetup user confirm report function
* @details	This function reports the user confirmation to easysetup
* @param[in]	iot_ctx		iot_context handle generated by iot_main_init()
* @param[in]	confirm		user confirmation result
*/
void st_conn_ownership_confirm(IOT_CTX *iot_ctx, bool confirm);

/**
* @brief	expanded st-iot-core server connection function
* @details	This function tries to connect server with extension arguments
* @param[in]	iot_ctx		iot_context handle generated by iot_main_init()
* @param[in]	ext_args	extension arguments for sepcific connection control
* @return 		return `(0)` if it works successfully, non-zero for error case.
*/
int st_conn_start_ex(IOT_CTX *iot_ctx, iot_ext_args_t *ext_args);

/**
* @brief	st-iot-core information getting function
* @details	This function tries to get current iot-core's information
* @param[in]	iot_ctx		iot_context handle generated by iot_main_init()
* @param[in]	info_type	type of iot_info_types_t to get its value
* @param[out]	info_data	A pointer to actual information data to get each type of iot_info_type_t
* @return 		return `(0)` if it works successfully, non-zero for error case.
 */
int st_info_get(IOT_CTX *iot_ctx, iot_info_type_t info_type, iot_info_data_t *info_data);

#ifdef __cplusplus
}
#endif

#endif /* _ST_DEV_H_ */
