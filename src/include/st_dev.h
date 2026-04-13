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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "st_caps.h"
#include "st_dev_version.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__GNUC__) || defined(__clang__)
#define DEPRECATED __attribute__((deprecated))
#elif defined(_MSC_VER)
#define DEPRECATED __declspec(deprecated)
#else
#pragma message("WARNING: You need to implement DEPRECATED for this compiler")
#define DEPRECATED
#endif

typedef void *IOT_CTX;
typedef void *IOT_CHILD_DEV;
typedef void *IOT_CAP_HANDLE;
typedef void *IOT_EVENT;

typedef enum _st_device_status {
    ST_DEVICE_STATUS_INIT,                    /**< @brief device is initialized */
    ST_DEVICE_STATUS_ONBOARDING_READY,        /**< @brief onboarding process ready */
    ST_DEVICE_STATUS_ONBOARDING_START,        /**< @brief onboarding process started */
    ST_DEVICE_STATUS_ONBOARDING_NEED_CONFIRM, /**< @brief onboarding step for waiting ownership confirm */
    ST_DEVICE_STATUS_ONBOARDING_ONBOARDED,    /**< @brief onboarding complete step */
    ST_DEVICE_STATUS_CLOUD_DISCONNECTED,      /**< @brief cloud disconnected */
    ST_DEVICE_STATUS_CLOUD_CONNECTED,         /**< @brief cloud connected */
} st_device_status;

/**
 * @brief Contains a pin values for pin type onboarding process.
 */
typedef struct iot_pin_t {
    unsigned char pin[8]; /**< @brief actual pin values */
} iot_pin_t;

/**
 * @brief Contains a enumeration values for types of capability.
 */
typedef enum iot_cap_val_type {
    IOT_CAP_VAL_TYPE_UNKNOWN = -1, /**< @brief For undefined type. */
    IOT_CAP_VAL_TYPE_NULL,         /**< @brief For null type. */
    IOT_CAP_VAL_TYPE_INTEGER,      /**< @brief For integer. */
    IOT_CAP_VAL_TYPE_NUMBER,       /**< @brief For float number. */
    IOT_CAP_VAL_TYPE_INT_OR_NUM,   /**< @brief For integer or float number. */
    IOT_CAP_VAL_TYPE_STRING,       /**< @brief For NULL-terminated string. */
    IOT_CAP_VAL_TYPE_STR_ARRAY,    /**< @brief For array of NULL-terminated strings. */
    IOT_CAP_VAL_TYPE_JSON_OBJECT,  /**< @brief For json object. */
    IOT_CAP_VAL_TYPE_BOOLEAN       /**< @brief For boolean. */
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
    int integer;     /**< @brief Integer. */

    union {
        double number;     /**< @brief Float number. */
        char *string;      /**< @brief NULL-terminated string. */
        char **strings;    /**< @brief Array of NULL-terminated strings. */
        char *json_object; /**< @brief Json object payload strings */
        bool boolean;      /**< @brief boolean */
    };
} iot_cap_val_t;

/**
 * @brief Attribute extended options structure
 */
typedef struct {
    uint8_t state_change; /**< @brief force this attribute value update event */
    char *command_id;     /**< @brief event related commandId, if not used, set NULL */
    bool *displayed; /**< @brief whether the event should be displayed in the history feed, if not used, set NULL */
} iot_cap_attr_option_t;

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
    char **args_str;

    iot_cap_val_t *cmd_data; /**< @brief Value of each arguments. */

    int total_commands_num; /**< @brief Total number of commands in a bunch of commands */
    int order_of_command;   /**< @brief Order of this command in a bunch of commands */

    char *command_id; /**< @brief commandId */
} iot_cap_cmd_data_t;

/**
 * @brief Preference data
 */
typedef struct {
    char *preference_name;         /**< @brief Name of the preference. */
    iot_cap_val_t preference_data; /**< @brief Value of the preference. */
} iot_preference_data;

/**
 * @brief Contains a enumeration values for types of notification.
 */
typedef enum iot_noti_type {
    IOT_NOTI_TYPE_UNKNOWN = -1,            /**< @brief For undefined type. */
    IOT_NOTI_TYPE_DEV_DELETED,             /**< @brief For device deleted event. */
    IOT_NOTI_TYPE_DEV_CLOUD_CONNECTED,     /**< @brief For device cloud connected event */
    IOT_NOTI_TYPE_DEV_CLOUD_DISCONNECTED,  /**< @brief For device clous disconnected event */
    IOT_NOTI_TYPE_RATE_LIMIT,              /**< @brief For rate limit event. */
    IOT_NOTI_TYPE_QUOTA_REACHED,           /**< @brief For data quota reached event. */
    IOT_NOTI_TYPE_SEND_FAILED,             /**< @brief For send failed event. */
    IOT_NOTI_TYPE_COMMANDS,                /**< @brief For commands */
    IOT_NOTI_TYPE_PREFERENCE_UPDATED,      /**< @brief For preference update */
    IOT_NOTI_TYPE_CHILD_DEVICE_SYNCED,     /**< @brief For child device server information synced */
    IOT_NOTI_TYPE_CHILD_DEVICE_REGISTERED, /**< @brief For child device registration */
} iot_noti_type_t;

/**
 * @brief Contains data for raw data of each notification.
 */
typedef union {
    /* rate limit case */
    struct _rate_limit {
        int count;          /**< @brief Current rate limit count. */
        int threshold;      /**< @brief Current rate limit threshold. */
        int remainingTime;  /**< @brief How much time remains for rate limit releasing. */
        int sequenceNumber; /**< @brief Sequence number of event that triggered rate limit */
    } rate_limit;
    /* quota reached case */
    struct _quota {
        int used;  /**< @brief Current used data usage in bytes. */
        int limit; /**< @brief Current data limit in bytes. */
    } quota;
    /* send fail case */
    struct _send_fail {
        int failed_sequence_num; /**< @brief Send failed events sequence number. */
    } send_fail;
    /* commands */
    struct _commands {
        st_command_data *commands_data; /**< @brief commands data list */
        int commands_num;               /**< @brief Number of commands data list */
    } commands;
    /* Preference */
    struct _preferences {
        size_t preferences_num;                /**< @brief Number of preferences data list */
        iot_preference_data *preferences_data; /**< @brief Preferences data list */
    } preferences;
    /* Child device registered */
    struct _child_device_registered {
        IOT_CHILD_DEV child_dev;
        char *mnId;
        char *serial_number;
    } child_device_registered;
} noti_data_raw_t;

/**
 * @brief Contains data for notification data.
 */
typedef struct {
    iot_noti_type_t type; /**< @brief Type of notification's data. */
    noti_data_raw_t raw;  /**< @brief Raw data of each notification. */
} iot_noti_data_t;

/* For user(apps) callback */
typedef void (*st_status_cb)(st_device_status device_status, void *usr_data);
typedef void (*st_cap_init_cb)(IOT_CAP_HANDLE *cap_handle, void *init_usr_data);
typedef void (*st_cap_noti_cb)(iot_noti_data_t *noti_data, void *noti_usr_data);
typedef void (*st_cap_cmd_cb)(IOT_CAP_HANDLE *cap_handle, iot_cap_cmd_data_t *cmd_data, void *usr_data);

/**
 * @brief Contains data for extension options.
 */
typedef struct {
    st_status_cb status_cb; /**< @brief user callback function to receive status of st-iot-core */
    void *usr_data;         /**< @brief user data(a pointer) to use in status_cb */
    iot_pin_t *pin_num;    /**< @brief if PIN ownership validation type used, valid 8 digit pin should be set. otherwise
                              set null. */
    bool skip_usr_confirm; /**< @brief set true to skip user-confirm, else false. */
    bool start_from_onboarding; /**< @brief flag for starting from onboarding process */
} iot_ext_args_t;

/**
 * @brief Contains a enumeration values for types of notification.
 */
typedef enum iot_info_type {
    IOT_INFO_TYPE_IOT_DEVICE_STATUS, /**< @brief to get current device status */
    IOT_INFO_TYPE_IOT_PROVISIONED,   /**< @brief to get provision state, provisioned or not */
    IOT_INFO_TYPE_IOT_SERVER_ENV,    /**< @brief server environment info */
    IOT_INFO_TYPE_IOT_DEVICEID,      /**< @brief to get deviceId */
} iot_info_type_t;

typedef enum iot_server_type {
    IOT_SERVER_PROD_AP_NORTH_EAST2,
    IOT_SERVER_PROD_US_EAST1,
    IOT_SERVER_PROD_EU_WEST1,
    IOT_SERVER_PROD_CHINA,
    IOT_SERVER_ACC_US_EAST2,
    IOT_SERVER_STG_US_EAST1,
    IOT_SERVER_STG_CHINA,
    IOT_SERVER_DEV_US_EAST1,
    IOT_SERVER_UNKNOWN,
} iot_server_type_t;

typedef enum {
    SERVER_ENV_UNKNOWN,
    SERVER_ENV_PRD,
    SERVER_ENV_ACC,
    SERVER_ENV_STG,
    SERVER_ENV_DEV,
} server_env_type;

#define IOT_DEVICE_ID_LEN (36)

/**
 * @brief Contains data for iot-core information.
 */
typedef union {
    st_device_status device_status; /**< @brief device status */
    /* to get provisioned state case */
    bool provisioned; /**< @brief to check provisoned or not */
    server_env_type server_env;
    char device_id[IOT_DEVICE_ID_LEN + 1]; /**< @brief uuid format deviceId info */
} iot_info_data_t;

/**
 * @brief Contains a enumeration values for mode of iot_dump
 */
typedef enum iot_dump_mode {
    IOT_DUMP_MODE_NEED_BASE64 = (1 << 0),     /**< @brief make log encoded to base64 */
    IOT_DUMP_MODE_NEED_DUMP_STATE = (1 << 1), /**< @brief add dump_state in log_dump */
} iot_dump_mode_t;

/**
 * @brief ST Server type
 */
typedef enum {
    SERVER_TYPE_UNKNOWN,        /**< @brief Unknown Server */
    SERVER_TYPE_AP_NORTH_EAST2, /**< @brief AP North East2 server location */
    SERVER_TYPE_US_EAST1,       /**< @brief US East1 server location */
    SERVER_TYPE_EU_WEST1,       /**< @brief EU West1 server location */
} st_server_type;

/**
 * @brief Device identity type
 */
typedef enum {
    ST_IDENTITY_METHOD_NONE,
    ST_IDENTITY_METHOD_MANUAL_ED25519, /**< Ed25519 device keys are included in config. This option for develop */
    ST_IDENTITY_METHOD_EMBEDDED_KEY,   /**< Device identity is embedded on device during manufacturing. This option for
                                          commercial. */
} st_identity_method;

/**
 * @brief Device configuration data
 */
typedef struct {
    /* Registration Info */
    char *device_id;            /**< @brief Optional, If device_id is presented, it skip onboarding process. */
    st_server_type server_type; /**< @brief Server info for device to connect. Only valid when device_is is presented */

    /* Device Identity */
    st_identity_method id_method; /**< @brief Method for this device to provide its identity. */
    union _identity {
        struct _ed25519 {
            char *sn;
            char *pubkey;
            char *prikey;
        } ed25519;
    } identity; /**< @brief identity should be provided only when METHOD_MANUAL is set */

    /**
     * Device Onboarding Info
     *
     * Below onboarding info is neede for onboarding process.
     **/
    char *onboarding_id;
    char *mnId;
    char *setup_id;
    char *vid;
    char *device_type_id;
    char **ownership_validation_types;

    /* Device Profile Info */
    char *dip_id;
    int dip_major_version;
    int dip_minor_version;
} st_device_config_t;

typedef struct {
    char *mnid;
    char *serial_number;
    char *vid;
    char *device_type_id;
    char *dip_id;
    int dip_major_version;
    int dip_minor_version;
} st_child_dev_reg_info;

//////////////////////////////////////////////////////////////

#define ST_CAP_CREATE_ATTR_NUMBER(cap_handle, attribute, value_number, unit, data, output_attr) \
    {                                                                                           \
        iot_cap_val_t value;                                                                    \
                                                                                                \
        value.type = IOT_CAP_VAL_TYPE_NUMBER;                                                   \
        value.number = value_number;                                                            \
        output_attr = st_cap_create_attr(cap_handle, attribute, &value, unit, data);            \
    }

#define ST_CAP_SEND_ATTR_NUMBER(cap_handle, attribute, value_number, unit, data, output_seq_num) \
    {                                                                                            \
        IOT_EVENT *attr = NULL;                                                                  \
        iot_cap_val_t value;                                                                     \
                                                                                                 \
        value.type = IOT_CAP_VAL_TYPE_NUMBER;                                                    \
        value.number = value_number;                                                             \
        attr = st_cap_create_attr(cap_handle, attribute, &value, unit, data);                    \
        if (attr != NULL) {                                                                      \
            output_seq_num = st_cap_send_attr(&attr, 1);                                         \
            st_cap_free_attr(attr);                                                              \
        }                                                                                        \
    }

#define ST_CAP_CREATE_ATTR_STRING(cap_handle, attribute, value_string, unit, data, output_attr) \
    {                                                                                           \
        iot_cap_val_t value;                                                                    \
                                                                                                \
        value.type = IOT_CAP_VAL_TYPE_STRING;                                                   \
        value.string = value_string;                                                            \
        output_attr = st_cap_create_attr(cap_handle, attribute, &value, unit, data);            \
    }

#define ST_CAP_SEND_ATTR_STRING(cap_handle, attribute, value_string, unit, data, output_seq_num) \
    {                                                                                            \
        IOT_EVENT *attr = NULL;                                                                  \
        iot_cap_val_t value;                                                                     \
                                                                                                 \
        value.type = IOT_CAP_VAL_TYPE_STRING;                                                    \
        value.string = value_string;                                                             \
        attr = st_cap_create_attr(cap_handle, attribute, &value, unit, data);                    \
        if (attr != NULL) {                                                                      \
            output_seq_num = st_cap_send_attr(&attr, 1);                                         \
            st_cap_free_attr(attr);                                                              \
        }                                                                                        \
    }

#define ST_CAP_CREATE_ATTR_STRINGS_ARRAY(cap_handle, attribute, value_string_array, array_num, unit, data, \
                                         output_attr)                                                      \
    {                                                                                                      \
        iot_cap_val_t value;                                                                               \
                                                                                                           \
        value.type = IOT_CAP_VAL_TYPE_STR_ARRAY;                                                           \
        value.str_num = array_num;                                                                         \
        value.strings = value_string_array;                                                                \
        output_attr = st_cap_create_attr(cap_handle, attribute, &value, unit, data);                       \
    }

#define ST_CAP_SEND_ATTR_STRINGS_ARRAY(cap_handle, attribute, value_string_array, array_num, unit, data, \
                                       output_seq_num)                                                   \
    {                                                                                                    \
        IOT_EVENT *attr = NULL;                                                                          \
        iot_cap_val_t value;                                                                             \
                                                                                                         \
        value.type = IOT_CAP_VAL_TYPE_STR_ARRAY;                                                         \
        value.str_num = array_num;                                                                       \
        value.strings = value_string_array;                                                              \
        attr = st_cap_create_attr(cap_handle, attribute, &value, unit, data);                            \
        if (attr != NULL) {                                                                              \
            output_seq_num = st_cap_send_attr(&attr, 1);                                                 \
            st_cap_free_attr(attr);                                                                      \
        }                                                                                                \
    }

#define ST_CAP_CREATE_ATTR_OBJECT(cap_handle, attribute, value_object, unit, data, output_attr) \
    {                                                                                           \
        iot_cap_val_t value;                                                                    \
                                                                                                \
        value.type = IOT_CAP_VAL_TYPE_JSON_OBJECT;                                              \
        value.json_object = value_object;                                                       \
        output_attr = st_cap_create_attr(cap_handle, attribute, &value, unit, data);            \
    }

#define ST_CAP_SEND_ATTR_OBJECT(cap_handle, attribute, value_object, unit, data, output_seq_num) \
    {                                                                                            \
        IOT_EVENT *attr = NULL;                                                                  \
        iot_cap_val_t value;                                                                     \
                                                                                                 \
        value.type = IOT_CAP_VAL_TYPE_JSON_OBJECT;                                               \
        value.json_object = value_object;                                                        \
        attr = st_cap_create_attr(cap_handle, attribute, &value, unit, data);                    \
        if (attr != NULL) {                                                                      \
            output_seq_num = st_cap_send_attr(&attr, 1);                                         \
            st_cap_free_attr(attr);                                                              \
        }                                                                                        \
    }

#define ST_CAP_CREATE_ATTR_BOOLEAN(cap_handle, attribute, value_boolean, unit, data, output_attr) \
    {                                                                                             \
        iot_cap_val_t value;                                                                      \
                                                                                                  \
        value.type = IOT_CAP_VAL_TYPE_BOOLEAN;                                                    \
        value.boolean = value_boolean;                                                            \
        output_attr = st_cap_create_attr(cap_handle, attribute, &value, unit, data);              \
    }

#define ST_CAP_SEND_ATTR_BOOLEAN(cap_handle, attribute, value_boolean, unit, data, output_seq_num) \
    {                                                                                              \
        IOT_EVENT *attr = NULL;                                                                    \
        iot_cap_val_t value;                                                                       \
                                                                                                   \
        value.type = IOT_CAP_VAL_TYPE_BOOLEAN;                                                     \
        value.boolean = value_boolean;                                                             \
        attr = st_cap_create_attr(cap_handle, attribute, &value, unit, data);                      \
        if (attr != NULL) {                                                                        \
            output_seq_num = st_cap_send_attr(&attr, 1);                                           \
            st_cap_free_attr(attr);                                                                \
        }                                                                                          \
    }

/**
 * @brief Create IOT_EVENT data.
 *
 * @details This function creates a new IOT_EVENT data with input parameters.
 * Once it returns, user has full responsibility for deallocating event data
 * by using [st_cap_free_attr](@ref st_cap_free_attr).
 * NOTE:IOT_EVENT created in this function must be passed to st_cap_send_attr function
 * for sending events.
 *
 * @param[in] cap_handle Capability reference which the event is created in.
 * @param[in] attribute The attribute string of IOT_EVENT data.
 * @param[in] value The value to add to IOT_EVENT data.
 * @param[in] unit The unit string if needed. Otherwise NULL.
 * @param[in] data The data json object if needed. Otherwise NULL.
 *
 * @return Pointer of `IOT_EVENT` which is used to publish device status.
 *
 * @warning Must call [st_cap_free_attr](@ref st_cap_free_attr)
 * to free IOT_EVENT data after using it.
 *
 * @see @ref st_cap_send_attr
 */
IOT_EVENT *st_cap_create_attr(IOT_CAP_HANDLE *cap_handle, const char *attribute, iot_cap_val_t *value, const char *unit,
                              const char *data);

/**
 * @brief Create IOT_EVENT data including options
 *
 * @param[in] cap_handle Capability reference which the event is created in.
 * @param[in] attribute The attribute string of IOT_EVENT data.
 * @param[in] value The value to add to IOT_EVENT data.
 * @param[in] unit The unit string if needed. Otherwise NULL.
 * @param[in] data The data json object if needed. Otherwise NULL.
 * @param[in] options The option object if needed. Otherwise NULL.
 *
 * @return Pointer of `IOT_EVENT` which is used to publish device status.
 *
 * @warning Must call [st_cap_free_attr](@ref st_cap_free_attr)
 * to free IOT_EVENT data after using it.
 *
 * @see @ref st_cap_send_attr
 */
IOT_EVENT *st_cap_create_attr_with_option(IOT_CAP_HANDLE *cap_handle, const char *attribute, iot_cap_val_t *value,
                                          const char *unit, const char *data, iot_cap_attr_option_t *options);

/**
 * @brief Create IOT_EVENT data with releated command ID.
 *
 * @details This function creates a new IOT_EVENT data with input parameters.
 * Once it returns, user has full responsibility for deallocating event data
 * by using [st_cap_free_attr](@ref st_cap_free_attr).
 * NOTE:IOT_EVENT created in this function must be passed to st_cap_send_attr function
 * for sending events.
 *
 * @param[in] cap_handle Capability reference which the event is created in.
 * @param[in] attribute The attribute string of IOT_EVENT data.
 * @param[in] value The value to add to IOT_EVENT data.
 * @param[in] unit The unit string if needed. Otherwise NULL.
 * @param[in] data The data json object if needed. Otherwise NULL.
 * @param[in] command_id The commandId related with the this event if needed. Otherwise NULL.
 *
 * @return Pointer of `IOT_EVENT` which is used to publish device status.
 *
 * @warning Must call [st_cap_free_attr](@ref st_cap_free_attr)
 * to free IOT_EVENT data after using it.
 *
 * @see @ref st_cap_send_attr
 */
IOT_EVENT *st_cap_create_attr_with_id(IOT_CAP_HANDLE *cap_handle, const char *attribute, iot_cap_val_t *value,
                                      const char *unit, const char *data, char *command_id);

/**
 * @brief Free IOT_EVENT data.
 *
 * @details This function frees IOT_EVENT data.
 *
 * @param[in] event The IOT_EVENT data to free.
 */
void st_cap_free_attr(IOT_EVENT *event);

/**
 * @brief Request to publish deviceEvent.
 *
 * @details This function creates a deviceEvent with the list of IOT_EVENT data,
 * and requests to publish it.
 * When there is no error, this function returns sequence number,
 * which is unique value to identify the deviceEvent message.
 * NOTE:IOT_EVENT must be created from st_cap_create_attr
 *
 * @param[in] event The IOT_EVENT data list to create the deviceEvent.
 * @param[in] evt_num The number of IOT_EVENT data in the event.
 *
 * @return return `sequence number`(which is positive integer) if successful,
 * negative integer for error case.
 */
int st_cap_send_attr(IOT_EVENT *event[], uint8_t evt_num);

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
IOT_CAP_HANDLE *st_cap_handle_init(IOT_CTX *iot_ctx, const char *component, const char *capability,
                                   st_cap_init_cb init_cb, void *init_usr_data);

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
int st_conn_set_noti_cb(IOT_CTX *iot_ctx, st_cap_noti_cb noti_cb, void *noti_usr_data);

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
int st_cap_cmd_set_cb(IOT_CAP_HANDLE *cap_handle, const char *cmd_type, st_cap_cmd_cb cmd_cb, void *usr_data);

/**
 * @brief	st-iot-core initialize function
 * @details	This function initializes st-iot-core for target
 * @param[in]	onboarding_config	starting pointer of onboarding_config.json contents
 * @param[in]	onboarding_config_len	size of onboarding_config.json contents
 * @param[in]	device_info		starting pointer of device_info.json contents
 * @param[in]	device_info_len		size of device_info.json contents
 * @return		return IOT_CTX handle(a pointer) if it succeeds, or NULL if it fails
 */
IOT_CTX *st_conn_init(unsigned char *onboarding_config, unsigned int onboarding_config_len, unsigned char *device_info,
                      unsigned int device_info_len);

/**
 * @brief	st-iot-core server connection function
 * @details	This function tries to connect server
 * This function can't be used in callback functions such as init_cb, noti_cb, cmd_cb, status_cb
 * @param[in]	iot_ctx		iot_context handle generated by st_conn_init()
 * @param[in]	status_cb	user callback function to receive status of st-iot-core
 * @param[in]	maps		status of st-iot-core interested to receive through status_cb
 * @param[in]	usr_data	user data(a pointer) to use in status_cb
 * @param[in]	pin_num		if PIN ownership validation type used, valid 8 digit pin should be set. otherwise set
 * null.
 * @return 		return `(0)` if it works successfully, non-zero for error case.
 */
int st_conn_start(IOT_CTX *iot_ctx, st_status_cb status_cb, void *usr_data, iot_pin_t *pin_num);

/**
 * @brief	st-iot-core device clean-up function
 * @details	This function cleans-up all DATA including provisioning & registered data
 * This function can't be used in callback functions such as init_cb, noti_cb, cmd_cb, status_cb
 * @param[in]	iot_ctx		iot_context handle generated by st_conn_init()
 * @param[in]	reboot		boolean set true for auto-reboot of system, else false.
 * @return 		return `(0)` if it works successfully, non-zero for error case.
 */
int st_conn_cleanup(IOT_CTX *iot_ctx, bool reboot);

/**
 * @brief	easysetup user confirm report function
 * @details	This function reports the user confirmation to easysetup
 * @param[in]	iot_ctx		iot_context handle generated by st_conn_init()
 * @param[in]	confirm		user confirmation result
 */
void st_conn_ownership_confirm(IOT_CTX *iot_ctx, bool confirm);

/**
 * @brief	expanded st-iot-core server connection function
 * @details	This function tries to connect server with extension arguments
 * This function can't be used in callback functions such as init_cb, noti_cb, cmd_cb, status_cb
 * @param[in]	iot_ctx		iot_context handle generated by st_conn_init()
 * @param[in]	ext_args	extension arguments for sepcific connection control
 * @return 		return `(0)` if it works successfully, non-zero for error case.
 */
int st_conn_start_ex(IOT_CTX *iot_ctx, iot_ext_args_t *ext_args);

/**
 * @brief	st-iot-core information getting function
 * @details	This function tries to get current iot-core's information
 * @param[in]	iot_ctx		iot_context handle generated by st_conn_init()
 * @param[in]	info_type	type of iot_info_types_t to get its value
 * @param[out]	info_data	A pointer to actual information data to get each type of iot_info_type_t
 * @return 		return `(0)` if it works successfully, non-zero for error case.
 */
int st_info_get(IOT_CTX *iot_ctx, iot_info_type_t info_type, iot_info_data_t *info_data);

/**
 * @brief create log_dump
 * @param[in] iot_ctx - iot_core context
 * @param[out] log_dump_output - a pointer of not allocated pointer for log dump buffer.
 *         it will allocated in this function
 * @param[in] max_log_dump_size - maximum size of log dump.
 * @param[out] allocated_size - allocated memory size of log_dump_output
 * @param[in] log_mode - log mode generated by OR operation of following values
 *    IOT_DUMP_MODE_NEED_BASE64 : make log encoded to base64
 *    IOT_DUMP_MODE_NEED_DUMP_STATE : add dump state in log
 * @retval return `(0)` if it works successfully, non-zero for error case.
 *
 * @warning must free log_dump_output after using it.
 */
int st_create_log_dump(IOT_CTX *iot_ctx, char **log_dump_output, size_t max_log_dump_size, size_t *allocated_size,
                       int log_mode);

#define ST_DEFAULT_HEALTH_PERIOD 240 /* default device health period is 240 seconds */
/**
 * @brief	change sending health period
 * @details	This function changes health ping period.
 * @param[in]	iot_ctx		iot_context handle generated by st_conn_init()
 * @param[in]	new_period	new health ping period to change (seconds)
 * @return 		return `(0)` if it works successfully, non-zero for error case.
 */
int st_change_health_period(IOT_CTX *iot_ctx, unsigned int new_period);

/**
 * @brief	change device name
 * @details	This function changes device name. It reflects ST app's device name.
 * @param[in]	iot_ctx		iot_context handle generated by st_conn_init()
 * @param[in]	new_name	new device name null-terminated string
 * @return 		return `(0)` if it works successfully, non-zero for error case.
 */
int st_change_device_name(IOT_CTX *iot_ctx, const char *new_name);

/**
 * @brief Request to publish deviceEvent.(version 2)
 *
 * @details This function sends list of attr data to server.
 * When there is no error, this function returns sequence number,
 * which is unique value to identify the deviceEvent message.
 *
 * @param[in]	iot_ctx		iot_context handle generated by st_conn_init()
 * @param[in] attr_data The st_attr_data data list to create the deviceEvent.
 * @param[in] attr_num The number of attr_data list.
 *
 * @return return `sequence number`(which is positive integer) if successful,
 * negative integer for error case.
 */
int st_cap_send_attr_v2(IOT_CTX *iot_ctx, st_attr_data *attr_data[], uint8_t attr_num);

/**
 * @brief	Initialize ST device
 * @details	This function initializes a ST device.
 * @param[in]	config	configuration data for a ST device
 * @return		return IOT_CTX handle(a pointer) if it succeeds, or NULL if it fails
 */
IOT_CTX *st_device_init(st_device_config_t *config);

/**
 * @brief Register child device
 *
 * @param[in] iot_ctx iot_context handle generated by st_conn_init()
 * @param[in] reg_info registration info for child device
 *
 * @return zero if it works successfully, non-zero for error case.
 */
int st_register_child_dev(IOT_CTX *iot_ctx, st_child_dev_reg_info *reg_info);

/**
 * @brief Get child device handle
 *
 * @param[in] iot_ctx iot_context handle generated by st_conn_init()
 * @param[in] mnId mnId for the child device
 * @param[in] serial_nmuber serial number for the child device
 *
 * @return child device handle if there is a matched child device registered, null if not.
 */
IOT_CHILD_DEV st_get_child_dev(IOT_CTX *iot_ctx, char *mnId, char *serial_number);

/**
 * @brief Make child device online and register notification callback
 *
 * @param[in] child_dev child device handle.
 * @param[in] noti_cb The callback function which will be called when notification event occurs.
 * @param[in] noti_usr_data User data for noti_cb.
 *
 * @return return `(0)` if it works successfully, non-zero for error case.
 */
int st_child_dev_start(IOT_CHILD_DEV child_dev, st_cap_noti_cb noti_cb, void *noti_usr_data);

/**
 * @brief Create and initialize a child device capability handle.
 *
 * @details This function creates a child device capability handle, and initializes it with input args.
 *
 * @param[in] child_dev child device handle.
 * @param[in] component Component string. Default component name is "main".
 * @param[in] capability Capability string. This should be matched with "id" value of capability definition json format.
 * @param[in] init_cb The function which is called to initialize device state.
 * @param[in] init_usr_data User data for init_cb.
 *
 * @return Pointer of created capability handle.
 */
IOT_CAP_HANDLE *st_child_dev_cap_handle_init(IOT_CHILD_DEV child_dev, const char *component, const char *capability,
                                             st_cap_init_cb init_cb, void *init_usr_data);

#ifdef __cplusplus
}
#endif

#endif /* _ST_DEV_H_ */
