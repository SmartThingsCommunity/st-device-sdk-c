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
#define SERVER_NOTI_TYPE_DEVICE_UPDATED "device.updated"
#define SERVER_NOTI_TYPE_DEVICE_GET "devices.get"
#define SERVER_NOTI_TYPE_DEVICE_CREATED "secondary.device.created"
#define SERVER_NOTI_TYPE_CHILD_DEVICE_HEALTH_RESPONSE "secondary.health.response"

#define MAX_SQNUM 0x7FFFFFFF

enum iot_cap_unit_type {
    IOT_CAP_UNIT_TYPE_UNUSED,
    IOT_CAP_UNIT_TYPE_STRING,
};

/**
 * @brief Contains a "unit" data.
 */
typedef struct {
    uint8_t type; /**< @brief Unused or string */
    char *string; /**< @brief NULL-terminated string. */
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

#if defined(CONFIG_STDK_IOT_CORE_SUPPORT_ATTR_CACHE)
#define IOT_CAP_ATTR_INVALID_CHUNK_ID (-1)

/**
 * @brief Sync state of a cached attribute value.
 */
typedef enum iot_cap_attr_state {
    IOT_CAP_ATTR_STATE_SYNCED = 0, /**< @brief value has been successfully delivered to the cloud */
    IOT_CAP_ATTR_STATE_UPDATING,   /**< @brief value is currently being published (in flight) */
} iot_cap_attr_state_t;

/**
 * @brief linked list node tracking the latest value of an attribute and its sync state.
 *
 * One node per attribute name. st_cap_send_attr compares against nodes in the
 * SYNCED state to skip publishing a value already delivered to the cloud, and
 * flips a node to SYNCED once the publish carrying it is acknowledged.
 */
typedef struct iot_cap_last_val {
    /**
     * @brief NULL-terminated attribute name, used as the lookup key.
     */
    char *attr_type;
    /**
     * @brief deep copy of the latest value handed to st_cap_send_attr.
     */
    iot_cap_val_t value;
    /**
     * @brief sync state of @ref value (SYNCED or UPDATING).
     */
    iot_cap_attr_state_t state;
    /**
     * @brief chunk id of the in-flight publish while UPDATING, used to match the
     *        publish acknowledgement; IOT_CAP_ATTR_INVALID_CHUNK_ID otherwise.
     */
    int chunk_id;
    /**
     * @brief a pointer to the next node.
     */
    struct iot_cap_last_val *next;
} iot_cap_last_val_t;
#endif /* CONFIG_STDK_IOT_CORE_SUPPORT_ATTR_CACHE */

/**
 * @brief Contains user command callback function data.
 */
typedef struct iot_cap_cmd_set {
    /**
     * @brief NULL-terminated string, which is name of `commands`.
     */
    char *cmd_type;

    st_cap_cmd_cb cmd_cb; /**< @brief User callback function. */
    void *usr_data;       /**< @brief User data for cmd_cb. */
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

    struct iot_cap_cmd_set_list *cmd_list; /**< @brief List of command data. */

#if defined(CONFIG_STDK_IOT_CORE_SUPPORT_ATTR_CACHE)
    struct iot_cap_last_val *last_val_list; /**< @brief List of last successfully sent value per attribute. */
#endif

    st_cap_init_cb init_cb; /**< @brief User callback function for init device state. */
    void *init_usr_data;    /**< @brief User data for init_cb. */

    struct iot_context *ctx;     /**< @brief ctx */
    iot_child_device *child_dev; /**< @brief related child device. NULL if it's not Capability of child device */
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
    char *msg;  /**< @brief final message for network handling layer such as MQTT */
    int msglen; /**< @brief final message length */
} iot_cap_msg_t;

#endif /* _IOT_CAPABILITY_H_ */
