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

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "device_control.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "iot_cli_cmd.h"
#include "iot_uart_cli.h"
#include "st_dev.h"

// onboarding_config_start is null-terminated string
extern const uint8_t onboarding_config_start[] asm("_binary_onboarding_config_json_start");
extern const uint8_t onboarding_config_end[] asm("_binary_onboarding_config_json_end");

// device_info_start is null-terminated string
extern const uint8_t device_info_start[] asm("_binary_device_info_json_start");
extern const uint8_t device_info_end[] asm("_binary_device_info_json_end");

static st_device_status g_device_status = ST_DEVICE_STATUS_INIT;

st_child_dev_reg_info child_register_info_1 = {.mnid = "MNID",
                                               .serial_number = "first_child_sn",
                                               .vid = "VID",
                                               .device_type_id = "TYPE",
                                               .dip_id = "DIP_UUID",
                                               .dip_major_version = 0,
                                               .dip_minor_version = 1};

st_child_dev_reg_info child_register_info_2 = {.mnid = "MNID",
                                               .serial_number = "second_child_sn",
                                               .vid = "VID",
                                               .device_type_id = "TYPE",
                                               .dip_id = "DIP_UUID",
                                               .dip_major_version = 0,
                                               .dip_minor_version = 1};

IOT_CTX *iot_ctx = NULL;
int need_child_device_registration = 0;
IOT_CHILD_DEV child_dev1 = NULL;
IOT_CHILD_DEV child_dev2 = NULL;
IOT_CAP_HANDLE *parent_cap_handle = NULL;
IOT_CAP_HANDLE *child_dev1_cap_handle = NULL;
IOT_CAP_HANDLE *child_dev2_cap_handle = NULL;
int parent_switch_state = SWITCH_OFF;
int child_dev1_switch_state = SWITCH_OFF;
int child_dev2_switch_state = SWITCH_OFF;

static void update_switch_attribute(IOT_CAP_HANDLE switch_cap_handle, int state)
{
    int32_t sequence_no = 1;

    /* Send initial switch attribute */
    if (state == SWITCH_OFF) {
        ST_CAP_SEND_ATTR_STRING(switch_cap_handle, "switch", "off", NULL, NULL, sequence_no);
    } else {
        ST_CAP_SEND_ATTR_STRING(switch_cap_handle, "switch", "on", NULL, NULL, sequence_no);
    }

    if (sequence_no < 0)
        printf("fail to send switch value\n");
    else
        printf("Sequence number return : %ld\n", sequence_no);
}

static void cap_switch_init_cb(IOT_CAP_HANDLE *handle, void *usr_data)
{
    printf("Init switch attribute\n");
    update_switch_attribute(parent_cap_handle, parent_switch_state);
}

static void cap_switch_cmd_off_cb(IOT_CAP_HANDLE *handle, iot_cap_cmd_data_t *cmd_data, void *usr_data)
{
    printf("OFF command received\n");

    parent_switch_state = SWITCH_OFF;
    update_switch_attribute(parent_cap_handle, SWITCH_OFF);
    change_switch_state(SWITCH_OFF);
}

static void cap_switch_cmd_on_cb(IOT_CAP_HANDLE *handle, iot_cap_cmd_data_t *cmd_data, void *usr_data)
{
    printf("ON command received\n");

    parent_switch_state = SWITCH_ON;
    update_switch_attribute(parent_cap_handle, SWITCH_ON);
    change_switch_state(SWITCH_ON);
}

static void iot_status_cb(st_device_status device_status, void *usr_data)
{
    printf("Device status %d\n", device_status);
    g_device_status = device_status;
    switch (device_status) {
        case ST_DEVICE_STATUS_INIT:
            break;
        case ST_DEVICE_STATUS_ONBOARDING_READY:
            break;
        case ST_DEVICE_STATUS_ONBOARDING_START:
            break;
        case ST_DEVICE_STATUS_ONBOARDING_NEED_CONFIRM:
            break;
        case ST_DEVICE_STATUS_ONBOARDING_ONBOARDED:
            need_child_device_registration = 1;
            break;
        case ST_DEVICE_STATUS_CLOUD_DISCONNECTED:
            break;
        case ST_DEVICE_STATUS_CLOUD_CONNECTED:
            break;
    }
}

static void child_dev1_cap_switch_cmd_off_cb(IOT_CAP_HANDLE *handle, iot_cap_cmd_data_t *cmd_data, void *usr_data)
{
    printf("Child device1 OFF command received\n");
    child_dev1_switch_state = SWITCH_OFF;
    update_switch_attribute(child_dev1_cap_handle, SWITCH_OFF);
}

static void child_dev1_cap_switch_cmd_on_cb(IOT_CAP_HANDLE *handle, iot_cap_cmd_data_t *cmd_data, void *usr_data)
{
    printf("Child device1 ON command received\n");
    child_dev1_switch_state = SWITCH_ON;
    update_switch_attribute(child_dev1_cap_handle, SWITCH_ON);
}

static void iot_child_dev1_noti_cb(iot_noti_data_t *noti_data, void *noti_usr_data)
{
    printf("Child device1 notification message received %d\n", noti_data->type);
    if (noti_data->type == IOT_NOTI_TYPE_DEV_CLOUD_CONNECTED) {
        update_switch_attribute(child_dev1_cap_handle, child_dev1_switch_state);
    }
}

static void init_child_dev1()
{
    int iot_err;
    if (child_dev1 == NULL) {
        printf("Still didn't get child device1 handle");
        return;
    }

    child_dev1_cap_handle = st_child_dev_cap_handle_init(child_dev1, "main", "switch", NULL, NULL);

    iot_err = st_cap_cmd_set_cb(child_dev1_cap_handle, "off", child_dev1_cap_switch_cmd_off_cb, NULL);
    if (iot_err) {
        printf("fail to set cmd_cb for off\n");
    }

    iot_err = st_cap_cmd_set_cb(child_dev1_cap_handle, "on", child_dev1_cap_switch_cmd_on_cb, NULL);
    if (iot_err) {
        printf("fail to set cmd_cb for on\n");
    }

    st_child_dev_start(child_dev1, iot_child_dev1_noti_cb, NULL);
}

static void child_dev2_cap_switch_cmd_off_cb(IOT_CAP_HANDLE *handle, iot_cap_cmd_data_t *cmd_data, void *usr_data)
{
    printf("Child device1 OFF command received\n");
    child_dev2_switch_state = SWITCH_OFF;
    update_switch_attribute(child_dev2_cap_handle, SWITCH_OFF);
}

static void child_dev2_cap_switch_cmd_on_cb(IOT_CAP_HANDLE *handle, iot_cap_cmd_data_t *cmd_data, void *usr_data)
{
    printf("Child device2 ON command received\n");
    child_dev2_switch_state = SWITCH_ON;
    update_switch_attribute(child_dev2_cap_handle, SWITCH_ON);
}

static void iot_child_dev2_noti_cb(iot_noti_data_t *noti_data, void *noti_usr_data)
{
    printf("Child device2 notification message received %d\n", noti_data->type);
    if (noti_data->type == IOT_NOTI_TYPE_DEV_CLOUD_CONNECTED) {
        update_switch_attribute(child_dev2_cap_handle, child_dev2_switch_state);
    }
}

static void init_child_dev2()
{
    int iot_err;
    if (child_dev2 == NULL) {
        printf("Still didn't get child device2 handle");
        return;
    }

    child_dev2_cap_handle = st_child_dev_cap_handle_init(child_dev2, "main", "switch", NULL, NULL);

    iot_err = st_cap_cmd_set_cb(child_dev2_cap_handle, "off", child_dev2_cap_switch_cmd_off_cb, NULL);
    if (iot_err) {
        printf("fail to set cmd_cb for off\n");
    }

    iot_err = st_cap_cmd_set_cb(child_dev2_cap_handle, "on", child_dev2_cap_switch_cmd_on_cb, NULL);
    if (iot_err) {
        printf("fail to set cmd_cb for on\n");
    }

    st_child_dev_start(child_dev2, iot_child_dev2_noti_cb, NULL);
}

static void iot_noti_cb(iot_noti_data_t *noti_data, void *noti_usr_data)
{
    int ret;
    printf("Notification message received\n");

    if (noti_data->type == IOT_NOTI_TYPE_DEV_DELETED) {
        printf("[device deleted]\n");
    } else if (noti_data->type == IOT_NOTI_TYPE_RATE_LIMIT) {
        printf("[rate limit] Remaining time:%d, sequence number:%d\n", noti_data->raw.rate_limit.remainingTime,
               noti_data->raw.rate_limit.sequenceNumber);
    } else if (noti_data->type == IOT_NOTI_TYPE_PREFERENCE_UPDATED) {
        for (int i = 0; i < noti_data->raw.preferences.preferences_num; i++) {
            printf("[preference update] name : %s value : ",
                   noti_data->raw.preferences.preferences_data[i].preference_name);
            if (noti_data->raw.preferences.preferences_data[i].preference_data.type == IOT_CAP_VAL_TYPE_NULL)
                printf("NULL\n");
            else if (noti_data->raw.preferences.preferences_data[i].preference_data.type == IOT_CAP_VAL_TYPE_STRING)
                printf("%s\n", noti_data->raw.preferences.preferences_data[i].preference_data.string);
            else if (noti_data->raw.preferences.preferences_data[i].preference_data.type == IOT_CAP_VAL_TYPE_NUMBER)
                printf("%f\n", noti_data->raw.preferences.preferences_data[i].preference_data.number);
            else if (noti_data->raw.preferences.preferences_data[i].preference_data.type == IOT_CAP_VAL_TYPE_INTEGER)
                printf("%d\n", noti_data->raw.preferences.preferences_data[i].preference_data.integer);
            else if (noti_data->raw.preferences.preferences_data[i].preference_data.type == IOT_CAP_VAL_TYPE_BOOLEAN)
                printf("%s\n",
                       noti_data->raw.preferences.preferences_data[i].preference_data.boolean ? "true" : "false");
            else
                printf("Unknown type\n");
        }
    } else if (noti_data->type == IOT_NOTI_TYPE_CHILD_DEVICE_SYNCED) {
        printf("Child device info is synced with server\n");
        if (need_child_device_registration) {
            printf("If it's first synced after main device onboarded, register child devices");
            ret = st_register_child_dev(iot_ctx, &child_register_info_1);
            if (ret) {
                printf("Failed to register child 1 device\n");
            }
            ret = st_register_child_dev(iot_ctx, &child_register_info_2);
            if (ret) {
                printf("Failed to register child 2 device\n");
            }
            need_child_device_registration = 0;
        } else {
            if (child_dev1 == NULL) {
                child_dev1 = st_get_child_dev(iot_ctx, "MNID", "first_child_sn");
                init_child_dev1();
            }
            if (child_dev2 == NULL) {
                child_dev2 = st_get_child_dev(iot_ctx, "MNID", "second_child_sn");
                init_child_dev2();
            }
        }
    } else if (noti_data->type == IOT_NOTI_TYPE_CHILD_DEVICE_REGISTERED) {
        printf("Child device(mnId = %s, serial number %s) registered\n", noti_data->raw.child_device_registered.mnId,
               noti_data->raw.child_device_registered.serial_number);
        if (!strncmp(noti_data->raw.child_device_registered.serial_number, "first_child_sn",
                     strlen("first_child_sn"))) {
            child_dev1 = noti_data->raw.child_device_registered.child_dev;
            init_child_dev1();
        }
        if (!strncmp(noti_data->raw.child_device_registered.serial_number, "second_child_sn",
                     strlen("second_child_sn"))) {
            child_dev2 = noti_data->raw.child_device_registered.child_dev;
            init_child_dev2();
        }
    }
}

static void connection_start(void)
{
    int err;

    // process on-boarding procedure. There is nothing more to do on the app side than call the API.
    err = st_conn_start(iot_ctx, (st_status_cb)&iot_status_cb, NULL, NULL);
    if (err) {
        printf("fail to start connection. err:%d\n", err);
    }
}

static void connection_start_task(void *arg)
{
    connection_start();
    vTaskDelete(NULL);
}

void button_event(int type, int count)
{
    if (type == BUTTON_SHORT_PRESS) {
        printf("Button short press, count: %d\n", count);
        switch (count) {
            case 1:
                if (g_device_status == ST_DEVICE_STATUS_ONBOARDING_NEED_CONFIRM) {
                    st_conn_ownership_confirm(iot_ctx, true);
                } else {
                    if (parent_switch_state == SWITCH_ON) {
                        parent_switch_state = SWITCH_OFF;
                    } else {
                        parent_switch_state = SWITCH_ON;
                    }
                    change_switch_state(parent_switch_state);
                    update_switch_attribute(parent_cap_handle, parent_switch_state);
                }
                break;
            case 5:
                /* clean-up provisioning & registered data with reboot option*/
                st_conn_cleanup(iot_ctx, true);
                break;
            default:
                break;
        }
    } else if (type == BUTTON_LONG_PRESS) {
        printf("Button long press\n");
        st_conn_cleanup(iot_ctx, false);
        xTaskCreate(connection_start_task, "connection_task", 1024 * 3, NULL, 10, NULL);
    }
}

static void app_main_task(void *arg)
{
    int button_event_type;
    int button_event_count;

    for (;;) {
        if (get_button_event(&button_event_type, &button_event_count)) {
            button_event(button_event_type, button_event_count);
        }

        vTaskDelay(10 / portTICK_PERIOD_MS);
    }
}

void app_main(void)
{
    /**
      SmartThings Device SDK(STDK) aims to make it easier to develop IoT devices by providing
      additional st_iot_core layer to the existing chip vendor SW Architecture.

      That is, you can simply develop a basic application
      by just calling the APIs provided by st_iot_core layer like below.

      // create a iot context
      1. st_conn_init();

      // create a handle to process capability
      2. st_cap_handle_init(); (called in function 'capability_init')

      // register a callback function to process capability command when it comes from the SmartThings Server.
      3. st_cap_cmd_set_cb(); (called in function 'capability_init')

      // process on-boarding procedure. There is nothing more to do on the app side than call the API.
      4. st_conn_start(); (called in function 'connection_start')
     */

    unsigned char *onboarding_config = (unsigned char *)onboarding_config_start;
    unsigned int onboarding_config_len = onboarding_config_end - onboarding_config_start;
    unsigned char *device_info = (unsigned char *)device_info_start;
    unsigned int device_info_len = device_info_end - device_info_start;

    int iot_err;

    // create a iot context
    iot_ctx = st_conn_init(onboarding_config, onboarding_config_len, device_info, device_info_len);
    if (iot_ctx != NULL) {
        iot_err = st_conn_set_noti_cb(iot_ctx, iot_noti_cb, NULL);
        if (iot_err)
            printf("fail to set notification callback function\n");

        //	implement init_callback function (cap_switch_init_cb)
        parent_cap_handle = st_cap_handle_init(iot_ctx, "main", "switch", cap_switch_init_cb, NULL);

        //	implement callback function (cap_switch_cmd_off_cb)
        iot_err = st_cap_cmd_set_cb(parent_cap_handle, "off", cap_switch_cmd_off_cb, NULL);
        if (iot_err)
            printf("fail to set cmd_cb for off\n");

        //	implement callback function (cap_switch_cmd_on_cb)
        iot_err = st_cap_cmd_set_cb(parent_cap_handle, "on", cap_switch_cmd_on_cb, NULL);
        if (iot_err)
            printf("fail to set cmd_cb for on\n");
    } else {
        printf("fail to create the iot_context\n");
    }

    iot_gpio_init();
    register_iot_cli_cmd();
    uart_cli_main();
    xTaskCreate(app_main_task, "app_main_task", 4096, NULL, 10, NULL);

    // connect to server
    connection_start();
}
