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

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#include "st_dev.h"


// onboarding_config_start is null-terminated string
extern const uint8_t onboarding_config_start[] asm("_binary_onboarding_config_json_start");
extern const uint8_t onboarding_config_end[] asm("_binary_onboarding_config_json_end");

// device_info_start is null-terminated string
extern const uint8_t device_info_start[] asm("_binary_device_info_json_start");
extern const uint8_t device_info_end[] asm("_binary_device_info_json_end");

static iot_status_t g_iot_status;

IOT_CTX *ctx = NULL;

volatile sig_atomic_t is_exit = false;

void signal_handler(int sig_num)
{
    is_exit = true;
}

void event_loop()
{
    while (!is_exit) {
        // event loop
    }

    printf("\nExit\n");
}

static void iot_status_cb(iot_status_t status,
                          iot_stat_lv_t stat_lv, void *usr_data)
{
    g_iot_status = status;
    printf("iot_status: %d, lv: %d\n", status, stat_lv);
}

void cap_switch_init_cb(IOT_CAP_HANDLE *handle, void *usr_data)
{
    int32_t sequence_no = 1;

    /* Send initial switch attribute */
    ST_CAP_SEND_ATTR_STRING(handle, "switch", "on", NULL, NULL, sequence_no);

    if (sequence_no < 0)
        printf("fail to send switch value\n");
    else
        printf("Sequence number return : %d\n", sequence_no);
}

void cap_switch_cmd_off_cb(IOT_CAP_HANDLE *handle,
                           iot_cap_cmd_data_t *cmd_data, void *usr_data)
{
    int32_t sequence_no = 1;

    printf("OFF command received");

    /* Update switch attribute */
    ST_CAP_SEND_ATTR_STRING(handle, "switch", "off", NULL, NULL, sequence_no);

    if (sequence_no < 0)
        printf("fail to send switch value\n");
    else
        printf("Sequence number return : %d\n", sequence_no);
}

void cap_switch_cmd_on_cb(IOT_CAP_HANDLE *handle,
                          iot_cap_cmd_data_t *cmd_data, void *usr_data)
{
    int32_t sequence_no = 1;

    printf("ON command received");

    /* Update switch attribute */
    ST_CAP_SEND_ATTR_STRING(handle, "switch", "on", NULL, NULL, sequence_no);

    if (sequence_no < 0)
        printf("fail to send switch value\n");
    else
        printf("Sequence number return : %d\n", sequence_no);
}

void iot_noti_cb(iot_noti_data_t *noti_data, void *noti_usr_data)
{
    printf("Notification message received\n");

    if (noti_data->type == IOT_NOTI_TYPE_DEV_DELETED) {
        printf("[device deleted]\n");
    } else if (noti_data->type == IOT_NOTI_TYPE_RATE_LIMIT) {
        printf("[rate limit] Remaining time:%d, sequence number:%d\n",
               noti_data->raw.rate_limit.remainingTime, noti_data->raw.rate_limit.sequenceNumber);
    }
}

void main(void)
{
    /**
	  SmartThings Device SDK(STDK) aims to make it easier to develop IoT devices by providing
	  additional st_iot_core layer to the existing chip vendor SW Architecture.

      That is, you can simply develop a basic application by just calling the APIs provided by st_iot_core layer
	  like below. st_iot_core currently offers 14 API.

      //create a iot context
	  1. st_conn_init();

      //create a handle to process capability
	  2. st_cap_handle_init();

      //register a callback function to process capability command when it comes from the SmartThings Server.
	  3. st_cap_cmd_set_cb();

      //needed when it is necessary to keep monitoring the device status
	  4. user_defined_task()

      //process on-boarding procedure. There is nothing more to do on the app side than call the API.
	  5. st_conn_start();
	 */

    unsigned char *onboarding_config = (unsigned char *)onboarding_config_start;
    unsigned int onboarding_config_len = onboarding_config_end - onboarding_config_start;
    unsigned char *device_info = (unsigned char *)device_info_start;
    unsigned int device_info_len = device_info_end - device_info_start;
    IOT_CAP_HANDLE *handle = NULL;
    int iot_err;

    // 1. create a iot context
    ctx = st_conn_init(onboarding_config, onboarding_config_len, device_info, device_info_len);
    if (ctx != NULL) {
        iot_err = st_conn_set_noti_cb(ctx, iot_noti_cb, NULL);
        if (iot_err)
            printf("fail to set notification callback function\n");

        // 2. create a handle to process capability
        //	implement init_callback function (cap_switch_init_cb)
        handle = st_cap_handle_init(ctx, "main", "switch", cap_switch_init_cb, NULL);

        // 3. register a callback function to process capability command when it comes from the SmartThings Server
        //	implement callback function (cap_switch_cmd_off_cb)
        iot_err = st_cap_cmd_set_cb(handle, "off", cap_switch_cmd_off_cb, NULL);
        if (iot_err)
            printf("fail to set cmd_cb for off\n");

        //	implement callback function (cap_switch_cmd_on_cb)
        iot_err = st_cap_cmd_set_cb(handle, "on", cap_switch_cmd_on_cb, NULL);
        if (iot_err)
            printf("fail to set cmd_cb for on\n");
    } else {
        printf("fail to create the iot_context\n");
    }

    // 4. needed when it is necessary to keep monitoring the device status
    //xTaskCreate(user_defined_task, "user_defined_task", 2048, (void *)handle, 10, NULL);

    // 5. process on-boarding procedure. There is nothing more to do on the app side than call the API.
    st_conn_start(ctx, (st_status_cb)&iot_status_cb, IOT_STATUS_ALL, NULL, NULL);

    // exit by using Ctrl+C
    signal(SIGINT, signal_handler);

    event_loop();
}
