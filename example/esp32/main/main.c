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

#include "st_dev.h"
#include "device_control.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "iot_uart_cli.h"
#include "iot_cli_cmd.h"

// onboarding_config_start is null-terminated string
extern const uint8_t onboarding_config_start[]    asm("_binary_onboarding_config_json_start");
extern const uint8_t onboarding_config_end[]    asm("_binary_onboarding_config_json_end");

// device_info_start is null-terminated string
extern const uint8_t device_info_start[]    asm("_binary_device_info_json_start");
extern const uint8_t device_info_end[]        asm("_binary_device_info_json_end");

static iot_status_t g_iot_status = IOT_STATUS_IDLE;
static iot_stat_lv_t g_iot_stat_lv;

IOT_CTX* iot_ctx = NULL;
IOT_CAP_HANDLE *cap_handle = NULL;
int switch_state = SWITCH_OFF;

static void update_switch_attribute(int state)
{
    int32_t sequence_no = 1;

    /* Send initial switch attribute */
	if (state == SWITCH_OFF) {
	    ST_CAP_SEND_ATTR_STRING(cap_handle, "switch", "off", NULL, NULL, sequence_no);
	}
	else {
		ST_CAP_SEND_ATTR_STRING(cap_handle, "switch", "on", NULL, NULL, sequence_no);
	}

    if (sequence_no < 0)
        printf("fail to send switch value\n");
    else
        printf("Sequence number return : %d\n", sequence_no);
}

static void cap_switch_init_cb(IOT_CAP_HANDLE *handle, void *usr_data)
{
    printf("Init switch attribute\n");

	update_switch_attribute(switch_state);
}

static void cap_switch_cmd_off_cb(IOT_CAP_HANDLE *handle,
                           iot_cap_cmd_data_t *cmd_data, void *usr_data)
{
    printf("OFF command received\n");

	switch_state = SWITCH_OFF;
	update_switch_attribute(SWITCH_OFF);
	change_switch_state(SWITCH_OFF);
}

static void cap_switch_cmd_on_cb(IOT_CAP_HANDLE *handle,
                          iot_cap_cmd_data_t *cmd_data, void *usr_data)
{
    printf("ON command received\n");

	switch_state = SWITCH_ON;
	update_switch_attribute(SWITCH_ON);
	change_switch_state(SWITCH_ON);
}



static void iot_status_cb(iot_status_t status,
                          iot_stat_lv_t stat_lv, void *usr_data)
{
    g_iot_status = status;
    g_iot_stat_lv = stat_lv;

    printf("status: %d, stat: %d\n", g_iot_status, g_iot_stat_lv);

    switch(status)
    {
        case IOT_STATUS_NEED_INTERACT:
            break;
        case IOT_STATUS_IDLE:
        case IOT_STATUS_CONNECTING:
            break;
        default:
            break;
    }
}

static void iot_noti_cb(iot_noti_data_t *noti_data, void *noti_usr_data)
{
    printf("Notification message received\n");

    if (noti_data->type == IOT_NOTI_TYPE_DEV_DELETED) {
        printf("[device deleted]\n");
    } else if (noti_data->type == IOT_NOTI_TYPE_RATE_LIMIT) {
        printf("[rate limit] Remaining time:%d, sequence number:%d\n",
               noti_data->raw.rate_limit.remainingTime, noti_data->raw.rate_limit.sequenceNumber);
    } else if(noti_data->type == IOT_NOTI_TYPE_PREFERENCE_UPDATED) {
		for (int i = 0; i < noti_data->raw.preferences.preferences_num; i++) {
			printf("[preference update] name : %s value : ", noti_data->raw.preferences.preferences_data[i].preference_name);
			if (noti_data->raw.preferences.preferences_data[i].preference_data.type == IOT_CAP_VAL_TYPE_NULL)
				printf("NULL\n");
			else if (noti_data->raw.preferences.preferences_data[i].preference_data.type == IOT_CAP_VAL_TYPE_STRING)
				printf("%s\n", noti_data->raw.preferences.preferences_data[i].preference_data.string);
			else if (noti_data->raw.preferences.preferences_data[i].preference_data.type == IOT_CAP_VAL_TYPE_NUMBER)
				printf("%f\n", noti_data->raw.preferences.preferences_data[i].preference_data.number);
			else if (noti_data->raw.preferences.preferences_data[i].preference_data.type == IOT_CAP_VAL_TYPE_INTEGER)
				printf("%d\n", noti_data->raw.preferences.preferences_data[i].preference_data.integer);
			else if (noti_data->raw.preferences.preferences_data[i].preference_data.type == IOT_CAP_VAL_TYPE_BOOLEAN)
				printf("%s\n", noti_data->raw.preferences.preferences_data[i].preference_data.boolean ? "true" : "false");
			else
				printf("Unknown type\n");
		}
	}
}

static void connection_start(void)
{
    int err;
    
	// process on-boarding procedure. There is nothing more to do on the app side than call the API.
    err = st_conn_start(iot_ctx, (st_status_cb)&iot_status_cb, IOT_STATUS_ALL, NULL, NULL);
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
        switch(count) {
            case 1:
                if (g_iot_status == IOT_STATUS_NEED_INTERACT) {
                    st_conn_ownership_confirm(iot_ctx, true);
                } else {
                    if (switch_state == SWITCH_ON) {
						switch_state = SWITCH_OFF;
                    } else {
						switch_state = SWITCH_ON;
                    }
                    change_switch_state(switch_state);
					update_switch_attribute(switch_state);
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
        printf("Button long press, iot_status: %d\n", g_iot_status);
        st_conn_cleanup(iot_ctx, false);
        xTaskCreate(connection_start_task, "connection_task", 2048, NULL, 10, NULL);
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

    unsigned char *onboarding_config = (unsigned char *) onboarding_config_start;
    unsigned int onboarding_config_len = onboarding_config_end - onboarding_config_start;
    unsigned char *device_info = (unsigned char *) device_info_start;
    unsigned int device_info_len = device_info_end - device_info_start;

    int iot_err;

    // create a iot context
    iot_ctx = st_conn_init(onboarding_config, onboarding_config_len, device_info, device_info_len);
    if (iot_ctx != NULL) {
        iot_err = st_conn_set_noti_cb(iot_ctx, iot_noti_cb, NULL);
        if (iot_err)
            printf("fail to set notification callback function\n");

        //	implement init_callback function (cap_switch_init_cb)
        cap_handle = st_cap_handle_init(iot_ctx, "main", "switch", cap_switch_init_cb, NULL);

        //	implement callback function (cap_switch_cmd_off_cb)
        iot_err = st_cap_cmd_set_cb(cap_handle, "off", cap_switch_cmd_off_cb, NULL);
        if (iot_err)
            printf("fail to set cmd_cb for off\n");

        //	implement callback function (cap_switch_cmd_on_cb)
        iot_err = st_cap_cmd_set_cb(cap_handle, "on", cap_switch_cmd_on_cb, NULL);
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
