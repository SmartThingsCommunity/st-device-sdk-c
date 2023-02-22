/* ***************************************************************************
 *
 * Copyright 2019-2020 Samsung Electronics All Rights Reserved.
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
#include <string.h>
#include <stdlib.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "driver/uart.h"

#include "iot_uart_cli.h"

#define UART_BUF_SIZE (20)

#define PROMPT_STRING "STDK # "

/**
* to decide whether the main function is running or not by user action...
*  0 : running the main function
*  1 : stop for a timeout
*  2 : stop before selecting the go_main function.

*/
int g_StopMainTask = 0;

static portMUX_TYPE spinlock = portMUX_INITIALIZER_UNLOCKED;

static struct cli_command_list *cli_cmd_list;

static void cli_cmd_help(char *string);

static struct cli_command help_cmd = {
    "help", "print command list", cli_cmd_help
};


static cli_cmd_t* cli_find_command (char* input_string) {
    cli_cmd_list_t* now = cli_cmd_list;

    while (now) {
        if (!now->cmd)
            continue;

        if (strncmp(input_string, now->cmd->command, strlen(now->cmd->command)) == 0) {
            switch (input_string[strlen(now->cmd->command)]) {
                case ' ':
                case '\r':
                case '\n':
                case '\0':
                    return now->cmd;
            }
        }
        now = now->next;
    }

    return NULL;
}

static void cli_process_command(char* input_string)
{
    cli_cmd_t *command;

    command = cli_find_command(input_string);

    if (command == NULL) {
        printf("command not found. please check 'help'\n");
        return;
    }

    command->command_fn(input_string);
}

void cli_register_command(cli_cmd_t* cmd)
{
    cli_cmd_list_t* now;


    if ( (!cmd) || (!cmd->command) ) {
        printf("register fail : cmd is invalid.\n");
        return;
    }

    if (cli_find_command(cmd->command)) {
        printf("register fail : same cmd is already exists.\n");
        return;
    }

    if (!cli_cmd_list) {
        cli_cmd_list = (cli_cmd_list_t*) malloc(sizeof(struct cli_command_list));
        cli_cmd_list->next = NULL;
        cli_cmd_list->cmd = cmd;
    } else {
        now = cli_cmd_list;
        while (now->next) now = now->next;
        now->next = (cli_cmd_list_t*) malloc(sizeof(struct cli_command_list));

        now = now->next;
        now->next = NULL;
        now->cmd = cmd;
    }
}

static void cli_cmd_help(char *cmd) {
    cli_cmd_list_t* now = cli_cmd_list;

    printf("----------Command List\n");
    while (now) {
        if (!now->cmd)
            continue;

        printf("%15s : %s\n", now->cmd->command, now->cmd->help_string);
        now = now->next;
    }
}

/**
* If there is user input("\n") within a given timeout, the main function will be suspended.
*
*/
static void _cli_util_wait_for_user_input(unsigned int timeout_ms)
{
    TickType_t cur = xTaskGetTickCount();
    TickType_t end = cur + pdMS_TO_TICKS(timeout_ms);
    while (xTaskGetTickCount() < end) {
        portENTER_CRITICAL(&spinlock);
        if (g_StopMainTask != 1) {
            portEXIT_CRITICAL(&spinlock);
            break;
        }
        portEXIT_CRITICAL(&spinlock);
        vTaskDelay(100 / portTICK_PERIOD_MS);
    }

    portENTER_CRITICAL(&spinlock);
    if (g_StopMainTask == 1) {
        // When there is no input("\n") for a set time, main task will be executed...
        g_StopMainTask = 0;
    }
    portEXIT_CRITICAL(&spinlock);

    if (g_StopMainTask != 0) {
        while (1) {
            portENTER_CRITICAL(&spinlock);
            if (g_StopMainTask == 0) {
                portEXIT_CRITICAL(&spinlock);
                break;
            }
            portEXIT_CRITICAL(&spinlock);
            vTaskDelay(100 / portTICK_PERIOD_MS);
        }
    }
}

/**
 * This is an example which echos any data it receives on UART0 back to the sender,
 * with hardware flow control turned off. It does not use UART driver event queue.
 *
 * - Port: UART0
 * - Receive (Rx) buffer: on
 * - Transmit (Tx) buffer: off
 * - Flow control: off
 * - Event queue: off
 */

static void esp_uart_init() {
    // Configure parameters of an UART driver,
    // communication pins and install the driver
    uart_config_t uart_config = {
#ifdef CONFIG_CONSOLE_UART_BAUDRATE
        .baud_rate = CONFIG_CONSOLE_UART_BAUDRATE,
#else
        .baud_rate = 115200, // ROM default BAUDRATE
#endif
        .data_bits = UART_DATA_8_BITS,
        .parity    = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE
    };
    uart_param_config(UART_NUM_0, &uart_config);
    uart_driver_install(UART_NUM_0, MAX_UART_LINE_SIZE * 2, 0, 0, NULL, ESP_INTR_FLAG_LOWMED);
}

static void esp_uart_cli_task()
{

    // Configure a temporary buffer for the incoming data
    uint8_t data[UART_BUF_SIZE];
    uint8_t line[MAX_UART_LINE_SIZE];
    uint8_t prev_line[MAX_UART_LINE_SIZE];
    memset(line, 0, MAX_UART_LINE_SIZE);
    memset(prev_line, 0, MAX_UART_LINE_SIZE);
    int line_len = 0;

    cli_register_command(&help_cmd);

    while (1) {
        memset(data, 0, UART_BUF_SIZE);

        // Read data from the UART
        int len = uart_read_bytes(UART_NUM_0, data, UART_BUF_SIZE, 20 / portTICK_RATE_MS);
        for (int i = 0; i < len; i++) {
            switch(data[i])
            {
                case '\r':
                case '\n':
                    portENTER_CRITICAL(&spinlock);
                    if (g_StopMainTask == 1) {
                        // when there is a user input("\n") within a given timeout, this value will be chaned into 2.
                        // but, if there is no user input within a given timeout, this value will be changed into 0 in order to run the main function
                        g_StopMainTask = 2;
                    }
                    portEXIT_CRITICAL(&spinlock);

                    uart_write_bytes(UART_NUM_0, "\r\n", 2);
                    if (line_len) {
                        cli_process_command((char *)line);
                        memcpy(prev_line, line, MAX_UART_LINE_SIZE);
                        memset(line, 0, MAX_UART_LINE_SIZE);
                        line_len = 0;
                    }
                    uart_write_bytes(UART_NUM_0, PROMPT_STRING, sizeof(PROMPT_STRING));
                    break;

                case '\b':
                    //backspace
                    if (line_len > 0) {
                        uart_write_bytes(UART_NUM_0, "\b \b", 3);
                        line[--line_len] = '\0';
                    }
                    break;

                case 0x03: //Ctrl + C
                    uart_write_bytes(UART_NUM_0, "^C\n", 3);
                    memset(line, 0, MAX_UART_LINE_SIZE);
                    line_len = 0;
                    uart_write_bytes(UART_NUM_0, PROMPT_STRING, sizeof(PROMPT_STRING));
                    break;

                case 0x1B: //arrow keys : 0x1B 0x5B 0x41~44
                    if ( data[i+1] == 0x5B ) {
                        switch (data[i+2]) {
                            case 0x41: //UP
                                memcpy(line, prev_line, MAX_UART_LINE_SIZE);
                                line_len = strlen((char*)line);
                                uart_write_bytes(UART_NUM_0, (const char *)&data[i+1], 2);
                                uart_write_bytes(UART_NUM_0, "\r\n", 2);
                                uart_write_bytes(UART_NUM_0, PROMPT_STRING, sizeof(PROMPT_STRING));
                                uart_write_bytes(UART_NUM_0, (const char *)line, line_len);
                                i+=3;
                                break;
                            case 0x42: //DOWN - ignore
                                i+=3;
                                break;
                            case 0x43: //right
                                if (line[line_len+1] != '\0') {
                                    line_len += 1;
                                    uart_write_bytes(UART_NUM_0, (const char *)&data[i], 3);
                                }
                                i+=3;
                                break;
                            case 0x44: //left
                                if (line_len > 0) {
                                    line_len -= 1;
                                    uart_write_bytes(UART_NUM_0, (const char *)&data[i], 3);
                                }
                                i+=3;
                                break;
                            default:
                                break;
                        }
                    }
                    break;

                    default:
                    //check whether character is valid
                    if ((data[i] >= ' ') && (data[i] <= '~')) {
                        if (line_len >= MAX_UART_LINE_SIZE - 2)
                            break;

                        // print character back
                        uart_write_bytes(UART_NUM_0, (const char *) &data[i], 1);

                        line[line_len++] = data[i];
                    }
            } // switch data[i]
        } //buf while loop
    } //main loop


}

void uart_cli_main()
{
    /* to decide whether the main function is running or not by user action... */
    g_StopMainTask = 1;    //default value is 1;  stop for a timeout

    esp_uart_init();
    xTaskCreate(esp_uart_cli_task, "uart_cli_task", CLI_TASK_SIZE, NULL, CLI_TASK_PRIORITY, NULL);

    _cli_util_wait_for_user_input(2000);
}

