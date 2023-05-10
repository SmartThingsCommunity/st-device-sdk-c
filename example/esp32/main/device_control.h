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


//#define CONFIG_TARGET_WEMOS_D1_R32
#ifdef CONFIG_TARGET_WEMOS_D1_R32

#define GPIO_INPUT_BUTTON 18

#define GPIO_OUTPUT_MAINLED 16
#define GPIO_OUTPUT_MAINLED_0 26 /* use as ground */

#define GPIO_OUTPUT_NOUSE1 17
#define GPIO_OUTPUT_NOUSE2 25
#else // ESP32_DEVKITC_V4

#define GPIO_INPUT_BUTTON 0

#define GPIO_OUTPUT_MAINLED 12
#define GPIO_OUTPUT_MAINLED_0 26 /* use as ground */

#define GPIO_OUTPUT_NOUSE1 14
#define GPIO_OUTPUT_NOUSE2 27

#endif

enum switch_onoff_state {
    SWITCH_OFF = 0,
    SWITCH_ON = 1,
};

enum main_led_gpio_state {
    MAINLED_GPIO_ON = 1,
    MAINLED_GPIO_OFF = 0,
};

enum button_gpio_state {
    BUTTON_GPIO_RELEASED = 1,
    BUTTON_GPIO_PRESSED = 0,
};

#define BUTTON_DEBOUNCE_TIME_MS 20
#define BUTTON_LONG_THRESHOLD_MS 5000
#define BUTTON_DELAY_MS 300

enum button_event_type {
    BUTTON_LONG_PRESS = 0,
    BUTTON_SHORT_PRESS = 1,
};

void change_switch_state(int switch_state);
int get_button_event(int* button_event_type, int* button_event_count);
void iot_gpio_init(void);
