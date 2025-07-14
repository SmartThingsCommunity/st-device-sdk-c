/* ***************************************************************************
 *
 * Copyright 2022 Samsung Electronics All Rights Reserved.
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

#ifndef _ADVERTISEMENT_H_
#define _ADVERTISEMENT_H_

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
#endif

void start_advertisement_server(void);
void stop_advertisement_server(void);
void start_advertisement(void);
void stop_advertisement(void);
int set_advertisement_data(uint16_t mn_code, uint8_t *mn_data, size_t mn_data_len, char *local_name);
int get_bt_dev_address(uint8_t mac_address[6]);

#ifdef __cplusplus
}
#endif

#endif
