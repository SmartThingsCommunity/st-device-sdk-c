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

#ifndef _IOT_BSP_SYSTEM_H_
#define _IOT_BSP_SYSTEM_H_

#include "iot_error.h"
#include <stddef.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * @brief get bsp name
 * @return return is string of bsp name
 */
const char* iot_bsp_get_bsp_name();

/*
 * @brief get bsp version string
 * @return return is string of bsp version
 */
const char* iot_bsp_get_bsp_version_string();

/**
  * @brief  Macro to use iot_bsp_system_reboot function
  *
  */
#define IOT_REBOOT() iot_bsp_system_reboot()

/**
  * @brief  Macro to use iot_bsp_system_poweroff function
  *
  */
#define IOT_POWEROFF() iot_bsp_system_poweroff()

/**
  * @brief  Restart system
  *
  * @details This function restarts system.
  */
void iot_bsp_system_reboot();

/**
  * @brief  Shutdown system
  *
  * @details This function shuts down system.
  */
void iot_bsp_system_poweroff();

/**
 * @brief Get system time in second.
 *
 * @param[out] time_in_sec A pointer to time_t data to store the system time in second.
 * @retval IOT_ERROR_NONE Set time successful.
 * @retval IOT_ERROR_INVALID_ARGS Invalid argument.
 */
iot_error_t iot_bsp_system_get_time_in_sec(time_t *time_in_sec);

/**
 * @brief Set system time in second.
 *
 * @param[in] time_in_sec A time value in second (ex : 1546300800)
 * @retval IOT_ERROR_NONE Set time successful.
 * @retval IOT_ERROR_INVALID_ARGS Invalid argument.
 */
iot_error_t iot_bsp_system_set_time_in_sec(time_t time_in_sec);

#ifdef __cplusplus
}
#endif

#endif /* _IOT_BSP_SYSTEM_H_ */
