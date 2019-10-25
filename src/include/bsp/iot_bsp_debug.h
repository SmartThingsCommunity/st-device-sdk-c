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

#ifndef _IOT_BSP_DEBUG_H_
#define _IOT_BSP_DEBUG_H_

#include <iot_debug.h>

#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief   Write message into the log
 *
 * This function is not intended to be used directly. Instead, use one of
 * IOT_ERROR, IOT_WARN, IOT_INFO, IOT_DEBUG macros.
 *
 * @param[in] level		log level
 *  - IOT_DEBUG_LEVEL_NONE
 *  - IOT_DEBUG_LEVEL_ERROR
 *  - IOT_DEBUG_LEVEL_WARN
 *  - IOT_DEBUG_LEVEL_INFO
 *  - IOT_DEBUG_LEVEL_DEBUG
 * @param[in] func		caller function
 * @param[in] line			line number
 * @param[in] fmt			user friendly string
 */
void iot_bsp_debug(iot_debug_level_t level, const char* tag, const char* fmt, ...);

/**
 * @brief  Check memory(heap) status
 *
 * This function check memory(heap) status
 *
 * @param[in] tag			tag
 * @param[in] func		caller function
 * @param[in] line			line number
 * @param[in] fmt			user friendly string
 */
void iot_bsp_debug_check_heap(const char* tag, const char* func, const int line, const char* fmt, ...);

#ifdef __cplusplus
}
#endif

#endif /* _IOT_BSP_DEBUG_H_ */
