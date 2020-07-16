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

#include <iot_error.h>
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

#if defined(CONFIG_STDK_IOT_CORE_LOG_FILE_FLASH_WITH_RAM)
/**
 * @brief  Read data from flash
 *
 * This function read data from flash
 *
 * @param[in] src_addr		flash address to read
 * @param[out] des_addr		ram destination address to copy
 * @param[in] size			size to read

 * @retval IOT_ERROR_NONE 		Reading data from flash was successful.
 * @retval IOT_ERROR_READ_FAIL 	Read Error
 */
iot_error_t iot_log_read_flash (unsigned int src_addr, void *des_addr, unsigned int size);


/**
 * @brief  Write data to flash
 *
 * This function read data from flash
 *
 * @param[out] des_addr		flash destination address to write
 * @param[in] src_addr		ram source address to copy
 * @param[in] size			size to write

 * @retval IOT_ERROR_NONE 		Writing data to flash was successful.
 * @retval IOT_ERROR_WRITE_FAIL 	Write Error
 */
iot_error_t iot_log_write_flash (unsigned int des_addr, void *src_addr, unsigned int size);

/**
 * @brief  erase flash sector
 *
 * This function erase a sector of flash
 *
 * @param[in] sector_num	sector number

 * @retval IOT_ERROR_NONE 		Erasing flash sector was successful.
 * @retval IOT_ERROR_WRITE_FAIL 	Erase Error
 */
iot_error_t iot_log_erase_sector (unsigned int sector_num);
#elif defined (CONFIG_STDK_IOT_CORE_LOG_FILE_RAM_ONLY)
static inline iot_error_t iot_log_read_flash (unsigned int src_addr, void *des_addr, unsigned int size) { return IOT_ERROR_BAD_REQ; }
static inline iot_error_t iot_log_write_flash (unsigned int des_addr, void *src_addr, unsigned int size) { return IOT_ERROR_BAD_REQ; }
static inline iot_error_t iot_log_erase_sector (unsigned int sector_num) { return IOT_ERROR_BAD_REQ; }
#endif


#ifdef __cplusplus
}
#endif

#endif /* _IOT_BSP_DEBUG_H_ */
