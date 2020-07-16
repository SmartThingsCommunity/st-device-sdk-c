/* ***************************************************************************
 *
 * Copyright 2020 Samsung Electronics All Rights Reserved.
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

#ifndef _IOT_LOG_FILE_H_
#define _IOT_LOG_FILE_H_

#include "iot_internal.h"
#include "iot_main.h"
#include "iot_debug.h"
#include "iot_bsp_debug.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define IOT_LOG_FILE_TRUE 1
#define IOT_LOG_FILE_FALSE 0

#define IOT_LOG_FILE_COLOR_RED "\033[0;31m"
#define IOT_LOG_FILE_COLOR_CYAN "\033[0;36m"
#define IOT_LOG_FILE_COLOR_END "\033[0;m"

#define IOT_LOG_FILE_DEBUG_ENABLE 0
#if IOT_LOG_FILE_DEBUG_ENABLE
#define IOT_LOG_FILE_DEBUG(fmt, args...) printf(IOT_LOG_FILE_COLOR_CYAN fmt IOT_LOG_FILE_COLOR_END, ##args)
#else
#define IOT_LOG_FILE_DEBUG(fmt, args...)
#endif

#define IOT_LOG_FILE_ERROR(fmt, args...) printf(IOT_LOG_FILE_COLOR_RED fmt IOT_LOG_FILE_COLOR_END, ##args)

#define IOT_LOG_FILE_MAX_STRING_SIZE 128 /* Max input string size */
#define IOT_LOG_FILE_MARGIN_CNT 1		 /* magin count */

#define IOT_LOG_FILE_EVENT_SYNC_REQ_BIT (1u << 0u)
#define IOT_LOG_FILE_EVENT_BIT_ALL (IOT_LOG_FILE_EVENT_SYNC_REQ_BIT)

#define IOT_LOG_FILE_TASK_NAME "iot-log-file-task"
#define IOT_LOG_FILE_TASK_STACK_SIZE (1024 * 5)
#define IOT_LOG_FILE_TASK_PRIORITY (IOT_TASK_PRIORITY + 1)

#define IOT_LOG_FILE_RAM_BUF_SIZE CONFIG_STDK_IOT_CORE_LOG_FILE_RAM_BUF_SIZE

#if defined(CONFIG_STDK_IOT_CORE_LOG_FILE_FLASH_WITH_RAM)
#define IOT_LOG_FILE_FLASH_ADDR CONFIG_STDK_IOT_CORE_LOG_FILE_FLASH_ADDR
#define IOT_LOG_FILE_FLASH_SIZE CONFIG_STDK_IOT_CORE_LOG_FILE_FLASH_SIZE
#define IOT_LOG_FILE_FLASH_SECTOR_SIZE CONFIG_STDK_IOT_CORE_LOG_FILE_FLASH_SECTOR_SIZE

#define IOT_LOG_FILE_FLASH_FIRST_SECTOR (IOT_LOG_FILE_FLASH_ADDR / IOT_LOG_FILE_FLASH_SECTOR_SIZE)
#define IOT_LOG_FILE_FLASH_MAX_ADDR (IOT_LOG_FILE_FLASH_ADDR + IOT_LOG_FILE_FLASH_SIZE)
#else
#define IOT_LOG_FILE_FLASH_ADDR (0xdead2bad)
#define IOT_LOG_FILE_FLASH_SIZE (sizeof(struct iot_log_file_header_tag))
#define IOT_LOG_FILE_FLASH_SECTOR_SIZE (1)

#define IOT_LOG_FILE_FLASH_FIRST_SECTOR (0)
#define IOT_LOG_FILE_FLASH_MAX_ADDR (0)
#endif

#define IOT_LOG_FILE_FLASH_HEADER_SIZE (sizeof(struct iot_log_file_header_tag))
#define IOT_LOG_FILE_FLASH_BUF_SIZE (2 * IOT_LOG_FILE_FLASH_SECTOR_SIZE)


typedef enum
{
	RAM_ONLY,
	FLASH_WITH_RAM,
} iot_log_file_type_t;

typedef struct
{
	unsigned int start_addr;
	unsigned int tail_addr;
	unsigned int cur_addr;
	size_t log_size;
	size_t max_log_size;

	iot_log_file_type_t file_type;
} iot_log_file_handle_t;

typedef enum
{
	NORMAL,
	NO_MAGIC,
	LOAD_FAIL,
} iot_log_file_header_state_t;

struct iot_log_file_buf_tag
{
	bool enable;
	unsigned int cnt;
	char buf[IOT_LOG_FILE_RAM_BUF_SIZE];
	bool overridden;

};

struct iot_log_file_sector_tag
{
	unsigned int num;
	unsigned int offset;
};

struct iot_log_file_header_tag
{
	char magic_code[4];
	unsigned int file_size;
	unsigned int written_size;
	struct iot_log_file_sector_tag sector;
	unsigned int checksum;
};

struct iot_log_file_ctx
{
	struct iot_log_file_buf_tag log_buf;
	iot_os_eventgroup *events;
	struct iot_log_file_header_tag file_header;
	char file_buf[IOT_LOG_FILE_FLASH_BUF_SIZE];
	bool file_opened;
};


/**
 * @brief Initialize a log file system.
 * @param[in] type Type of log file system for initialize.
 * @retval IOT_ERROR_NONE log file init successful.
 * @retval IOT_ERROR_MEM_ALLOC log file task alloc failed.
 */
iot_error_t iot_log_file_init(iot_log_file_type_t type);

/**
 * @brief Free the log_ctx resource.
 *
 * @details This function to free the log_ctx resource
 */
void iot_log_file_exit(void);

/**
 * @brief Store log data to log file.
 * @param[in] log_data a pointer to the log data to store
 * @param[in] log_size the size of log data pointed by log_data in bytes
 * @return The length of the stored data. -1 is failure.
 */
int iot_log_file_store(const char *log_data, size_t log_size);

/**
 * @brief Log file synchronize with ram log data.
 * 
 * @details This function store log data on ram to flash memory
 */
void iot_log_file_sync(void);

/**
 * @brief Remove Iot log file
 * 
 * @details This function remove log data
 * @param[in] type Type of log file system for deleting.
 * @retval IOT_ERROR_NONE Log file remove successful.
 * @retval IOT_ERROR_BAD_REQ Log file remove failed.
 */
iot_error_t iot_log_file_remove(iot_log_file_type_t type);

/**
 * @brief Open Iot log file to read
 * 
 * @details This function make ready to read, if this function is called, log will be saved any more.
 * @param[out] filesize Log file size
 * @param[in] file_type Type of log file system for accessing.
 * @return Pointer of log file handle
 */
iot_log_file_handle_t *iot_log_file_open(size_t *filesize, iot_log_file_type_t file_type);

/**
 * @brief Reposition file position indicator
 *
 * @details This function update cur_addr to value calculated from offset and origin considering circular buffer
 * @param[in] file_handle Handle to access file
 * @param[in] seek_offset Number of bytes to offset from origin(can be positive or negative or zero).
 * @param[in] origin_addr Position used as reference for the offset.
 * @retval IOT_ERROR_NONE success
 */
iot_error_t iot_log_file_seek(iot_log_file_handle_t *file_handle, int seek_offset, unsigned int origin_addr);
/**
 * @brief Read file data using file handle
 * 
 * @details You can read log file as much as you want using file handle
 * @param[in] file_handle Handle to access file
 * @param[out] buffer Buffer where read data will be located
 * @param[in] buf_size Size to read
 * @param[out] read_size optional, update actual reading size if it is assigned
 * @retval IOT_ERROR_NONE log file read successful.
 * @retval IOT_ERROR_READ_FAIL log file read failed.
 */
iot_error_t iot_log_file_read(iot_log_file_handle_t *file_handle,
	void *buffer, size_t buf_size, size_t *read_size);

/**
 * @brief Close opened log file
 * 
 * @details This function makes close opend file handle,
 			And saving log data to flash memory will be started from this function called.
 * @param[in] file_handle A file to close
 * @retval IOT_ERROR_NONE log file close successful.
 * @retval IOT_ERROR_INVALID_ARGS log file close failed.
 */
iot_error_t iot_log_file_close(iot_log_file_handle_t *file_handle);

#ifdef __cplusplus
}
#endif

#endif /* _IOT_LOG_FILE_H_ */

