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

#ifndef _IOT_DEBUG_H_
#define _IOT_DEBUG_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "iot_dump_log.h"

/**
 * @name iot_debug_level_t
 * @brief internal debug level.
 */
typedef enum {
	IOT_DEBUG_LEVEL_NONE = 0,
	IOT_DEBUG_LEVEL_ERROR,
	IOT_DEBUG_LEVEL_WARN,
	IOT_DEBUG_LEVEL_INFO,
	IOT_DEBUG_LEVEL_DEBUG,

	IOT_DEBUG_LEVEL_MAX
} iot_debug_level_t;

#ifdef SUPPORT_TC_ON_STATIC_FUNC
#define STATIC_FUNCTION
#define STATIC_VARIABLE
#else
#define STATIC_FUNCTION static
#define STATIC_VARIABLE static
#endif


#define IOT_DEBUG_PREFIX "[IoT]"
#define COLOR_CYAN "\033[0;36m"
#define COLOR_END "\033[0;m"

extern void iot_dump_log(iot_debug_level_t level, dump_log_id_t log_id, int arg1, int arg2);

extern void iot_bsp_debug(iot_debug_level_t level, const char* tag, const char* fmt, ...);
extern void iot_bsp_debug_check_heap(const char* tag, const char* func, const int line, const char* fmt, ...);
#if defined(CONFIG_STDK_IOT_CORE_EASYSETUP_LOG_SUPPORT_NO_USE_LOGFILE)
extern void iot_debug_save_log(char* buf);
extern char *iot_debug_get_log(void);
#endif

#if defined(CONFIG_STDK_IOT_CORE_LOG_FILE)
#define IOT_DUMP(level, msg, arg1, arg2) iot_dump_log(level, msg, arg1, arg2)
#else
#define IOT_DUMP(level, msg, arg1, arg2)
#endif
/**
 * @brief Error level logging macro.
 *
 * Macro to use log function
 */
#if defined(CONFIG_STDK_IOT_CORE_LOG_LEVEL_ERROR)
#define IOT_ERROR(fmt, args...) iot_bsp_debug(IOT_DEBUG_LEVEL_ERROR, IOT_DEBUG_PREFIX, "%s(%d) > "fmt, __FUNCTION__, __LINE__, ##args)
#else
#define IOT_ERROR(fmt, args...)
#endif

/**
 * @brief Warning level logging macro.
 *
 * Macro to use log function
 */
#if defined(CONFIG_STDK_IOT_CORE_LOG_LEVEL_WARN)
#define IOT_WARN(fmt, args...) iot_bsp_debug(IOT_DEBUG_LEVEL_WARN, IOT_DEBUG_PREFIX, "%s(%d) > "fmt, __FUNCTION__, __LINE__, ##args)
#else
#define IOT_WARN(fmt, args...)
#endif

/**
 * @brief Info level logging macro.
 *
 * Macro to use log function
 */
#if defined(CONFIG_STDK_IOT_CORE_LOG_LEVEL_INFO)
#define IOT_INFO(fmt, args...) iot_bsp_debug(IOT_DEBUG_LEVEL_INFO, IOT_DEBUG_PREFIX, "%s(%d) > "fmt, __FUNCTION__, __LINE__, ##args)
#define IOT_REMARK(fmt, args...) iot_bsp_debug(IOT_DEBUG_LEVEL_INFO, IOT_DEBUG_PREFIX, "%s(%d) > "fmt, __FUNCTION__, __LINE__, ##args)
#else
#define IOT_INFO(fmt, args...)
#define IOT_REMARK(fmt, args...)
#endif

/**
 * @brief Debug level logging macro.
 *
 * Macro to use log function
 */
#if defined(CONFIG_STDK_IOT_CORE_LOG_LEVEL_DEBUG)
#define IOT_DEBUG(fmt, args...) iot_bsp_debug(IOT_DEBUG_LEVEL_DEBUG, IOT_DEBUG_PREFIX, "%s(%d) > "fmt, __FUNCTION__, __LINE__, ##args)
#define HIT() iot_bsp_debug(IOT_DEBUG_LEVEL_DEBUG, IOT_DEBUG_PREFIX, "%s(%d) > " COLOR_CYAN ">>>HIT<<<" COLOR_END, __FUNCTION__, __LINE__)
#define ENTER() iot_bsp_debug(IOT_DEBUG_LEVEL_DEBUG, IOT_DEBUG_PREFIX, "%s(%d) > " COLOR_CYAN "ENTER >>>>" COLOR_END, __FUNCTION__, __LINE__)
#define LEAVE() iot_bsp_debug(IOT_DEBUG_LEVEL_DEBUG, IOT_DEBUG_PREFIX, "%s(%d) > " COLOR_CYAN "LEAVE <<<<" COLOR_END, __FUNCTION__, __LINE__)
#else
#define IOT_DEBUG(fmt, args...)
#define HIT()
#define ENTER()
#define LEAVE()
#endif


/**
 * @brief Memory(heap) checking macro.
 *
 * Macro to check memory(heap)
 */
#if defined(CONFIG_STDK_DEBUG_MEMORY_CHECK)
#define IOT_MEM_CHECK(fmt, args...) iot_bsp_debug_check_heap(IOT_DEBUG_PREFIX, __FUNCTION__, __LINE__, fmt, ##args)
#else
#define IOT_MEM_CHECK(fmt, args...)
#endif
/**
 * @brief Condition checking macro.
 *
 * Macro to check condition
 */
#define IOT_ERROR_CHECK(condition, ret, fmt, args...) do { \
		if ((condition)) { \
			IOT_ERROR(fmt, ##args); \
			return (ret); \
		} \
} while (0)

#define IOT_WARN_CHECK(condition, ret, fmt, args...) do { \
		if ((condition)) { \
			IOT_WARN(fmt, ##args); \
			return (ret); \
		} \
} while (0)

#define IOT_DEBUG_CHECK(condition, ret, fmt, args...) do { \
		if ((condition)) { \
			IOT_DEBUG(fmt, ##args); \
			return (ret); \
		} \
} while (0)

#ifdef __cplusplus
}
#endif

#endif /* _IOT_DEBUG_H_ */
