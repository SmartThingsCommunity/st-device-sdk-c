/* ***************************************************************************
 *
 * Copyright 2019-2022 Samsung Electronics All Rights Reserved.
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

#ifndef _ST_CAPS_H_
#define _ST_CAPS_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	ST_COMPONENT_DEFULAT,		/* default "main" component */
	ST_COMPONENT_CUSTOM,
} st_component_type;

typedef enum {
	ST_CAPABILITY_SWITCH,
	ST_CAPABILITY_CUSTOM,
} st_capability_type;

typedef enum {
	ST_ATTR_SWITCH_SWITCH = ST_CAPABILITY_SWITCH << 8 | 0x00,
	ST_ATTR_CUSTOM,
} st_attr_type;

typedef enum {
	ST_ATTR_COMMAND,
} st_command_type;

typedef enum {
	ST_DATA_TYPE_STRING,
	ST_DATA_TYPE_NUMBER,
	ST_DATA_TYPE_JSON_OBJECT,
	ST_DATA_TYPE_JSON_ARRAY,
	ST_DATA_TYPE_BOOLEAN,
	ST_DATA_TYPE_NULL,
	ST_DATA_TYPE_RAW_JSON,
} st_data_type;

struct _st_data_json_object;
struct _st_data_json_array;

typedef struct _st_data {
	st_data_type data_type;
	union {
		char *string;
		double number;
		struct _st_data_json_object *json_object;
		struct _st_data_json_array *json_array;
		bool boolean;
		char *raw_json;
	} data;
} st_data;

typedef struct _st_data_json_object {
	char *key;
	st_data value;
} st_data_json_object;

typedef struct _st_data_json_array {
	st_data *array;
	int array_num;
} st_data_json_array;

typedef struct {
	st_component_type component_type;
	char *custom_component_name;
	st_attr_type attr_type;
	char *custom_cap_name;
	char *custom_attr_name;
	st_data value;
	char *unit;
	char *data;
	bool support_history;
	bool state_change;			/**< Indicator whether forces state change event even if value is not changed. */
	char *related_command_id;	/**< null-terminated Command ID string(UUID-format)
								  related with this attribute data. Set null if there isn't. */
} st_attr_data;

typedef struct {
	char *command_id;			/**< null-terminated Command ID string(UUID-format) */
	st_component_type component_type;
	char *custom_component_name;
	st_command_type command_type;
	char *custom_cap_name;
	char *custom_command_name;
	st_data *param_list;
	uint8_t param_num;
} st_command_data;

#ifdef __cplusplus
}
#endif

#endif
