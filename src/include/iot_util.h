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

#ifndef _IOT_UTIL_H_
#define _IOT_UTIL_H_

#include "iot_error.h"
#include "iot_os_util.h"
#include "iot_bsp_wifi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief	Dump a memory on console
 * @param[in]	tag	a string to know the memory attribute
 * @param[in]	buf	a pointer to a buffer to dump
 * @param[in]	len	the size of buffer pointed by buf in bytes
 */
void iot_util_dump_mem(char *tag, uint8_t *buf, size_t len);

#define IOT_UUID_BYTES				(16)

/**
 * @brief Contains "uuid" data
 */
struct iot_uuid {
	unsigned char id[IOT_UUID_BYTES];	/**< @brief actual uuid values, 16 octet */
};

/**
 * @brief Contains a "url parse" data
 */
typedef struct {
	char *protocol;		/**< @brief broker url's protocol part such as "ssl", "https" */
	char *domain;		/**< @brief broker url's domain part such as "test.example.com" */
	int port;		/**< @brief broker url's port number part such as 443, 8883' */
} url_parse_t;

/**
 * @brief iot_util_queue data struct
 */
typedef struct iot_util_queue_data {
	void *data;
	struct iot_util_queue_data *next;
} iot_util_queue_data_t;

/**
 * @brief internal queue struct
 */
typedef struct {
	iot_os_mutex lock;
	size_t item_size;
	struct iot_util_queue_data *head;
	struct iot_util_queue_data *tail;
} iot_util_queue_t;

/**
 * @brief	create queue
 *
 * This function create queue and return queue struct pointer
 *
 * @param[in] item_size	size of queue data item
 *
 * @return
 *	return is queue struct pointer.
 *	If queue was not created, NULL is returned.
 *
 */
iot_util_queue_t* iot_util_queue_create(size_t item_size);

/**
 * @brief	delete queue
 *
 * This function delete queue
 *
 * @param[in] queue	queue struct pointer to be deleted
 *
 */
void iot_util_queue_delete(iot_util_queue_t* queue);

/**
 * @brief	send message to the back of queue.
 *
 * This function will send item to the back of queue
 *
 * @param[in] queue	pointer of queue to save item
 * @param[in] data	item to be saved in queue
 *
 * @return	return IOT_ERROR_NONE on success, or iot_error_t errors if it fails
 *
 */
iot_error_t iot_util_queue_send(iot_util_queue_t* queue, void * data);

/**
 * @brief	receive message from the front of queue.
 *
 * This function will receive item from the front of queue
 *
 * @param[in] queue	pointer of queue to receive item
 * @param[out] data	buffer for item received from queue
 *
 * @return	return IOT_ERROR_NONE on success, or iot_error_t errors if it fails
 *
 */
iot_error_t iot_util_queue_receive(iot_util_queue_t* queue, void * data);

/**
 * @brief	generate retry back time.
 *
 * @param[in] try_count retry count for generating backoff time
 * @param[in] maximum_backoff	maximum backoff time
 *
 * @return	return generated backoff time
 *
 */
unsigned int iot_util_generator_backoff(unsigned int try_count, unsigned int maximum_backoff);

/**
 * @brief	parse url with protocol, domain, port number parts for st-iot-core
 * @details	This function parse give url protocol, domain, port number parts
 * @param[in]	url		null-terminated url string like "https://example.sample.com:1234"
 * @param[out]	output	parsed output with url_parse_t type
 * @return	return IOT_ERROR_NONE on success, or iot_error_t errors if it fails
 */
iot_error_t iot_util_url_parse(char *url, url_parse_t *output);

/**
 * @brief	validate uuid string format
 * @details	This function validate given string meets uuid string format.
 * @param[in]	str	null-terminated uuid string
 * @param[in]	strlen	string length of str
 * @return	return IOT_ERROR_NONE on uuid format, IOT_ERROR_INVALID_ARGS on invalid format
 */
iot_error_t validate_uuid_format(const char *str, size_t str_len);

/**
 * @brief	uuid type string to iot_uuid struct converting function for st-iot-core
 * @details	This function tries to convert from uuid type string to iot_uuid struct
 * @param[in]	str	uuid type string pointer such as 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
 * @param[in]	uuid	allocated iot_uuid struct pointer to get iot_uuid value from str
 * @return	return IOT_ERROR_NONE on success, or iot_error_t errors if it fails
 */
iot_error_t iot_util_convert_str_uuid(const char* str, struct iot_uuid* uuid);

/**
 * @brief	iot_uuid struct based value to uuid type string converting function for st-iot-core
 * @details	This function tries to convert from iot_uuid struct based value to uuid type string
 * @param[in]	uuid	converting wanted iot_uuid struct value pointer
 * @param[in]	str	allocated memory pointer for converted uuid type string
 * @param[in]	max_sz	max size of allocated memory pointer
 * @return	return IOT_ERROR_NONE on success, or iot_error_t errors if it fails
 */
iot_error_t iot_util_convert_uuid_str(struct iot_uuid* uuid, char* str, size_t max_sz);

/**
 * @brief	To convert WIFI mac string into iot_mac struct value
 * @details	This function tries to convert from the string to iot_mac struct value
 * @param[in]	str	WIFI mac string pointer such as 'xx:xx:xx:xx:xx:xx'
 * @param[in]	mac	allocated iot_mac struct pointer to get iot_mac value from str
 * @return	iot_error_t
 * @retval	IOT_ERROR_NONE	success
 * @retval	IOT_ERROR_INVALID_ARGS	invalid arguments
 */
iot_error_t iot_util_convert_str_mac(char* str, struct iot_mac* mac);

/**
 * @brief	To convert iot_mac value intto WIFI mac string
 * @details	This function tries to convert from the iot_mac struct value to string
 * @param[in]	mac	converting wanted iot_mac struct value pointer
 * @param[in]	str	allocated memory pointer for converted WIFI mac string
 * @param[in]	max_sz	max size of allocated memory pointer
 * @return	iot_error_t
 * @retval	IOT_ERROR_NONE	success
 * @retval	IOT_ERROR_INVALID_ARGS invalid arguments
 */
iot_error_t iot_util_convert_mac_str(struct iot_mac* mac, char* str, int max_sz);

/**
 * @brief	To convert Wi-Fi channel into frequency value
 * @details	This function tries to convert from the channel to frequency
 * @param[in]	Wi-Fi channel
 * @return	Wi-Fi frequency
 */
uint16_t iot_util_convert_channel_freq(uint8_t channel);

#ifdef __cplusplus
}
#endif

#endif /* _IOT_UTIL_H_ */
