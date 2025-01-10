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

#ifndef _IOT_SERIALIZE_H_
#define _IOT_SERIALIZE_H_

#include "JSON.h"

#ifdef __cplusplus
extern "C" {
#endif

#define IOT_CBOR_MAX_BUF_LEN	1024
/* In case of nano newlib, it doesn't support float printf,sprintf family */
#define IOT_SERIALIZE_SPRINTF_FLOAT	0
#define IOT_SERIALIZE_DECIMAL_PRECISION	1000000

/**
 * @brief	Convert cbor payload to json payload
 * @param[in]	cbor	a pointer to a buffer of cbor payload
 * @param[in]	cborlen	the size of buffer pointed by cbor in bytes
 * @param[out]	json	a pointer to a buffer to store json payload
 * @param[out]	jsonlen	the size of buffer pointed by json in bytes
 * @return	iot_state_t
 * @retval	IOT_ERROR_NONE		cbor successfully converted to json
 * @retval	IOT_ERROR_INVALID_ARG	there is something wrong with the inputs
 * @retval	IOT_ERROR_MEM_ALLOC	failed to alloc buffer to store json
 * @retval	IOT_ERROR_CBOR_PARSE	failed to parse cbor payload
 * @retval	IOT_ERROR_CBOR_TO_JSON	failed to write payload with json
 */
iot_error_t iot_serialize_cbor2json(uint8_t *cbor, size_t cborlen, char **json, size_t *jsonlen);

/**
 * @brief	Convert json structure to cbor payload
 * @param[in]	json	a node to a json strucure
 * @param[out]	cbor	a pointer to a buffer to store cbor payload
 * @param[out]	cborlen	the size of buffer pointed by cbor in bytes
 * @return	iot_state_t
 * @retval	IOT_ERROR_NONE		cbor successfully converted to json
 * @retval	IOT_ERROR_INVALID_ARG	there is something wrong with the inputs
 * @retval	IOT_ERROR_MEM_ALLOC	failed to alloc buffer to store json
 */
iot_error_t iot_serialize_json2cbor(JSON_H *json, uint8_t **cbor, size_t *cborlen);

#ifdef __cplusplus
}
#endif

#endif /* _IOT_SERIALIZE_H_ */
