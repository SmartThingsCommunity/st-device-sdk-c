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

#ifndef _IOT_UUID_H_
#define _IOT_UUID_H_

#include <iot_error.h>
#include <iot_main.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief	Change mac to random uuid
 * This function changes mac to random uuid
 * @param[out]	uuid		created random uuid
 * @return	IOT_ERROR_NONE on success
 */
iot_error_t iot_get_random_uuid_from_mac(struct iot_uuid *uuid);

/**
 * @brief	Change mac to uuid
 * This function changes mac to the uuid
 * @param[out]	uuid		created uuid
 * @return	IOT_ERROR_NONE on success
 */
iot_error_t iot_get_uuid_from_mac(struct iot_uuid *uuid);

/**
 * @brief	To get random uuid based on iot_uuid struct
 * @details	This function tries to make random iot_uuid values
 * @param[in]	uuid	allocated iot_uuid struct pointer to get random iot_uuid value
 * @return	return IOT_ERROR_NONE on success, or iot_error_t errors if it fails
 */
iot_error_t iot_get_random_uuid(struct iot_uuid* uuid);

#ifdef __cplusplus
}
#endif

#endif /* _IOT_UUID_H_ */
