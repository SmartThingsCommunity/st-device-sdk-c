/* ***************************************************************************
 *
 * Copyright (c) 2020 Samsung Electronics All Rights Reserved.
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

#ifndef _IOT_SECURITY_SECURE_STORAGE_H_
#define _IOT_SECURITY_SECURE_STORAGE_H_

#include "iot_nv_data.h"
#include "iot_security_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define IOT_SECURITY_STORAGE_BUF_MAX_LEN	2048
#define IOT_SECURITY_STORAGE_FILENAME_MAX_LEN	64

typedef iot_nvd_t iot_security_storage_id_t;

typedef enum {
	IOT_SECURITY_STORAGE_TARGET_UNKNOWN = 0,
	IOT_SECURITY_STORAGE_TARGET_NV,
	IOT_SECURITY_STORAGE_TARGET_FACTORY,
	IOT_SECURITY_STORAGE_TARGET_INVALID,
} iot_security_storage_target_t;

#ifdef __cplusplus
}
#endif

#endif /* _IOT_SECURITY_SECURE_STORAGE_H_ */
