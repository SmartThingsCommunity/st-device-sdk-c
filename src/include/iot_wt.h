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

#ifndef _IOT_WT_H_
#define _IOT_WT_H_

#include "security/iot_security_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief	Create a Web Token as proof of the device's identity
 * @details	This function makes a Web Token string to connect to ST Cloud.
 *		Pass the Web Token as password.
 *		Supported key types are RS256 and ED25519.
 * @param[in]	sn_buf a device serial number as user name
 * @param[out]	token_buf a pointer of buffer to store a formatted and signed string
 * @retval	IOT_ERROR_NONE		Web Token is sucessfully generated
 * @retval	IOT_ERROR_MEM_ALLOC	no more available heap memory
 * @retval	IOT_ERROR_WEBTOKEN_FAIL	failed to make json
 */
iot_error_t iot_wt_create(const iot_security_buffer_t *sn_buf, iot_security_buffer_t *token_buf);

#ifdef __cplusplus
}
#endif

#endif /* _IOT_WT_H_ */
