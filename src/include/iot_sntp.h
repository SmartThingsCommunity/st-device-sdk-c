/* ***************************************************************************
 *
 * Copyright (c) 2026 Samsung Electronics All Rights Reserved.
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

#ifndef _IOT_SNTP_H_
#define _IOT_SNTP_H_

#include "iot_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Synchronize the system time with an SNTP server
 *
 * This function queries the built-in SNTP server list over UDP and sets
 * the system time through iot_bsp_system_set_time_in_sec() with the first
 * valid response. It is best-effort and returns after all servers have
 * been tried once. Even if it fails, the SDK can adjust the system time
 * through the server connection afterwards.
 *
 * @retval IOT_ERROR_NONE  time was synchronized successfully
 * @retval IOT_ERROR_NET_SNTP  no server returned a valid time
 */
iot_error_t iot_sntp_sync(void);

#ifdef __cplusplus
}
#endif

#endif /* _IOT_SNTP_H_ */
