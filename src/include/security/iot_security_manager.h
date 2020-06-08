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

#ifndef _IOT_SECURITY_MANAGER_H_
#define _IOT_SECURITY_MANAGER_H_

#ifdef __cplusplus
extern "C" {
#endif

enum iot_security_cert_id {
	IOT_SECURITY_CERT_ID_UNKNOWN = 0,
	IOT_SECURITY_CERT_ID_ROOT_CA,
	IOT_SECURITY_CERT_ID_SUB_CA,
	IOT_SECURITY_CERT_ID_DEVICE,
	IOT_SECURITY_CERT_ID_MAX,
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_SECURITY_MANAGER_H_ */
