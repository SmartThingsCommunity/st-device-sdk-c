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

#ifndef _LIBSODIUM_HELPER_H_
#define _LIBSODIUM_HELPER_H_

#include "security/iot_security_common.h"

#ifdef __cplusplus
extern "C" {
#endif

iot_error_t libsodium_helper_pk_sign_ed25519(iot_security_pk_params_t *pk_params, iot_security_buffer_t *input_buf, iot_security_buffer_t *sig_buf);

iot_error_t libsodium_helper_pk_verify_ed25519(iot_security_pk_params_t *pk_params, iot_security_buffer_t *input_buf, iot_security_buffer_t *sig_buf);

#ifdef __cplusplus
}
#endif

#endif /* _LIBSODIUM_HELPER_H_ */
