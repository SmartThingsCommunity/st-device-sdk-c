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

#ifndef _IOT_SECURITY_HELPER_H_
#define _IOT_SECURITY_HELPER_H_

#include "iot_security_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief	Converts an ed25519 public key to an x25519 public key
 * @param[in]	ed25519_key a pointer to a public key buffer
 * @param[out]	curve25519_key a pointer to a buffer to store converted x25519 public key
 * @retval	IOT_ERROR_NONE success
 * @retval	IOT_ERROR_INVALID_ARGS input parameter is invalid
 * @retval	IOT_ERROR_CRYPTO_ED_KEY_CONVERT failed to convert to x25519
 */
iot_error_t iot_security_ed25519_convert_pubkey(unsigned char *ed25519_key, unsigned char *curve25519_key);

/**
 * @brief	Converts an ed25519 secret key to an x25519 secret key
 * @param[in]	ed25519_key a pointer to a secret key buffer
 * @param[out]	curve25519_key a pointer to a buffer to store converted x25519 secret key
 * @retval	IOT_ERROR_NONE success
 * @retval	IOT_ERROR_INVALID_ARGS input parameter is invalid
 * @retval	IOT_ERROR_CRYPTO_ED_KEY_CONVERT failed to convert to x25519
 */
iot_error_t iot_security_ed25519_convert_seckey(unsigned char *ed25519_key, unsigned char *curve25519_key);

#ifdef __cplusplus
}
#endif

#endif /* _IOT_SECURITY_HELPER_H_ */
