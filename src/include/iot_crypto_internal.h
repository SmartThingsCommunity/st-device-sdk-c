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

#ifndef _IOT_CRYPTO_INTERNAL_H_
#define _IOT_CRYPTO_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#if defined(CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_RSA)
extern const iot_crypto_pk_funcs_t iot_crypto_pk_rsa_funcs;
#endif

#if defined(CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_ED25519)
extern const iot_crypto_pk_funcs_t iot_crypto_pk_ed25519_funcs;
#endif

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CRYPTO_INTERNAL_H_ */
