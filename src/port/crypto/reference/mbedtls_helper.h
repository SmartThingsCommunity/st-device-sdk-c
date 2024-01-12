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

#ifndef _MBEDTLS_HELPER_H_
#define _MBEDTLS_HELPER_H_

#include "security/iot_security_common.h"

#ifdef __cplusplus
extern "C" {
#endif

iot_error_t mbedtls_helper_sha512(const unsigned char *input, size_t input_len, unsigned char *output, size_t output_len);

iot_error_t mbedtls_helper_sha256(const unsigned char *input, size_t input_len, unsigned char *output, size_t output_len);

iot_error_t mbedtls_helper_gen_secp256r1_keypair(iot_security_buffer_t *seckey_buf, iot_security_buffer_t *pubkey_buf);

iot_error_t mbedtls_helper_pk_sign_rsa(iot_security_pk_params_t *pk_params, iot_security_buffer_t *input_buf, iot_security_buffer_t *sig_buf);

iot_error_t mbedtls_helper_pk_sign_ecdsa(iot_security_pk_params_t *pk_params, iot_security_buffer_t *input_buf, iot_security_buffer_t *sig_buf);

iot_error_t mbedtls_helper_pk_verify_rsa(iot_security_pk_params_t *pk_params, iot_security_buffer_t *input_buf, iot_security_buffer_t *sig_buf);

iot_error_t mbedtls_helper_pk_verify_ecdsa(iot_security_pk_params_t *pk_params, iot_security_buffer_t *input_buf, iot_security_buffer_t *sig_buf);

iot_error_t mbedtls_helper_cipher_aes(iot_security_cipher_params_t *cipher_params, iot_security_buffer_t *input_buf, iot_security_buffer_t *output_buf, bool is_encrypt);

iot_error_t mbedtls_helper_ecdh_compute_shared_ecdsa(iot_security_buffer_t *t_seckey_buf, iot_security_buffer_t *c_pubkey_buf, iot_security_buffer_t *output_buf);

iot_error_t mbedtls_helper_ecdh_compute_shared_ed25519(iot_security_buffer_t *t_seckey_buf, iot_security_buffer_t *c_pubkey_buf, iot_security_buffer_t *output_buf);

#ifdef __cplusplus
}
#endif

#endif /* _MBEDTLS_HELPER_H_ */
