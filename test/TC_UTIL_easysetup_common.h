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

#ifndef ST_DEVICE_SDK_C_TC_UTIL_EASYSETUP_COMMON_H
#define ST_DEVICE_SDK_C_TC_UTIL_EASYSETUP_COMMON_H

#define TEST_FIRMWARE_VERSION "testFirmwareVersion"
#define TEST_DEVICE_PUBLIC_B64_KEY "BKb7+m1Mo8OuMsodM91ohz/+rZKDc/otzUPSn4UkCUk="
#define TEST_DEVICE_SECRET_B64_KEY "ztqmQ24u86J9bpFLjaoMfwauUZwKLjUIGsnrDwwnDM8="
#define TEST_DEVICE_SERIAL_NUMBER "STDKtESt7968d226"

#define TEST_SERVER_PUBLIC_B64_KEY "+NOQ46BofjUn5f8OQ34Knwg3h7ByLMtlIQc3wQew+Ag="
#define TEST_SERVER_SECRET_B64_KEY "7BVH45ba3HSubazIky5IzV2COWAdiGjw63d1TQsEOIA="
#define TEST_SRAND "OTI0NTU3YjQ5OTRjNmRiN2UxOTAzMzAwYzc1ZmRlMmFmNTYwMDJiYmZhOWQzMGZjZGMwZWJiMDYwYWZlOWIxZg=="

struct tc_key_pair {
    unsigned char curve25519_pk[IOT_SECURITY_ED25519_LEN];
    unsigned char ed25519_pk[IOT_SECURITY_ED25519_LEN];
    unsigned char curve25519_sk[IOT_SECURITY_ED25519_LEN];
    unsigned char ed25519_sk[IOT_SECURITY_ED25519_LEN];
};

struct tc_key_pair* _generate_test_keypair(const unsigned char *pk_b64url, size_t pk_b64url_len,
                                            const unsigned char *sk_b64url, size_t sk_b64url_len);
char *_decode_and_decrypt_message(iot_security_cipher_params_t *cipher, unsigned char *b64url_aes256_message, size_t b64url_aes256_message_length);
char *_encrypt_and_encode_message(iot_security_cipher_params_t *cipher, unsigned char *message, size_t message_length);
iot_security_cipher_params_t* _generate_server_cipher(unsigned char *iv_data, size_t iv_length);
iot_security_cipher_params_t* _generate_device_cipher(unsigned char *iv_data, size_t iv_length);
void _free_cipher(iot_security_cipher_params_t *cipher);

unsigned char * _get_server_test_pubkey();

int TC_iot_easysetup_common_setup(void **state);
int TC_iot_easysetup_common_teardown(void **state);

char *_generate_post_keyinfo_payload(int year, char *time_to_set, size_t time_to_set_len);
void assert_iv_buffer(iot_security_buffer_t iv_buffer);
void assert_keyinfo(char *payload, iot_security_cipher_params_t *server_cipher, unsigned int expected_otm_support);


#endif //ST_DEVICE_SDK_C_TC_UTIL_EASYSETUP_COMMON_H
