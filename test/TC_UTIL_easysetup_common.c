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
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <st_dev.h>
#include <string.h>
#include <iot_main.h>
#include <iot_internal.h>
#include <iot_nv_data.h>
#include <iot_error.h>
#include <iot_easysetup.h>
#include <bsp/iot_bsp_random.h>
#include <external/JSON.h>
#include <security/iot_security_crypto.h>
#include <security/iot_security_ecdh.h>
#include <security/iot_security_helper.h>
#include "TC_MOCK_functions.h"
#include "TC_UTIL_easysetup_common.h"

static char sample_device_info[] = {
        "{\n"
        "\t\"deviceInfo\": {\n"
        "\t\t\"firmwareVersion\": \""TEST_FIRMWARE_VERSION"\",\n"
        "\t\t\"privateKey\": \""TEST_DEVICE_SECRET_B64_KEY"\",\n"
        "\t\t\"publicKey\": \""TEST_DEVICE_PUBLIC_B64_KEY"\",\n"
        "\t\t\"serialNumber\": \""TEST_DEVICE_SERIAL_NUMBER"\"\n"
        "\t}\n"
        "}"
};

static char sample_onboarding_config[] = {
        "{\n"
        "  \"onboardingConfig\": {\n"
        "    \"deviceOnboardingId\": \"STDK\",\n"
        "    \"mnId\": \"fTST\",\n"
        "    \"setupId\": \"001\",\n"
        "    \"vid\": \"STDK_BULB_0001\",\n"
        "    \"deviceTypeId\": \"Switch\",\n"
        "    \"ownershipValidationTypes\": [\n"
        "      \"BUTTON\"\n"
        "    ],\n"
        "    \"identityType\": \"ED25519\"\n"
        "  }\n"
        "}"
};

static struct tc_key_pair* SERVER_KEYPAIR;
static struct tc_key_pair* DEVICE_KEYPAIR;

unsigned char * _get_server_test_pubkey()
{
    if (SERVER_KEYPAIR) {
        return SERVER_KEYPAIR->curve25519_pk;
    }
    return NULL;
}

int TC_iot_easysetup_common_setup(void **state)
{
    iot_error_t err;
    struct iot_devconf_prov_data *devconf;
    struct iot_device_info *device_info;
    struct iot_context *context;

#if !defined(CONFIG_STDK_IOT_CORE_SUPPORT_STNV_PARTITION)
    err = iot_nv_init((unsigned char *)sample_device_info, strlen(sample_device_info));
#else
    err = iot_nv_init(NULL, 0);
#endif
    assert_int_equal(err, IOT_ERROR_NONE);

    context = (struct iot_context *) malloc((sizeof(struct iot_context)));
    assert_non_null(context);
    memset(context, '\0', sizeof(struct iot_context));
    devconf = &context->devconf;

    err = iot_api_onboarding_config_load(sample_onboarding_config, sizeof(sample_onboarding_config), devconf);
    assert_int_equal(err, IOT_ERROR_NONE);

    device_info = &context->device_info;
    err = iot_api_device_info_load(sample_device_info, sizeof(sample_device_info), device_info);
    assert_int_equal(err, IOT_ERROR_NONE);

    context->easysetup_security_context = iot_security_init();
    assert_non_null(context->easysetup_security_context);

    err = iot_security_cipher_init(context->easysetup_security_context);
    assert_int_equal(err, IOT_ERROR_NONE);

    SERVER_KEYPAIR = _generate_test_keypair((const unsigned char*)TEST_SERVER_PUBLIC_B64_KEY, strlen(TEST_SERVER_PUBLIC_B64_KEY),
                                            (const unsigned char*)TEST_SERVER_SECRET_B64_KEY, strlen(TEST_SERVER_SECRET_B64_KEY));
    assert_non_null(SERVER_KEYPAIR);
    DEVICE_KEYPAIR = _generate_test_keypair((const unsigned char*)TEST_DEVICE_PUBLIC_B64_KEY, strlen(TEST_DEVICE_PUBLIC_B64_KEY),
                                            (const unsigned char*)TEST_DEVICE_SECRET_B64_KEY, strlen(TEST_DEVICE_SECRET_B64_KEY));
    assert_non_null(DEVICE_KEYPAIR);

    *state = context;

    return 0;
}

int TC_iot_easysetup_common_teardown(void **state)
{
    iot_error_t err;
    struct iot_context *context = (struct iot_context *)*state;
    struct iot_devconf_prov_data *devconf = &context->devconf;
    struct iot_device_info *device_info = &context->device_info;
    iot_security_context_t *security_context = context->easysetup_security_context;

    do_not_use_mock_iot_os_malloc_failure();

    iot_api_onboarding_config_mem_free(devconf);
    iot_api_device_info_mem_free(device_info);
    iot_security_cipher_deinit(security_context);
    iot_security_deinit(security_context);

    err = iot_nv_erase_prov_data();
    assert_int_equal(err, IOT_ERROR_NONE);
    err = iot_nv_deinit();
    assert_int_equal(err, IOT_ERROR_NONE);
    free(context);

    if (SERVER_KEYPAIR) {
        free(SERVER_KEYPAIR);
        SERVER_KEYPAIR = NULL;
    }
    if (DEVICE_KEYPAIR) {
        free(DEVICE_KEYPAIR);
        DEVICE_KEYPAIR = NULL;
    }

    return 0;
}

struct tc_key_pair* _generate_test_keypair(const unsigned char *pk_b64url, size_t pk_b64url_len,
                                                  const unsigned char *sk_b64url, size_t sk_b64url_len)
{
    struct tc_key_pair *keypair;
    iot_error_t err;
    size_t out_length;

    keypair = (struct tc_key_pair *) malloc(sizeof(struct tc_key_pair));
    assert_non_null(keypair);
    memset(keypair, '\0', sizeof(struct tc_key_pair));

    err = iot_security_base64_decode(pk_b64url, pk_b64url_len,
                                   keypair->ed25519_pk, sizeof(keypair->ed25519_pk), &out_length);
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_int_equal(out_length, IOT_SECURITY_ED25519_LEN);

    err = iot_security_base64_decode(sk_b64url, sk_b64url_len,
                                   keypair->ed25519_sk, sizeof(keypair->ed25519_sk), &out_length);
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_int_equal(out_length, IOT_SECURITY_ED25519_LEN);

    err = iot_security_ed25519_convert_pubkey(keypair->ed25519_pk, keypair->curve25519_pk);
    assert_int_equal(err, IOT_ERROR_NONE);

    err = iot_security_ed25519_convert_seckey(keypair->ed25519_sk, keypair->curve25519_sk);
    assert_int_equal(err, IOT_ERROR_NONE);

    return keypair;
}

void _free_cipher(iot_security_cipher_params_t *cipher)
{
    assert_non_null(cipher);
    if (cipher->iv.p) {
        free(cipher->iv.p);
        cipher->iv.p = NULL;
        cipher->iv.len = 0;
    }
    if (cipher->key.p) {
        free(cipher->key.p);
        cipher->key.p = NULL;
        cipher->key.len = 0;
    }

    free(cipher);
}


char *_encrypt_and_encode_message(iot_security_cipher_params_t *cipher, unsigned char *message, size_t message_length)
{
    iot_security_context_t *security_context = NULL;
    iot_security_buffer_t message_buffer = { 0 };
    iot_security_buffer_t aes256_message_buffer = { 0 };
    size_t b64_aes256_len;
    size_t out_length;
    unsigned char *b64url_aes256_message;
    iot_error_t err;

    assert_non_null(cipher);
    assert_non_null(message);
    assert_true(message_length > 0);

    security_context = iot_security_init();
    assert_non_null(security_context);
    err = iot_security_cipher_init(security_context);
    assert_int_equal(err, IOT_ERROR_NONE);

    err = iot_security_cipher_set_params(security_context, cipher);
    assert_int_equal(err, IOT_ERROR_NONE);

    message_buffer.p = message;
    message_buffer.len = message_length;
    err = iot_security_cipher_aes_encrypt(security_context, &message_buffer, &aes256_message_buffer);
    assert_int_equal(err, IOT_ERROR_NONE);

    b64_aes256_len = IOT_SECURITY_B64_ENCODE_LEN(aes256_message_buffer.len);
    b64url_aes256_message = (unsigned char *) malloc(b64_aes256_len);
    assert_non_null(b64url_aes256_message);
    err = iot_security_base64_encode_urlsafe(aes256_message_buffer.p, aes256_message_buffer.len, b64url_aes256_message, b64_aes256_len, &out_length);
    assert_int_equal(err, IOT_ERROR_NONE);

    free(aes256_message_buffer.p);

    err = iot_security_cipher_deinit(security_context);
    assert_int_equal(err, IOT_ERROR_NONE);
    err = iot_security_deinit(security_context);
    assert_int_equal(err, IOT_ERROR_NONE);

    return b64url_aes256_message;
}

char *_decode_and_decrypt_message(iot_security_cipher_params_t *cipher, unsigned char *b64url_aes256_message, size_t b64url_aes256_message_length)
{
    iot_error_t err;
    iot_security_context_t *security_context = NULL;
    iot_security_buffer_t plain_message_buffer = { 0 };
    iot_security_buffer_t aes256_message_buffer = { 0 };
    size_t aes256_message_actual_length;
    assert_non_null(cipher);
    assert_non_null(b64url_aes256_message);
    assert_true(b64url_aes256_message_length > 0);

    // Given
    security_context = iot_security_init();
    assert_non_null(security_context);
    err = iot_security_cipher_init(security_context);
    assert_int_equal(err, IOT_ERROR_NONE);
    err = iot_security_cipher_set_params(security_context, cipher);
    assert_int_equal(err, IOT_ERROR_NONE);

    // Decode
    aes256_message_buffer.len = IOT_SECURITY_B64_DECODE_LEN(b64url_aes256_message_length);
    aes256_message_buffer.p = malloc(aes256_message_buffer.len);
    assert_non_null(aes256_message_buffer.p);

    err = iot_security_base64_decode_urlsafe(b64url_aes256_message, b64url_aes256_message_length,
                             aes256_message_buffer.p, aes256_message_buffer.len,
                             &aes256_message_actual_length);
    assert_int_equal(err, IOT_ERROR_NONE);

    // Decrypt
    aes256_message_buffer.len = aes256_message_actual_length;
    err = iot_security_cipher_aes_decrypt(security_context, &aes256_message_buffer, &plain_message_buffer);
    assert_int_equal(err, IOT_ERROR_NONE);

    free(aes256_message_buffer.p);

    // Teardown
    err = iot_security_cipher_deinit(security_context);
    assert_int_equal(err, IOT_ERROR_NONE);
    err = iot_security_deinit(security_context);
    assert_int_equal(err, IOT_ERROR_NONE);

    return (char *)plain_message_buffer.p;
}

static void _generate_hash_token(unsigned char *hash_token, size_t hash_token_size)
{
    unsigned char rand_ascii[IOT_SECURITY_SHA256_LEN * 2 + 1] = {0 };
    iot_error_t err;
    char tmp[3] = {0};
    size_t out_length;
    int i, j;

    assert_non_null(hash_token_size);
    assert_true(hash_token_size >= IOT_SECURITY_SHA256_LEN);

    memset(rand_ascii, '\0', sizeof(rand_ascii));
    err = iot_security_base64_decode((const unsigned char*)TEST_SRAND, strlen(TEST_SRAND),
                                   rand_ascii, sizeof(rand_ascii),
                                   &out_length);
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_int_equal(out_length, IOT_SECURITY_SHA256_LEN * 2);

    for (i = 0, j = 0; i < sizeof(rand_ascii) - 1; i += 2, j++) {
        memcpy(tmp, rand_ascii + i, 2);
        tmp[2] = '\0';
        hash_token[j] = (unsigned char)strtol((const char *)tmp, NULL, 16);
    }
}

static iot_security_cipher_params_t* _generate_cipher(unsigned char *pk, unsigned char *sk, unsigned char *iv, size_t iv_len)
{
    iot_error_t err;
    iot_security_context_t *security_context;
    iot_security_cipher_params_t* cipher = NULL;
    iot_security_ecdh_params_t ecdh_params = { 0 };
    iot_security_buffer_t shared_secret = { 0 };
    unsigned char hash_token[IOT_SECURITY_SHA256_LEN];
    unsigned char *master_secret = NULL;

    assert_non_null(pk);
    assert_non_null(sk);

    security_context = iot_security_init();
    assert_non_null(security_context);
    err = iot_security_ecdh_init(security_context);
    assert_int_equal(err, IOT_ERROR_NONE);

    cipher = (iot_security_cipher_params_t *)malloc(sizeof(iot_security_cipher_params_t));
    assert_non_null(cipher);
    memset(cipher, '\0', sizeof(iot_security_cipher_params_t));
    cipher->iv.len = IOT_SECURITY_IV_LEN;
    cipher->iv.p = (unsigned char *) malloc(IOT_SECURITY_IV_LEN);
    assert_non_null(cipher->iv.p);
    if (iv) {
        assert_int_equal(iv_len, IOT_SECURITY_IV_LEN);
        memcpy(cipher->iv.p, iv, IOT_SECURITY_IV_LEN);
    } else {
        for (int i = 0; i < IOT_SECURITY_IV_LEN; i++) {
            cipher->iv.p[i] = (unsigned char)iot_bsp_random();
        }
    }
    assert_iv_buffer(cipher->iv);

    memset(hash_token, '\0', sizeof(hash_token));
    _generate_hash_token(hash_token, sizeof(hash_token));

    ecdh_params.t_seckey.p = sk;
    ecdh_params.t_seckey.len = IOT_SECURITY_ED25519_LEN;
    ecdh_params.c_pubkey.p = pk;
    ecdh_params.c_pubkey.len = IOT_SECURITY_ED25519_LEN;
    ecdh_params.salt.p = hash_token;
    ecdh_params.salt.len = sizeof(hash_token);
    err = iot_security_ecdh_set_params(security_context, &ecdh_params);
    assert_int_equal(err, IOT_ERROR_NONE);

    master_secret = malloc(IOT_SECURITY_SECRET_LEN + 1);
    assert_non_null(master_secret);
    memset(master_secret, '\0', IOT_SECURITY_SECRET_LEN + 1);
    err = iot_security_ecdh_compute_shared_secret(security_context, &shared_secret);
    assert_int_equal(err, IOT_ERROR_NONE);

    cipher->type = IOT_SECURITY_KEY_TYPE_AES256;
    cipher->key = shared_secret;

    err = iot_security_ecdh_deinit(security_context);
    assert_int_equal(err, IOT_ERROR_NONE);
    err = iot_security_deinit(security_context);
    assert_int_equal(err, IOT_ERROR_NONE);

    return cipher;
}

iot_security_cipher_params_t* _generate_server_cipher(unsigned char *iv_data, size_t iv_length)
{
    return _generate_cipher(DEVICE_KEYPAIR->curve25519_pk, SERVER_KEYPAIR->curve25519_sk, iv_data, iv_length);
}

iot_security_cipher_params_t* _generate_device_cipher(unsigned char *iv_data, size_t iv_length)
{
    return _generate_cipher(SERVER_KEYPAIR->curve25519_pk, DEVICE_KEYPAIR->curve25519_sk, iv_data, iv_length);
}

char *_generate_post_keyinfo_payload(int year, char *time_to_set, size_t time_to_set_len)
{
    char *post_message;
    JSON_H *root = NULL;
    iot_error_t err;
    size_t out_length;
    unsigned char *curve25519_server_pk_b64;
    size_t curve25519_server_pk_b64_len = IOT_SECURITY_B64_ENCODE_LEN(IOT_SECURITY_ED25519_LEN) + 1;
    char datetime[32];
    char regionaldatetime[32];
    char timezoneid[16];
    unsigned char *b64url_datetime;
    unsigned char *b64url_regionaldatetime;
    unsigned char *b64url_timezoneid;
    struct tm test_tm;
    time_t test_time;
    unsigned char* spub = _get_server_test_pubkey();


    assert_non_null(spub);
    assert_non_null(time_to_set);
    assert_true(year > 2000);

    if (sizeof(time_t) == 4) {
        assert_true(year < 2038);
    }

    curve25519_server_pk_b64 = malloc(curve25519_server_pk_b64_len);
    memset(curve25519_server_pk_b64, '\0', curve25519_server_pk_b64_len);
    err = iot_security_base64_encode_urlsafe(spub, IOT_SECURITY_ED25519_LEN,
                                           curve25519_server_pk_b64, curve25519_server_pk_b64_len, &out_length);
    assert_int_equal(err, IOT_ERROR_NONE);

    snprintf(datetime, sizeof(datetime), "%04d-03-25T02.40.14 UTC", year);
    snprintf(regionaldatetime, sizeof(regionaldatetime), "%04d-03-25T11.40.14 GMT+09:00", year);
    snprintf(timezoneid, sizeof(timezoneid), "Asia/Seoul");

    memset(&test_tm, '\0', sizeof(struct tm));
    test_tm.tm_year = year - 1900;
    test_tm.tm_mon = 2;
    test_tm.tm_mday = 25;
    test_tm.tm_hour = 2;
    test_tm.tm_min = 40;
    test_tm.tm_sec = 14;

    test_time = mktime(&test_tm);
    snprintf(time_to_set, time_to_set_len, "%ld", test_time);

    b64url_datetime = (unsigned char*) malloc(IOT_SECURITY_B64_ENCODE_LEN(strlen(datetime)));
    b64url_regionaldatetime = (unsigned char*) malloc(IOT_SECURITY_B64_ENCODE_LEN(strlen(regionaldatetime)));
    b64url_timezoneid = (unsigned char*) malloc(IOT_SECURITY_B64_ENCODE_LEN(strlen(timezoneid)));

    err = iot_security_base64_encode_urlsafe(datetime, strlen(datetime),
                                           b64url_datetime, IOT_SECURITY_B64_ENCODE_LEN(strlen(datetime)), &out_length);
    assert_int_equal(err, IOT_ERROR_NONE);

    err = iot_security_base64_encode_urlsafe(regionaldatetime, strlen(regionaldatetime),
                                           b64url_regionaldatetime, IOT_SECURITY_B64_ENCODE_LEN(strlen(regionaldatetime)), &out_length);
    assert_int_equal(err, IOT_ERROR_NONE);

    err = iot_security_base64_encode_urlsafe(timezoneid, strlen(timezoneid),
                                           b64url_timezoneid, IOT_SECURITY_B64_ENCODE_LEN(strlen(datetime)), &out_length);
    assert_int_equal(err, IOT_ERROR_NONE);

    root = JSON_CREATE_OBJECT();
    assert_non_null(root);
    JSON_ADD_ITEM_TO_OBJECT(root, "spub", JSON_CREATE_STRING((const char *) curve25519_server_pk_b64));
    JSON_ADD_ITEM_TO_OBJECT(root, "rand", JSON_CREATE_STRING(TEST_SRAND));
    JSON_ADD_ITEM_TO_OBJECT(root, "datetime", JSON_CREATE_STRING((const char *) b64url_datetime));
    JSON_ADD_ITEM_TO_OBJECT(root, "regionaldatetime", JSON_CREATE_STRING((const char *) b64url_regionaldatetime));
    JSON_ADD_ITEM_TO_OBJECT(root, "timezoneid", JSON_CREATE_STRING((const char *)b64url_timezoneid));
    post_message = JSON_PRINT(root);
    JSON_DELETE(root);
    free(curve25519_server_pk_b64);
    free(b64url_datetime);
    free(b64url_regionaldatetime);
    free(b64url_timezoneid);

    return post_message;
}

void assert_iv_buffer(iot_security_buffer_t iv_buffer)
{
    int i;
    unsigned char result = 0x00;

    assert_non_null(iv_buffer.p);

    for (i = 0; i < iv_buffer.len; i++) {
        result |= iv_buffer.p[i];
    }

    for (i = 0; i < iv_buffer.len; i++) {
        if (iv_buffer.p[i] != 0xff) {
            assert_int_not_equal(iv_buffer.p[i], result);
            break;
        }
    }

    if (i == iv_buffer.len) {
        // all iv[i] is 0xff
        assert_false(true);
    }
}

void assert_keyinfo(char *payload, iot_security_cipher_params_t *server_cipher, unsigned int expected_otm_support)
{
    JSON_H *root = NULL;
    JSON_H *array = NULL;
    JSON_H *item = NULL;
    JSON_H *error_message = NULL;
    char *b64url_aes256_message = NULL;
    char *plain_message = NULL;
    unsigned int otm_support = 0;

    assert_non_null(payload);
    assert_non_null(server_cipher);

    root = JSON_PARSE(payload);
    assert_non_null(root);
    error_message = JSON_GET_OBJECT_ITEM(root, "error");
    assert_null(error_message);

    item = JSON_GET_OBJECT_ITEM(root, "message");
    assert_non_null(item);
    b64url_aes256_message = JSON_GET_STRING_VALUE(item);
    assert_true(strlen( b64url_aes256_message) > 10);

    plain_message = _decode_and_decrypt_message(server_cipher, (unsigned char*) b64url_aes256_message, strlen(b64url_aes256_message));
    JSON_DELETE(root);

    // validate values
    root = JSON_PARSE((const char*) plain_message);
    assert_non_null(root);
    array = JSON_GET_OBJECT_ITEM(root, "otmSupportFeatures");
    assert_non_null(array);
    for (int i = 0; i < JSON_GET_ARRAY_SIZE(array); i++) {
        item = JSON_GET_ARRAY_ITEM(array, i);
        otm_support |= (1u << (unsigned)item->valueint);
    }
    assert_int_equal(otm_support, expected_otm_support);

    JSON_DELETE(root);
    free(plain_message);
}