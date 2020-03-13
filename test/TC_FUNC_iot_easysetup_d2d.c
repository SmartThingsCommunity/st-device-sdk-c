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
#include <string.h>
#include <iot_error.h>
#include <iot_easysetup.h>
#include <iot_nv_data.h>
#include <iot_internal.h>
#include <cJSON.h>
#include "TC_MOCK_functions.h"

#define UNUSED(x) (void**)(x)

#define TEST_FIRMWARE_VERSION "testFirmwareVersion"
#define TEST_DEVICE_PUBLIC_B64_KEY "BKb7+m1Mo8OuMsodM91ohz/+rZKDc/otzUPSn4UkCUk="
#define TEST_DEVICE_SECRET_B64_KEY "ztqmQ24u86J9bpFLjaoMfwauUZwKLjUIGsnrDwwnDM8="
static char sample_device_info[] = {
        "{\n"
        "\t\"deviceInfo\": {\n"
        "\t\t\"firmwareVersion\": \""TEST_FIRMWARE_VERSION"\",\n"
        "\t\t\"privateKey\": \""TEST_DEVICE_SECRET_B64_KEY"\",\n"
        "\t\t\"publicKey\": \""TEST_DEVICE_PUBLIC_B64_KEY"\",\n"
        "\t\t\"serialNumber\": \"STDKtESt7968d226\"\n"
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

static const char sample_ssid[] = "STDK_E4fTST0016LWpcd226";
static char sample_hashed_sn_b64url[] = "LWpcna0H5C-NEFcoRXRRBUWFqeU1XmOeyaigeYcxl1Q=";

#define TEST_SERVER_PUBLIC_B64_KEY "+NOQ46BofjUn5f8OQ34Knwg3h7ByLMtlIQc3wQew+Ag="
#define TEST_SERVER_SECRET_B64_KEY "7BVH45ba3HSubazIky5IzV2COWAdiGjw63d1TQsEOIA="
#define TEST_SRAND "OTI0NTU3YjQ5OTRjNmRiN2UxOTAzMzAwYzc1ZmRlMmFmNTYwMDJiYmZhOWQzMGZjZGMwZWJiMDYwYWZlOWIxZg=="

struct tc_key_pair {
    unsigned char curve25519_pk[IOT_CRYPTO_ED25519_LEN];
    unsigned char ed25519_pk[IOT_CRYPTO_ED25519_LEN];
    unsigned char curve25519_sk[IOT_CRYPTO_ED25519_LEN];
    unsigned char ed25519_sk[IOT_CRYPTO_ED25519_LEN];
};

struct tc_key_pair* SERVER_KEYPAIR;
struct tc_key_pair* DEVICE_KEYPAIR;
static struct tc_key_pair* _generate_test_keypair(const unsigned char *pk_b64url, size_t pk_b64url_len,
                                                  const unsigned char *sk_b64url, size_t sk_b64url_len);

int TC_iot_easysetup_d2d_setup(void **state)
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
    devconf = &context->devconf;

    err = iot_api_onboarding_config_load(sample_onboarding_config, sizeof(sample_onboarding_config), devconf);
    assert_int_equal(err, IOT_ERROR_NONE);

    device_info = &context->device_info;
    err = iot_api_device_info_load(sample_device_info, sizeof(sample_device_info), device_info);
    assert_int_equal(err, IOT_ERROR_NONE);

    context->es_crypto_cipher_info = (iot_crypto_cipher_info_t *) malloc(sizeof(iot_crypto_cipher_info_t));
    assert_non_null(context->es_crypto_cipher_info);

    SERVER_KEYPAIR = _generate_test_keypair(TEST_SERVER_PUBLIC_B64_KEY, strlen(TEST_SERVER_PUBLIC_B64_KEY),
                                            TEST_SERVER_SECRET_B64_KEY, strlen(TEST_SERVER_SECRET_B64_KEY));
    assert_non_null(SERVER_KEYPAIR);
    DEVICE_KEYPAIR = _generate_test_keypair(TEST_DEVICE_PUBLIC_B64_KEY, strlen(TEST_DEVICE_PUBLIC_B64_KEY),
                                            TEST_DEVICE_SECRET_B64_KEY, strlen(TEST_DEVICE_SECRET_B64_KEY));
    assert_non_null(DEVICE_KEYPAIR);

    *state = context;

    return 0;
}

int TC_iot_easysetup_d2d_teardown(void **state)
{
    iot_error_t err;
    struct iot_context *context = (struct iot_context *)*state;
    struct iot_devconf_prov_data *devconf = &context->devconf;
    struct iot_device_info *device_info = &context->device_info;

    do_not_use_mock_iot_os_malloc_failure();

    iot_api_onboarding_config_mem_free(devconf);
    iot_api_device_info_mem_free(device_info);
    free(context->es_crypto_cipher_info);

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


void TC_iot_easysetup_create_ssid_null_parameters(void **state)
{
    iot_error_t err;
    char ssid[33];
    struct iot_devconf_prov_data devconf;
    UNUSED(state);

    // When: All parameters null
    err = iot_easysetup_create_ssid(NULL, NULL, 0);
    // Then: returns error
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // When: devconf is null
    err = iot_easysetup_create_ssid(NULL, ssid, sizeof(ssid));
    // Then: returns error
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // When: ssid is null
    err = iot_easysetup_create_ssid(&devconf, NULL, 0);
    // Then: returns error
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_easysetup_create_ssid_success(void **state)
{
    iot_error_t err;
    char ssid[33];
    struct iot_context *context = (struct iot_context *)*state;
    struct iot_devconf_prov_data *devconf;

    // Given
    devconf = &context->devconf;
    // When: valid parameters
    err = iot_easysetup_create_ssid(devconf, ssid, sizeof(ssid));
    // Then: returns success
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_string_equal(ssid, sample_ssid);
    assert_string_equal(devconf->hashed_sn, sample_hashed_sn_b64url);
}

void TC_iot_easysetup_request_handler_null_parameters(void **state)
{
    iot_error_t err;
    struct iot_easysetup_payload request;
    UNUSED(state);

    // Given
    request.step = IOT_EASYSETUP_STEP_DEVICEINFO;
    request.payload = NULL;
    request.err = IOT_ERROR_NONE;
    // When: ctx is null
    err = iot_easysetup_request_handler(NULL, request);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

// Static function declare for test
extern iot_error_t _es_deviceinfo_handler(struct iot_context *ctx, char **out_payload);

void TC_STATIC_es_deviceinfo_handler_null_parameter(void **state)
{
    iot_error_t err;
    struct iot_context *context;
    char *out_payload = NULL;
    UNUSED(state);

    // Given
    context = NULL;
    // When
    err = _es_deviceinfo_handler(context, &out_payload);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

static void assert_deviceinfo(char *payload, char *expected_firmware_version, char *expected_hashed_sn);
void TC_STATIC_es_deviceinfo_handler_success(void **state)
{
    iot_error_t err;
    char *out_payload = NULL;
    struct iot_context *context;
    struct iot_devconf_prov_data *devconf;

    // Given
    context = (struct iot_context *)*state;
    devconf = &context->devconf;
    devconf->hashed_sn = sample_hashed_sn_b64url;
    // When
    err = _es_deviceinfo_handler(context, &out_payload);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_deviceinfo(out_payload, TEST_FIRMWARE_VERSION, sample_hashed_sn_b64url);

    // Local teardown
    free(out_payload);
}

static void assert_deviceinfo(char *payload, char *expected_firmware_version, char *expected_hashed_sn)
{
    cJSON *root;
    cJSON *item;
    assert_non_null(payload);

    root = cJSON_Parse(payload);
    item = cJSON_GetObjectItem(root, "error");
    assert_null(item);
    item = cJSON_GetObjectItem(root, "firmwareVersion");
    assert_string_equal(cJSON_GetStringValue(item), expected_firmware_version);
    item = cJSON_GetObjectItem(root, "hashedSn");
    assert_string_equal(cJSON_GetStringValue(item), expected_hashed_sn);
    item = cJSON_GetObjectItem(root, "wifiSupportFrequency");
    assert_in_range(item->valueint, 0, 2); // 0 for 2.4GHz, 1 for 5GHz, 2 for All
    item = cJSON_GetObjectItem(root, "iv");
    assert_true(strlen(cJSON_GetStringValue(item)) > 4);

    cJSON_Delete(root);
}

// Static function of STDK declared to test
extern iot_error_t _es_keyinfo_handler(struct iot_context *ctx, char *in_payload, char **out_payload);
extern iot_error_t _es_crypto_cipher_gen_iv(iot_crypto_cipher_info_t *iv_info);

// static functions for test
static char* _create_post_keyinfo_payload(void);
static iot_crypto_cipher_info_t* _generate_server_cipher(unsigned char *iv_data, size_t iv_length);
static void assert_keyinfo(char *payload, iot_crypto_cipher_info_t *server_cipher, unsigned int expected_otm_support);


void TC_STATIC_es_keyinfo_handler_success(void **state)
{
    iot_error_t err;
    char *out_payload = NULL;
    char *in_payload = NULL;
    struct iot_context *context;
    iot_crypto_cipher_info_t *server_cipher;

    // Given
    context = (struct iot_context *)*state;
    err = _es_crypto_cipher_gen_iv(context->es_crypto_cipher_info);
    assert_int_equal(err, IOT_ERROR_NONE);
    in_payload = _create_post_keyinfo_payload();
    server_cipher = _generate_server_cipher(context->es_crypto_cipher_info->iv, context->es_crypto_cipher_info->iv_len);
    assert_non_null(server_cipher);
    // When
    err = _es_keyinfo_handler(context, in_payload, &out_payload);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(out_payload);
    assert_keyinfo(out_payload, server_cipher, IOT_OVF_TYPE_BUTTON);

    // Local teardown
    free(server_cipher);
    free(out_payload);
    free(in_payload);
}

static struct tc_key_pair* _generate_test_keypair(const unsigned char *pk_b64url, size_t pk_b64url_len,
                                                  const unsigned char *sk_b64url, size_t sk_b64url_len)
{
    struct tc_key_pair *keypair;
    iot_error_t err;
    size_t out_length;

    keypair = (struct tc_key_pair *) malloc(sizeof(struct tc_key_pair));
    assert_non_null(keypair);
    memset(keypair, '\0', sizeof(struct tc_key_pair));

    err = iot_crypto_base64_decode(pk_b64url, pk_b64url_len,
                                           keypair->ed25519_pk, sizeof(keypair->ed25519_pk), &out_length);
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_int_equal(out_length, IOT_CRYPTO_ED25519_LEN);

    err = iot_crypto_base64_decode(sk_b64url, sk_b64url_len,
                                           keypair->ed25519_sk, sizeof(keypair->ed25519_sk), &out_length);
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_int_equal(out_length, IOT_CRYPTO_ED25519_LEN);

    err = iot_crypto_ed25519_convert_pubkey(keypair->ed25519_pk, keypair->curve25519_pk);
    assert_int_equal(err, IOT_ERROR_NONE);

    err = iot_crypto_ed25519_convert_seckey(keypair->ed25519_sk, keypair->curve25519_sk);
    assert_int_equal(err, IOT_ERROR_NONE);

    return keypair;
}

static char* _create_post_keyinfo_payload(void)
{
    char *post_message;
    cJSON *root = NULL;
    iot_error_t err;
    size_t out_length;
    unsigned char *curve25519_server_pk_b64;
    size_t curve25519_server_pk_b64_len = IOT_CRYPTO_CAL_B64_LEN(IOT_CRYPTO_ED25519_LEN) + 1;

    assert_non_null(SERVER_KEYPAIR);

    curve25519_server_pk_b64 = malloc(curve25519_server_pk_b64_len);
    memset(curve25519_server_pk_b64, '\0', curve25519_server_pk_b64_len);
    err = iot_crypto_base64_encode_urlsafe(SERVER_KEYPAIR->curve25519_pk, sizeof(SERVER_KEYPAIR->curve25519_pk),
            curve25519_server_pk_b64, curve25519_server_pk_b64_len, &out_length);
    assert_int_equal(err, IOT_ERROR_NONE);

    root = cJSON_CreateObject();
    assert_non_null(root);
    cJSON_AddItemToObject(root, "spub", cJSON_CreateString((const char *) curve25519_server_pk_b64));
    cJSON_AddItemToObject(root, "rand", cJSON_CreateString(TEST_SRAND));
    post_message = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    free(curve25519_server_pk_b64);

    return post_message;
}

void assert_keyinfo(char *payload, iot_crypto_cipher_info_t *server_cipher, unsigned int expected_otm_support)
{
    cJSON *root = NULL;
    cJSON *array = NULL;
    cJSON *item = NULL;
    cJSON *error_message = NULL;
    unsigned char *b64url_aes256_message = NULL;
    unsigned char *aes256_message = NULL;
    unsigned char *plain_message = NULL;
    size_t aes256_message_buffer_length;
    size_t aes256_message_actual_length;
    size_t plain_message_buffer_length;
    size_t plain_message_actual_length;
    iot_error_t err;
    unsigned int otm_support = 0;

    assert_non_null(payload);
    assert_non_null(server_cipher);

    root = cJSON_Parse(payload);
    assert_non_null(root);
    error_message = cJSON_GetObjectItem(root, "error");
    assert_null(error_message);

    item = cJSON_GetObjectItem(root, "message");
    assert_non_null(item);
    b64url_aes256_message = (unsigned char *) cJSON_GetStringValue(item);
    assert_true(strlen((const char *) b64url_aes256_message) > 10);

    // Decode
    // TODO: calc more accurate decoded size
    aes256_message_buffer_length = strlen((const char *) b64url_aes256_message);
    aes256_message = malloc(aes256_message_buffer_length);

    err = iot_crypto_base64_decode_urlsafe(b64url_aes256_message, strlen((const char *) b64url_aes256_message),
                                           aes256_message, aes256_message_buffer_length, &aes256_message_actual_length);
    assert_int_equal(err, IOT_ERROR_NONE);
    cJSON_Delete(root);

    // Decrypt
    plain_message_buffer_length = iot_crypto_cipher_get_align_size(IOT_CRYPTO_CIPHER_AES256, aes256_message_actual_length);
    plain_message = malloc(plain_message_buffer_length);
    memset(plain_message, '\0', plain_message_buffer_length);

    server_cipher->mode = IOT_CRYPTO_CIPHER_DECRYPT;
    err = iot_crypto_cipher_aes(server_cipher, aes256_message, aes256_message_actual_length,
            plain_message, &plain_message_actual_length, plain_message_buffer_length);
    assert_int_equal(err, IOT_ERROR_NONE);

    // null termination
    if (plain_message_actual_length < plain_message_buffer_length)
        *(plain_message + plain_message_actual_length) = '\0';

    // validate values
    root = cJSON_Parse((const char*) plain_message);
    assert_non_null(root);
    array = cJSON_GetObjectItem(root, "otmSupportFeatures");
    assert_non_null(array);
    for (int i = 0; i < cJSON_GetArraySize(array); i++) {
        item = cJSON_GetArrayItem(array, i);
        otm_support |= (1u << (unsigned)item->valueint);
    }
    assert_int_equal(otm_support, expected_otm_support);

    cJSON_Delete(root);
}


static void _generate_hash_token(unsigned char *hash_token, size_t hash_token_size)
{
    unsigned char rand_ascii[IOT_CRYPTO_SHA256_LEN * 2 + 1] = {0 };
    iot_error_t err;
    char tmp[3] = {0};
    size_t out_length;
    int i, j;

    assert_non_null(hash_token_size);
    assert_true(hash_token_size >= IOT_CRYPTO_SHA256_LEN);

    memset(rand_ascii, '\0', sizeof(rand_ascii));
    err = iot_crypto_base64_decode(TEST_SRAND, strlen(TEST_SRAND),
                                   rand_ascii, sizeof(rand_ascii),
                                   &out_length);
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_int_equal(out_length, IOT_CRYPTO_SHA256_LEN * 2);

    for (i = 0, j = 0; i < sizeof(rand_ascii) - 1; i += 2, j++) {
        memcpy(tmp, rand_ascii + i, 2);
        tmp[2] = '\0';
        hash_token[j] = (unsigned char)strtol((const char *)tmp, NULL, 16);
    }
}

static iot_crypto_cipher_info_t* _generate_server_cipher(unsigned char *iv_data, size_t iv_length)
{
    iot_error_t err;
    iot_crypto_ecdh_params_t ecdh_param;
    unsigned char hash_token[IOT_CRYPTO_SHA256_LEN];
    unsigned char *master_secret = NULL;
    iot_crypto_cipher_info_t* cipher = NULL;

    assert_non_null(SERVER_KEYPAIR);
    assert_non_null(iv_data);
    assert_int_equal(iv_length, IOT_CRYPTO_IV_LEN);

    cipher = (iot_crypto_cipher_info_t*) malloc(sizeof(iot_crypto_cipher_info_t));
    assert_non_null(cipher);
    memset(cipher, '\0', sizeof(iot_crypto_cipher_info_t));
    cipher->iv = iv_data;
    cipher->iv_len = iv_length;


    memset(hash_token, '\0', sizeof(hash_token));
    _generate_hash_token(hash_token, sizeof(hash_token));

    // iot_crypto_ecdh_gen_master_secret API is designed for device.
    // so we need to assign variables in opposite to make it as a server perspective
    ecdh_param.s_pubkey = DEVICE_KEYPAIR->curve25519_pk;
    ecdh_param.t_seckey = SERVER_KEYPAIR->curve25519_sk;
    ecdh_param.hash_token = hash_token;
    ecdh_param.hash_token_len = IOT_CRYPTO_SHA256_LEN;
    master_secret = malloc(IOT_CRYPTO_SECRET_LEN + 1);
    assert_non_null(master_secret);
    memset(master_secret, '\0', IOT_CRYPTO_SECRET_LEN + 1);
    err = iot_crypto_ecdh_gen_master_secret(master_secret, IOT_CRYPTO_SECRET_LEN, &ecdh_param);
    assert_int_equal(err, IOT_ERROR_NONE);

    cipher->type = IOT_CRYPTO_CIPHER_AES256;
    cipher->key = master_secret;
    cipher->key_len = IOT_CRYPTO_SECRET_LEN;

    return cipher;
}