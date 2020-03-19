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
#include <JSON.h>
#include <bsp/iot_bsp_random.h>
#include <sys/types.h>
#include <regex.h>
#include <errno.h>
#include <iot_util.h>
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
static void _free_cipher(iot_crypto_cipher_info_t *cipher);

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
    memset(context, '\0', sizeof(struct iot_context));
    devconf = &context->devconf;

    err = iot_api_onboarding_config_load(sample_onboarding_config, sizeof(sample_onboarding_config), devconf);
    assert_int_equal(err, IOT_ERROR_NONE);

    device_info = &context->device_info;
    err = iot_api_device_info_load(sample_device_info, sizeof(sample_device_info), device_info);
    assert_int_equal(err, IOT_ERROR_NONE);

    context->es_crypto_cipher_info = (iot_crypto_cipher_info_t *) malloc(sizeof(iot_crypto_cipher_info_t));
    assert_non_null(context->es_crypto_cipher_info);
    memset(context->es_crypto_cipher_info, '\0', sizeof(iot_crypto_cipher_info_t));

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
    iot_crypto_cipher_info_t *cipher_info = context->es_crypto_cipher_info;

    do_not_use_mock_iot_os_malloc_failure();

    iot_api_onboarding_config_mem_free(devconf);
    iot_api_device_info_mem_free(device_info);
    _free_cipher(cipher_info);

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
    JSON_H *root;
    JSON_H *item;
    assert_non_null(payload);

    root = JSON_PARSE(payload);
    item = JSON_GET_OBJECT_ITEM(root, "error");
    assert_null(item);
    item = JSON_GET_OBJECT_ITEM(root, "firmwareVersion");
    assert_string_equal(JSON_GET_STRING_VALUE(item), expected_firmware_version);
    item = JSON_GET_OBJECT_ITEM(root, "hashedSn");
    assert_string_equal(JSON_GET_STRING_VALUE(item), expected_hashed_sn);
    item = JSON_GET_OBJECT_ITEM(root, "wifiSupportFrequency");
    assert_in_range(item->valueint, 0, 2); // 0 for 2.4GHz, 1 for 5GHz, 2 for All
    item = JSON_GET_OBJECT_ITEM(root, "iv");
    assert_true(strlen(JSON_GET_STRING_VALUE(item)) > 4);

    JSON_DELETE(root);
}

// Static function of STDK declared to test
extern iot_error_t _es_keyinfo_handler(struct iot_context *ctx, char *in_payload, char **out_payload);
extern iot_error_t _es_crypto_cipher_gen_iv(iot_crypto_cipher_info_t *iv_info);

// static functions for test
static char* _create_post_keyinfo_payload(void);
static iot_crypto_cipher_info_t* _generate_server_cipher(unsigned char *iv_data, size_t iv_length);
static iot_crypto_cipher_info_t* _generate_device_cipher(unsigned char *iv_data, size_t iv_length);
static void assert_keyinfo(char *payload, iot_crypto_cipher_info_t *server_cipher, unsigned int expected_otm_support);
void assert_cipher_iv(iot_crypto_cipher_info_t cipher);

void TC_STATIC_es_crypto_cipher_gen_iv_success(void **state)
{
    iot_error_t err;
    iot_crypto_cipher_info_t cipher;
    UNUSED(state);

    // When
    err = _es_crypto_cipher_gen_iv(&cipher);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_cipher_iv(cipher);
}

void assert_cipher_iv(iot_crypto_cipher_info_t cipher)
{
    int i;
    unsigned char result = 0x00;

    for (i = 0; i < cipher.iv_len; i++) {
        result |= cipher.iv[i];
    }

    for (i = 0; i < cipher.iv_len; i++) {
        if (cipher.iv[i] != 0xff) {
            assert_int_not_equal(cipher.iv[i], result);
            break;
        }
    }

    if (i == cipher.iv_len) {
        // all iv[i] is 0xff
        assert_false(true);
    }

}

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
    // When
    err = _es_keyinfo_handler(context, in_payload, &out_payload);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(out_payload);
    assert_keyinfo(out_payload, server_cipher, IOT_OVF_TYPE_BUTTON);

    // Local teardown
    _free_cipher(server_cipher);
    free(out_payload);
    free(in_payload);
}

struct test_wifi_provisioning_data {
    char *ssid;
    char *password;
    char *mac_address;
    int auth_type;
    char *broker_url;
    char *location_id;
    char *room_id;
    char *device_name;
};

// Static function of STDK declared to test
extern iot_error_t _es_wifiprovisioninginfo_handler(struct iot_context *ctx, char *in_payload, char **out_payload);

// static functions for test
static char* _create_post_wifiprovisioninginfo_payload(iot_crypto_cipher_info_t *cipher, struct test_wifi_provisioning_data prov);
static void assert_lookup_id(const char *payload, iot_crypto_cipher_info_t *cipher);

static void assert_wifi_provisioning(struct iot_context *context, struct test_wifi_provisioning_data prov);

void TC_STATIC_es_wifiprovisioninginfo_handler_success(void **state)
{
    iot_error_t err;
    char *out_payload = NULL;
    char *in_payload = NULL;
    struct iot_context *context;
    iot_crypto_cipher_info_t *server_cipher;
    unsigned char device_mac[IOT_WIFI_MAX_BSSID_LEN] = { 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x01 };
    struct test_wifi_provisioning_data wifi_prov = {
            .ssid = "fakeSsid",
            .password = "fakePassword",
            .mac_address = "11:22:33:44:55:66",
            .auth_type = IOT_WIFI_AUTH_WPA2_PSK,
            .broker_url = "https://test.domain.com:5676",
            .location_id = "123e4567-e89b-12d3-a456-426655440000",
            .room_id = "123e4567-e89b-12d3-a456-426655440000",
            .device_name = "fakeDevice",
    };

    // Given
    context = (struct iot_context *)*state;
    context->es_crypto_cipher_info = _generate_device_cipher(NULL, 0);
    server_cipher = _generate_server_cipher(context->es_crypto_cipher_info->iv, context->es_crypto_cipher_info->iv_len);
    in_payload = _create_post_wifiprovisioninginfo_payload(server_cipher, wifi_prov);
    will_return(__wrap_iot_bsp_wifi_get_mac, cast_ptr_to_largest_integral_type(device_mac));
    will_return(__wrap_iot_bsp_wifi_get_mac, IOT_ERROR_NONE);
    // When
    err = _es_wifiprovisioninginfo_handler(context, in_payload, &out_payload);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(out_payload);
    assert_lookup_id(out_payload, server_cipher);
    assert_wifi_provisioning(context, wifi_prov);

    // Local teardown
    _free_cipher(server_cipher);
    free(out_payload);
    free(in_payload);

}

static void assert_wifi_provisioning(struct iot_context *context, struct test_wifi_provisioning_data prov)
{
    iot_error_t err;
    struct iot_mac mac;

    err = iot_util_convert_str_mac(prov.mac_address, &mac);
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_memory_equal(context->prov_data.wifi.bssid.addr, mac.addr, IOT_WIFI_MAX_BSSID_LEN);
    assert_string_equal(context->prov_data.wifi.ssid, prov.ssid);
    assert_string_equal(context->prov_data.wifi.password, prov.password);
    assert_int_equal(context->prov_data.wifi.security_type, prov.auth_type);
    assert_string_equal(context->prov_data.wifi.ssid, prov.ssid);
}

// Static function of STDK declared to test
extern iot_error_t _es_wifiscaninfo_handler(struct iot_context *ctx, char **out_payload);

void TC_STATIC_es_wifiscaninfo_handler_invalid_parameters(void **state)
{
    iot_error_t err;
    struct iot_context *context;
    char *payload;

    // Given: null payload
    context = (struct iot_context *)*state;
    payload = NULL;
    // When
    err = _es_wifiscaninfo_handler(context, &payload);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Given: null context, payload
    context = NULL;
    payload = NULL;
    // When
    err = _es_wifiscaninfo_handler(context, &payload);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
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
    JSON_H *root = NULL;
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

    root = JSON_CREATE_OBJECT();
    assert_non_null(root);
    JSON_ADD_ITEM_TO_OBJECT(root, "spub", JSON_CREATE_STRING((const char *) curve25519_server_pk_b64));
    JSON_ADD_ITEM_TO_OBJECT(root, "rand", JSON_CREATE_STRING(TEST_SRAND));
    post_message = JSON_PRINT(root);
    JSON_DELETE(root);
    free(curve25519_server_pk_b64);

    return post_message;
}

static char *_encryt_and_encode_mssage(iot_crypto_cipher_info_t *cipher, unsigned char *message, size_t message_length)
{
    size_t aes256_len;
    size_t b64_aes256_len;
    size_t out_length;
    unsigned char *aes256_message;
    unsigned char *b64url_aes256_message;
    iot_error_t err;

    assert_non_null(cipher);
    assert_non_null(message);
    assert_true(message_length > 0);

    aes256_len = iot_crypto_cipher_get_align_size(IOT_CRYPTO_CIPHER_AES256, message_length);
    aes256_message = (unsigned char *) malloc(aes256_len);
    assert_non_null(aes256_message);
    err = iot_crypto_cipher_aes(cipher, message, message_length, aes256_message, &out_length, aes256_len);
    assert_int_equal(err, IOT_ERROR_NONE);

    aes256_len = out_length;
    b64_aes256_len = IOT_CRYPTO_CAL_B64_LEN(aes256_len);
    b64url_aes256_message = (unsigned char *) malloc(b64_aes256_len);
    assert_non_null(b64url_aes256_message);
    err = iot_crypto_base64_encode_urlsafe(aes256_message, aes256_len, b64url_aes256_message, b64_aes256_len, &out_length);
    assert_int_equal(err, IOT_ERROR_NONE);

    free(aes256_message);
    return b64url_aes256_message;
}

static char *_decode_and_decrypt_message(iot_crypto_cipher_info_t *cipher, unsigned char *b64url_aes256_message, size_t b64url_aes256_message_length)
{
    iot_error_t err;
    unsigned char *aes256_message;
    unsigned char *plain_message;
    size_t aes256_message_buffer_length;
    size_t aes256_message_actual_length;
    size_t plain_message_buffer_length;
    size_t plain_message_actual_length;
    assert_non_null(cipher);
    assert_non_null(b64url_aes256_message);
    assert_true(b64url_aes256_message_length > 0);

    // Decode
    // TODO: calc more accurate decoded size
    aes256_message_buffer_length = b64url_aes256_message_length;
    aes256_message = malloc(aes256_message_buffer_length);

    err = iot_crypto_base64_decode_urlsafe(b64url_aes256_message, b64url_aes256_message_length,
                                           aes256_message, aes256_message_buffer_length, &aes256_message_actual_length);
    assert_int_equal(err, IOT_ERROR_NONE);


    // Decrypt
    plain_message_buffer_length = iot_crypto_cipher_get_align_size(IOT_CRYPTO_CIPHER_AES256, aes256_message_actual_length);
    plain_message = malloc(plain_message_buffer_length);
    memset(plain_message, '\0', plain_message_buffer_length);

    cipher->mode = IOT_CRYPTO_CIPHER_DECRYPT;
    err = iot_crypto_cipher_aes(cipher, aes256_message, aes256_message_actual_length,
                                plain_message, &plain_message_actual_length, plain_message_buffer_length);
    assert_int_equal(err, IOT_ERROR_NONE);

    // null termination
    if (plain_message_actual_length < plain_message_buffer_length)
        *(plain_message + plain_message_actual_length) = '\0';

    free(aes256_message);

    return plain_message;
}

static char* _create_post_wifiprovisioninginfo_payload(iot_crypto_cipher_info_t *cipher, struct test_wifi_provisioning_data prov)
{
    char *post_message;
    char *encoded_message;
    char *plain_message;
    JSON_H *root = NULL;
    JSON_H *wifi_credential = NULL;

    root = JSON_CREATE_OBJECT();
    assert_non_null(root);
    wifi_credential = JSON_CREATE_OBJECT();
    if (prov.ssid) {
        JSON_ADD_ITEM_TO_OBJECT(wifi_credential, "ssid", JSON_CREATE_STRING(prov.ssid));
    }
    if (prov.password) {
        JSON_ADD_ITEM_TO_OBJECT(wifi_credential, "password", JSON_CREATE_STRING(prov.password));
    }
    if (prov.mac_address) {
        JSON_ADD_ITEM_TO_OBJECT(wifi_credential, "macAddress", JSON_CREATE_STRING(prov.mac_address));
    }
    JSON_ADD_ITEM_TO_OBJECT(wifi_credential, "authType", JSON_CREATE_NUMBER((double) prov.auth_type));
    JSON_ADD_ITEM_TO_OBJECT(root, "wifiCredential", wifi_credential);
    if (prov.broker_url) {
        JSON_ADD_ITEM_TO_OBJECT(root, "brokerUrl", JSON_CREATE_STRING(prov.broker_url));
    }
    if (prov.location_id) {
        JSON_ADD_ITEM_TO_OBJECT(root, "locationId", JSON_CREATE_STRING(prov.location_id));
    }
    if (prov.room_id) {
        JSON_ADD_ITEM_TO_OBJECT(root, "roomId", JSON_CREATE_STRING(prov.room_id));
    }
    if (prov.device_name) {
        JSON_ADD_ITEM_TO_OBJECT(root, "deviceName", JSON_CREATE_STRING(prov.device_name));
    }
    plain_message = JSON_PRINT(root);
    JSON_DELETE(root);

    cipher->mode = IOT_CRYPTO_CIPHER_ENCRYPT;
    encoded_message = _encryt_and_encode_mssage(cipher, (unsigned char*) plain_message, strlen(plain_message));
    free(plain_message);

    // { "message": "XXXXX" }
    root = JSON_CREATE_OBJECT();
    assert_non_null(root);
    JSON_ADD_ITEM_TO_OBJECT(root, "message", JSON_CREATE_STRING(encoded_message));

    post_message = JSON_PRINT(root);
    JSON_DELETE(root);
    free(encoded_message);

    return post_message;
}

static void assert_keyinfo(char *payload, iot_crypto_cipher_info_t *server_cipher, unsigned int expected_otm_support)
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

static void assert_uuid_format(char *input_string)
{
    regex_t regex;
    int result;
    const char *uuid_pattern = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$";

    assert_non_null(input_string);
    result = regcomp(&regex, uuid_pattern, REG_EXTENDED);
    assert_return_code(result, errno);
    result = regexec(&regex, input_string, 0, NULL, 0);
    assert_int_not_equal(result, REG_NOMATCH);
    assert_int_equal(result, 0);
}

static void assert_lookup_id(const char *payload, iot_crypto_cipher_info_t *cipher)
{
    JSON_H *root;
    JSON_H *item;
    unsigned char *b64url_aes256_message;
    char *plain_message;
    assert_non_null(payload);
    assert_non_null(cipher);

    root = JSON_PARSE(payload);
    item = JSON_GET_OBJECT_ITEM(root, "message");
    b64url_aes256_message = (unsigned char*) JSON_GET_STRING_VALUE(item);

    plain_message = _decode_and_decrypt_message(cipher, b64url_aes256_message, strlen((const char*)b64url_aes256_message));
    JSON_DELETE(root);

    root = JSON_PARSE(plain_message);
    item = JSON_GET_OBJECT_ITEM(root, "lookupId");
    assert_non_null(item);
    assert_uuid_format(JSON_GET_STRING_VALUE(item));
    free(plain_message);
    JSON_DELETE(root);
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
    err = iot_crypto_base64_decode((const unsigned char*)TEST_SRAND, strlen(TEST_SRAND),
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

static iot_crypto_cipher_info_t* _generate_cipher(unsigned char *pk, unsigned char *sk, unsigned char *iv, size_t iv_len)
{
    iot_error_t err;
    iot_crypto_ecdh_params_t ecdh_param;
    unsigned char hash_token[IOT_CRYPTO_SHA256_LEN];
    unsigned char *master_secret = NULL;
    iot_crypto_cipher_info_t* cipher = NULL;

    assert_non_null(pk);
    assert_non_null(sk);

    cipher = (iot_crypto_cipher_info_t*) malloc(sizeof(iot_crypto_cipher_info_t));
    assert_non_null(cipher);
    memset(cipher, '\0', sizeof(iot_crypto_cipher_info_t));
    cipher->iv_len = IOT_CRYPTO_IV_LEN;
    cipher->iv = (unsigned char *) malloc(IOT_CRYPTO_IV_LEN);
    assert_non_null(cipher->iv);
    if (iv) {
        assert_int_equal(iv_len, IOT_CRYPTO_IV_LEN);
        memcpy(cipher->iv, iv, IOT_CRYPTO_IV_LEN);
    } else {
        for (int i = 0; i < IOT_CRYPTO_IV_LEN; i++) {
            cipher->iv[i] = (unsigned char)iot_bsp_random();
        }
    }

    memset(hash_token, '\0', sizeof(hash_token));
    _generate_hash_token(hash_token, sizeof(hash_token));

    ecdh_param.s_pubkey = pk;
    ecdh_param.t_seckey = sk;
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

static iot_crypto_cipher_info_t* _generate_server_cipher(unsigned char *iv_data, size_t iv_length)
{
    return _generate_cipher(DEVICE_KEYPAIR->curve25519_pk, SERVER_KEYPAIR->curve25519_sk, iv_data, iv_length);
}

static iot_crypto_cipher_info_t* _generate_device_cipher(unsigned char *iv_data, size_t iv_length)
{
    return _generate_cipher(SERVER_KEYPAIR->curve25519_pk, DEVICE_KEYPAIR->curve25519_sk, iv_data, iv_length);
}

static void _free_cipher(iot_crypto_cipher_info_t *cipher)
{
    assert_non_null(cipher);
    if (cipher->iv) {
        free(cipher->iv);
        cipher->iv = NULL;
    }
    if (cipher->key) {
        free(cipher->key);
        cipher->key = NULL;
    }

    free(cipher);
}