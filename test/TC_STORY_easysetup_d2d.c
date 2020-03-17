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
#include <curl/curl.h>
#include <cJSON.h>
#include <errno.h>
#include <st_dev.h>
#include <iot_easysetup.h>
#include <iot_internal.h>
#include <iot_debug.h>

#define UNUSED(x) (void**)(x)
#define TEST_FIRMWARE_VERSION "testFirmwareVersion"
#define TEST_PRIVATE_KEY "ztqmQ24u86J9bpFLjaoMfwauUZwKLjUIGsnrDwwnDM8="
#define TEST_PUBLIC_KEY "BKb7+m1Mo8OuMsodM91ohz/+rZKDc/otzUPSn4UkCUk="
#define TEST_SERIAL_NUMBER "STDKtESt7968d226"
#define TEST_SERIAL_NUMBER_HASHED "LWpcna0H5C-NEFcoRXRRBUWFqeU1XmOeyaigeYcxl1Q="

static char device_info_for_easysetup_d2d[] = {
        "{\n"
        "\t\"deviceInfo\": {\n"
        "\t\t\"firmwareVersion\": \""TEST_FIRMWARE_VERSION"\",\n"
        "\t\t\"privateKey\": \""TEST_PRIVATE_KEY"\",\n"
        "\t\t\"publicKey\": \""TEST_PUBLIC_KEY"\",\n"
        "\t\t\"serialNumber\": \""TEST_SERIAL_NUMBER"\"\n"
        "\t}\n"
        "}"
};

static char onboarding_config_for_easysetup_d2d[] = {
        "{\n"
        "  \"onboardingConfig\": {\n"
        "    \"deviceOnboardingId\": \"STDK\",\n"
        "    \"mnId\": \"tESt\",\n"
        "    \"setupId\": \"001\",\n"
        "    \"vid\": \"STDK_BULB_0001\",\n"
        "    \"deviceTypeId\": \"Switch\",\n"
        "    \"ownershipValidationTypes\": [\n"
        "      \"JUSTWORKS\"\n"
        "    ],\n"
        "    \"identityType\": \"ED25519\"\n"
        "  }\n"
        "}"
};

int TC_easysetup_d2d_setup(void **state)
{
    IOT_CTX* context = NULL;
    int err = 0;

    context = st_conn_init(onboarding_config_for_easysetup_d2d, sizeof(onboarding_config_for_easysetup_d2d),
                           device_info_for_easysetup_d2d, sizeof(device_info_for_easysetup_d2d));
    assert_non_null(context);
    err = st_conn_start(context, NULL, IOT_STATUS_ALL, NULL, NULL);
    assert_int_equal(err, 0);

    *state = (void*) context;

    return 0;
}

int TC_easysetup_d2d_teardown(void **state)
{
    struct iot_context *context = *state;

    iot_easysetup_deinit(context);

    if (context->pin) {
        free(context->pin);
    }
    if (context->es_crypto_cipher_info) {
        free(context->es_crypto_cipher_info);
    }
    if (context->easysetup_req_queue) {
        iot_os_queue_delete(context->easysetup_req_queue);
    }
    if (context->easysetup_resp_queue) {
        iot_os_queue_delete(context->easysetup_resp_queue);
    }
    if (context->devconf.hashed_sn) {
        free(context->devconf.hashed_sn);
    }

    iot_os_eventgroup_delete(context->iot_events);
    iot_os_queue_delete(context->pub_queue);
    iot_os_eventgroup_delete(context->usr_events);
    iot_os_queue_delete(context->cmd_queue);
    iot_api_device_info_mem_free(&context->device_info);
    iot_api_onboarding_config_mem_free(&context->devconf);
    free(context);

    return 0;
}

struct mem_buffer {
    char *mem;
    size_t size;
};

static size_t _write_mem_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t actual_size = 0;
    struct mem_buffer *mem = NULL;
    char *ptr = NULL;

    actual_size =  size * nmemb;
    mem = (struct mem_buffer *) userp;
    ptr = realloc(mem->mem, mem->size + actual_size + 1);
    if (!ptr) {
        IOT_ERROR("failed to malloc buffer for curl");
        return 0;
    }

    mem->mem = ptr;
    memcpy(&(mem->mem[mem->size]), contents, actual_size);
    mem->size += actual_size;
    mem->mem[mem->size] = '\0';

    return actual_size;
}


static int _http_operation(char *full_url, char *in_buffer,
                           char *out_buffer, unsigned int out_len, long timeout)
{
    int ret = 0;
    CURL *curl;
    CURLcode res;
    struct mem_buffer chunk;
    struct curl_slist *headerlist = NULL;

    chunk.mem = malloc(sizeof(char));
    chunk.size = 0;

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (curl) {
        headerlist = curl_slist_append(headerlist, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);
        curl_easy_setopt(curl, CURLOPT_URL, full_url);
        if (in_buffer) {
            IOT_DEBUG("payload: %s", in_buffer);
            curl_easy_setopt(curl, CURLOPT_POST, 1L);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, in_buffer);
        }
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, _write_mem_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "libcurl-agent/1.0");
#ifdef _CURL_DEBUG_ON_
        curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, my_trace);
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
#endif
        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            IOT_DEBUG("curl error %s", curl_easy_strerror(res));
        } else {
            IOT_DEBUG("%zu byte recv", chunk.size);
        }

        curl_easy_cleanup(curl);
    } else {
        IOT_DEBUG("curl init error");
        ret = -EIO;
        goto get_out;
    }

    strncpy(out_buffer, chunk.mem, out_len - 1);
get_out:
    return ret;
}

static int _testcase_http_operation(char *uri, char *in_buffer,
                                    char *out_buffer, unsigned int out_len, long timeout)
{
    char url_buffer[128] = { 0,};
    snprintf(url_buffer, sizeof(url_buffer), "http://127.0.0.1:8888/%s", uri);
    IOT_DEBUG("url: %s", url_buffer);
    return _http_operation(url_buffer, in_buffer, out_buffer, out_len, timeout);
}

static void _dump_json(cJSON* item)
{
    char *ptr = cJSON_Print(item);
    IOT_DEBUG("%s", ptr);
    cJSON_free(ptr);
}

void TC_easysetup_d2d_get_deviceinfo_success(void **state)
{
    int ret = 0;
    char buffer[1024];
    cJSON *root = NULL;
    cJSON *item = NULL;
    cJSON *errmsg = NULL;
    UNUSED(state);

    // Given
    memset(buffer, '\0', sizeof(buffer));
    // When: request deviceinfo
    ret = _testcase_http_operation("deviceinfo", NULL, buffer, sizeof(buffer), 0);
    // Then
    assert_int_equal(ret, 0);
    root = cJSON_Parse(buffer);
    assert_non_null(root);
    errmsg = cJSON_GetObjectItem(root, "error");
    _dump_json(root);
    assert_null(errmsg);
    item = cJSON_GetObjectItem(root, "firmwareVersion");
    assert_string_equal(cJSON_GetStringValue(item), TEST_FIRMWARE_VERSION);
    item = cJSON_GetObjectItem(root, "hashedSn");
    assert_string_equal(cJSON_GetStringValue(item), TEST_SERIAL_NUMBER_HASHED);
    item = cJSON_GetObjectItem(root, "wifiSupportFrequency");
    assert_in_range(item->valueint, 0, 2); // 0 for 2.4GHz, 1 for 5GHz, 2 for All
    item = cJSON_GetObjectItem(root, "iv");
    assert_true(strlen(cJSON_GetStringValue(item)) > 4);

    // local teardown
    cJSON_Delete(root);
}