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
#include <bsp/iot_bsp_nv_data.h>
#include <certs/root_ca.h>
#include <iot_nv_data.h>
#include <iot_util.h>
#include <security/iot_security_manager.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "TC_MOCK_functions.h"
#include "cmocka_custom.h"
#define UNUSED(x) (void **)(x)

// External declarations for static functions
extern iot_error_t _iot_nv_write_data(const iot_nvd_t nv_type, const char *data, size_t data_len);
extern iot_error_t _iot_nv_read_data(const iot_nvd_t nv_type, char *data, size_t data_len, size_t *read_len);

typedef enum { NONE, DONE } wifi_status_cmd_t;

#define SAMPLE_PUBLIC_KEY "BKb7+m1Mo8OuMsodM91ohz/+rZKDc/otzUPSn4UkCUk="

static char sample_device_info[] = {
    "{\n"
    "\t\"deviceInfo\": {\n"
    "\t\t\"firmwareVersion\": \"testFirmwareVersion\",\n"
    "\t\t\"privateKey\": \"ztqmQ24u86J9bpFLjaoMfwauUZwKLjUIGsnrDwwnDM8=\",\n"
    "\t\t\"publicKey\": \"" SAMPLE_PUBLIC_KEY
    "\",\n"
    "\t\t\"serialNumber\": \"STDKtESt7968d226\"\n"
    "\t}\n"
    "}"};

static const char *sample_wifi_ssid = "fakeSsid_04_XXXXXX";
static const char *sample_wifi_password = "fakePassword1";
static const char *sample_wifi_bssid_str = "42:00:43:54:00:76";
static struct iot_mac sample_wifi_bssid;
static const iot_wifi_auth_mode_t sample_security_type = IOT_WIFI_AUTH_WPA2_PSK;

static void _setup_wifi_prov_status(wifi_status_cmd_t cmd);
static void _setup_wifi_prov_data(iot_nvd_t nv_type);
static void _teardown_wifi_prov_data();

int TC_iot_nv_data_setup(void **state)
{
    iot_error_t err;
    UNUSED(state);

#if !defined(CONFIG_STDK_IOT_CORE_SUPPORT_STNV_PARTITION)
    err = iot_nv_init((unsigned char *)sample_device_info, strlen(sample_device_info));
#else
    err = iot_nv_init(NULL, 0);
#endif
    assert_int_equal(err, IOT_ERROR_NONE);
    return 0;
}

int TC_iot_nv_data_teardown(void **state)
{
    iot_error_t err;
    UNUSED(state);

    do_not_use_mock_iot_os_malloc_failure();
    err = iot_nv_deinit();
    assert_int_equal(err, IOT_ERROR_NONE);
    return 0;
}

void TC_iot_nv_get_wifi_prov_data_success(void **state)
{
    iot_error_t err;
    struct iot_wifi_prov_data *wifi_prov = NULL;
    wifi_prov = malloc(sizeof(struct iot_wifi_prov_data));
    UNUSED(state);

    // Given : All data
    _setup_wifi_prov_status(DONE);
    _setup_wifi_prov_data(IOT_NVD_AP_SSID);
    _setup_wifi_prov_data(IOT_NVD_AP_PASS);
    _setup_wifi_prov_data(IOT_NVD_AP_BSSID);
    _setup_wifi_prov_data(IOT_NVD_AP_AUTH_TYPE);

    memset(wifi_prov, 0, sizeof(struct iot_wifi_prov_data));

    // When
    err = iot_nv_get_wifi_prov_data(wifi_prov);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_memory_equal(wifi_prov->ssid, sample_wifi_ssid, strlen(sample_wifi_ssid));
    assert_memory_equal(wifi_prov->password, sample_wifi_password, strlen(sample_wifi_password));
    assert_memory_equal(wifi_prov->mac_str, sample_wifi_bssid_str, strlen(sample_wifi_bssid_str));
    assert_memory_equal(wifi_prov->bssid.addr, sample_wifi_bssid.addr, IOT_WIFI_MAX_BSSID_LEN);
    assert_int_equal(wifi_prov->security_type, sample_security_type);

    // Local teardown
    _teardown_wifi_prov_data();

    // Given : Status done only
    _setup_wifi_prov_status(DONE);

    memset(wifi_prov, 0, sizeof(struct iot_wifi_prov_data));

    // When
    err = iot_nv_get_wifi_prov_data(wifi_prov);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);

    // Local teardown
    _teardown_wifi_prov_data();

    // Given : Status none only
    _setup_wifi_prov_status(NONE);

    memset(wifi_prov, 0, sizeof(struct iot_wifi_prov_data));

    // When
    err = iot_nv_get_wifi_prov_data(wifi_prov);
    // Then
    assert_int_equal(err, IOT_ERROR_NV_DATA_ERROR);

    // Local teardown
    _teardown_wifi_prov_data();

    free(wifi_prov);
}

void TC_iot_nv_get_wifi_prov_data_null_parameters(void **state)
{
    iot_error_t err;
    UNUSED(state);

    // When : All parameters null
    err = iot_nv_get_wifi_prov_data(NULL);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_nv_get_certificate_success(void **state)
{
    iot_error_t err;
    iot_security_cert_id_t cert_id;
    char *cert = NULL;
    size_t cert_len = 0;
    UNUSED(state);

    // Given
    cert_id = IOT_SECURITY_CERT_ID_ROOT_CA;
    // When
    err = iot_nv_get_certificate(cert_id, &cert, &cert_len);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_memory_equal(cert, st_root_ca, st_root_ca_len);
    assert_int_equal(cert_len, st_root_ca_len);

    // Local teardown
    free(cert);
}

void TC_iot_nv_get_certificate_null_parameters(void **state)
{
    iot_error_t err;
    iot_security_cert_id_t cert_id = IOT_SECURITY_CERT_ID_ROOT_CA;
    char *cert = NULL;
    size_t cert_len = 0;
    UNUSED(state);

    // When: All null parameters
    err = iot_nv_get_certificate(0, NULL, NULL);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // When: len is null
    err = iot_nv_get_certificate(cert_id, &cert, NULL);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    assert_null(cert);

    // When: cert is null
    err = iot_nv_get_certificate(cert_id, NULL, &cert_len);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    assert_int_equal(cert_len, 0);

    // When: cert id is unknown
    err = iot_nv_get_certificate(0, &cert, &cert_len);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    assert_null(cert);
    assert_int_equal(cert_len, 0);
}

void TC_iot_nv_get_certificate_internal_failure(void **state)
{
    iot_error_t err;
    iot_security_cert_id_t cert_id = IOT_SECURITY_CERT_ID_ROOT_CA;
    char *cert = NULL;
    size_t cert_len = 0;
    UNUSED(state);

    // Given: malloc failed
    set_mock_iot_os_malloc_failure();
    // When
    err = iot_nv_get_certificate(cert_id, &cert, &cert_len);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_nv_get_serial_number_success(void **state)
{
    iot_error_t err;
    char *serial_number = NULL;
    size_t serial_number_len = 0;
    const char *sample_serial_number = "STDKtESt7968d226";
    UNUSED(state);

    // When
    err = iot_nv_get_serial_number(&serial_number, &serial_number_len);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_memory_equal(serial_number, sample_serial_number, strlen(sample_serial_number));
    assert_int_equal(serial_number_len, strlen(sample_serial_number));

    // Local teardown
    free(serial_number);
}

void TC_iot_nv_get_serial_number_null_parameters(void **state)
{
    iot_error_t err;
    char *serial_number = NULL;
    size_t serial_number_len = 0;
    UNUSED(state);

    // When: All parameters null
    err = iot_nv_get_serial_number(NULL, NULL);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // When: Key is null
    err = iot_nv_get_serial_number(NULL, &serial_number_len);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    assert_int_equal(serial_number_len, 0);

    // When: Len is null
    err = iot_nv_get_serial_number(&serial_number, NULL);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    assert_int_equal(serial_number_len, 0);
    assert_null(serial_number);
}

void TC_iot_nv_get_device_id_null_parameters(void **state)
{
    iot_error_t err;
    size_t len;
    char *device_id;
    UNUSED(state);

    // When: All parameters null
    err = iot_nv_get_device_id(NULL, NULL);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // When: device_id is null
    err = iot_nv_get_device_id(NULL, &len);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // When: len is null
    err = iot_nv_get_device_id(&device_id, NULL);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_nv_set_device_id_null_parameter(void **state)
{
    iot_error_t err;
    UNUSED(state);

    // When: device_id is null
    err = iot_nv_set_device_id(NULL);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_nv_get_set_erase_device_id_success(void **state)
{
    iot_error_t err;
    char *set_device_id = "1cd8e3f2-0c88-4298-90e3-cd9b35a82140";
    char *got_device_id;
    size_t len;

    // When: set device id
    err = iot_nv_set_device_id(set_device_id);
    // Then:
    assert_int_equal(err, IOT_ERROR_NONE);

    // When: get device id
    err = iot_nv_get_device_id(&got_device_id, &len);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_string_equal(set_device_id, got_device_id);
    assert_int_equal(strlen(set_device_id), len);

    // When: erase device id
    err = iot_nv_erase(IOT_NVD_DEVICE_ID);
    // Then:
    assert_int_equal(err, IOT_ERROR_NONE);

    // Teardown
    free(got_device_id);
}

void TC_iot_nv_erase_internal_failure(void **state)
{
    iot_error_t err;

    // When: out ranged
    err = iot_nv_erase(IOT_NVD_MAX);
    // Then
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);

    // When: not existed
    err = iot_nv_erase(IOT_NVD_DEVICE_ID);
    // Then
    assert_int_equal(err, IOT_ERROR_NV_DATA_NOT_EXIST);
}

void TC_iot_nv_get_data_from_device_info_failure(void **state)
{
    iot_error_t err;
    iot_security_buffer_t buf;
    iot_nvd_t nv_id;

    // When: null
    err = iot_nv_get_data_from_device_info(nv_id, NULL);
    // Then
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);

    // Given: id not in device info
    nv_id = IOT_NVD_SERVER_URL;
    // When
    err = iot_nv_get_data_from_device_info(nv_id, &buf);
    // Then
    assert_int_equal(err, IOT_ERROR_NV_DATA_ERROR);
}

void TC_iot_nv_get_data_from_device_info_success(void **state)
{
    iot_error_t err;
    iot_nvd_t nv_id;
    iot_security_buffer_t buf;
    char *sample_public_key = SAMPLE_PUBLIC_KEY;

    // Given
    nv_id = IOT_NVD_PUBLIC_KEY;
    // When
    err = iot_nv_get_data_from_device_info(nv_id, &buf);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(buf.p);
    assert_int_not_equal(buf.len, 0);
    assert_memory_equal(buf.p, sample_public_key, strlen(sample_public_key));
}

void TC_iot_nv_prov_data_exist_null_parameters(void **state)
{
    UNUSED(state);
    // When: function is called
    bool result = iot_nv_prov_data_exist();
    // Then: function should not crash

    // Done: If no crash
}

void TC_iot_nv_prov_data_exist_no_prov_data(void **state)
{
    iot_error_t err;
    bool result;
    UNUSED(state);

    // Given: no provisioning data exists
    err = iot_nv_erase(IOT_NVD_WIFI_PROV_STATUS);
    err = iot_nv_erase(IOT_NVD_CLOUD_PROV_STATUS);

    // When: function is called
    result = iot_nv_prov_data_exist();
    // Then: should return false
    assert_false(result);
}

void TC_iot_nv_prov_data_exist_wifi_only(void **state)
{
    iot_error_t err;
    bool result;
    UNUSED(state);

    // Given: only wifi provisioning status is set to DONE
    err = _iot_nv_write_data(IOT_NVD_WIFI_PROV_STATUS, "DONE", strlen("DONE"));
    assert_int_equal(err, IOT_ERROR_NONE);

    err = iot_nv_erase(IOT_NVD_CLOUD_PROV_STATUS);

    // When: function is called
    result = iot_nv_prov_data_exist();
    // Then: should return false
    assert_false(result);

    // Teardown
    err = iot_nv_erase(IOT_NVD_WIFI_PROV_STATUS);
}

void TC_iot_nv_prov_data_exist_cloud_only(void **state)
{
    iot_error_t err;
    bool result;
    UNUSED(state);

    // Given: only cloud provisioning status is set to DONE
    err = iot_nv_erase(IOT_NVD_WIFI_PROV_STATUS);

    err = _iot_nv_write_data(IOT_NVD_CLOUD_PROV_STATUS, "DONE", strlen("DONE"));
    assert_int_equal(err, IOT_ERROR_NONE);

    // When: function is called
    result = iot_nv_prov_data_exist();
    // Then: should return false
    assert_false(result);

    // Teardown
    err = iot_nv_erase(IOT_NVD_CLOUD_PROV_STATUS);
}

void TC_iot_nv_prov_data_exist_both_done(void **state)
{
    iot_error_t err;
    bool result;
    UNUSED(state);

    // Given: both provisioning statuses are set to DONE
    err = _iot_nv_write_data(IOT_NVD_WIFI_PROV_STATUS, "DONE", strlen("DONE"));
    assert_int_equal(err, IOT_ERROR_NONE);

    err = _iot_nv_write_data(IOT_NVD_CLOUD_PROV_STATUS, "DONE", strlen("DONE"));
    assert_int_equal(err, IOT_ERROR_NONE);

    // When: function is called
    result = iot_nv_prov_data_exist();
    // Then: should return true
    assert_true(result);

    // Teardown
    err = iot_nv_erase(IOT_NVD_WIFI_PROV_STATUS);
    err = iot_nv_erase(IOT_NVD_CLOUD_PROV_STATUS);
}

void TC_iot_nv_prov_data_exist_wifi_not_done(void **state)
{
    iot_error_t err;
    bool result;
    UNUSED(state);

    // Given: wifi provisioning status is NONE, cloud is DONE
    err = _iot_nv_write_data(IOT_NVD_WIFI_PROV_STATUS, "NONE", strlen("NONE"));
    assert_int_equal(err, IOT_ERROR_NONE);

    err = _iot_nv_write_data(IOT_NVD_CLOUD_PROV_STATUS, "DONE", strlen("DONE"));
    assert_int_equal(err, IOT_ERROR_NONE);

    // When: function is called
    result = iot_nv_prov_data_exist();
    // Then: should return false
    assert_false(result);

    // Teardown
    err = iot_nv_erase(IOT_NVD_WIFI_PROV_STATUS);
    err = iot_nv_erase(IOT_NVD_CLOUD_PROV_STATUS);
}

void TC_iot_nv_prov_data_exist_cloud_not_done(void **state)
{
    iot_error_t err;
    bool result;
    UNUSED(state);

    // Given: wifi provisioning status is DONE, cloud is NONE
    err = _iot_nv_write_data(IOT_NVD_WIFI_PROV_STATUS, "DONE", strlen("DONE"));
    assert_int_equal(err, IOT_ERROR_NONE);

    err = _iot_nv_write_data(IOT_NVD_CLOUD_PROV_STATUS, "NONE", strlen("NONE"));
    assert_int_equal(err, IOT_ERROR_NONE);

    // When: function is called
    result = iot_nv_prov_data_exist();
    // Then: should return false
    assert_false(result);

    // Teardown
    err = iot_nv_erase(IOT_NVD_WIFI_PROV_STATUS);
    err = iot_nv_erase(IOT_NVD_CLOUD_PROV_STATUS);
}

void TC_iot_nv_get_prov_data_success(void **state)
{
    iot_error_t err;
    struct iot_device_prov_data prov_data;
    UNUSED(state);

    // Given: wifi provisioning data is set
    _setup_wifi_prov_status(DONE);
    _setup_wifi_prov_data(IOT_NVD_AP_SSID);
    _setup_wifi_prov_data(IOT_NVD_AP_PASS);
    _setup_wifi_prov_data(IOT_NVD_AP_BSSID);
    _setup_wifi_prov_data(IOT_NVD_AP_AUTH_TYPE);

    // Given: cloud provisioning data is set
    err = _iot_nv_write_data(IOT_NVD_CLOUD_PROV_STATUS, "DONE", strlen("DONE"));
    assert_int_equal(err, IOT_ERROR_NONE);

    err = _iot_nv_write_data(IOT_NVD_SERVER_URL, "test.example.com", strlen("test.example.com"));
    assert_int_equal(err, IOT_ERROR_NONE);

    err = _iot_nv_write_data(IOT_NVD_SERVER_PORT, "8883", strlen("8883"));
    assert_int_equal(err, IOT_ERROR_NONE);

    err = _iot_nv_write_data(IOT_NVD_LABEL, "Test Device", strlen("Test Device"));
    assert_int_equal(err, IOT_ERROR_NONE);

    // When: function is called
    memset(&prov_data, 0, sizeof(prov_data));
    err = iot_nv_get_prov_data(&prov_data);
    // Then: should succeed
    assert_int_equal(err, IOT_ERROR_NONE);

    // Teardown
    _teardown_wifi_prov_data();
    err = iot_nv_erase(IOT_NVD_CLOUD_PROV_STATUS);
    err = iot_nv_erase(IOT_NVD_SERVER_URL);
    err = iot_nv_erase(IOT_NVD_SERVER_PORT);
    err = iot_nv_erase(IOT_NVD_LABEL);
    if (prov_data.cloud.broker_url)
        free(prov_data.cloud.broker_url);
    if (prov_data.cloud.label)
        free(prov_data.cloud.label);
}

void TC_iot_nv_get_prov_data_null_parameters(void **state)
{
    iot_error_t err;
    UNUSED(state);

    // When: function is called with NULL parameter
    err = iot_nv_get_prov_data(NULL);
    // Then: should return error
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_nv_get_prov_data_wifi_fail(void **state)
{
    iot_error_t err;
    struct iot_device_prov_data prov_data;
    UNUSED(state);

    // Given: cloud provisioning data is set but not wifi
    err = _iot_nv_write_data(IOT_NVD_CLOUD_PROV_STATUS, "DONE", strlen("DONE"));
    assert_int_equal(err, IOT_ERROR_NONE);

    // When: function is called
    memset(&prov_data, 0, sizeof(prov_data));
    err = iot_nv_get_prov_data(&prov_data);
    // Then: should return error
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Teardown
    err = iot_nv_erase(IOT_NVD_CLOUD_PROV_STATUS);
}

void TC_iot_nv_get_prov_data_cloud_fail(void **state)
{
    iot_error_t err;
    struct iot_device_prov_data prov_data;
    UNUSED(state);

    // Given: wifi provisioning data is set but not cloud
    _setup_wifi_prov_status(DONE);
    _setup_wifi_prov_data(IOT_NVD_AP_SSID);
    _setup_wifi_prov_data(IOT_NVD_AP_PASS);
    _setup_wifi_prov_data(IOT_NVD_AP_BSSID);
    _setup_wifi_prov_data(IOT_NVD_AP_AUTH_TYPE);

    // When: function is called
    memset(&prov_data, 0, sizeof(prov_data));
    err = iot_nv_get_prov_data(&prov_data);
    // Then: should return error
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Teardown
    _teardown_wifi_prov_data();
}

void TC_iot_nv_set_prov_data_success(void **state)
{
    iot_error_t err;
    struct iot_device_prov_data prov_data;
    UNUSED(state);

    // Given: provisioning data is prepared
    memset(&prov_data, 0, sizeof(prov_data));

    // Wifi data
    strncpy(prov_data.wifi.ssid, sample_wifi_ssid, IOT_WIFI_PROV_SSID_STR_LEN);
    strncpy(prov_data.wifi.password, sample_wifi_password, IOT_WIFI_PROV_PASSWORD_STR_LEN);
    strncpy(prov_data.wifi.mac_str, sample_wifi_bssid_str, IOT_WIFI_PROV_MAC_STR_LEN);
    prov_data.wifi.security_type = sample_security_type;

    // Cloud data
    prov_data.cloud.broker_url = "test.example.com";
    prov_data.cloud.broker_port = 8883;
    prov_data.cloud.label = "Test Device";

    // When: function is called
    err = iot_nv_set_prov_data(&prov_data);
    // Then: should succeed
    assert_int_equal(err, IOT_ERROR_NONE);

    // Teardown
    err = iot_nv_erase(IOT_NVD_WIFI_PROV_STATUS);
    err = iot_nv_erase(IOT_NVD_AP_SSID);
    err = iot_nv_erase(IOT_NVD_AP_PASS);
    err = iot_nv_erase(IOT_NVD_AP_BSSID);
    err = iot_nv_erase(IOT_NVD_AP_AUTH_TYPE);
    err = iot_nv_erase(IOT_NVD_CLOUD_PROV_STATUS);
    err = iot_nv_erase(IOT_NVD_SERVER_URL);
    err = iot_nv_erase(IOT_NVD_SERVER_PORT);
    err = iot_nv_erase(IOT_NVD_LABEL);
}

void TC_iot_nv_set_prov_data_null_parameters(void **state)
{
    iot_error_t err;
    UNUSED(state);

    // When: function is called with NULL parameter
    err = iot_nv_set_prov_data(NULL);
    // Then: should return error
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_nv_erase_prov_data_success(void **state)
{
    iot_error_t err;
    UNUSED(state);

    // Given: provisioning data exists
    err = _iot_nv_write_data(IOT_NVD_WIFI_PROV_STATUS, "DONE", strlen("DONE"));
    assert_int_equal(err, IOT_ERROR_NONE);

    err = _iot_nv_write_data(IOT_NVD_CLOUD_PROV_STATUS, "DONE", strlen("DONE"));
    assert_int_equal(err, IOT_ERROR_NONE);

    // When: function is called
    err = iot_nv_erase_prov_data();
    // Then: should succeed
    assert_int_equal(err, IOT_ERROR_NONE);

    // Then: verify data is erased
    char status[5];
    err = _iot_nv_read_data(IOT_NVD_WIFI_PROV_STATUS, status, sizeof(status) - 1, NULL);
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_string_equal(status, "NONE");

    err = _iot_nv_read_data(IOT_NVD_CLOUD_PROV_STATUS, status, sizeof(status) - 1, NULL);
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_string_equal(status, "NONE");
}

void TC_iot_nv_set_wifi_prov_data_success(void **state)
{
    iot_error_t err;
    struct iot_wifi_prov_data wifi_prov;
    UNUSED(state);

    // Given: wifi provisioning data is prepared
    memset(&wifi_prov, 0, sizeof(wifi_prov));
    strncpy(wifi_prov.ssid, sample_wifi_ssid, IOT_WIFI_PROV_SSID_STR_LEN);
    strncpy(wifi_prov.password, sample_wifi_password, IOT_WIFI_PROV_PASSWORD_STR_LEN);
    strncpy(wifi_prov.mac_str, sample_wifi_bssid_str, IOT_WIFI_PROV_MAC_STR_LEN);
    wifi_prov.security_type = sample_security_type;

    // When: function is called
    err = iot_nv_set_wifi_prov_data(&wifi_prov);
    // Then: should succeed
    assert_int_equal(err, IOT_ERROR_NONE);

    // Then: verify data was written
    struct iot_wifi_prov_data read_wifi_prov;
    memset(&read_wifi_prov, 0, sizeof(read_wifi_prov));
    err = iot_nv_get_wifi_prov_data(&read_wifi_prov);
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_string_equal(read_wifi_prov.ssid, sample_wifi_ssid);
    assert_string_equal(read_wifi_prov.password, sample_wifi_password);
    assert_string_equal(read_wifi_prov.mac_str, sample_wifi_bssid_str);
    assert_int_equal(read_wifi_prov.security_type, sample_security_type);

    // Teardown
    _teardown_wifi_prov_data();
}

void TC_iot_nv_set_wifi_prov_data_null_parameters(void **state)
{
    iot_error_t err;
    UNUSED(state);

    // When: function is called with NULL parameter
    err = iot_nv_set_wifi_prov_data(NULL);
    // Then: should return error
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_nv_set_wifi_prov_data_empty_ssid(void **state)
{
    iot_error_t err;
    struct iot_wifi_prov_data wifi_prov;
    UNUSED(state);

    // Given: wifi provisioning data with empty SSID
    memset(&wifi_prov, 0, sizeof(wifi_prov));
    wifi_prov.ssid[0] = '\0';  // Empty SSID
    strncpy(wifi_prov.password, sample_wifi_password, IOT_WIFI_PROV_PASSWORD_STR_LEN);
    strncpy(wifi_prov.mac_str, sample_wifi_bssid_str, IOT_WIFI_PROV_MAC_STR_LEN);
    wifi_prov.security_type = sample_security_type;

    // When: function is called
    err = iot_nv_set_wifi_prov_data(&wifi_prov);
    // Then: should succeed
    assert_int_equal(err, IOT_ERROR_NONE);

    // Teardown
    _teardown_wifi_prov_data();
}

void TC_iot_nv_set_wifi_prov_data_empty_password(void **state)
{
    iot_error_t err;
    struct iot_wifi_prov_data wifi_prov;
    UNUSED(state);

    // Given: wifi provisioning data with empty password
    memset(&wifi_prov, 0, sizeof(wifi_prov));
    strncpy(wifi_prov.ssid, sample_wifi_ssid, IOT_WIFI_PROV_SSID_STR_LEN);
    wifi_prov.password[0] = '\0';  // Empty password
    strncpy(wifi_prov.mac_str, sample_wifi_bssid_str, IOT_WIFI_PROV_MAC_STR_LEN);
    wifi_prov.security_type = sample_security_type;

    // When: function is called
    err = iot_nv_set_wifi_prov_data(&wifi_prov);
    // Then: should succeed
    assert_int_equal(err, IOT_ERROR_NONE);

    // Teardown
    _teardown_wifi_prov_data();
}

void TC_iot_nv_set_wifi_prov_data_empty_bssid(void **state)
{
    iot_error_t err;
    struct iot_wifi_prov_data wifi_prov;
    UNUSED(state);

    // Given: wifi provisioning data with empty BSSID
    memset(&wifi_prov, 0, sizeof(wifi_prov));
    strncpy(wifi_prov.ssid, sample_wifi_ssid, IOT_WIFI_PROV_SSID_STR_LEN);
    strncpy(wifi_prov.password, sample_wifi_password, IOT_WIFI_PROV_PASSWORD_STR_LEN);
    wifi_prov.mac_str[0] = '\0';  // Empty BSSID
    wifi_prov.security_type = sample_security_type;

    // When: function is called
    err = iot_nv_set_wifi_prov_data(&wifi_prov);
    // Then: should succeed
    assert_int_equal(err, IOT_ERROR_NONE);

    // Teardown
    _teardown_wifi_prov_data();
}

void TC_iot_nv_set_wifi_prov_data_invalid_security_type(void **state)
{
    iot_error_t err;
    struct iot_wifi_prov_data wifi_prov;
    UNUSED(state);

    // Given: wifi provisioning data with invalid security type
    memset(&wifi_prov, 0, sizeof(wifi_prov));
    strncpy(wifi_prov.ssid, sample_wifi_ssid, IOT_WIFI_PROV_SSID_STR_LEN);
    strncpy(wifi_prov.password, sample_wifi_password, IOT_WIFI_PROV_PASSWORD_STR_LEN);
    strncpy(wifi_prov.mac_str, sample_wifi_bssid_str, IOT_WIFI_PROV_MAC_STR_LEN);
    wifi_prov.security_type = IOT_WIFI_AUTH_MAX + 1;  // Invalid security type

    // When: function is called
    err = iot_nv_set_wifi_prov_data(&wifi_prov);
    // Then: should succeed
    assert_int_equal(err, IOT_ERROR_NONE);

    // Teardown
    _teardown_wifi_prov_data();
}

void TC_iot_nv_get_cloud_prov_data_success(void **state)
{
    iot_error_t err;
    struct iot_cloud_prov_data cloud_prov;
    UNUSED(state);

    // Given: cloud provisioning data is set
    err = _iot_nv_write_data(IOT_NVD_CLOUD_PROV_STATUS, "DONE", strlen("DONE"));
    assert_int_equal(err, IOT_ERROR_NONE);

    err = _iot_nv_write_data(IOT_NVD_SERVER_URL, "test.example.com", strlen("test.example.com"));
    assert_int_equal(err, IOT_ERROR_NONE);

    err = _iot_nv_write_data(IOT_NVD_SERVER_PORT, "8883", strlen("8883"));
    assert_int_equal(err, IOT_ERROR_NONE);

    err = _iot_nv_write_data(IOT_NVD_LABEL, "Test Device", strlen("Test Device"));
    assert_int_equal(err, IOT_ERROR_NONE);

    // When: function is called
    memset(&cloud_prov, 0, sizeof(cloud_prov));
    err = iot_nv_get_cloud_prov_data(&cloud_prov);
    // Then: should succeed
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(cloud_prov.broker_url);
    assert_string_equal(cloud_prov.broker_url, "test.example.com");
    assert_int_equal(cloud_prov.broker_port, 8883);
    assert_non_null(cloud_prov.label);
    assert_string_equal(cloud_prov.label, "Test Device");

    // Teardown
    err = iot_nv_erase(IOT_NVD_CLOUD_PROV_STATUS);
    err = iot_nv_erase(IOT_NVD_SERVER_URL);
    err = iot_nv_erase(IOT_NVD_SERVER_PORT);
    err = iot_nv_erase(IOT_NVD_LABEL);
    if (cloud_prov.broker_url)
        free(cloud_prov.broker_url);
    if (cloud_prov.label)
        free(cloud_prov.label);
}

void TC_iot_nv_get_cloud_prov_data_null_parameters(void **state)
{
    iot_error_t err;
    UNUSED(state);

    // When: function is called with NULL parameter
    err = iot_nv_get_cloud_prov_data(NULL);
    // Then: should return error
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_nv_get_cloud_prov_data_no_status(void **state)
{
    iot_error_t err;
    struct iot_cloud_prov_data cloud_prov;
    UNUSED(state);

    // Given: cloud provisioning status is erased
    err = iot_nv_erase(IOT_NVD_CLOUD_PROV_STATUS);

    // When: function is called
    memset(&cloud_prov, 0, sizeof(cloud_prov));
    err = iot_nv_get_cloud_prov_data(&cloud_prov);
    // Then: should return error
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_nv_get_cloud_prov_data_status_not_done(void **state)
{
    iot_error_t err;
    struct iot_cloud_prov_data cloud_prov;
    UNUSED(state);

    // Given: cloud provisioning status is set to NONE
    err = _iot_nv_write_data(IOT_NVD_CLOUD_PROV_STATUS, "NONE", strlen("NONE"));
    assert_int_equal(err, IOT_ERROR_NONE);

    // When: function is called
    memset(&cloud_prov, 0, sizeof(cloud_prov));
    err = iot_nv_get_cloud_prov_data(&cloud_prov);
    // Then: should return error
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Teardown
    err = iot_nv_erase(IOT_NVD_CLOUD_PROV_STATUS);
}

void TC_iot_nv_get_cloud_prov_data_no_url(void **state)
{
    iot_error_t err;
    struct iot_cloud_prov_data cloud_prov;
    UNUSED(state);

    // Given: cloud provisioning status is DONE but no URL
    err = _iot_nv_write_data(IOT_NVD_CLOUD_PROV_STATUS, "DONE", strlen("DONE"));
    assert_int_equal(err, IOT_ERROR_NONE);

    // When: function is called
    memset(&cloud_prov, 0, sizeof(cloud_prov));
    err = iot_nv_get_cloud_prov_data(&cloud_prov);
    // Then: should succeed but with NULL values
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_null(cloud_prov.broker_url);
    assert_int_equal(cloud_prov.broker_port, -1);
    assert_null(cloud_prov.label);

    // Teardown
    err = iot_nv_erase(IOT_NVD_CLOUD_PROV_STATUS);
}

void TC_iot_nv_set_cloud_prov_data_success(void **state)
{
    iot_error_t err;
    struct iot_cloud_prov_data cloud_prov;
    UNUSED(state);

    // Given: cloud provisioning data is prepared
    memset(&cloud_prov, 0, sizeof(cloud_prov));
    cloud_prov.broker_url = "test.example.com";
    cloud_prov.broker_port = 8883;
    cloud_prov.label = "Test Device";

    // When: function is called
    err = iot_nv_set_cloud_prov_data(&cloud_prov);
    // Then: should succeed
    assert_int_equal(err, IOT_ERROR_NONE);

    // Teardown
    err = iot_nv_erase(IOT_NVD_CLOUD_PROV_STATUS);
    err = iot_nv_erase(IOT_NVD_SERVER_URL);
    err = iot_nv_erase(IOT_NVD_SERVER_PORT);
    err = iot_nv_erase(IOT_NVD_LABEL);
}

void TC_iot_nv_set_cloud_prov_data_null_parameters(void **state)
{
    iot_error_t err;
    UNUSED(state);

    // When: function is called with NULL parameter
    err = iot_nv_set_cloud_prov_data(NULL);
    // Then: should return error
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_nv_set_cloud_prov_data_null_url(void **state)
{
    iot_error_t err;
    struct iot_cloud_prov_data cloud_prov;
    UNUSED(state);

    // Given: cloud provisioning data with NULL URL
    memset(&cloud_prov, 0, sizeof(cloud_prov));
    cloud_prov.broker_url = NULL;
    cloud_prov.broker_port = 8883;
    cloud_prov.label = "Test Device";

    // When: function is called
    err = iot_nv_set_cloud_prov_data(&cloud_prov);
    // Then: should succeed
    assert_int_equal(err, IOT_ERROR_NONE);

    // Teardown
    err = iot_nv_erase(IOT_NVD_CLOUD_PROV_STATUS);
    err = iot_nv_erase(IOT_NVD_SERVER_PORT);
    err = iot_nv_erase(IOT_NVD_LABEL);
}

void TC_iot_nv_set_cloud_prov_data_null_label(void **state)
{
    iot_error_t err;
    struct iot_cloud_prov_data cloud_prov;
    UNUSED(state);

    // Given: cloud provisioning data with NULL label
    memset(&cloud_prov, 0, sizeof(cloud_prov));
    cloud_prov.broker_url = "test.example.com";
    cloud_prov.broker_port = 8883;
    cloud_prov.label = NULL;

    // When: function is called
    err = iot_nv_set_cloud_prov_data(&cloud_prov);
    // Then: should succeed
    assert_int_equal(err, IOT_ERROR_NONE);

    // Teardown
    err = iot_nv_erase(IOT_NVD_CLOUD_PROV_STATUS);
    err = iot_nv_erase(IOT_NVD_SERVER_URL);
    err = iot_nv_erase(IOT_NVD_SERVER_PORT);
}

void TC_iot_nv_set_device_id_success(void **state)
{
    iot_error_t err;
    const char *test_device_id = "12345678-1234-1234-1234-123456789012";
    UNUSED(state);

    // When
    err = iot_nv_set_device_id(test_device_id);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);

    // Verify data was written
    char *read_device_id;
    size_t len;
    err = iot_nv_get_device_id(&read_device_id, &len);
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_string_equal(read_device_id, test_device_id);
    assert_int_equal(len, strlen(test_device_id));

    // Teardown
    free(read_device_id);
    err = iot_nv_erase(IOT_NVD_DEVICE_ID);
}

void TC_iot_nv_set_device_id_null_parameters(void **state)
{
    iot_error_t err;
    UNUSED(state);

    // When
    err = iot_nv_set_device_id(NULL);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_nv_get_misc_info_success(void **state)
{
    iot_error_t err;
    char *misc_info = NULL;
    size_t len = 0;
    const char *test_misc_info = "Test miscellaneous info";
    UNUSED(state);

    // Given: misc info is set
    err = _iot_nv_write_data(IOT_NVD_MISC_INFO, test_misc_info, strlen(test_misc_info));
    assert_int_equal(err, IOT_ERROR_NONE);

    // When
    err = iot_nv_get_misc_info(&misc_info, &len);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(misc_info);
    assert_string_equal(misc_info, test_misc_info);
    assert_int_equal(len, strlen(test_misc_info));

    // Teardown
    free(misc_info);
    err = iot_nv_erase(IOT_NVD_MISC_INFO);
}

void TC_iot_nv_get_misc_info_null_parameters(void **state)
{
    iot_error_t err;
    char *misc_info = NULL;
    size_t len = 0;
    UNUSED(state);

    // When: All parameters null
    err = iot_nv_get_misc_info(NULL, NULL);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // When: misc_info is null
    err = iot_nv_get_misc_info(NULL, &len);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    assert_int_equal(len, 0);

    // When: len is null
    err = iot_nv_get_misc_info(&misc_info, NULL);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    assert_null(misc_info);
}

void TC_iot_nv_get_misc_info_not_exist(void **state)
{
    iot_error_t err;
    char *misc_info = NULL;
    size_t len = 0;
    UNUSED(state);

    // Given: no misc info exists
    err = iot_nv_erase(IOT_NVD_MISC_INFO);

    // When
    err = iot_nv_get_misc_info(&misc_info, &len);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_nv_set_misc_info_success(void **state)
{
    iot_error_t err;
    const char *test_misc_info = "Test miscellaneous info";
    UNUSED(state);

    // When
    err = iot_nv_set_misc_info(test_misc_info);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);

    // Teardown
    err = iot_nv_erase(IOT_NVD_MISC_INFO);
}

void TC_iot_nv_set_misc_info_null_parameters(void **state)
{
    iot_error_t err;
    UNUSED(state);

    // When
    err = iot_nv_set_misc_info(NULL);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_nv_get_static_certificate_success(void **state)
{
    iot_error_t err;
    iot_security_buffer_t output_buf;
    UNUSED(state);

    // When
    err = iot_nv_get_static_certificate(IOT_SECURITY_CERT_ID_ROOT_CA, &output_buf);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(output_buf.p);
    assert_int_not_equal(output_buf.len, 0);

    // Teardown
    iot_os_free(output_buf.p);
}

void TC_iot_nv_get_static_certificate_null_parameters(void **state)
{
    iot_error_t err;
    UNUSED(state);

    // When: output_buf is null
    err = iot_nv_get_static_certificate(IOT_SECURITY_CERT_ID_ROOT_CA, NULL);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_nv_get_static_certificate_invalid_cert_id(void **state)
{
    iot_error_t err;
    iot_security_buffer_t output_buf;
    UNUSED(state);

    // When: invalid cert_id
    err = iot_nv_get_static_certificate(IOT_SECURITY_CERT_ID_MAX, &output_buf);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

#define SECURITY_TYPE_MAX 10

static void _setup_wifi_prov_status(wifi_status_cmd_t cmd)
{
    iot_error_t err;

    if (cmd == NONE) {
        err = _iot_nv_write_data(IOT_NVD_WIFI_PROV_STATUS, "NONE", strlen("NONE"));
        assert_int_equal(err, IOT_ERROR_NONE);
    } else if (cmd == DONE) {
        err = _iot_nv_write_data(IOT_NVD_WIFI_PROV_STATUS, "DONE", strlen("DONE"));
        assert_int_equal(err, IOT_ERROR_NONE);
    }
}

static void _setup_wifi_prov_data(iot_nvd_t nv_type)
{
    iot_error_t err;
    char data[SECURITY_TYPE_MAX] = {
        0,
    };

    switch (nv_type) {
        case IOT_NVD_AP_SSID: {
            err = _iot_nv_write_data(IOT_NVD_AP_SSID, sample_wifi_ssid, strlen(sample_wifi_ssid));
            assert_int_equal(err, IOT_ERROR_NONE);
            break;
        }
        case IOT_NVD_AP_PASS: {
            err = _iot_nv_write_data(IOT_NVD_AP_PASS, sample_wifi_password, strlen(sample_wifi_password));
            assert_int_equal(err, IOT_ERROR_NONE);
            break;
        }
        case IOT_NVD_AP_BSSID: {
            err = iot_util_convert_str_mac((char *)sample_wifi_bssid_str, &sample_wifi_bssid);
            assert_int_equal(err, IOT_ERROR_NONE);

            err = _iot_nv_write_data(IOT_NVD_AP_BSSID, sample_wifi_bssid_str, strlen(sample_wifi_bssid_str));
            assert_int_equal(err, IOT_ERROR_NONE);
            break;
        }
        case IOT_NVD_AP_AUTH_TYPE: {
            int size = snprintf(data, SECURITY_TYPE_MAX, "%d", sample_security_type);
            data[size] = '\0';

            err = _iot_nv_write_data(IOT_NVD_AP_AUTH_TYPE, data, size);
            assert_int_equal(err, IOT_ERROR_NONE);
            break;
        }
        default:
            break;
    }
}

static void _teardown_wifi_prov_data()
{
    iot_error_t err;

    err = iot_nv_erase(IOT_NVD_WIFI_PROV_STATUS);
    err = iot_nv_erase(IOT_NVD_AP_SSID);
    err = iot_nv_erase(IOT_NVD_AP_PASS);
    err = iot_nv_erase(IOT_NVD_AP_BSSID);
    err = iot_nv_erase(IOT_NVD_AP_AUTH_TYPE);
}
