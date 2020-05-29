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
#include <iot_nv_data.h>
#include <certs/root_ca.h>
#include <string.h>
#include <iot_util.h>
#include <bsp/iot_bsp_nv_data.h>
#include "TC_MOCK_functions.h"
#define UNUSED(x) (void**)(x)

typedef enum {
    NONE,
    DONE
} wifi_status_cmd_t;

#define SAMPLE_PUBLIC_KEY	"BKb7+m1Mo8OuMsodM91ohz/+rZKDc/otzUPSn4UkCUk="

static char sample_device_info[] = {
        "{\n"
        "\t\"deviceInfo\": {\n"
        "\t\t\"firmwareVersion\": \"testFirmwareVersion\",\n"
        "\t\t\"privateKey\": \"ztqmQ24u86J9bpFLjaoMfwauUZwKLjUIGsnrDwwnDM8=\",\n"
        "\t\t\"publicKey\": \"" SAMPLE_PUBLIC_KEY "\",\n"
        "\t\t\"serialNumber\": \"STDKtESt7968d226\"\n"
        "\t}\n"
        "}"
};

static const char *sample_wifi_ssid = "fakeSsid_04_XXXXXX";
static const char *sample_wifi_password = "fakePassword1";
static struct iot_mac sample_wifi_bssid;
static char sample_bssid[] = "42:32:43:54:65:76";
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
    //Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_memory_equal(wifi_prov->ssid, sample_wifi_ssid, strlen(sample_wifi_ssid));
    assert_memory_equal(wifi_prov->password, sample_wifi_password, strlen(sample_wifi_password));
    assert_memory_equal(wifi_prov->bssid.addr, sample_wifi_bssid.addr, IOT_WIFI_MAX_BSSID_LEN);
    assert_int_equal(wifi_prov->security_type, sample_security_type);

    // Local teardown
    _teardown_wifi_prov_data();


    // Given : Status done only
    _setup_wifi_prov_status(DONE);

    memset(wifi_prov, 0, sizeof(struct iot_wifi_prov_data));

    // When
    err = iot_nv_get_wifi_prov_data(wifi_prov);
    //Then
    assert_int_equal(err, IOT_ERROR_NV_DATA_ERROR);

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
    //Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_nv_get_root_certificate_success(void **state)
{
    iot_error_t err;
    char *root_cert = NULL;
    size_t root_cert_len = 0;
    UNUSED(state);

    // When
    err = iot_nv_get_root_certificate(&root_cert, &root_cert_len);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_memory_equal(root_cert, st_root_ca, st_root_ca_len);
    assert_int_equal(root_cert_len, st_root_ca_len);

    // Local teardown
    free(root_cert);
}

void TC_iot_nv_get_root_certificate_null_parameters(void **state)
{
    iot_error_t err;
    char *root_cert = NULL;
    size_t root_cert_len = 0;
    UNUSED(state);

    // When: All null parameters
    err = iot_nv_get_root_certificate(NULL, NULL);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // When: len is null
    err = iot_nv_get_root_certificate(&root_cert, NULL);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    assert_null(root_cert);

    // When: cert is null
    err = iot_nv_get_root_certificate(NULL, &root_cert_len);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    assert_int_equal(root_cert_len, 0);
}

void TC_iot_nv_get_root_certificate_internal_failure(void **state)
{
    iot_error_t err;
    char *root_cert = NULL;
    size_t root_cert_len = 0;
    UNUSED(state);

    // Given: malloc failed
    set_mock_iot_os_malloc_failure();
    // When
    err = iot_nv_get_root_certificate(&root_cert, &root_cert_len);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Local teardown
    free(root_cert);
}

void TC_iot_nv_get_client_certificate_null_parameters(void **state)
{
    iot_error_t err;
    char *client_cert = NULL;
    size_t client_cert_len = 0;
    UNUSED(state);

    // When: All null parameters
    err = iot_nv_get_client_certificate(NULL, NULL);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // When: len is null
    err = iot_nv_get_client_certificate(&client_cert, NULL);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    assert_null(client_cert);

    // When: cert is null
    err = iot_nv_get_client_certificate(NULL, &client_cert_len);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    assert_int_equal(client_cert_len, 0);
}

void TC_iot_nv_get_public_key_success(void **state)
{
    iot_error_t err;
    char *public_key = NULL;
    size_t public_key_len = 0;
    const char *sample_public_key = "BKb7+m1Mo8OuMsodM91ohz/+rZKDc/otzUPSn4UkCUk=";
    UNUSED(state);

    // When
    err = iot_nv_get_public_key(&public_key, &public_key_len);
    //Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_memory_equal(public_key, sample_public_key, strlen(sample_public_key));
    assert_int_equal(public_key_len, strlen(sample_public_key));

    // Local teardown
    free(public_key);
}

void TC_iot_nv_get_public_key_null_parameters(void **state)
{
    iot_error_t err;
    char *public_key = NULL;
    size_t public_key_len = 0;
    UNUSED(state);

    // When: All parameters null
    err = iot_nv_get_public_key(NULL, NULL);
    //Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // When: Key is null
    err = iot_nv_get_public_key(NULL, &public_key_len);
    //Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    assert_int_equal(public_key_len, 0);

    // When: Len is null
    err = iot_nv_get_public_key(&public_key, NULL);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    assert_int_equal(public_key_len, 0);
    assert_null(public_key);
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
    //Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // When: Key is null
    err = iot_nv_get_serial_number(NULL, &serial_number_len);
    //Then
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

void TC_iot_nv_erase_internal_failure(void** state)
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

void TC_iot_nv_get_data_from_device_info_failure(void** state)
{
	iot_error_t err;
	iot_security_buffer_t buf;
	iot_nvd_t nv_id;

	// When: null
	err = iot_nv_get_data_from_device_info(nv_id, NULL);
	// Then
	assert_int_equal(err, IOT_ERROR_INVALID_ARGS);

	// Given: id not in device info
	nv_id = IOT_NVD_ROOM_ID;
	// When
	err = iot_nv_get_data_from_device_info(nv_id, &buf);
	// Then
	assert_int_equal(err, IOT_ERROR_NV_DATA_ERROR);
}

void TC_iot_nv_get_data_from_device_info_success(void** state)
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

#define SECURITY_TYPE_MAX 10
extern iot_error_t _iot_nv_write_data(const char* path, const char* data, size_t size);

static void _setup_wifi_prov_status(wifi_status_cmd_t cmd)
{
    iot_error_t err;

    if (cmd == NONE) {
        err = _iot_nv_write_data(iot_bsp_nv_get_data_path(IOT_NVD_WIFI_PROV_STATUS), "NONE", strlen("NONE"));
        assert_int_equal(err, IOT_ERROR_NONE);
    } else if (cmd == DONE) {
        err = _iot_nv_write_data(iot_bsp_nv_get_data_path(IOT_NVD_WIFI_PROV_STATUS), "DONE", strlen("DONE"));
        assert_int_equal(err, IOT_ERROR_NONE);
    }
}

static void _setup_wifi_prov_data(iot_nvd_t nv_type)
{
    iot_error_t err;
    char data[SECURITY_TYPE_MAX] = {0,};

    switch (nv_type) {
        case IOT_NVD_AP_SSID: {
            err = _iot_nv_write_data(iot_bsp_nv_get_data_path(IOT_NVD_AP_SSID), sample_wifi_ssid,
                                     strlen(sample_wifi_ssid));
            assert_int_equal(err, IOT_ERROR_NONE);
            break;
        }
        case IOT_NVD_AP_PASS: {
            err = _iot_nv_write_data(iot_bsp_nv_get_data_path(IOT_NVD_AP_PASS), sample_wifi_password,
                                     strlen(sample_wifi_password));
            assert_int_equal(err, IOT_ERROR_NONE);
            break;
        }
        case IOT_NVD_AP_BSSID: {
            err = iot_util_convert_str_mac(sample_bssid, &sample_wifi_bssid);
            assert_int_equal(err, IOT_ERROR_NONE);

            err = _iot_nv_write_data(iot_bsp_nv_get_data_path(IOT_NVD_AP_BSSID), sample_wifi_bssid.addr,
                                     strlen(sample_wifi_bssid.addr));
            assert_int_equal(err, IOT_ERROR_NONE);
            break;
        }
        case IOT_NVD_AP_AUTH_TYPE: {
            int size = snprintf(data, SECURITY_TYPE_MAX, "%d", sample_security_type);
            data[size] = '\0';

            err = _iot_nv_write_data(iot_bsp_nv_get_data_path(IOT_NVD_AP_AUTH_TYPE), data, size);
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
