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
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <iot_error.h>
#include <iot_nv_data.h>
#include <bsp/iot_bsp_random.h>
#include <security/iot_security_crypto.h>

#include "TC_MOCK_functions.h"

#if defined(CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_ED25519)
static char sample_device_info[] = {
	"{\n"
	"\t\"deviceInfo\": {\n"
	"\t\t\"firmwareVersion\": \"testFirmwareVersion\",\n"
	"\t\t\"privateKey\": \"y04i7Pme6rJTkLBPngQoZfEI5KEAyE70A9xOhoX8uTI=\",\n"
	"\t\t\"publicKey\": \"Sh4cBHRnPuEFyinaVuEd+mE5IQTkwPHmbOrgD3fwPsw=\",\n"
	"\t\t\"serialNumber\": \"STDKtestc77078cc\"\n"
	"\t}\n"
	"}"
};
#elif defined(CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_RSA)
#define TEST_RSA_PRIVATE_KEY \
"-----BEGIN RSA PRIVATE KEY-----\r\n" \
"MIIEpAIBAAKCAQEA1/1kys9cGjIhdbQ96GeuVhC8AsTzxVHxGxLghS2UkLJ3lsbj\r\n" \
"v1L1D24Re+Unn57I8Ib+QwfhdmFpD8UpBl2n7ndFOcf3VLpm59pQ29Fim1k8VLva\r\n" \
"epLYDRGF27vf/5LgG4lg2o5HOFhUs5kTLs5LWplaJlCmFu3EyfBE7d5wcuxLAImF\r\n" \
"UamlnIzVPo1HKsvO1h+pMiP8dAAiDnI/1Ul0lJjuLay4P1w6WgjtWqMvK8QTF7wQ\r\n" \
"iGE9HWsMT/zC4Fs10ct3fnX7HAUV78mxjppTOWdrzeBEcqb7psRFPVQbsAu5q4Qx\r\n" \
"7j3u9eM+TsNOdF2yd7LpSaJ1R1lYSf/tuxPXIQIDAQABAoIBAQCZiwQk/OYPpUWO\r\n" \
"BDTiSxpvCnRtT4+v3UGWKoQ7iJyNhKFpKThsIVAeyPNa7RuO6HUWMBD+m9KWskba\r\n" \
"tCEm6ltgNZ+bpODZda2D8vn6Wk5L+1LdNbHp4wv9tlA/Vb62U7ZHPRECLZTJpFmK\r\n" \
"Vy6A3pxI6q1ggYKg2CRGHi0SIEg2GSATy/heFUbxaF4nwj4v6ju0YxFiGrd54VDb\r\n" \
"1HkZZiV22rbPh1hdJeuU8C/pIsCfDjY5VQ7DUh07trZQ8BZWbfiNPRFpmB4mmTOg\r\n" \
"F7JKuar6IWUD4uYvtt1qwgrnn/+YJlZShwwrJiJ+bAK+WRp/PF1IO1b+vh0fbXNw\r\n" \
"Uepdzbd1AoGBAO9NWUouNKNR6rsv7xYSjhEjM2OipWNDvWqYKJzPDQw/7+sdD2Os\r\n" \
"PkPbdbtRYx5DdeFB7QbQF69b+svssPRoi+IUhlE3VTlkoLp1jfGeQ6LUWvnK3OSF\r\n" \
"/aReQKM3fON45Gxzem9dZ5P3hU3IFD++viHvlwbYn2bXpgNS0t+nnYvXAoGBAOcP\r\n" \
"nf7TnmP96vMU1JdXmDdJJ1TsVzJyppCvHRiLKo+dCwJWlztOfXyrLvslbgPwzSmw\r\n" \
"Vna4JScaAqrY4ka29IFjtLxM459PItitHTDUEVtGZAhZfeM/i7ChuehQnBrM9zri\r\n" \
"H7xSkWLMe1pFz/YmrOAyyAVPtmX6Om9K69PFiJXHAoGBAMu2PuKlPu4hV/+NqKxT\r\n" \
"k1kHbEHPPZepHOBXM4t5vxPEggrWLDmfcUn20txpRkWHDBx8MLjyAJepZ3Cdx23o\r\n" \
"adxFuKn+vrAi96iDVhhvsAg3WlL23OA1KFz6V3AaVliWm22vSHTxQLF3rqUuQ/6X\r\n" \
"8+eTvC95zQiRX6PIp/b5C2b1AoGACRigS6vhDGaunSsww1R7dZG3rqwvMpk43XFH\r\n" \
"X/P6lPTFvi3Sfk80uXezvcdXcWhFa2K5xKqzK7rmZ/tpzQbe0UkvkEomm9rtsEIA\r\n" \
"aC+xDzrSLVH4lr2lripvuymRO6zd/r9wKGXHu2/5WzBsY3BaVekp3quorpMPQdpd\r\n" \
"NlUMb3kCgYB7o0KEvx3gGuAOqr7rkLduvq6KHt29mBr9+aGcxe54npiiTgMUQvuz\r\n" \
"NaAMmtShsr5lcaTl/vrKSWFeRGVuzp92bhgHVKc12muBr7QfaOZfZfvZ8ht1PosT\r\n" \
"Bw+wAUXFJuTmYky9uk5RBI5QiaKjS3jAs64oFcUihVcy3zTnVQmXTg==\r\n" \
"-----END RSA PRIVATE KEY-----"

#define TEST_RSA_CERTIFICATE \
"-----BEGIN CERTIFICATE-----\r\n" \
"MIID0jCCArqgAwIBAgIJAOmRaXeUY/lXMA0GCSqGSIb3DQEBCwUAMHMxCzAJBgNV\r\n" \
"BAYTAktSMR8wHQYDVQQKDBZTbWFydFRoaW5ncyBEZXZpY2UgU0RLMRUwEwYDVQQL\r\n" \
"DAxNUVRUIFJvb3QgQ0ExLDAqBgNVBAMMI1NtYXJ0VGhpbmdzIERldmljZSBTREsg\r\n" \
"Um9vdCBDQSBURVNUMCAXDTIwMDMxOTA5MDkzMVoYDzIwNjAwMzA5MDkwOTMxWjBh\r\n" \
"MQswCQYDVQQGEwJLUjEfMB0GA1UECgwWU21hcnRUaGluZ3MgRGV2aWNlIFNESzEU\r\n" \
"MBIGA1UECwwLTVFUVCBEZXZpY2UxGzAZBgNVBAMMElNtYXJ0VGhpbmdzIERldmlj\r\n" \
"ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANf9ZMrPXBoyIXW0Pehn\r\n" \
"rlYQvALE88VR8RsS4IUtlJCyd5bG479S9Q9uEXvlJ5+eyPCG/kMH4XZhaQ/FKQZd\r\n" \
"p+53RTnH91S6ZufaUNvRYptZPFS72nqS2A0Rhdu73/+S4BuJYNqORzhYVLOZEy7O\r\n" \
"S1qZWiZQphbtxMnwRO3ecHLsSwCJhVGppZyM1T6NRyrLztYfqTIj/HQAIg5yP9VJ\r\n" \
"dJSY7i2suD9cOloI7VqjLyvEExe8EIhhPR1rDE/8wuBbNdHLd351+xwFFe/JsY6a\r\n" \
"Uzlna83gRHKm+6bERT1UG7ALuauEMe497vXjPk7DTnRdsney6UmidUdZWEn/7bsT\r\n" \
"1yECAwEAAaN5MHcwCQYDVR0TBAIwADAfBgNVHSMEGDAWgBRNfBbpcuDMVV2TAU3w\r\n" \
"tohHHkZEczAdBgNVHQ4EFgQU4dGfYxzu3k2Qu/ZwyCZWbzdg4P8wCwYDVR0PBAQD\r\n" \
"AgXgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjANBgkqhkiG9w0BAQsF\r\n" \
"AAOCAQEAmMlYsf32MuuGtFQxSkgif1ahumBRRQIh6gIXzZ5FiPYzRmK/CkvluLl1\r\n" \
"fOsXF9loWHfX78mqdZrYcnYkt6YNg5RIMk4Rg6GUHT8mb6+r9vWSkTcKC8VkVNak\r\n" \
"BPRzWRVbVIur4BKZn7xL6CgizYL4WeseJUUBqxNLWg4aDelHYuhMCqQbnThmAv6Z\r\n" \
"d2a9T9hzxJASoWA6cLDh3m6EMwjKPbEyMPEd4n1l2t7n2yc81DCNNtegz3QEsCMt\r\n" \
"onE+w5kmmxSPX/5Jn1122IzX1nRXlFuhK1U6riQ/8SxxuiIm33OXh2gYmwtpQATY\r\n" \
"SdxhWUDsV4MxNuDc5todC5xNMePMBQ==\r\n" \
"-----END CERTIFICATE-----"

static char sample_device_info[] = {
	"{\n"
	"\t\"deviceInfo\": {\n"
	"\t\t\"firmwareVersion\": \"testFirmwareVersion\",\n"
	"\t\t\"privateKey\": \"" TEST_RSA_PRIVATE_KEY """\",\n"
	"\t\t\"deviceCert\": \"" TEST_RSA_CERTIFICATE "\",\n"
	"\t\t\"serialNumber\": \"STDKtestc77078cc\"\n"
	"\t}\n"
	"}"
};
#elif defined(CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_ECDSA)
#define TEST_ECDSA_PRIVATE_KEY \
"-----BEGIN EC PRIVATE KEY-----\r\n" \
"MHcCAQEEID9/vyoZcyY7OI7LbnkyfMTnINtYOLpNk5x9KCM8lmLdoAoGCCqGSM49\r\n" \
"AwEHoUQDQgAEPYS01pFX7+PsnY2GUfpRTjohuSnQxP+3zdEP5Ovd5CnTTLzvPwbb\r\n" \
"C0tUb0s4Jet0duPc7Vz9b91zqX5A5yZO8w==\r\n" \
"-----END EC PRIVATE KEY-----"

#define TEST_ECDSA_CERTIFICATE \
"-----BEGIN CERTIFICATE-----\r\n" \
"MIICMDCCAdegAwIBAgIJANC5Hjw2G4qUMAoGCCqGSM49BAMCMGcxCzAJBgNVBAYT\r\n" \
"AktSMRYwFAYDVQQKDA1UaGluZ3MgU3lzdGVtMRkwFwYDVQQLDBBTbWFydFRoaW5n\r\n" \
"cyBNUVRUMSUwIwYDVQQDDBxUaGluZ3Mgc2VsZi1zaWduZWQgcm9vdCBjZXJ0MCAX\r\n" \
"DTIwMDYzMDAyMjExMVoYDzIwNjAwNjIwMDIyMTExWjBYMQswCQYDVQQGEwJLUjEW\r\n" \
"MBQGA1UECgwNVGhpbmdzIFN5c3RlbTEZMBcGA1UECwwQU21hcnRUaGluZ3MgTVFU\r\n" \
"VDEWMBQGA1UEAwwNVGhpbmdzIERldmljZTBZMBMGByqGSM49AgEGCCqGSM49AwEH\r\n" \
"A0IABD2EtNaRV+/j7J2NhlH6UU46Ibkp0MT/t83RD+Tr3eQp00y87z8G2wtLVG9L\r\n" \
"OCXrdHbj3O1c/W/dc6l+QOcmTvOjeTB3MAkGA1UdEwQCMAAwHwYDVR0jBBgwFoAU\r\n" \
"7ZcCOlSfrHMs4F9+InsLj57fQsYwHQYDVR0OBBYEFJy/7DNDLa3DuAFMmYHhHtJg\r\n" \
"PP/EMAsGA1UdDwQEAwIF4DAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIw\r\n" \
"CgYIKoZIzj0EAwIDRwAwRAIgNDgGFm5fDKtUNJMLXNWmnkeGYlmq4r4X7beHOu2Z\r\n" \
"Ei8CIFdv66Rn53RtLL4AgpfBk8k1ut4ZJpQUEYG7F9P+GZOf\r\n" \
"-----END CERTIFICATE-----"

static char sample_device_info[] = {
	"{\n"
	"\t\"deviceInfo\": {\n"
	"\t\t\"firmwareVersion\": \"testFirmwareVersion\",\n"
	"\t\t\"privateKey\": \"" TEST_ECDSA_PRIVATE_KEY """\",\n"
	"\t\t\"deviceCert\": \"" TEST_ECDSA_CERTIFICATE "\",\n"
	"\t\t\"serialNumber\": \"STDKtestc77078cc\"\n"
	"\t}\n"
	"}"
};
#endif

int TC_iot_security_pk_init_setup(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;

	set_mock_detect_memory_leak(true);

#if !defined(CONFIG_STDK_IOT_CORE_SUPPORT_STNV_PARTITION)
	err = iot_nv_init((unsigned char *)sample_device_info, strlen(sample_device_info));
#else
	err = iot_nv_init(NULL, 0);
#endif
	assert_int_equal(err, IOT_ERROR_NONE);

	context = iot_security_init();
	assert_non_null(context);

	*state = context;

	return 0;
}

int TC_iot_security_pk_init_teardown(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	err = iot_security_deinit(context);
	assert_int_equal(err, IOT_ERROR_NONE);

	set_mock_detect_memory_leak(false);

	return 0;
}

int TC_iot_security_pk_setup(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;

	set_mock_detect_memory_leak(true);

#if !defined(CONFIG_STDK_IOT_CORE_SUPPORT_STNV_PARTITION)
	err = iot_nv_init((unsigned char *)sample_device_info, strlen(sample_device_info));
#else
	err = iot_nv_init(NULL, 0);
#endif
	assert_int_equal(err, IOT_ERROR_NONE);

	context = iot_security_init();
	assert_non_null(context);

	err = iot_security_pk_init(context);
	assert_int_equal(err, IOT_ERROR_NONE);

	*state = context;

	return 0;
}

int TC_iot_security_pk_teardown(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	err = iot_security_pk_deinit(context);
	assert_int_equal(err, IOT_ERROR_NONE);

	err = iot_security_deinit(context);
	assert_int_equal(err, IOT_ERROR_NONE);

	set_mock_detect_memory_leak(false);

	return 0;
}

void TC_iot_security_pk_init_null_parameters(void **state)
{
	iot_error_t err;

	// When
	err = iot_security_pk_init(NULL);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_pk_init_malloc_failure(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	do_not_use_mock_iot_os_malloc_failure();

	// Given
	set_mock_iot_os_malloc_failure_with_index(0);
	// When
	err = iot_security_pk_init(context);
	// Then
	assert_int_equal(err, IOT_ERROR_MEM_ALLOC);

	// Local teardown
	do_not_use_mock_iot_os_malloc_failure();
}

void TC_iot_security_pk_init_success(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	// When
	err = iot_security_pk_init(context);
	// Then
	assert_int_equal(err, IOT_ERROR_NONE);
	// Teardown
	err = iot_security_pk_deinit(context);
	assert_int_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_pk_deinit_null_parameters(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	// When
	err = iot_security_pk_deinit(NULL);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_pk_deinit_success(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	// Given
	err = iot_security_pk_init(context);
	assert_int_equal(err, IOT_ERROR_NONE);
	// When
	err = iot_security_pk_deinit(context);
	// Then
	assert_int_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_pk_get_signature_len_failure(void **state)
{
	iot_security_key_type_t pk_type;
	size_t sig_len;

	// Given
	pk_type = IOT_SECURITY_KEY_TYPE_UNKNOWN;
	// When
	sig_len = iot_security_pk_get_signature_len(pk_type);
	// Then
	assert_int_equal((int)sig_len, IOT_SECURITY_SIGNATURE_UNKNOWN_LEN);
}

void TC_iot_security_pk_get_signature_len_success(void **state)
{
	iot_security_key_type_t pk_type;
	size_t sig_len;

	// Given
	pk_type = IOT_SECURITY_KEY_TYPE_RSA2048;
	// When
	sig_len = iot_security_pk_get_signature_len(pk_type);
	// Then
	assert_int_equal((int)sig_len, IOT_SECURITY_SIGNATURE_RSA2048_LEN);

	// Given
	pk_type = IOT_SECURITY_KEY_TYPE_ED25519;
	// When
	sig_len = iot_security_pk_get_signature_len(pk_type);
	// Then
	assert_int_equal((int)sig_len, IOT_SECURITY_SIGNATURE_ED25519_LEN);

	// Given
	pk_type = IOT_SECURITY_KEY_TYPE_ECCP256;
	// When
	sig_len = iot_security_pk_get_signature_len(pk_type);
	// Then
	assert_int_equal((int)sig_len, IOT_SECURITY_SIGNATURE_ECCP256_LEN);
}

void TC_iot_security_pk_get_key_type_failure(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;
	iot_security_key_type_t key_type;

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	// When: get key type without pk_init
	err = iot_security_pk_get_key_type(context, &key_type);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_pk_get_key_type_success(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;
	iot_security_key_type_t key_type;

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	// When
	err = iot_security_pk_get_key_type(context, &key_type);
	// Then
	assert_int_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_pk_sign_invalid_parameters(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;
	iot_security_buffer_t msg_buf = { 0 };
	iot_security_buffer_t sig_buf = { 0 };
	unsigned char buf[256];

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	// Given
	msg_buf.p = NULL;
	msg_buf.len = sizeof(buf);
	// When
	err = iot_security_pk_sign(context, &msg_buf, &sig_buf);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// Given
	msg_buf.p = buf;
	msg_buf.len = 0;
	// When
	err = iot_security_pk_sign(context, &msg_buf, &sig_buf);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_pk_sign_null_parameters(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;
	iot_security_buffer_t msg_buf = { 0 };
	iot_security_buffer_t sig_buf = { 0 };
	unsigned char msg[256];

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	// When
	err = iot_security_pk_sign(NULL, NULL, NULL);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// When
	err = iot_security_pk_sign(NULL, &msg_buf, &sig_buf);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// When
	err = iot_security_pk_sign(context, NULL, &sig_buf);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// Given
	msg_buf.p = msg;
	msg_buf.len = sizeof(msg);
	// When
	err = iot_security_pk_sign(context, &msg_buf, NULL);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_pk_sign_malloc_failure(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;
	iot_security_buffer_t msg_buf = { 0 };
	iot_security_buffer_t sig_buf = { 0 };
	int i;

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	// Given: message buffer
	msg_buf.len = 256;
	msg_buf.p = (unsigned char *)iot_os_malloc(msg_buf.len);
	assert_non_null(msg_buf.p);
	for (i = 0; i < msg_buf.len; i++) {
		msg_buf.p[i] = (unsigned char)iot_bsp_random();
	}

	for (int i = 0; i < 1; i++) {
		// Given: i-th malloc failure
		do_not_use_mock_iot_os_malloc_failure();
		set_mock_iot_os_malloc_failure_with_index(i);
		// When
		err = iot_security_pk_sign(context, &msg_buf, &sig_buf);
		// Then
		assert_int_not_equal(err, IOT_ERROR_NONE);
	}

	// Local teardown
	iot_os_free(msg_buf.p);
	do_not_use_mock_iot_os_malloc_failure();
}

void TC_iot_security_pk_sign_failure(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;
	iot_security_buffer_t msg_buf = { 0 };
	iot_security_buffer_t sig_buf = { 0 };

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	// When: sign without pk_init
	err = iot_security_pk_sign(context, &msg_buf, &sig_buf);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_pk_verify_invalid_parameters(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;
	iot_security_buffer_t msg_buf = { 0 };
	iot_security_buffer_t sig_buf = { 0 };
	iot_security_buffer_t msg_buf_backup;
	iot_security_buffer_t sig_buf_backup;
	unsigned char buf[256];

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	// Given: valid signature
	msg_buf.p = buf;
	msg_buf.len = sizeof(buf);
	err = iot_security_pk_sign(context, &msg_buf, &sig_buf);
	assert_int_equal(err, IOT_ERROR_NONE);

	msg_buf_backup = msg_buf;
	sig_buf_backup = sig_buf;

	// Given
	msg_buf = msg_buf_backup;
	msg_buf.p = NULL;
	// When
	err = iot_security_pk_verify(context, &msg_buf, &sig_buf);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// Given
	msg_buf = msg_buf_backup;
	msg_buf.len = 0;
	// When
	err = iot_security_pk_verify(context, &msg_buf, &sig_buf);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// Given
	sig_buf = sig_buf_backup;
	sig_buf.p = NULL;
	// When
	err = iot_security_pk_verify(context, &msg_buf, &sig_buf);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// Given
	sig_buf = sig_buf_backup;
	sig_buf.len = 0;
	// When
	err = iot_security_pk_verify(context, &msg_buf, &sig_buf);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// Local teardown
	iot_os_free(sig_buf.p);
}

void TC_iot_security_pk_verify_null_parameters(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;
	iot_security_buffer_t msg_buf = { 0 };
	iot_security_buffer_t sig_buf = { 0 };
	unsigned char msg[256];

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	// When
	err = iot_security_pk_verify(NULL, NULL, NULL);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// When
	err = iot_security_pk_verify(NULL, &msg_buf, &sig_buf);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// When
	err = iot_security_pk_verify(context, NULL, &sig_buf);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// Given: valid input data
	msg_buf.p = msg;
	msg_buf.len = sizeof(msg);
	// When
	err = iot_security_pk_verify(context, &msg_buf, NULL);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_pk_verify_failure(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;
	iot_security_buffer_t msg_buf = { 0 };
	iot_security_buffer_t sig_buf = { 0 };

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	// When: verity without pk_init
	err = iot_security_pk_verify(context, &msg_buf, &sig_buf);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_pk_success(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;
	iot_security_buffer_t msg_buf = { 0 };
	iot_security_buffer_t sig_buf = { 0 };
	int i;

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	// Given: message buffer
	msg_buf.len = 256;
	msg_buf.p = (unsigned char *)iot_os_malloc(msg_buf.len);
	assert_non_null(msg_buf.p);
	for (i = 0; i < msg_buf.len; i++) {
		msg_buf.p[i] = (unsigned char)iot_bsp_random();
	}
	// When
	err = iot_security_pk_sign(context, &msg_buf, &sig_buf);
	// Then
	assert_int_equal(err, IOT_ERROR_NONE);
	assert_non_null(sig_buf.p);
	assert_int_not_equal(sig_buf.len, 0);

	// When
	err = iot_security_pk_verify(context, &msg_buf, &sig_buf);
	// Then
	assert_int_equal(err, IOT_ERROR_NONE);

	// Local teardown
	iot_os_free(msg_buf.p);
	iot_os_free(sig_buf.p);
}

int TC_iot_security_cipher_init_setup(void **state)
{
	iot_security_context_t *context;

	context = iot_security_init();
	assert_non_null(context);

	*state = context;

	return 0;
}

int TC_iot_security_cipher_init_teardown(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	err = iot_security_deinit(context);
	assert_int_equal(err, IOT_ERROR_NONE);

	return 0;
}

int TC_iot_security_cipher_setup(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;

	/*
	 * set_mock_detect_memory_leak are not available by set_params
	 */

	context = iot_security_init();
	assert_non_null(context);

	err = iot_security_cipher_init(context);
	assert_int_equal(err, IOT_ERROR_NONE);


	*state = context;

	return 0;
}

int TC_iot_security_cipher_teardown(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	err = iot_security_cipher_deinit(context);
	assert_int_equal(err, IOT_ERROR_NONE);

	err = iot_security_deinit(context);
	assert_int_equal(err, IOT_ERROR_NONE);

	return 0;
}

void TC_iot_security_cipher_init_null_parameters(void **state)
{
	iot_error_t err;

	// When
	err = iot_security_cipher_init(NULL);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_cipher_init_malloc_failure(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	do_not_use_mock_iot_os_malloc_failure();

	// Given
	set_mock_iot_os_malloc_failure_with_index(0);
	// When
	err = iot_security_cipher_init(context);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// Local teardown
	do_not_use_mock_iot_os_malloc_failure();
}

void TC_iot_security_cipher_init_success(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	// When
	err = iot_security_cipher_init(context);
	// Then
	assert_int_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_cipher_deinit_null_parameters(void **state)
{
	iot_error_t err;

	// When
	err = iot_security_cipher_deinit(NULL);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_cipher_deinit_success(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	// When
	err = iot_security_cipher_deinit(context);
	// Then
	assert_int_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_cipher_get_align_size_failure(void **state)
{
	iot_security_key_type_t key_type;
	size_t data_size;
	size_t align_size;

	// Given: unknown key type
	key_type = IOT_SECURITY_KEY_TYPE_UNKNOWN;
	// When
	align_size = iot_security_cipher_get_align_size(key_type, data_size);
	// Then
	assert_int_equal(align_size, 0);

	// Given: invalid input size
	key_type = IOT_SECURITY_KEY_TYPE_AES256;
	data_size = 0;
	// When
	align_size = iot_security_cipher_get_align_size(key_type, data_size);
	// Then
	assert_int_equal(align_size, 0);
}

void TC_iot_security_cipher_get_align_size_success(void **state)
{
	iot_security_key_type_t key_type;
	size_t data_size;
	size_t align_size;
	size_t expected_size;

	// Given
	key_type = IOT_SECURITY_KEY_TYPE_AES256;
	data_size = 16;
	expected_size = 32;
	// When
	align_size = iot_security_cipher_get_align_size(key_type, data_size);
	// Then
	assert_int_equal(align_size, expected_size);

	// Given
	key_type = IOT_SECURITY_KEY_TYPE_AES256;
	data_size = 24;
	expected_size = 32;
	// When
	align_size = iot_security_cipher_get_align_size(key_type, data_size);
	// Then
	assert_int_equal(align_size, expected_size);
}

void TC_iot_security_cipher_set_params_invalid_parameters(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;
	iot_security_cipher_params_t aes_params = { 0 };
	unsigned char buf[IOT_SECURITY_SECRET_LEN];

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	// Given: key len is zero
	aes_params.key.p = buf;
	aes_params.key.len = 0;
	// When
	err = iot_security_cipher_set_params(context, &aes_params);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// Given: iv len is zero
	aes_params.iv.p = buf;
	aes_params.iv.len = 0;
	// When
	err = iot_security_cipher_set_params(context, &aes_params);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_cipher_set_params_null_parameters(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;
	iot_security_cipher_params_t aes_params = { 0 };

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	// When
	err = iot_security_cipher_set_params(NULL, NULL);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// When
	err = iot_security_cipher_set_params(NULL, &aes_params);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// When
	err = iot_security_cipher_set_params(context, NULL);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_cipher_set_params_success(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;
	iot_security_cipher_params_t aes_params = { 0 };
	unsigned char secret_buf[IOT_SECURITY_SECRET_LEN];
	unsigned char iv_buf[IOT_SECURITY_IV_LEN];
	size_t secret_len = sizeof(secret_buf);
	size_t iv_len = sizeof(iv_buf);

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	// Given
	aes_params.type = IOT_SECURITY_KEY_TYPE_AES256;
	aes_params.key.p = secret_buf;
	aes_params.key.len = secret_len;
	aes_params.iv.p = iv_buf;
	aes_params.iv.len = iv_len;
	// When
	err = iot_security_cipher_set_params(context, &aes_params);
	// Then
	assert_int_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_cipher_aes_encrypt_invalid_parameters(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;
	iot_security_buffer_t plain_buf = { 0 };
	iot_security_buffer_t encrypt_buf = { 0 };
	unsigned char msg[128];
	int i;

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	// When: input data is all zero
	err = iot_security_cipher_aes_encrypt(context, &plain_buf, &encrypt_buf);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// Given: input buf is null
	plain_buf.p = NULL;
	plain_buf.len = sizeof(msg);
	// When
	err = iot_security_cipher_aes_encrypt(context, &plain_buf, &encrypt_buf);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// Given: input buf len is zero
	plain_buf.p = msg;
	plain_buf.len = 0;
	// When
	err = iot_security_cipher_aes_encrypt(context, &plain_buf, &encrypt_buf);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_cipher_aes_encrypt_null_parameters(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;
	iot_security_buffer_t plain_buf = { 0 };
	iot_security_buffer_t encrypt_buf = { 0 };
	unsigned char msg[128];

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	// When
	err = iot_security_cipher_aes_encrypt(NULL, NULL, NULL);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// When
	err = iot_security_cipher_aes_encrypt(NULL, &plain_buf, &encrypt_buf);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// When
	err = iot_security_cipher_aes_encrypt(context, NULL, &encrypt_buf);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// Given: valid input data
	plain_buf.p = msg;
	plain_buf.len = sizeof(msg);
	// When
	err = iot_security_cipher_aes_encrypt(context, &plain_buf, NULL);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_cipher_aes_encrypt_malloc_failure(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;
	iot_security_cipher_params_t aes_params = { 0 };
	unsigned char secret_buf[IOT_SECURITY_SECRET_LEN];
	unsigned char iv_buf[IOT_SECURITY_IV_LEN];
	iot_security_buffer_t plain_buf = { 0 };
	iot_security_buffer_t encrypt_buf = { 0 };
	size_t secret_len = sizeof(secret_buf);
	size_t iv_len = sizeof(iv_buf);
	int i;

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	// Given: cipher algorithm and iv
	aes_params.type = IOT_SECURITY_KEY_TYPE_AES256;
	for (i = 0; i < iv_len; i++) {
		iv_buf[i] = (unsigned char)iot_bsp_random();
	}
	aes_params.iv.p = iv_buf;
	aes_params.iv.len = iv_len;
#if defined(CONFIG_STDK_IOT_CORE_SECURITY_BACKEND_SOFTWARE)
	for (i = 0; i < secret_len; i++) {
		secret_buf[i] = (unsigned char)iot_bsp_random();
	}
	aes_params.key.p = secret_buf;
	aes_params.key.len = secret_len;
#endif
	err = iot_security_cipher_set_params(context, &aes_params);
	assert_int_equal(err, IOT_ERROR_NONE);
	// Given: input data
	plain_buf.p = secret_buf;
	plain_buf.len = secret_len;

	for (int i = 0; i < 1; i++) {
		// Given: i-th malloc failure
		do_not_use_mock_iot_os_malloc_failure();
		set_mock_iot_os_malloc_failure_with_index(i);
		// When
		err = iot_security_cipher_aes_encrypt(context, &plain_buf, &encrypt_buf);
		// Then
		assert_int_not_equal(err, IOT_ERROR_NONE);
	}

	// Local teardown
	do_not_use_mock_iot_os_malloc_failure();
}

void TC_iot_security_cipher_aes_encrypt_failure(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;
	iot_security_buffer_t plain_buf = { 0 };
	iot_security_buffer_t encrypt_buf = { 0 };

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	// When: encrypt without pk_init
	err = iot_security_cipher_aes_encrypt(context, &plain_buf, &encrypt_buf);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_cipher_aes_decrypt_invalid_parameters(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;
	iot_security_buffer_t encrypt_buf = { 0 };
	iot_security_buffer_t decrypt_buf = { 0 };
	unsigned char msg[128];

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	encrypt_buf.p = msg;
	encrypt_buf.len = sizeof(msg);

	// When: input data is all zero
	err = iot_security_cipher_aes_decrypt(context, &encrypt_buf, &decrypt_buf);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// Given: output buf is null
	decrypt_buf.p = NULL;
	decrypt_buf.len = sizeof(msg);
	// When
	err = iot_security_cipher_aes_decrypt(context, &encrypt_buf, &decrypt_buf);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// Given: output buf len is zero
	decrypt_buf.p = msg;
	decrypt_buf.len = 0;
	// When
	err = iot_security_cipher_aes_decrypt(context, &encrypt_buf, &decrypt_buf);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_cipher_aes_decrypt_null_parameters(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;
	iot_security_buffer_t encrypt_buf = { 0 };
	iot_security_buffer_t decrypt_buf = { 0 };
	unsigned char msg[128];

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	// When
	err = iot_security_cipher_aes_decrypt(NULL, NULL, NULL);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// When
	err = iot_security_cipher_aes_decrypt(NULL, &encrypt_buf, &decrypt_buf);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// When
	err = iot_security_cipher_aes_decrypt(context, NULL, &decrypt_buf);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// Given: valid input data
	encrypt_buf.p = msg;
	encrypt_buf.len = sizeof(msg);
	// When
	err = iot_security_cipher_aes_decrypt(context, &encrypt_buf, NULL);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_cipher_aes_decrypt_malloc_failure(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;
	iot_security_cipher_params_t aes_params = { 0 };
	unsigned char secret_buf[IOT_SECURITY_SECRET_LEN];
	unsigned char iv_buf[IOT_SECURITY_IV_LEN];
	iot_security_buffer_t plain_buf = { 0 };
	iot_security_buffer_t encrypt_buf = { 0 };
	iot_security_buffer_t decrypt_buf = { 0 };
	size_t secret_len = sizeof(secret_buf);
	size_t iv_len = sizeof(iv_buf);
	int i;

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	// Given: cipher algorithm and iv
	aes_params.type = IOT_SECURITY_KEY_TYPE_AES256;
	for (i = 0; i < iv_len; i++) {
		iv_buf[i] = (unsigned char)iot_bsp_random();
	}
	aes_params.iv.p = iv_buf;
	aes_params.iv.len = iv_len;
#if defined(CONFIG_STDK_IOT_CORE_SECURITY_BACKEND_SOFTWARE)
	for (i = 0; i < secret_len; i++) {
		secret_buf[i] = (unsigned char)iot_bsp_random();
	}
	aes_params.key.p = secret_buf;
	aes_params.key.len = secret_len;
#endif
	err = iot_security_cipher_set_params(context, &aes_params);
	assert_int_equal(err, IOT_ERROR_NONE);

	// Given: encrypted data
	plain_buf.p = secret_buf;
	plain_buf.len = secret_len;
	err = iot_security_cipher_aes_encrypt(context, &plain_buf, &encrypt_buf);
	assert_int_equal(err, IOT_ERROR_NONE);

	for (int i = 0; i < 1; i++) {
		// Given: i-th malloc failure
		do_not_use_mock_iot_os_malloc_failure();
		set_mock_iot_os_malloc_failure_with_index(i);
		// When
		err = iot_security_cipher_aes_decrypt(context, &encrypt_buf, &decrypt_buf);
		// Then
		assert_int_not_equal(err, IOT_ERROR_NONE);
	}

	// Local teardown
	do_not_use_mock_iot_os_malloc_failure();
	iot_os_free(encrypt_buf.p);
}

void TC_iot_security_cipher_aes_decrypt_failure(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;
	iot_security_buffer_t encrypt_buf = { 0 };
	iot_security_buffer_t decrypt_buf = { 0 };

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	// When: decrypt without pk_init
	err = iot_security_cipher_aes_decrypt(context, &encrypt_buf, &decrypt_buf);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_cipher_aes_success(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;
	iot_security_cipher_params_t aes_params = { 0 };
	unsigned char secret_buf[IOT_SECURITY_SECRET_LEN];
	unsigned char iv_buf[IOT_SECURITY_IV_LEN];
	iot_security_buffer_t plain_buf = { 0 };
	iot_security_buffer_t encrypt_buf = { 0 };
	iot_security_buffer_t decrypt_buf = { 0 };
	size_t secret_len = sizeof(secret_buf);
	size_t iv_len = sizeof(iv_buf);
	int i;

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	// buffer for plain
	plain_buf.len = 256;
	plain_buf.p = (unsigned char *)iot_os_malloc(plain_buf.len);
	assert_non_null(plain_buf.p);
	for (i = 0; i < plain_buf.len; i++) {
		plain_buf.p[i] = (unsigned char)iot_bsp_random();
	}

	// Given: cipher algorithm and iv
	aes_params.type = IOT_SECURITY_KEY_TYPE_AES256;
	for (i = 0; i < iv_len; i++) {
		iv_buf[i] = (unsigned char)iot_bsp_random();
	}
	aes_params.iv.p = iv_buf;
	aes_params.iv.len = iv_len;
#if defined(CONFIG_STDK_IOT_CORE_SECURITY_BACKEND_SOFTWARE)
	for (i = 0; i < secret_len; i++) {
		secret_buf[i] = (unsigned char)iot_bsp_random();
	}
	aes_params.key.p = secret_buf;
	aes_params.key.len = secret_len;
#endif
	// When
	err = iot_security_cipher_set_params(context, &aes_params);
	// Then
	assert_int_equal(err, IOT_ERROR_NONE);

	// When
	err = iot_security_cipher_aes_encrypt(context, &plain_buf, &encrypt_buf);
	// Then
	assert_int_equal(err, IOT_ERROR_NONE);
	assert_non_null(encrypt_buf.p);
	assert_int_not_equal(encrypt_buf.len, 0);

	// When
	err = iot_security_cipher_aes_decrypt(context, &encrypt_buf, &decrypt_buf);
	// Then
	assert_int_equal(err, IOT_ERROR_NONE);
	assert_non_null(decrypt_buf.p);
	assert_int_not_equal(decrypt_buf.len, 0);
	assert_int_equal(decrypt_buf.len, plain_buf.len);
	assert_memory_equal(decrypt_buf.p, plain_buf.p, plain_buf.len);

	// Local teardown
	iot_os_free(decrypt_buf.p);
	iot_os_free(encrypt_buf.p);
	iot_os_free(plain_buf.p);
}