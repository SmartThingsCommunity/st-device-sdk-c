/* ***************************************************************************
 *
 * Copyright (c) 2021 Samsung Electronics All Rights Reserved.
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
#include <string.h>
#include <iot_error.h>
#include <iot_nv_data.h>
#include <security/iot_security_crypto.h>
#include <security/iot_security_ecdh.h>
#include <bsp/iot_bsp_random.h>
#include <security/iot_security_manager.h>
#include <iot_util.h>
#include <security/iot_security_helper.h>

#define SAMPLE_ROOT_CA_CERT \
"-----BEGIN CERTIFICATE-----\r\n" \
"MIICaDCCAgygAwIBAgIBAjAMBggqhkjOPQQDAgUAMHAxLTArBgNVBAMTJFNhbXN1\r\n" \
"bmcgRWxlY3Ryb25pY3MgT0NGIFJvb3QgQ0EgVEVTVDEUMBIGA1UECxMLT0NGIFJv\r\n" \
"b3QgQ0ExHDAaBgNVBAoTE1NhbXN1bmcgRWxlY3Ryb25pY3MxCzAJBgNVBAYTAktS\r\n" \
"MCAXDTE2MTEyNDAyNDcyN1oYDzIwNjkxMjMxMTQ1OTU5WjBwMS0wKwYDVQQDEyRT\r\n" \
"YW1zdW5nIEVsZWN0cm9uaWNzIE9DRiBSb290IENBIFRFU1QxFDASBgNVBAsTC09D\r\n" \
"RiBSb290IENBMRwwGgYDVQQKExNTYW1zdW5nIEVsZWN0cm9uaWNzMQswCQYDVQQG\r\n" \
"EwJLUjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABBzzury7p8HANVn+v4CIa2h/\r\n" \
"R/SAt3VVst+vTv4/kR+lgU1OEiT3t9+mOWE7J+oddpRofFW2DdeJkpfQUVOn4NOj\r\n" \
"gZIwgY8wDgYDVR0PAQH/BAQDAgHGMC4GA1UdHwQnMCUwI6AhoB+GHWh0dHA6Ly9j\r\n" \
"YS5zYW1zdW5naW90cy5jb20vY3JsMA8GA1UdEwEB/wQFMAMBAf8wPAYIKwYBBQUH\r\n" \
"AQEEMDAuMCwGCCsGAQUFBzABhiBodHRwOi8vb2NzcC10ZXN0LnNhbXN1bmdpb3Rz\r\n" \
"LmNvbTAMBggqhkjOPQQDAgUAA0gAMEUCIQCIsi3BcOQMXO/pCiUA+S75bYFWS27E\r\n" \
"GAq9e2E3+hQ2TAIgWrTieFAZ5xRH3BnSHG+XEF2HPD99y/SYSa6T59YW+jE=\r\n" \
"-----END CERTIFICATE-----\r\n"

#define SAMPLE_SUB_CA_CERT \
"-----BEGIN CERTIFICATE-----\r\n" \
"MIICkjCCAjagAwIBAgIUfSmsDder32Y6TTSZ/0P8y8T3kVIwDAYIKoZIzj0EAwIF\r\n" \
"ADBwMS0wKwYDVQQDEyRTYW1zdW5nIEVsZWN0cm9uaWNzIE9DRiBSb290IENBIFRF\r\n" \
"U1QxFDASBgNVBAsTC09DRiBSb290IENBMRwwGgYDVQQKExNTYW1zdW5nIEVsZWN0\r\n" \
"cm9uaWNzMQswCQYDVQQGEwJLUjAgFw0xNjEyMDkwMTM3NDVaGA8yMDY5MTIzMTE0\r\n" \
"NTk1OVowgYMxODA2BgNVBAMTL1NhbXN1bmcgRWxlY3Ryb25pY3MgT0NGIEhBIERl\r\n" \
"dmljZSBTdWJDQSB2MSBURVNUMRwwGgYDVQQLExNPQ0YgSEEgRGV2aWNlIFN1YkNB\r\n" \
"MRwwGgYDVQQKExNTYW1zdW5nIEVsZWN0cm9uaWNzMQswCQYDVQQGEwJLUjBZMBMG\r\n" \
"ByqGSM49AgEGCCqGSM49AwEHA0IABAJmBp1E4Oklec0Eo4QUSsx7Bu8DT4G7iSTs\r\n" \
"7UhPqbjcTxhoUOyRUNXVsVoWXj8R0YHPRa9/VUL8T98AX8ukN+6jgZUwgZIwDgYD\r\n" \
"VR0PAQH/BAQDAgHGMC4GA1UdHwQnMCUwI6AhoB+GHWh0dHA6Ly9jYS5zYW1zdW5n\r\n" \
"aW90cy5jb20vY3JsMBIGA1UdEwEB/wQIMAYBAf8CAQAwPAYIKwYBBQUHAQEEMDAu\r\n" \
"MCwGCCsGAQUFBzABhiBodHRwOi8vb2NzcC10ZXN0LnNhbXN1bmdpb3RzLmNvbTAM\r\n" \
"BggqhkjOPQQDAgUAA0gAMEUCIE9pLI8LBrhL/0udGudlPzpb04Z6MTvfzemX5OJN\r\n" \
"Tf7uAiEA9RAQNZj80rGkxoIgFGekywvuBybpXJrrZu/BP2TWkFU=\r\n" \
"-----END CERTIFICATE-----\r\n"

#define SAMPLE_DEVICE_CERT \
"-----BEGIN CERTIFICATE-----\r\n" \
"MIICpjCCAkqgAwIBAgIUSEEwMVQxOTAyMjUwNDAwMDAwMTAwDAYIKoZIzj0EAwIF\r\n" \
"ADCBgzE4MDYGA1UEAxMvU2Ftc3VuZyBFbGVjdHJvbmljcyBPQ0YgSEEgRGV2aWNl\r\n" \
"IFN1YkNBIHYxIFRFU1QxHDAaBgNVBAsTE09DRiBIQSBEZXZpY2UgU3ViQ0ExHDAa\r\n" \
"BgNVBAoTE1NhbXN1bmcgRWxlY3Ryb25pY3MxCzAJBgNVBAYTAktSMCAXDTE5MDIy\r\n" \
"NTAyMDUxNloYDzIwNjkxMjMxMTQ1OTU5WjCBijFFMEMGA1UEAxM8T0NGIERldmlj\r\n" \
"ZSBURVNUOiBUZXN0ICg1MmNlNmYyMC1jNjBlLTRhMWItYTZlZi0xMDk3MmMxMTMz\r\n" \
"OWYpMRYwFAYDVQQLEw1PQ0YgSEEgRGV2aWNlMRwwGgYDVQQKExNTYW1zdW5nIEVs\r\n" \
"ZWN0cm9uaWNzMQswCQYDVQQGEwJLUjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IA\r\n" \
"BLKVYfsMsUmaQb8pN25oBdJQ/H/pRT0Bbz5dk0PoZfheIwWcug8LTVCUIeYGgcQa\r\n" \
"b+PE+L22rqV/6WnTL7cZhuujgY4wgYswPAYIKwYBBQUHAQEEMDAuMCwGCCsGAQUF\r\n" \
"BzABhiBodHRwOi8vb2NzcC10ZXN0LnNhbXN1bmdpb3RzLmNvbTAOBgNVHQ8BAf8E\r\n" \
"BAMCBsAwOwYDVR0fBDQwMjAwoC6gLIYqaHR0cDovL2NybC10ZXN0LnNhbXN1bmdp\r\n" \
"b3RzLmNvbS9oYXYxY2EuY3JsMAwGCCqGSM49BAMCBQADSAAwRQIgJ6uRdR4WZE1e\r\n" \
"U2dfcN2YT+FQmEBv0Yl4/sAAQW4GVqYCIQDQDpe9yMCGPz2LTFhBIrphH6zZ16m7\r\n" \
"EqFB6e+CqQKGBA==\r\n" \
"-----END CERTIFICATE-----\r\n"

#define SAMPLE_PRIVATE_KEY \
"-----BEGIN EC PRIVATE KEY-----\r\n" \
"MHcCAQEEIJOSBZJQ1RJFR7yOhjIm6Xzf8G81LxxZhLegfdDWBIi4oAoGCCqGSM49\r\n" \
"AwEHoUQDQgAEspVh+wyxSZpBvyk3bmgF0lD8f+lFPQFvPl2TQ+hl+F4jBZy6DwtN\r\n" \
"UJQh5gaBxBpv48T4vbaupX/padMvtxmG6w==\r\n" \
"-----END EC PRIVATE KEY-----\r\n"

#define SAMPLE_PUBLIC_KEY \
"-----BEGIN PUBLIC KEY-----\r\n" \
"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEspVh+wyxSZpBvyk3bmgF0lD8f+lF\r\n" \
"PQFvPl2TQ+hl+F4jBZy6DwtNUJQh5gaBxBpv48T4vbaupX/padMvtxmG6w==\r\n" \
"-----END PUBLIC KEY-----\r\n"

#define SAMPLE_SERIAL_NUMBER \
"sample_cert_00000011"

static char sample_device_info[] = {
"{\n"
"\t\"deviceInfo\": {\n"
"\t\t\"firmwareVersion\": \"testFirmwareVersion\",\n"
"\t\t\"rootCaCert\": \"" SAMPLE_ROOT_CA_CERT "\",\n"
"\t\t\"subCaCert\": \"" SAMPLE_SUB_CA_CERT "\",\n"
"\t\t\"deviceCert\": \"" SAMPLE_DEVICE_CERT "\",\n"
"\t\t\"privateKey\": \"" SAMPLE_PRIVATE_KEY "\",\n"
"\t\t\"publicKey\": \"" SAMPLE_PUBLIC_KEY "\",\n"
"\t\t\"serialNum\": \"" SAMPLE_SERIAL_NUMBER "\"\n"
"\t}\n"
"}"
};

#define ECDH_BLE_RANDOM_LEN		16

static unsigned char c_random[ECDH_BLE_RANDOM_LEN] = {
	0x05, 0x3B, 0xAB, 0x31, 0xD7, 0xD0, 0xA3, 0xA9,
	0xBC, 0xE7, 0x2F, 0x21, 0x5F, 0x27, 0x1E, 0xBA,
};

static unsigned char s_random[ECDH_BLE_RANDOM_LEN] = {
	0x20, 0x2D, 0xD9, 0x0C, 0xDF, 0xE8, 0x9B, 0xC2,
	0x8F, 0xC6, 0x8C, 0x74, 0x85, 0x54, 0xF7, 0xF4,
};

//	Own ephemeral key
//
//	-----BEGIN EC PRIVATE KEY-----
//	MHcCAQEEIAwjClTp1gMVmL7pF70g67BOBaZSq8bc8HM9HLVyuU0VoAoGCCqGSM49
//	AwEHoUQDQgAEcwvB6BN4QrHZKXhO5/LTMTY/kr8jk9Z61GgHYWIVXNI5CPHQe4wu
//	taIh3pMNF/JqM3xbfMYXvKh9JTOn6OP2cA==
//	-----END EC PRIVATE KEY-----

static unsigned char own_ephemeral_seckey_secp256r1[] = {
	0x0c, 0x23, 0x0a, 0x54, 0xe9, 0xd6, 0x03, 0x15,
	0x98, 0xbe, 0xe9, 0x17, 0xbd, 0x20, 0xeb, 0xb0,
	0x4e, 0x05, 0xa6, 0x52, 0xab, 0xc6, 0xdc, 0xf0,
	0x73, 0x3d, 0x1c, 0xb5, 0x72, 0xb9, 0x4d, 0x15
};

static unsigned char own_ephemeral_pubkey_secp256r1[] = {
	0x73, 0x0b, 0xc1, 0xe8, 0x13, 0x78, 0x42, 0xb1,
	0xd9, 0x29, 0x78, 0x4e, 0xe7, 0xf2, 0xd3, 0x31,
	0x36, 0x3f, 0x92, 0xbf, 0x23, 0x93, 0xd6, 0x7a,
	0xd4, 0x68, 0x07, 0x61, 0x62, 0x15, 0x5c, 0xd2,
	0x39, 0x08, 0xf1, 0xd0, 0x7b, 0x8c, 0x2e, 0xb5,
	0xa2, 0x21, 0xde, 0x93, 0x0d, 0x17, 0xf2, 0x6a,
	0x33, 0x7c, 0x5b, 0x7c, 0xc6, 0x17, 0xbc, 0xa8,
	0x7d, 0x25, 0x33, 0xa7, 0xe8, 0xe3, 0xf6, 0x70
};

static unsigned char own_ephemeral_pubkey_secp256r1_der[] = {
	0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
	0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
	0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
	0x42, 0x00, 0x04, 0x73, 0x0b, 0xc1, 0xe8, 0x13,
	0x78, 0x42, 0xb1, 0xd9, 0x29, 0x78, 0x4e, 0xe7,
	0xf2, 0xd3, 0x31, 0x36, 0x3f, 0x92, 0xbf, 0x23,
	0x93, 0xd6, 0x7a, 0xd4, 0x68, 0x07, 0x61, 0x62,
	0x15, 0x5c, 0xd2, 0x39, 0x08, 0xf1, 0xd0, 0x7b,
	0x8c, 0x2e, 0xb5, 0xa2, 0x21, 0xde, 0x93, 0x0d,
	0x17, 0xf2, 0x6a, 0x33, 0x7c, 0x5b, 0x7c, 0xc6,
	0x17, 0xbc, 0xa8, 0x7d, 0x25, 0x33, 0xa7, 0xe8,
	0xe3, 0xf6, 0x70
};

static unsigned char own_ephemeral_pubkey_secp256r1_der_header[] = {
	0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
	0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
	0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
	0x42, 0x00, 0x04
};

//	Peer ephemeral key
//
//	-----BEGIN EC PRIVATE KEY-----
//	MHcCAQEEIIbJgk3bEfPlfq6T0AMOEaczTT6ZDVN32qMAqiryU1hboAoGCCqGSM49
//	AwEHoUQDQgAEdOZfApC/M+LzoZYnS+FMwb/WRAVTqMhPnVVfMTNh6Cg9FcF+Vw2c
//	jq/CC+Qv4tDmJ5+Ym7AF/3Ls5+DKWTclSg==
//	-----END EC PRIVATE KEY-----

static unsigned char peer_ephemeral_seckey_secp256r1[] = {
	0x86, 0xc9, 0x82, 0x4d, 0xdb, 0x11, 0xf3, 0xe5,
	0x7e, 0xae, 0x93, 0xd0, 0x03, 0x0e, 0x11, 0xa7,
	0x33, 0x4d, 0x3e, 0x99, 0x0d, 0x53, 0x77, 0xda,
	0xa3, 0x00, 0xaa, 0x2a, 0xf2, 0x53, 0x58, 0x5b
};

static unsigned char peer_ephemeral_pubkey_secp256r1[] = {
	0x74, 0xe6, 0x5f, 0x02, 0x90, 0xbf, 0x33, 0xe2,
	0xf3, 0xa1, 0x96, 0x27, 0x4b, 0xe1, 0x4c, 0xc1,
	0xbf, 0xd6, 0x44, 0x05, 0x53, 0xa8, 0xc8, 0x4f,
	0x9d, 0x55, 0x5f, 0x31, 0x33, 0x61, 0xe8, 0x28,
	0x3d, 0x15, 0xc1, 0x7e, 0x57, 0x0d, 0x9c, 0x8e,
	0xaf, 0xc2, 0x0b, 0xe4, 0x2f, 0xe2, 0xd0, 0xe6,
	0x27, 0x9f, 0x98, 0x9b, 0xb0, 0x05, 0xff, 0x72,
	0xec, 0xe7, 0xe0, 0xca, 0x59, 0x37, 0x25, 0x4a
};

static unsigned char shared_secret_expected[] = {
	0xa1, 0x85, 0x3e, 0xe2, 0x19, 0xe6, 0x5e, 0xed,
	0xf6, 0x8d, 0xda, 0x4a, 0x40, 0xb4, 0x4d, 0x45,
	0x15, 0xea, 0xab, 0xfe, 0x1a, 0x25, 0x8f, 0x84,
	0xac, 0x4f, 0xd1, 0x7c, 0xfe, 0x5e, 0xe6, 0x22
};

int iot_easysetup_ble_ecdh_setup(iot_security_context_t **state)
{
	iot_error_t err;
	iot_security_context_t *context;

#if !defined(CONFIG_STDK_IOT_CORE_SUPPORT_STNV_PARTITION)
	err = iot_nv_init((unsigned char *)sample_device_info, strlen(sample_device_info));
    printf("iot_nv_init[%d]\n", err);
#else
	err = iot_nv_init(NULL, 0);
#endif

	context = iot_security_init();

	err = iot_security_pk_init(context);

	err = iot_security_manager_init(context);

	err = iot_security_cipher_init(context);

	*state = context;

	return 0;
}

int iot_easysetup_ble_ecdh_teardown(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;

	context = (iot_security_context_t *)*state;

	err = iot_security_manager_deinit(context);

	err = iot_security_pk_deinit(context);

	err = iot_security_deinit(context);

	return err;
}

void iot_easysetup_ble_ecdh_compute_shared_secret_static_success(iot_security_context_t **state, 
								 unsigned char *sec_random, unsigned char **dev_cert, unsigned char **sub_cert, unsigned char **spub_key,
								 size_t *spub_key_len, unsigned char **signature, size_t *signature_len)
{
	iot_error_t err;
	iot_security_context_t *context;
	iot_security_cert_id_t cert_id;
	unsigned char random[ECDH_BLE_RANDOM_LEN * 2] = { 0 };
	unsigned char secret[IOT_SECURITY_SECRET_LEN] = { 0 };
	unsigned char iv[IOT_SECURITY_IV_LEN] = { 0 };
	size_t secret_len = sizeof(secret);
	size_t iv_len = sizeof(iv);
	int dump_raw = 0;

	memcpy(&random[0], sec_random, (ECDH_BLE_RANDOM_LEN * 2));

	if (dump_raw) {
		printf("<- random\n");
		iot_util_dump_mem("dump", random, (ECDH_BLE_RANDOM_LEN*2));
	}

	// <- certificates

	iot_security_buffer_t cert_device_buf = { 0 };
	iot_security_buffer_t cert_sub_buf = { 0 };
	iot_security_buffer_t cert_blob_buf = { 0 };

	context = (iot_security_context_t *)*state;

	cert_id = IOT_SECURITY_CERT_ID_DEVICE;
	err = iot_security_manager_get_certificate(context, cert_id, &cert_device_buf);

	if (dump_raw) {
		printf("<- leaf certificate\n");
		iot_util_dump_mem("dump", cert_device_buf.p, (int)cert_device_buf.len);
	}

	cert_id = IOT_SECURITY_CERT_ID_SUB_CA;
	err = iot_security_manager_get_certificate(context, cert_id, &cert_sub_buf);

	if (dump_raw) {
		printf("<- intermediate certificate\n");
		iot_util_dump_mem("dump", cert_sub_buf.p, (int)cert_sub_buf.len);
	}

	cert_blob_buf.len = cert_sub_buf.len + cert_device_buf.len;
	cert_blob_buf.p = (unsigned char *)iot_os_malloc(cert_blob_buf.len);
	memcpy(cert_blob_buf.p, cert_device_buf.p, cert_device_buf.len);
	memcpy(cert_blob_buf.p + cert_device_buf.len, cert_sub_buf.p, cert_sub_buf.len);

	*dev_cert = iot_os_malloc(cert_device_buf.len);
	*sub_cert = iot_os_malloc(cert_sub_buf.len);
	memcpy(*dev_cert, cert_device_buf.p, cert_device_buf.len);
	memcpy(*sub_cert, cert_sub_buf.p, cert_sub_buf.len);

	if (dump_raw) {
		printf("<- certificate blob\n");
		iot_util_dump_mem("dump", cert_blob_buf.p, (int)cert_blob_buf.len);
	}

	iot_os_free(cert_device_buf.p);
	iot_os_free(cert_sub_buf.p);
	iot_os_free(cert_blob_buf.p);

	// <- own public key
	iot_security_buffer_t own_pubkey_buf = { 0 };
	iot_security_buffer_t own_pubkey_der_buf = { 0 };

	err = iot_security_ecdh_init(context);

	iot_security_ecdh_params_t ecdh_params = { 0 };
	iot_security_buffer_t secret_buf = { 0 };

	ecdh_params.key_id = IOT_SECURITY_KEY_ID_EPHEMERAL;
	ecdh_params.salt.p = random;
	ecdh_params.salt.len = sizeof(random);

	err = iot_security_manager_generate_key(context, ecdh_params.key_id);
    err = iot_security_manager_get_key(context, ecdh_params.key_id, &own_pubkey_buf);

    own_pubkey_der_buf.len = own_pubkey_buf.len + sizeof(own_ephemeral_pubkey_secp256r1_der_header);

	own_pubkey_der_buf.p = (unsigned char *)iot_os_malloc(own_pubkey_der_buf.len);
    memcpy(own_pubkey_der_buf.p, own_ephemeral_pubkey_secp256r1_der_header, sizeof(own_ephemeral_pubkey_secp256r1_der_header));
	memcpy(own_pubkey_der_buf.p + sizeof(own_ephemeral_pubkey_secp256r1_der_header), own_pubkey_buf.p, own_pubkey_buf.len);

	*spub_key = iot_os_malloc(own_pubkey_der_buf.len);
	memcpy(*spub_key, own_pubkey_der_buf.p, own_pubkey_der_buf.len);
    *spub_key_len = own_pubkey_der_buf.len;

	if (dump_raw) {
		printf("<- own ephemeral public key\n");
		iot_util_dump_mem("dump", own_pubkey_der_buf.p, own_pubkey_der_buf.len);
	}

	// <- signature

	iot_security_buffer_t data_buf = { 0 };
	iot_security_buffer_t hash_buf = { 0 };
	iot_security_buffer_t sig_buf = { 0 };

	data_buf.len = own_pubkey_der_buf.len + sizeof(random);
	data_buf.p = (unsigned char *)iot_os_malloc(data_buf.len);

	memcpy(data_buf.p, own_pubkey_der_buf.p, own_pubkey_der_buf.len);
	memcpy(data_buf.p + own_pubkey_der_buf.len, random, sizeof(random));

	hash_buf.len = IOT_SECURITY_SHA256_LEN;
	hash_buf.p = (unsigned char *)iot_os_malloc(hash_buf.len);

	err = iot_security_sha256(data_buf.p, data_buf.len, hash_buf.p, hash_buf.len);

	if (dump_raw) {
		printf("-- hash\n");
		iot_util_dump_mem("dump", hash_buf.p, hash_buf.len);
	}

	err = iot_security_pk_sign(context, &hash_buf, &sig_buf);

	*signature = iot_os_malloc(sig_buf.len);
	memcpy(*signature, sig_buf.p, sig_buf.len);

    *signature_len = sig_buf.len;

	if (dump_raw) {
		printf("<- signature\n");
		iot_util_dump_mem("dump", sig_buf.p, sig_buf.len);
	}

	iot_os_free(data_buf.p);
	iot_os_free(hash_buf.p);
	iot_os_free(sig_buf.p);
	iot_os_free(own_pubkey_der_buf.p);
	iot_os_free(own_pubkey_buf.p);
}
