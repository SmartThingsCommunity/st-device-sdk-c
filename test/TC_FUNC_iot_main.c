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
#include <iot_capability.h>
#include <iot_easysetup.h>
#include <iot_internal.h>
#include <iot_main.h>
#include <iot_mqtt_client.h>
#include <iot_nv_data.h>
#include <iot_util.h>
#include <st_dev.h>
#include <stdbool.h>
#include <string.h>

#include "TC_MOCK_functions.h"
#include "cmocka_custom.h"

extern bool _con_timeout_check(struct iot_context *ctx);
extern iot_error_t _delete_dev_card_by_usr(struct iot_context *ctx);
extern iot_error_t _create_easysetup_resources(struct iot_context *ctx, iot_pin_t *pin_num);
extern void _command_work_handler(struct iot_context *ctx, device_work_param param);
extern void _next_connection_retry_timeout(iot_os_timer_handle handle, void *user_data);
extern void _iot_state_timeout_cb(iot_os_timer_handle handle, void *user_data);
extern void _get_device_preference(struct iot_context *ctx);
extern iot_error_t _create_easysetup_resources(struct iot_context *ctx, iot_pin_t *pin_num);

#define UNUSED(x) (void **)(x)

#define TEST_FIRMWARE_VERSION "testFirmwareVersion"
#define TEST_DEVICE_PUBLIC_B64_KEY "BKb7+m1Mo8OuMsodM91ohz/+rZKDc/otzUPSn4UkCUk="
#define TEST_DEVICE_SECRET_B64_KEY "ztqmQ24u86J9bpFLjaoMfwauUZwKLjUIGsnrDwwnDM8="
#define TEST_DEVICE_SERIAL_NUMBER "STDKtESt7968d226"
#define REG_TEST_DIP_ID "bb000ddd-92a0-42a3-86f0-b531f278af06"
static char sample_device_info[] = {
    "{\n"
    "\t\"deviceInfo\": {\n"
    "\t\t\"firmwareVersion\": \"" TEST_FIRMWARE_VERSION
    "\",\n"
    "\t\t\"privateKey\": \"" TEST_DEVICE_SECRET_B64_KEY
    "\",\n"
    "\t\t\"publicKey\": \"" TEST_DEVICE_PUBLIC_B64_KEY
    "\",\n"
    "\t\t\"serialNumber\": \"" TEST_DEVICE_SERIAL_NUMBER
    "\"\n"
    "\t}\n"
    "}"};

static char wrong_device_info_no_firmwareVersion[] = {
    "{\n"
    "\t\"deviceInfo\": {\n"
    "\t\t\"privateKey\": \"" TEST_DEVICE_SECRET_B64_KEY
    "\",\n"
    "\t\t\"publicKey\": \"" TEST_DEVICE_PUBLIC_B64_KEY
    "\",\n"
    "\t\t\"serialNumber\": \"" TEST_DEVICE_SERIAL_NUMBER
    "\"\n"
    "\t}\n"
    "}"};

#define TEST_ONBOARDING_MNID "fTST"
#define TEST_ONBOARDING_SETUPID "001"
#define TEST_ONBOARDING_VID "STDK_BULB_0001"
#define TEST_ONBOARDING_DEVICETYPEID "Switch"

static char sample_onboarding_config[] = {
    "{\n"
    "  \"onboardingConfig\": {\n"
    "    \"deviceOnboardingId\": \"STDK\",\n"
    "    \"mnId\": \"" TEST_ONBOARDING_MNID
    "\",\n"
    "    \"setupId\": \"" TEST_ONBOARDING_SETUPID
    "\",\n"
    "    \"vid\": \"" TEST_ONBOARDING_VID
    "\",\n"
    "    \"deviceTypeId\": \"" TEST_ONBOARDING_DEVICETYPEID
    "\",\n"
    "    \"ownershipValidationTypes\": [\n"
    "      \"BUTTON\"\n"
    "    ],\n"
    "    \"identityType\": \"ED25519\"\n"
    "  }\n"
    "}"};

static char wrong_onboarding_config_no_mnId[] = {
    "{\n"
    "  \"onboardingConfig\": {\n"
    "    \"deviceOnboardingId\": \"STDK\",\n"
    "    \"setupId\": \"001\",\n"
    "    \"vid\": \"STDK_BULB_0001\",\n"
    "    \"deviceTypeId\": \"Switch\",\n"
    "    \"ownershipValidationTypes\": [\n"
    "      \"BUTTON\"\n"
    "    ],\n"
    "    \"identityType\": \"ED25519\"\n"
    "  }\n"
    "}"};

void _dummy_client_callback(st_mqtt_event event, void *event_data, void *usr_data)
{
    UNUSED(event);
    UNUSED(event_data);
    UNUSED(usr_data);
    return;
}

static void _status_cb_test(st_device_status device_status, void *usr_data)
{
    return;
}

static void test_st_cap_noti_cb(iot_noti_data_t *noti_data, void *noti_usr_data)
{
    assert_non_null(noti_data);
    UNUSED(noti_usr_data);
}

void TC_st_conn_init_null_parameters(void **state)
{
    IOT_CTX *context;
    UNUSED(state);

    // Given: all parameters are null
    // When
    context = st_conn_init(NULL, 0, NULL, 0);
    // Then
    assert_null(context);

    // Given: null device_info
    // When
    context = st_conn_init(sample_onboarding_config, sizeof(sample_onboarding_config), NULL, 0);
    // Then
    assert_null(context);

    // Given: null onboarding_config
    // When
    context = st_conn_init(NULL, 0, sample_device_info, sizeof(sample_device_info));
    // Then
    assert_null(context);
}

void TC_st_conn_init_malloc_failure(void **state)
{
    IOT_CTX *context;
    UNUSED(state);

    // Given: malloc failure
    set_mock_iot_os_malloc_failure();
    // When
    context = st_conn_init(sample_onboarding_config, sizeof(sample_onboarding_config), sample_device_info,
                           sizeof(sample_device_info));
    // Then
    assert_null(context);

    // Teardown
    do_not_use_mock_iot_os_malloc_failure();
}

void TC_st_conn_init_wrong_onboarding_config(void **state)
{
    IOT_CTX *context;
    UNUSED(state);

    // Given: wrong onboarding config
    // When
    context = st_conn_init(wrong_onboarding_config_no_mnId, sizeof(wrong_onboarding_config_no_mnId), sample_device_info,
                           sizeof(sample_device_info));
    // Then
    assert_null(context);
}

void TC_st_conn_init_wrong_device_info(void **state)
{
    IOT_CTX *context;
    UNUSED(state);

    // Given: wrong device info
    // When
    context = st_conn_init(sample_onboarding_config, sizeof(sample_onboarding_config),
                           wrong_device_info_no_firmwareVersion, sizeof(wrong_device_info_no_firmwareVersion));
    // Then
    assert_null(context);
}

void TC_st_conn_init_success(void **state)
{
    IOT_CTX *context;
    struct iot_context *internal_context;
    size_t count = 0;
    UNUSED(state);

    // When
    context = st_conn_init(sample_onboarding_config, sizeof(sample_onboarding_config), sample_device_info,
                           sizeof(sample_device_info));
    // Then
    assert_non_null(context);
    internal_context = (struct iot_context *)context;
    assert_string_equal(internal_context->devconf.mnid, TEST_ONBOARDING_MNID);
    assert_string_equal(internal_context->devconf.vid, TEST_ONBOARDING_VID);
    assert_string_equal(internal_context->devconf.setupid, TEST_ONBOARDING_SETUPID);
    assert_string_equal(internal_context->devconf.device_type, TEST_ONBOARDING_DEVICETYPEID);
    assert_int_equal(internal_context->devconf.pk_type, IOT_SECURITY_KEY_TYPE_ED25519);
    assert_string_equal(internal_context->device_info.firmware_version, TEST_FIRMWARE_VERSION);
    assert_non_null(internal_context->work_queue);
    assert_non_null(internal_context->usr_events);
    assert_non_null(internal_context->iot_events);
    assert_non_null(internal_context->work_queue_thread);
    // Teardown
    iot_os_eventgroup_set_bits(internal_context->work_queue_signal, DEVICE_WORK_QUEUE_KILL_SIGNAL);
    while (internal_context->work_queue_thread && count < 100) {
        iot_os_delay(50);
        count++;
    }
    if (internal_context->work_queue_thread) {
        print_error("Failed to kill work queue thread\n");
        return;
    }
    iot_os_mutex_destroy(&internal_context->st_conn_lock);
    iot_os_eventgroup_delete(internal_context->work_queue_signal);
    iot_os_eventgroup_delete(internal_context->iot_events);
    iot_os_eventgroup_delete(internal_context->usr_events);
    iot_util_queue_delete(internal_context->work_queue);
    iot_api_device_info_mem_free(&internal_context->device_info);
    iot_api_onboarding_config_mem_free(&internal_context->devconf);
    iot_nv_deinit();
    iot_os_free(internal_context);
}

void TC_st_change_health_period_null_context(void **state)
{
    int err;
    UNUSED(state);

    // When: NULL context
    err = st_change_health_period(NULL, 300);
    // Then
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);
}

void TC_st_change_health_period_invalid_context(void **state)
{
    int err;
    struct iot_context context = {0};
    UNUSED(state);

    // When: invalid context (not connected to cloud)
    err = st_change_health_period((IOT_CTX *)&context, 300);
    // Then
    assert_int_equal(err, IOT_ERROR_BAD_REQ);
}

struct mqtt_pub_test_data {
    int qos;
    char *topic;
    char *payload;
    char pub_fixed_header;
    char response_fixed_header;
};

void TC_st_change_health_period_success(void **state)
{
    int err;
    iot_error_t iot_err;
    struct iot_context *context;
    UNUSED(state);

    st_mqtt_client client;
    MQTTClient *c;

    // Given
    context = (struct iot_context *)calloc(1, sizeof(struct iot_context));
    assert_non_null(context);

    context->curr_state = IOT_STATE_CLOUD_CONNECTED;
    context->mqtt_health_topic = "/health/topic";  // health topic

    err = st_mqtt_create(&client, _dummy_client_callback, NULL, NULL, NULL);
    assert_return_code(err, 0);
    c = (MQTTClient *)client;
    c->isconnected = 1;
    port_net_mock_reset_socket_status(1);
    c->last_sent = iot_os_timer_create(NULL, 10000, NULL);
    iot_err = iot_os_timer_start(c->last_sent);
    assert_int_equal(iot_err, IOT_ERROR_NONE);

    c->last_received = iot_os_timer_create(NULL, 10000, NULL);
    iot_err = iot_os_timer_start(c->last_received);
    assert_int_equal(iot_err, IOT_ERROR_NONE);

    context->evt_mqttcli = (st_mqtt_client)client;  // Mock MQTT client

    char expected_payload[] = "{\"status\":\"changePeriod\",\"newPeriod\":300}";
    size_t expected_payload_len = strlen(expected_payload);

    // Calculate MQTT publish packet structure
    size_t mqtt_publish_header_len =
        2 + 2 + strlen(context->mqtt_health_topic) + 2;  // Fixed header + topic length + topic + packet ID
    char *mqtt_publish = malloc(mqtt_publish_header_len + expected_payload_len);
    assert_non_null(mqtt_publish);

    unsigned int header_index = 0;
    // Fixed header for PUBLISH QoS1
    mqtt_publish[header_index++] = 0x32;  // PUBLISH QoS1
    mqtt_publish[header_index++] =
        (char)(2 + strlen(context->mqtt_health_topic) + 2 + expected_payload_len);  // Remaining Length

    // Topic length
    mqtt_publish[header_index++] = 0x00;
    mqtt_publish[header_index++] = (char)strlen(context->mqtt_health_topic);

    // Topic
    for (size_t j = 0; j < strlen(context->mqtt_health_topic); j++) {
        mqtt_publish[header_index++] = context->mqtt_health_topic[j];
    }

    // Packet ID
    char packet_id_msb = 0x00;
    char packet_id_lsb = (char)(c->next_packetid + 1);
    mqtt_publish[header_index++] = packet_id_msb;
    mqtt_publish[header_index++] = packet_id_lsb;

    // Payload
    memcpy(&mqtt_publish[header_index], expected_payload, expected_payload_len);

    // Set up mock expectations for the actual payload that will be sent
    expect_value(__wrap_port_net_write, len, mqtt_publish_header_len + expected_payload_len);
    expect_memory(__wrap_port_net_write, buf, mqtt_publish, mqtt_publish_header_len + expected_payload_len);

    // Set up mock response (PUBACK for QoS1)
    unsigned char mock_read_buffer_puback[4];
    mock_read_buffer_puback[0] = 0x40;  // PUBACK fixed header
    mock_read_buffer_puback[1] = 0x02;  // Remaining Length
    mock_read_buffer_puback[2] = packet_id_msb;
    mock_read_buffer_puback[3] = packet_id_lsb;
    port_net_mock_reset_read_stream(mock_read_buffer_puback, 4);

    // When: valid parameters
    err = st_change_health_period((IOT_CTX *)context, 300);
    assert_int_equal(err, IOT_ERROR_NONE);

    // Teardown
    free(mqtt_publish);
    free(context);
}

void TC_create_easysetup_resources_pin_type_null_pin(void **state)
{
    iot_error_t result;
    struct iot_context context = {0};
    UNUSED(state);

    // Given: PIN type ownership validation but NULL pin_num
    context.devconf.ownership_validation_type = IOT_OVF_TYPE_PIN;
    context.pin = NULL;

    // When: PIN type with NULL pin_num
    result = _create_easysetup_resources(&context, NULL);
    // Then: should return IOT_ERROR_INVALID_ARGS
    assert_int_equal(result, IOT_ERROR_INVALID_ARGS);
    // Verify cleanup was called
    assert_null(context.pin);
    assert_null(context.easysetup_security_context);
    assert_null(context.easysetup_resp_queue);
}

void TC_create_easysetup_resources_pin_malloc_failure(void **state)
{
    iot_error_t result;
    struct iot_context context = {0};
    iot_pin_t pin_data = {0};
    UNUSED(state);

    // Given: PIN type ownership validation with valid pin_num
    context.devconf.ownership_validation_type = IOT_OVF_TYPE_PIN;
    context.pin = NULL;

    // Setup: malloc failure for pin allocation
    set_mock_iot_os_malloc_failure();

    // When: Memory allocation failure for pin
    result = _create_easysetup_resources(&context, &pin_data);
    // Then: should return IOT_ERROR_MEM_ALLOC
    assert_int_equal(result, IOT_ERROR_MEM_ALLOC);
    // Verify cleanup was called
    assert_null(context.pin);
    assert_null(context.easysetup_security_context);
    assert_null(context.easysetup_resp_queue);

    // Teardown
    do_not_use_mock_iot_os_malloc_failure();
}

void TC_st_change_device_name_null_context(void **state)
{
    int result;
    UNUSED(state);

    // When: NULL context
    result = st_change_device_name(NULL, "new_device_name");
    // Then
    assert_int_equal(result, IOT_ERROR_INVALID_ARGS);
}

void TC_st_change_device_name_null_new_name(void **state)
{
    int result;
    struct iot_context context = {0};
    UNUSED(state);

    // When: NULL new_name
    result = st_change_device_name((IOT_CTX *)&context, NULL);
    // Then
    assert_int_equal(result, IOT_ERROR_INVALID_ARGS);
}

void TC_st_change_device_name_invalid_context_state(void **state)
{
    int result;
    struct iot_context context = {0};
    UNUSED(state);

    // Given: Context not in connected state
    context.curr_state = IOT_STATE_INITIALIZED;  // Not connected
    context.evt_mqttcli = (st_mqtt_client)1;     // Valid MQTT client

    // When: Invalid context state
    result = st_change_device_name((IOT_CTX *)&context, "new_device_name");
    // Then
    assert_int_equal(result, IOT_ERROR_BAD_REQ);
}

void TC_st_change_device_name_null_mqtt_client(void **state)
{
    int result;
    struct iot_context context = {0};
    UNUSED(state);

    // Given: Context in connected state but NULL MQTT client
    context.curr_state = IOT_STATE_CLOUD_CONNECTED;
    context.evt_mqttcli = NULL;  // NULL MQTT client

    // When: NULL MQTT client
    result = st_change_device_name((IOT_CTX *)&context, "new_device_name");
    // Then
    assert_int_equal(result, IOT_ERROR_BAD_REQ);
}

void TC_st_change_device_name_name_too_long(void **state)
{
    int result;
    struct iot_context context = {0};
    char long_name[IOT_DEVICE_NAME_MAX_LENGTH + 2];  // One character too long
    UNUSED(state);

    // Given: Context in connected state with valid MQTT client
    context.curr_state = IOT_STATE_CLOUD_CONNECTED;
    context.evt_mqttcli = (st_mqtt_client)1;  // Valid MQTT client

    // Create a string that's one character too long
    memset(long_name, 'a', sizeof(long_name) - 1);
    long_name[sizeof(long_name) - 1] = '\0';

    // When: new_name exceeding maximum length
    result = st_change_device_name((IOT_CTX *)&context, long_name);
    // Then
    assert_int_equal(result, IOT_ERROR_INVALID_ARGS);
}

void TC_st_change_device_name_success(void **state)
{
    int result;
    int err;
    iot_error_t iot_err;
    struct iot_context *context;
    st_mqtt_client client;
    MQTTClient *c;
    UNUSED(state);

    // Given
    context = (struct iot_context *)calloc(1, sizeof(struct iot_context));
    assert_non_null(context);

    context->curr_state = IOT_STATE_CLOUD_CONNECTED;

    err = st_mqtt_create(&client, _dummy_client_callback, NULL, NULL, NULL);
    assert_return_code(err, 0);
    c = (MQTTClient *)client;
    c->isconnected = 1;
    port_net_mock_reset_socket_status(1);
    c->last_sent = iot_os_timer_create(NULL, 10000, NULL);
    iot_err = iot_os_timer_start(c->last_sent);
    assert_int_equal(iot_err, IOT_ERROR_NONE);

    c->last_received = iot_os_timer_create(NULL, 10000, NULL);
    iot_err = iot_os_timer_start(c->last_received);
    assert_int_equal(iot_err, IOT_ERROR_NONE);

    context->evt_mqttcli = (st_mqtt_client)client;

    // Set up mock expectations for the actual payload that will be sent
    set_mock_port_net_write_skip_buf_check(1);  // Skip buffer content checking
    set_mock_port_net_write_skip_len_check(1);  // Skip length checking

    // Set up mock response (PUBACK for QoS1)
    unsigned char mock_read_buffer_puback[4];
    mock_read_buffer_puback[0] = 0x40;  // PUBACK fixed header
    mock_read_buffer_puback[1] = 0x02;  // Remaining Length

    char packet_id_msb = 0x00;
    char packet_id_lsb = (char)(c->next_packetid + 1);
    mock_read_buffer_puback[2] = packet_id_msb;
    mock_read_buffer_puback[3] = packet_id_lsb;
    port_net_mock_reset_read_stream(mock_read_buffer_puback, 4);

    // When: valid parameters
    result = st_change_device_name((IOT_CTX *)context, "new_device_name");
    // Then
    assert_int_equal(result, IOT_ERROR_NONE);

    reset_mock_port_net_write_skip_flags();

    // Teardown
    st_mqtt_destroy(client);
    free(context);
}

void TC_con_timeout_check_null_timer(void **state)
{
    bool result;
    struct iot_context context = {0};
    UNUSED(state);

    // Given: context with cloud_con_timer set to NULL (default initialization)
    // When: _con_timeout_check is called with this context
    result = _con_timeout_check(&context);
    // Then: should return false
    assert_false(result);
}

void TC_con_timeout_check_timer_expired(void **state)
{
    bool result;
    struct iot_context context = {0};
    iot_error_t iot_err;
    UNUSED(state);

    // Given: context with cloud_con_timer created and expired
    context.cloud_con_timer = iot_os_timer_create(NULL, 1, NULL);  // 1ms timeout
    assert_non_null(context.cloud_con_timer);

    iot_err = iot_os_timer_start(context.cloud_con_timer);
    assert_int_equal(iot_err, IOT_ERROR_NONE);

    iot_os_delay(10);  // Wait for timer to expire

    // When: _con_timeout_check is called with this context
    result = _con_timeout_check(&context);
    // Then: should return true
    assert_true(result);

    // Teardown
    iot_os_timer_delete(context.cloud_con_timer);
}

void TC_st_info_get_null_context(void **state)
{
    int err;
    iot_info_data_t info_data = {0};
    UNUSED(state);

    // When: NULL context
    err = st_info_get(NULL, IOT_INFO_TYPE_IOT_DEVICE_STATUS, &info_data);
    // Then
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);
}

void TC_st_info_get_null_info_data(void **state)
{
    int err;
    struct iot_context context = {0};
    UNUSED(state);

    // When: NULL info_data
    err = st_info_get((IOT_CTX *)&context, IOT_INFO_TYPE_IOT_DEVICE_STATUS, NULL);
    // Then
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);
}

void TC_st_info_get_invalid_info_type(void **state)
{
    int err;
    struct iot_context context = {0};
    iot_info_data_t info_data = {0};
    UNUSED(state);

    // Initialize context with minimal valid fields to pass IS_CTX_VALID check
    context.work_queue = (void *)1;  // Non-NULL to pass validation
    context.usr_events = (void *)1;
    context.iot_events = (void *)1;
    iot_os_mutex_init(&context.st_conn_lock);  // Initialize mutex

    // When: invalid info_type
    err = st_info_get((IOT_CTX *)&context, (iot_info_type_t)999, &info_data);
    // Then
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);

    // Teardown
    iot_os_mutex_destroy(&context.st_conn_lock);
}

void TC_st_info_get_missing_broker_url(void **state)
{
    int err;
    struct iot_context context = {0};
    iot_info_data_t info_data = {0};
    UNUSED(state);

    // Given :
    context.work_queue = (void *)1;
    context.usr_events = (void *)1;
    context.iot_events = (void *)1;
    context.prov_data.cloud.broker_url = NULL;  // No broker URL

    // When: IOT_INFO_TYPE_IOT_SERVER_ENV with no broker_url
    err = st_info_get((IOT_CTX *)&context, IOT_INFO_TYPE_IOT_SERVER_ENV, &info_data);
    // Then
    assert_int_equal(err, IOT_ERROR_BAD_REQ);
}

void TC_st_info_get_invalid_context_missing_fields(void **state)
{
    int err;
    struct iot_context context = {0};
    iot_info_data_t info_data = {0};
    UNUSED(state);

    // Given :
    context.work_queue = NULL;
    context.usr_events = (void *)1;
    context.iot_events = (void *)1;

    // When: invalid context (missing work_queue)
    err = st_info_get((IOT_CTX *)&context, IOT_INFO_TYPE_IOT_DEVICE_STATUS, &info_data);
    // Then
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);
}

void TC_st_info_get_status_and_stat_success(void **state)
{
    int err;
    struct iot_context context = {0};
    iot_info_data_t info_data = {0};
    UNUSED(state);

    // Given
    context.work_queue = (void *)1;
    context.usr_events = (void *)1;
    context.iot_events = (void *)1;

    // Initialize mutex
    iot_os_mutex_init(&context.st_conn_lock);

    // When: valid IOT_INFO_TYPE_IOT_DEVICE_STATUS request
    err = st_info_get((IOT_CTX *)&context, IOT_INFO_TYPE_IOT_DEVICE_STATUS, &info_data);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);

    // Teardown
    iot_os_mutex_destroy(&context.st_conn_lock);
}

void TC_st_info_get_provisioned_success(void **state)
{
    int err;
    struct iot_context context = {0};
    iot_info_data_t info_data = {0};
    UNUSED(state);

    // Given :
    context.work_queue = (void *)1;
    context.usr_events = (void *)1;
    context.iot_events = (void *)1;

    // Initialize mutex
    iot_os_mutex_init(&context.st_conn_lock);

    // When: valid IOT_INFO_TYPE_IOT_PROVISIONED request
    err = st_info_get((IOT_CTX *)&context, IOT_INFO_TYPE_IOT_PROVISIONED, &info_data);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);

    // Teardown
    iot_os_mutex_destroy(&context.st_conn_lock);
}

void TC_st_info_get_server_env_prod_ap_northeast2_success(void **state)
{
    int err;
    struct iot_context context = {0};
    iot_info_data_t info_data = {0};
    UNUSED(state);

    // Given :
    context.work_queue = (void *)1;
    context.usr_events = (void *)1;
    context.iot_events = (void *)1;

    iot_os_mutex_init(&context.st_conn_lock);

    context.prov_data.cloud.broker_url = "mqtt-regional-apnortheast2.api.smartthings.com";

    // When: valid IOT_INFO_TYPE_IOT_SERVER_ENV request
    err = st_info_get((IOT_CTX *)&context, IOT_INFO_TYPE_IOT_SERVER_ENV, &info_data);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_int_equal(info_data.server_env, SERVER_ENV_PRD);

    // Teardown
    iot_os_mutex_destroy(&context.st_conn_lock);
}

void TC_st_info_get_server_env_prod_us_east1_success(void **state)
{
    int err;
    struct iot_context context = {0};
    iot_info_data_t info_data = {0};
    UNUSED(state);

    // Given :
    context.work_queue = (void *)1;
    context.usr_events = (void *)1;
    context.iot_events = (void *)1;

    // Initialize mutex
    iot_os_mutex_init(&context.st_conn_lock);

    // Set a broker_url that matches one of the recognized server URLs
    context.prov_data.cloud.broker_url = "mqtt-regional-useast1.api.smartthings.com";

    // When: valid IOT_INFO_TYPE_IOT_SERVER_ENV request
    err = st_info_get((IOT_CTX *)&context, IOT_INFO_TYPE_IOT_SERVER_ENV, &info_data);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_int_equal(info_data.server_env, SERVER_ENV_PRD);

    // Teardown
    iot_os_mutex_destroy(&context.st_conn_lock);
}

void TC_st_info_get_server_env_prod_eu_west1_success(void **state)
{
    int err;
    struct iot_context context = {0};
    iot_info_data_t info_data = {0};
    UNUSED(state);

    // Given :
    context.work_queue = (void *)1;
    context.usr_events = (void *)1;
    context.iot_events = (void *)1;

    // Initialize mutex
    iot_os_mutex_init(&context.st_conn_lock);

    // Set a broker_url that matches one of the recognized server URLs
    context.prov_data.cloud.broker_url = "mqtt-regional-euwest1.api.smartthings.com";

    // When: valid IOT_INFO_TYPE_IOT_SERVER_ENV request
    err = st_info_get((IOT_CTX *)&context, IOT_INFO_TYPE_IOT_SERVER_ENV, &info_data);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_int_equal(info_data.server_env, SERVER_ENV_PRD);

    // Teardown
    iot_os_mutex_destroy(&context.st_conn_lock);
}

void TC_st_info_get_server_env_prod_china_success(void **state)
{
    int err;
    struct iot_context context = {0};
    iot_info_data_t info_data = {0};
    UNUSED(state);

    // Given :
    context.work_queue = (void *)1;
    context.usr_events = (void *)1;
    context.iot_events = (void *)1;

    // Initialize mutex
    iot_os_mutex_init(&context.st_conn_lock);

    // Set a broker_url that matches one of the recognized server URLs
    context.prov_data.cloud.broker_url = "mqtt-regional-cnnorth1.samsungiotcloud.cn";

    // When: valid IOT_INFO_TYPE_IOT_SERVER_ENV request
    err = st_info_get((IOT_CTX *)&context, IOT_INFO_TYPE_IOT_SERVER_ENV, &info_data);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_int_equal(info_data.server_env, SERVER_ENV_PRD);

    // Teardown
    iot_os_mutex_destroy(&context.st_conn_lock);
}

void TC_st_info_get_server_env_acc_us_east2_success(void **state)
{
    int err;
    struct iot_context context = {0};
    iot_info_data_t info_data = {0};
    UNUSED(state);

    // Given :
    context.work_queue = (void *)1;
    context.usr_events = (void *)1;
    context.iot_events = (void *)1;

    // Initialize mutex
    iot_os_mutex_init(&context.st_conn_lock);

    // Set a broker_url that matches one of the recognized server URLs
    context.prov_data.cloud.broker_url = "mqtt-acceptance-useast2.stacceptance.com";

    // When: valid IOT_INFO_TYPE_IOT_SERVER_ENV request
    err = st_info_get((IOT_CTX *)&context, IOT_INFO_TYPE_IOT_SERVER_ENV, &info_data);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_int_equal(info_data.server_env, SERVER_ENV_ACC);

    // Teardown
    iot_os_mutex_destroy(&context.st_conn_lock);
}

void TC_st_info_get_server_env_stg_us_east1_success(void **state)
{
    int err;
    struct iot_context context = {0};
    iot_info_data_t info_data = {0};
    UNUSED(state);

    // Given :
    context.work_queue = (void *)1;
    context.usr_events = (void *)1;
    context.iot_events = (void *)1;

    // Initialize mutex
    iot_os_mutex_init(&context.st_conn_lock);

    // Set a broker_url that matches one of the recognized server URLs
    context.prov_data.cloud.broker_url = "mqtt-staging-useast1.smartthingsgdev.com";

    // When: valid IOT_INFO_TYPE_IOT_SERVER_ENV request
    err = st_info_get((IOT_CTX *)&context, IOT_INFO_TYPE_IOT_SERVER_ENV, &info_data);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_int_equal(info_data.server_env, SERVER_ENV_STG);

    // Teardown
    iot_os_mutex_destroy(&context.st_conn_lock);
}

void TC_st_info_get_server_env_stg_china_success(void **state)
{
    int err;
    struct iot_context context = {0};
    iot_info_data_t info_data = {0};
    UNUSED(state);

    // Given :
    context.work_queue = (void *)1;
    context.usr_events = (void *)1;
    context.iot_events = (void *)1;

    // Initialize mutex
    iot_os_mutex_init(&context.st_conn_lock);

    // Set a broker_url that matches one of the recognized server URLs
    context.prov_data.cloud.broker_url = "mqtt-staging-cnnorth1.samsungiots.cn";

    // When: valid IOT_INFO_TYPE_IOT_SERVER_ENV request
    err = st_info_get((IOT_CTX *)&context, IOT_INFO_TYPE_IOT_SERVER_ENV, &info_data);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_int_equal(info_data.server_env, SERVER_ENV_STG);

    // Teardown
    iot_os_mutex_destroy(&context.st_conn_lock);
}

void TC_st_info_get_server_env_dev_us_east1_success(void **state)
{
    int err;
    struct iot_context context = {0};
    iot_info_data_t info_data = {0};
    UNUSED(state);

    // Given :
    context.work_queue = (void *)1;
    context.usr_events = (void *)1;
    context.iot_events = (void *)1;

    // Initialize mutex
    iot_os_mutex_init(&context.st_conn_lock);

    // Set a broker_url that matches one of the recognized server URLs
    context.prov_data.cloud.broker_url = "mqtt-dev-useast1.smartthingsgdev.com";

    // When: valid IOT_INFO_TYPE_IOT_SERVER_ENV request
    err = st_info_get((IOT_CTX *)&context, IOT_INFO_TYPE_IOT_SERVER_ENV, &info_data);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_int_equal(info_data.server_env, SERVER_ENV_DEV);

    // Teardown
    iot_os_mutex_destroy(&context.st_conn_lock);
}

void TC_st_info_get_server_env_unknown_server_success(void **state)
{
    int err;
    struct iot_context context = {0};
    iot_info_data_t info_data = {0};
    UNUSED(state);

    // Given :
    context.work_queue = (void *)1;
    context.usr_events = (void *)1;
    context.iot_events = (void *)1;

    // Initialize mutex
    iot_os_mutex_init(&context.st_conn_lock);

    // Set a broker_url that doesn't match any known server URLs
    context.prov_data.cloud.broker_url = "mqtt-unknown-server.example.com";

    // When: valid IOT_INFO_TYPE_IOT_SERVER_ENV request with unknown server
    err = st_info_get((IOT_CTX *)&context, IOT_INFO_TYPE_IOT_SERVER_ENV, &info_data);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_int_equal(info_data.server_env, SERVER_ENV_UNKNOWN);

    // Teardown
    iot_os_mutex_destroy(&context.st_conn_lock);
}

void TC_st_conn_start_null_context(void **state)
{
    int err;
    UNUSED(state);

    // When: NULL context
    err = st_conn_start(NULL, NULL, NULL, NULL);
    // Then
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);
}

void TC_st_conn_start_invalid_context(void **state)
{
    int err;
    struct iot_context context = {0};
    UNUSED(state);

    // When: invalid context (missing required fields)
    err = st_conn_start((IOT_CTX *)&context, NULL, NULL, NULL);
    // Then
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);
}

void TC_st_conn_start_already_running(void **state)
{
    int err;
    struct iot_context context = {0};
    UNUSED(state);

    // Given :
    context.work_queue = (void *)1;
    context.usr_events = (void *)1;
    context.iot_events = (void *)1;

    context.curr_state = IOT_STATE_PROV_ENTER;

    // When: context with already running state
    err = st_conn_start((IOT_CTX *)&context, NULL, NULL, NULL);
    // Then
    assert_int_equal(err, IOT_ERROR_BAD_REQ);
}

void TC_st_conn_start_missing_status_cb(void **state)
{
    int err;
    struct iot_context context = {0};
    UNUSED(state);

    // Given :
    context.work_queue = (void *)1;
    context.usr_events = (void *)1;
    context.iot_events = (void *)1;

    // Set context to have BUTTON ownership validation type
    context.devconf.ownership_validation_type = IOT_OVF_TYPE_BUTTON;

    // Set context to IOT_STATE_INITIALIZED
    context.curr_state = IOT_STATE_INITIALIZED;

    // When: BUTTON ownership validation but no status callback
    err = st_conn_start((IOT_CTX *)&context, NULL, NULL, NULL);
    // Then
    assert_int_equal(err, IOT_ERROR_BAD_REQ);
}

void TC_st_conn_start_ex_null_context(void **state)
{
    int err;
    iot_ext_args_t ext_args = {0};
    UNUSED(state);

    // When: NULL context
    err = st_conn_start_ex(NULL, &ext_args);
    // Then
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);
}

void TC_st_conn_start_ex_null_ext_args(void **state)
{
    int err;
    struct iot_context context = {0};
    UNUSED(state);

    // Given
    context.work_queue = (void *)1;
    context.usr_events = (void *)1;
    context.iot_events = (void *)1;

    // When: NULL ext_args
    err = st_conn_start_ex((IOT_CTX *)&context, NULL);
    // Then
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);
}

void TC_st_conn_start_ex_invalid_start_pt(void **state)
{
    int err;
    struct iot_context context = {0};
    iot_ext_args_t ext_args = {0};
    UNUSED(state);

    // Given :
    context.work_queue = (void *)1;
    context.usr_events = (void *)1;
    context.iot_events = (void *)1;

    // Set invalid start_from_onboarding value
    ext_args.start_from_onboarding = false;  // Invalid value for this test

    // When: invalid start_from_onboarding
    err = st_conn_start_ex((IOT_CTX *)&context, &ext_args);
    // Then
    assert_int_equal(err, IOT_ERROR_BAD_REQ);
}

void TC_st_conn_start_ex_missing_status_cb(void **state)
{
    int err;
    struct iot_context context = {0};
    iot_ext_args_t ext_args = {0};
    UNUSED(state);

    // Given :
    context.work_queue = (void *)1;
    context.usr_events = (void *)1;
    context.iot_events = (void *)1;

    // Set context to have BUTTON ownership validation type
    context.devconf.ownership_validation_type = IOT_OVF_TYPE_BUTTON;

    // Set ext_args for provisioning without skipping user confirm and without status_cb
    ext_args.start_from_onboarding = true;
    ext_args.skip_usr_confirm = false;
    ext_args.status_cb = NULL;

    // When: missing status callback for BUTTON validation
    err = st_conn_start_ex((IOT_CTX *)&context, &ext_args);
    // Then
    assert_int_equal(err, IOT_ERROR_BAD_REQ);
}

void TC_st_conn_cleanup_invalid_parameters(void **state)
{
    IOT_CTX *context;
    int err;
    UNUSED(state);

    // When: Null iot_ctx
    err = st_conn_cleanup(NULL, false);
    // Then
    assert_int_not_equal(err, 0);

    // Given: empty context
    context = (IOT_CTX *)malloc(sizeof(struct iot_context));
    memset(context, '\0', sizeof(struct iot_context));
    // When: empty iot_ctx
    err = st_conn_cleanup(context, false);
    // Then
    assert_int_not_equal(err, 0);
    // Teardown
    free(context);
}

void TC_st_conn_cleanup_success(void **state)
{
    IOT_CTX *context;
    struct iot_context *internal_context;
    int err;
    iot_os_thread test_thread;
    UNUSED(state);

    // Given
    internal_context = malloc(sizeof(struct iot_context));
    assert_non_null(internal_context);
    memset(internal_context, '\0', sizeof(struct iot_context));
    context = (IOT_CTX *)internal_context;
    internal_context->work_queue = iot_util_queue_create(sizeof(device_work_data_t));
    assert_non_null(internal_context->work_queue);
    internal_context->usr_events = iot_os_eventgroup_create();
    assert_non_null(internal_context->usr_events);
    internal_context->iot_events = iot_os_eventgroup_create();
    assert_non_null(internal_context->iot_events);
    err = iot_os_mutex_init(&internal_context->st_conn_lock);
    assert_int_equal(err, IOT_OS_TRUE);
    // When: Null iot_ctx
    err = st_conn_cleanup(context, false);
    // Then
    assert_return_code(err, 0);
    // Teardown
    iot_util_queue_delete(internal_context->work_queue);
    iot_os_eventgroup_delete(internal_context->usr_events);
    iot_os_eventgroup_delete(internal_context->iot_events);
    iot_os_mutex_destroy(&internal_context->st_conn_lock);
    free(internal_context);
}

extern void _delete_easysetup_resources_all(struct iot_context *ctx);

void TC_easysetup_resources_create_delete_success(void **state)
{
    iot_error_t err;
    struct iot_context *context;
    UNUSED(state);

    set_mock_detect_memory_leak(true);
    // Given: pin type context
    iot_pin_t pin = {.pin = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}};
    context = (struct iot_context *)calloc(1, sizeof(struct iot_context));
    context->devconf.ownership_validation_type = IOT_OVF_TYPE_PIN;

    // When: create resource
    err = _create_easysetup_resources(context, &pin);
    // Then: success and has proper resources
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_memory_equal(&pin.pin, context->pin, sizeof(iot_pin_t));
    assert_non_null(context->easysetup_security_context);
    assert_non_null(context->easysetup_resp_queue);
    assert_true(context->es_res_created);

    // When: delete resource
    _delete_easysetup_resources_all(context);
    // Then: verify deletion
    assert_null(context->pin);
    assert_null(context->easysetup_security_context);
    assert_null(context->easysetup_resp_queue);
    assert_false(context->es_res_created);

    set_mock_detect_memory_leak(false);
}

extern iot_error_t _check_prov_data_validation(struct iot_device_prov_data *prov_data);

struct _prov_test_data {
    iot_error_t expected;
    char *ssid;
    char *url;
    int num;
};

static struct iot_device_prov_data *_generate_test_prov_data(struct _prov_test_data data)
{
    struct iot_device_prov_data *prov_data;
    struct iot_wifi_prov_data *wifi_prov;
    struct iot_cloud_prov_data *cloud_prov;

    prov_data = (struct iot_device_prov_data *)calloc(1, sizeof(struct iot_device_prov_data));
    assert_non_null(prov_data);
    wifi_prov = &prov_data->wifi;
    cloud_prov = &prov_data->cloud;
    if (data.ssid) {
        strncpy(wifi_prov->ssid, data.ssid, sizeof(wifi_prov->ssid) - 1);
    }
    if (data.url) {
        cloud_prov->broker_url = strdup(data.url);
    }

    cloud_prov->broker_port = data.num;

    return prov_data;
}

void TC_check_prov_data_validation(void **state)
{
    iot_error_t err;
    struct _prov_test_data test_set[] = {
        {IOT_ERROR_NONE, "TestSsid", "test.domain.com", 443},
        {IOT_ERROR_INVALID_ARGS, NULL, "test.domain.com", 443},
        {IOT_ERROR_INVALID_ARGS, "TestSsid", NULL, 443},
        {IOT_ERROR_INVALID_ARGS, "TestSsid", "test.domain.com", -5},
    };

    for (int i = 0; i < sizeof(test_set) / sizeof(struct _prov_test_data); i++) {
        // Given
        struct iot_device_prov_data *prov_data = _generate_test_prov_data(test_set[i]);
        // When
        err = _check_prov_data_validation(prov_data);
        // Then
        assert_int_equal(err, test_set[i].expected);
        // Teardown
        free(prov_data);
    }
}

extern iot_error_t iot_command_send(struct iot_context *ctx, enum iot_command_type new_cmd, const void *param,
                                    int param_size);
extern iot_error_t iot_put_device_work(struct iot_context *ctx, device_work_handler handler, device_work_param param);

void TC_iot_command_send_success(void **state)
{
    iot_error_t err;
    struct iot_context *context;
    struct iot_command test_cmd = {0};
    UNUSED(state);

    // Given: valid context with work queue and mutex
    context = (struct iot_context *)calloc(1, sizeof(struct iot_context));
    assert_non_null(context);
    context->work_queue = iot_util_queue_create(sizeof(struct iot_command));
    assert_non_null(context->work_queue);
    context->work_queue_signal = iot_os_eventgroup_create();
    assert_non_null(context->work_queue_signal);
    // Initialize required fields to avoid segmentation fault
    iot_os_mutex_init(&context->st_conn_lock);

    // When: valid parameters
    err = iot_command_send(context, IOT_COMMAND_STATE_UPDATE, &test_cmd, sizeof(test_cmd));
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);

    // Teardown
    iot_util_queue_delete(context->work_queue);
    iot_os_eventgroup_delete(context->work_queue_signal);
    iot_os_mutex_destroy(&context->st_conn_lock);
    free(context);
}

extern iot_error_t _do_iot_main_command(struct iot_context *ctx, struct iot_command *cmd);

void TC_do_iot_main_command_state_update_positive(void **state)
{
    iot_error_t err;
    struct iot_command cmd = {0};
    struct iot_state_data state_data = {0};

    // Given:
    struct iot_context *context = (struct iot_context *)*state;
    context->work_queue = iot_util_queue_create(sizeof(struct iot_command));
    assert_non_null(context->work_queue);
    context->work_queue_signal = iot_os_eventgroup_create();
    assert_non_null(context->work_queue_signal);
    iot_os_mutex_init(&context->st_conn_lock);
    context->status_cb = _status_cb_test;
    context->child_device_list = (iot_child_device *)iot_os_malloc(sizeof(iot_child_device));
    memset(context->child_device_list, '\0', sizeof(iot_child_device));
    context->child_device_list->noti_cb = test_st_cap_noti_cb;
    context->child_device_list->next = NULL;  // Ensure the next pointer is NULL
    context->status_usr_data = NULL;
    context->state_timer = iot_os_timer_create(NULL, 10000, NULL);
    iot_os_timer_start(context->state_timer);
    context->cap_handle_list = NULL;
    err = st_mqtt_create(&context->evt_mqttcli, _dummy_client_callback, NULL, NULL, NULL);
    assert_return_code(err, 0);
    context->es_ble_ready = false;

    context->curr_state = IOT_STATE_INITIALIZED;
    cmd.cmd_type = IOT_COMMAND_STATE_UPDATE;
    cmd.param = &state_data;
    state_data.iot_state = IOT_STATE_PROV_ENTER;
    state_data.opt = IOT_STATE_OPT_NONE;

    // When:
    err = _do_iot_main_command(context, &cmd);

    // Then: should return IOT_ERROR_NONE
    assert_int_equal(err, IOT_ERROR_NONE);
}

void TC_do_iot_main_command_cloud_registering_negative(void **state)
{
    iot_error_t err;
    struct iot_context *context;
    struct iot_command cmd = {0};

    UNUSED(state);

    // Given:
    err = iot_nv_init((unsigned char *)sample_device_info, strlen(sample_device_info));
    assert_int_equal(err, IOT_ERROR_NONE);

    context = (struct iot_context *)calloc(1, sizeof(struct iot_context));
    assert_non_null(context);
    context->work_queue = iot_util_queue_create(sizeof(struct iot_command));
    assert_non_null(context->work_queue);
    context->work_queue_signal = iot_os_eventgroup_create();
    assert_non_null(context->work_queue_signal);
    iot_os_mutex_init(&context->st_conn_lock);

    context->curr_state = IOT_STATE_PROV_CONFIRM;
    context->usr_events = iot_os_eventgroup_create();
    context->iot_events = iot_os_eventgroup_create();

    context->is_wifi_station = false;
    context->reg_mqttcli = NULL;
    context->wifi_update_enabled = false;
    context->rate_limit = true;

    cmd.cmd_type = IOT_COMMAND_CLOUD_REGISTERING;
    cmd.param = NULL;

    expect_value(__wrap_iot_bsp_wifi_set_mode, conf->mode, IOT_WIFI_MODE_STATION);
    will_return(__wrap_iot_bsp_wifi_set_mode, IOT_ERROR_NONE);

    context->cloud_con_timer = iot_os_timer_create(NULL, 10000, NULL);
    iot_os_timer_start(context->cloud_con_timer);
    // When: cmd type is cloud registering
    err = _do_iot_main_command(context, &cmd);
    // Then:
    assert_int_equal(err, IOT_ERROR_MQTT_CONNECT_FAIL);

    // Teardown
    iot_util_queue_delete(context->work_queue);
    iot_os_eventgroup_delete(context->work_queue_signal);
    iot_os_eventgroup_delete(context->usr_events);
    iot_os_eventgroup_delete(context->iot_events);
    iot_os_mutex_destroy(&context->st_conn_lock);
    iot_os_timer_stop(context->cloud_con_timer);
    iot_os_timer_destroy(&context->cloud_con_timer);
    free(context);
    iot_nv_deinit();
}

void TC_do_iot_main_command_cloud_connecting_positive(void **state)
{
    iot_error_t err;
    struct iot_context *context;
    struct iot_command cmd = {0};

    UNUSED(state);

    // Given:
    err = iot_nv_init((unsigned char *)sample_device_info, strlen(sample_device_info));
    assert_int_equal(err, IOT_ERROR_NONE);

    context = (struct iot_context *)calloc(1, sizeof(struct iot_context));
    assert_non_null(context);
    context->work_queue = iot_util_queue_create(sizeof(struct iot_command));
    assert_non_null(context->work_queue);
    context->work_queue_signal = iot_os_eventgroup_create();
    assert_non_null(context->work_queue_signal);
    iot_os_mutex_init(&context->st_conn_lock);

    context->curr_state = IOT_STATE_CLOUD_DISCONNECTED;
    context->usr_events = iot_os_eventgroup_create();
    context->iot_events = iot_os_eventgroup_create();
    context->cloud_con_timer = NULL;
    context->next_connection_retry_timer = iot_os_timer_create(NULL, 100, NULL);
    iot_os_timer_start(context->next_connection_retry_timer);

    cmd.cmd_type = IOT_COMMAND_CLOUD_CONNECTING;
    cmd.param = NULL;
    context->cloud_connection_pause = true;

    // When:
    err = _do_iot_main_command(context, &cmd);

    // Then:
    assert_int_equal(err, IOT_ERROR_NONE);

    // Teardown
    iot_util_queue_delete(context->work_queue);
    iot_os_eventgroup_delete(context->work_queue_signal);
    iot_os_eventgroup_delete(context->usr_events);
    iot_os_eventgroup_delete(context->iot_events);
    iot_os_mutex_destroy(&context->st_conn_lock);

    if (context->next_connection_retry_timer) {
        iot_os_timer_stop(context->next_connection_retry_timer);
        iot_os_timer_delete(context->next_connection_retry_timer);
    }

    free(context);
    iot_nv_deinit();
}

void TC_do_iot_main_command_notification_rate_limit_positive(void **state)
{
    iot_error_t err;
    struct iot_context context = {0};
    struct iot_command cmd = {0};
    iot_noti_data_t noti_data = {0};

    UNUSED(state);

    // Given:
    context.curr_state = IOT_STATE_CLOUD_CONNECTED;
    context.usr_events = iot_os_eventgroup_create();
    context.iot_events = iot_os_eventgroup_create();
    context.work_queue_signal = iot_os_eventgroup_create();
    iot_os_mutex_init(&context.st_conn_lock);
    context.noti_cb = test_st_cap_noti_cb;

    noti_data.type = _IOT_NOTI_TYPE_RATE_LIMIT;

    cmd.cmd_type = IOT_COMMAND_NOTIFICATION_RECEIVED;
    cmd.param = &noti_data;

    // When:
    err = _do_iot_main_command(&context, &cmd);

    // Then: should return IOT_ERROR_NONE
    assert_int_equal(err, IOT_ERROR_NONE);

    // Teardown
    iot_os_eventgroup_delete(context.usr_events);
    iot_os_eventgroup_delete(context.iot_events);
    iot_os_eventgroup_delete(context.work_queue_signal);
    iot_os_mutex_destroy(&context.st_conn_lock);
}

void TC_do_iot_main_command_notification_dev_deleted_positive(void **state)
{
    iot_error_t err;
    struct iot_context context = {0};
    struct iot_command cmd = {0};
    iot_noti_data_t noti_data = {0};

    UNUSED(state);

    // Given:
    context.curr_state = IOT_STATE_CLOUD_CONNECTED;
    context.usr_events = iot_os_eventgroup_create();
    context.iot_events = iot_os_eventgroup_create();
    context.work_queue_signal = iot_os_eventgroup_create();
    iot_os_mutex_init(&context.st_conn_lock);
    context.noti_cb = test_st_cap_noti_cb;

    noti_data.type = _IOT_NOTI_TYPE_DEV_DELETED;

    cmd.cmd_type = IOT_COMMAND_NOTIFICATION_RECEIVED;
    cmd.param = &noti_data;

    // When:
    err = _do_iot_main_command(&context, &cmd);

    // Then: should return IOT_ERROR_NONE
    assert_int_equal(err, IOT_ERROR_NONE);

    // Teardown
    iot_os_eventgroup_delete(context.usr_events);
    iot_os_eventgroup_delete(context.iot_events);
    iot_os_eventgroup_delete(context.work_queue_signal);
    iot_os_mutex_destroy(&context.st_conn_lock);
}

void TC_do_iot_main_command_notification_quota_reached_positive(void **state)
{
    iot_error_t err;
    struct iot_context context = {0};
    struct iot_command cmd = {0};
    iot_noti_data_t noti_data = {0};

    UNUSED(state);

    // Given:
    context.curr_state = IOT_STATE_CLOUD_CONNECTED;
    context.usr_events = iot_os_eventgroup_create();
    context.iot_events = iot_os_eventgroup_create();
    context.work_queue_signal = iot_os_eventgroup_create();
    iot_os_mutex_init(&context.st_conn_lock);
    context.noti_cb = test_st_cap_noti_cb;

    noti_data.type = _IOT_NOTI_TYPE_QUOTA_REACHED;
    noti_data.raw.quota.used = 100;
    noti_data.raw.quota.limit = 200;

    cmd.cmd_type = IOT_COMMAND_NOTIFICATION_RECEIVED;
    cmd.param = &noti_data;

    // When:
    err = _do_iot_main_command(&context, &cmd);

    // Then: should return IOT_ERROR_NONE
    assert_int_equal(err, IOT_ERROR_NONE);

    // Teardown
    iot_os_eventgroup_delete(context.usr_events);
    iot_os_eventgroup_delete(context.iot_events);
    iot_os_eventgroup_delete(context.work_queue_signal);
    iot_os_mutex_destroy(&context.st_conn_lock);
}

void TC_do_iot_main_command_notification_preference_updated_positive(void **state)
{
    iot_error_t err;
    struct iot_context context = {0};
    struct iot_command cmd = {0};
    iot_noti_data_t noti_data = {0};
    iot_preference_data pref_data = {0};

    UNUSED(state);

    // Given:
    context.curr_state = IOT_STATE_CLOUD_CONNECTED;
    context.usr_events = iot_os_eventgroup_create();
    context.iot_events = iot_os_eventgroup_create();
    context.work_queue_signal = iot_os_eventgroup_create();
    iot_os_mutex_init(&context.st_conn_lock);
    context.noti_cb = test_st_cap_noti_cb;

    // Set up notification data for preference updated
    noti_data.type = _IOT_NOTI_TYPE_PREFERENCE_UPDATED;
    noti_data.raw.preferences.preferences_num = 1;
    noti_data.raw.preferences.preferences_data =
        iot_os_malloc(noti_data.raw.preferences.preferences_num * sizeof(iot_noti_data_t));
    noti_data.raw.preferences.preferences_data[0].preference_data.type = IOT_CAP_VAL_TYPE_STRING;
    noti_data.raw.preferences.preferences_data[0].preference_data.string = iot_os_strdup("xyz");
    noti_data.raw.preferences.preferences_data[0].preference_name = iot_os_strdup("abc");
    cmd.cmd_type = IOT_COMMAND_NOTIFICATION_RECEIVED;
    cmd.param = &noti_data;

    // When:
    err = _do_iot_main_command(&context, &cmd);

    // Then: should return IOT_ERROR_NONE
    assert_int_equal(err, IOT_ERROR_NONE);

    // Teardown
    iot_os_eventgroup_delete(context.usr_events);
    iot_os_eventgroup_delete(context.iot_events);
    iot_os_eventgroup_delete(context.work_queue_signal);
    iot_os_mutex_destroy(&context.st_conn_lock);
}

void TC_do_iot_main_command_notification_send_failed_positive(void **state)
{
    iot_error_t err;
    struct iot_context context = {0};
    struct iot_command cmd = {0};
    iot_noti_data_t noti_data = {0};

    UNUSED(state);

    // Given:
    context.curr_state = IOT_STATE_CLOUD_CONNECTED;
    context.usr_events = iot_os_eventgroup_create();
    context.iot_events = iot_os_eventgroup_create();
    context.work_queue_signal = iot_os_eventgroup_create();
    iot_os_mutex_init(&context.st_conn_lock);
    context.noti_cb = test_st_cap_noti_cb;

    // Set up notification data for send failed
    noti_data.type = _IOT_NOTI_TYPE_SEND_FAILED;
    noti_data.raw.send_fail.failed_sequence_num = 123;

    cmd.cmd_type = IOT_COMMAND_NOTIFICATION_RECEIVED;
    cmd.param = &noti_data;

    // When:
    err = _do_iot_main_command(&context, &cmd);

    // Then: should return IOT_ERROR_NONE
    assert_int_equal(err, IOT_ERROR_NONE);

    // Teardown
    iot_os_eventgroup_delete(context.usr_events);
    iot_os_eventgroup_delete(context.iot_events);
    iot_os_eventgroup_delete(context.work_queue_signal);
    iot_os_mutex_destroy(&context.st_conn_lock);
}

void TC_do_iot_main_command_notification_jwt_expired_positive(void **state)
{
    iot_error_t err;
    struct iot_context context = {0};
    struct iot_command cmd = {0};
    iot_noti_data_t noti_data = {0};

    UNUSED(state);

    // Given:
    context.curr_state = IOT_STATE_CLOUD_CONNECTED;
    context.usr_events = iot_os_eventgroup_create();
    context.iot_events = iot_os_eventgroup_create();
    context.work_queue_signal = iot_os_eventgroup_create();
    iot_os_mutex_init(&context.st_conn_lock);

    // Set up notification data for JWT expired
    noti_data.type = _IOT_NOTI_TYPE_JWT_EXPIRED;

    cmd.cmd_type = IOT_COMMAND_NOTIFICATION_RECEIVED;
    cmd.param = &noti_data;

    // When:
    err = _do_iot_main_command(&context, &cmd);

    // Then: should return IOT_ERROR_NONE
    assert_int_equal(err, IOT_ERROR_NONE);

    // Teardown
    iot_os_eventgroup_delete(context.usr_events);
    iot_os_eventgroup_delete(context.iot_events);
    iot_os_eventgroup_delete(context.work_queue_signal);
    iot_os_mutex_destroy(&context.st_conn_lock);
}

void TC_do_iot_main_command_notification_child_device_synced_positive(void **state)
{
    iot_error_t err;
    struct iot_context context = {0};
    struct iot_command cmd = {0};
    iot_noti_data_t noti_data = {0};

    UNUSED(state);

    // Given:
    context.curr_state = IOT_STATE_CLOUD_CONNECTED;
    context.usr_events = iot_os_eventgroup_create();
    context.iot_events = iot_os_eventgroup_create();
    context.work_queue_signal = iot_os_eventgroup_create();
    iot_os_mutex_init(&context.st_conn_lock);
    context.noti_cb = test_st_cap_noti_cb;

    // Set up notification data for child device synced
    noti_data.type = _IOT_NOTI_TYPE_CHILD_DEVICE_SYNCED;

    cmd.cmd_type = IOT_COMMAND_NOTIFICATION_RECEIVED;
    cmd.param = &noti_data;

    // When:
    err = _do_iot_main_command(&context, &cmd);

    // Then: should return IOT_ERROR_NONE
    assert_int_equal(err, IOT_ERROR_NONE);

    // Teardown
    iot_os_eventgroup_delete(context.usr_events);
    iot_os_eventgroup_delete(context.iot_events);
    iot_os_eventgroup_delete(context.work_queue_signal);
    iot_os_mutex_destroy(&context.st_conn_lock);
}

void TC_do_iot_main_command_notification_child_device_registered_positive(void **state)
{
    iot_error_t err;
    struct iot_context context = {0};
    struct iot_command cmd = {0};
    iot_noti_data_t noti_data = {0};

    UNUSED(state);

    // Given:
    context.curr_state = IOT_STATE_CLOUD_CONNECTED;
    context.usr_events = iot_os_eventgroup_create();
    context.iot_events = iot_os_eventgroup_create();
    context.work_queue_signal = iot_os_eventgroup_create();
    iot_os_mutex_init(&context.st_conn_lock);
    context.noti_cb = test_st_cap_noti_cb;

    // Set up notification data for child device registered
    noti_data.type = _IOT_NOTI_TYPE_CHILD_DEVICE_REGISTERED;

    cmd.cmd_type = IOT_COMMAND_NOTIFICATION_RECEIVED;
    cmd.param = &noti_data;

    // When:
    err = _do_iot_main_command(&context, &cmd);

    // Then: should return IOT_ERROR_NONE
    assert_int_equal(err, IOT_ERROR_NONE);

    // Teardown
    iot_os_eventgroup_delete(context.usr_events);
    iot_os_eventgroup_delete(context.iot_events);
    iot_os_eventgroup_delete(context.work_queue_signal);
    iot_os_mutex_destroy(&context.st_conn_lock);
}

void TC_do_iot_main_command_system_reboot_positive(void **state)
{
    iot_error_t err;
    struct iot_context context = {0};
    struct iot_command cmd = {0};

    UNUSED(state);

    // Given:
    context.curr_state = IOT_STATE_CLOUD_CONNECTED;
    context.usr_events = iot_os_eventgroup_create();
    context.iot_events = iot_os_eventgroup_create();
    context.work_queue_signal = iot_os_eventgroup_create();
    iot_os_mutex_init(&context.st_conn_lock);

    cmd.cmd_type = IOT_COMMAND_SYSTEM_REBOOT;
    cmd.param = NULL;

    // When:
    err = _do_iot_main_command(&context, &cmd);

    // Then: should return IOT_ERROR_NONE
    assert_int_equal(err, IOT_ERROR_NONE);

    // Teardown
    iot_os_eventgroup_delete(context.usr_events);
    iot_os_eventgroup_delete(context.iot_events);
    iot_os_eventgroup_delete(context.work_queue_signal);
    iot_os_mutex_destroy(&context.st_conn_lock);
}

void TC_do_iot_main_command_invalid_command_type_negative(void **state)
{
    iot_error_t err;
    struct iot_context context = {0};
    struct iot_command cmd = {0};

    UNUSED(state);

    // Given:
    context.curr_state = IOT_STATE_INITIALIZED;
    cmd.cmd_type = IOT_COMMAND_TYPE_MAX + 1;  // Invalid command type
    cmd.param = NULL;

    // When:
    err = _do_iot_main_command(&context, &cmd);

    // Then:
    assert_int_equal(err, IOT_ERROR_BAD_REQ);
}

void TC_do_iot_main_command_invalid_state_negative(void **state)
{
    iot_error_t err;
    struct iot_context context = {0};
    struct iot_command cmd = {0};
    struct iot_state_data state_data = {0};

    UNUSED(state);

    // Given:
    context.curr_state = IOT_STATE_CLOUD_CONNECTED;
    context.usr_events = iot_os_eventgroup_create();
    context.iot_events = iot_os_eventgroup_create();
    context.work_queue_signal = iot_os_eventgroup_create();
    iot_os_mutex_init(&context.st_conn_lock);

    cmd.cmd_type = IOT_COMMAND_STATE_UPDATE;
    cmd.param = &state_data;
    state_data.iot_state = IOT_STATE_PROV_ENTER;
    state_data.opt = IOT_STATE_OPT_NONE;

    // When:
    err = _do_iot_main_command(&context, &cmd);

    // Then:
    assert_int_equal(err, IOT_ERROR_NONE);

    // Teardown
    iot_os_eventgroup_delete(context.usr_events);
    iot_os_eventgroup_delete(context.iot_events);
    iot_os_eventgroup_delete(context.work_queue_signal);
    iot_os_mutex_destroy(&context.st_conn_lock);
}

extern iot_error_t _check_prov_status(struct iot_context *ctx, bool cmd_only);

void TC_check_prov_status_failure(void **state)
{
    iot_error_t err;
    struct iot_context *context;
    struct iot_device_prov_data dummy_prov_data = {0};
    UNUSED(state);

    err = iot_nv_init((unsigned char *)sample_device_info, strlen(sample_device_info));
    assert_int_equal(err, IOT_ERROR_NONE);

    // Given:
    context = (struct iot_context *)calloc(1, sizeof(struct iot_context));
    assert_non_null(context);
    context->work_queue = iot_util_queue_create(sizeof(struct iot_command));
    assert_non_null(context->work_queue);
    context->work_queue_signal = iot_os_eventgroup_create();
    assert_non_null(context->work_queue_signal);
    iot_os_mutex_init(&context->st_conn_lock);

    strncpy(dummy_prov_data.wifi.ssid, "TestSSID", IOT_WIFI_PROV_SSID_STR_LEN);
    strncpy(dummy_prov_data.wifi.password, "TestPassword", IOT_WIFI_PROV_PASSWORD_STR_LEN);
    strncpy(dummy_prov_data.wifi.mac_str, "00:11:22:33:44:55", IOT_WIFI_PROV_MAC_STR_LEN);
    dummy_prov_data.wifi.security_type = IOT_WIFI_AUTH_WPA2_PSK;

    dummy_prov_data.cloud.broker_url = iot_os_strdup("test.mqtt.server.com");
    dummy_prov_data.cloud.broker_port = 8883;
    dummy_prov_data.cloud.label = iot_os_strdup("TestDevice");

    err = iot_nv_set_prov_data(&dummy_prov_data);
    assert_int_equal(err, IOT_ERROR_NONE);

    set_mock_iot_os_malloc_failure();

    // When: cmd_only is false
    err = _check_prov_status(context, false);
    // Then:
    assert_int_equal(err, IOT_ERROR_MEM_ALLOC);

    // Teardown
    if (dummy_prov_data.cloud.broker_url) {
        iot_os_free(dummy_prov_data.cloud.broker_url);
    }
    if (dummy_prov_data.cloud.label) {
        iot_os_free(dummy_prov_data.cloud.label);
    }
    iot_util_queue_delete(context->work_queue);
    iot_os_eventgroup_delete(context->work_queue_signal);
    iot_os_mutex_destroy(&context->st_conn_lock);
    iot_api_prov_data_mem_free(&context->prov_data);
    free(context);
    iot_nv_deinit();
    do_not_use_mock_iot_os_malloc_failure();
}

void TC_check_prov_status_dip_need_update_negative(void **state)
{
    iot_error_t err;
    struct iot_context *context;
    struct iot_device_prov_data dummy_prov_data = {0};
    char *set_device_id = "1cd8e3f2-0c88-4298-90e3-cd9b35a82140";
    UNUSED(state);

    err = iot_nv_init((unsigned char *)sample_device_info, strlen(sample_device_info));
    assert_int_equal(err, IOT_ERROR_NONE);

    // Given:
    context = (struct iot_context *)calloc(1, sizeof(struct iot_context));
    assert_non_null(context);
    context->work_queue = iot_util_queue_create(sizeof(struct iot_command));
    assert_non_null(context->work_queue);
    context->work_queue_signal = iot_os_eventgroup_create();
    assert_non_null(context->work_queue_signal);
    iot_os_mutex_init(&context->st_conn_lock);

    strncpy(dummy_prov_data.wifi.ssid, "TestSSID", IOT_WIFI_PROV_SSID_STR_LEN);
    strncpy(dummy_prov_data.wifi.password, "TestPassword", IOT_WIFI_PROV_PASSWORD_STR_LEN);
    strncpy(dummy_prov_data.wifi.mac_str, "00:11:22:33:44:55", IOT_WIFI_PROV_MAC_STR_LEN);
    dummy_prov_data.wifi.security_type = IOT_WIFI_AUTH_WPA2_PSK;

    dummy_prov_data.cloud.broker_url = iot_os_strdup("test.mqtt.server.com");
    dummy_prov_data.cloud.broker_port = 8883;
    dummy_prov_data.cloud.label = iot_os_strdup("TestDevice");

    err = iot_nv_set_prov_data(&dummy_prov_data);
    assert_int_equal(err, IOT_ERROR_NONE);
    err = iot_nv_set_device_id(set_device_id);
    assert_int_equal(err, IOT_ERROR_NONE);
    context->devconf.dip = (struct iot_dip_data *)malloc(sizeof(struct iot_dip_data));
    iot_util_convert_str_uuid(REG_TEST_DIP_ID, &context->devconf.dip->dip_id);
    context->devconf.dip->dip_major_version = 0;
    context->devconf.dip->dip_minor_version = 1;

    // When: misc info data is not present
    err = _check_prov_status(context, false);
    // Then:
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_false(!context->dip_need_update);

    // When: cmd_only is true
    err = _check_prov_status(context, true);
    // Then:
    assert_int_equal(err, IOT_ERROR_NONE);

    // Teardown
    if (dummy_prov_data.cloud.broker_url) {
        iot_os_free(dummy_prov_data.cloud.broker_url);
    }
    if (dummy_prov_data.cloud.label) {
        iot_os_free(dummy_prov_data.cloud.label);
    }
    iot_util_queue_delete(context->work_queue);
    iot_os_eventgroup_delete(context->work_queue_signal);
    iot_os_mutex_destroy(&context->st_conn_lock);
    iot_api_prov_data_mem_free(&context->prov_data);
    free(context);
    iot_nv_deinit();
    iot_nv_erase(IOT_NVD_DEVICE_ID);
}

static struct iot_dip_data dip_example = {
    .dip_id.id = {0xbb, 0x00, 0x0d, 0xdd, 0x92, 0xa0, 0x42, 0xa3, 0x86, 0xf0, 0xb5, 0x31, 0xf2, 0x78, 0xaf, 0x06},
    .dip_major_version = 0,
    .dip_minor_version = 1,
};

void TC_check_prov_status_success(void **state)
{
    iot_error_t err;
    struct iot_context *context;
    struct iot_device_prov_data dummy_prov_data = {0};
    char *set_device_id = "1cd8e3f2-0c88-4298-90e3-cd9b35a82140";
    UNUSED(state);

    err = iot_nv_init((unsigned char *)sample_device_info, strlen(sample_device_info));
    assert_int_equal(err, IOT_ERROR_NONE);

    // Given:
    context = (struct iot_context *)calloc(1, sizeof(struct iot_context));
    assert_non_null(context);
    context->work_queue = iot_util_queue_create(sizeof(struct iot_command));
    assert_non_null(context->work_queue);
    context->work_queue_signal = iot_os_eventgroup_create();
    assert_non_null(context->work_queue_signal);
    iot_os_mutex_init(&context->st_conn_lock);

    strncpy(dummy_prov_data.wifi.ssid, "TestSSID", IOT_WIFI_PROV_SSID_STR_LEN);
    strncpy(dummy_prov_data.wifi.password, "TestPassword", IOT_WIFI_PROV_PASSWORD_STR_LEN);
    strncpy(dummy_prov_data.wifi.mac_str, "00:11:22:33:44:55", IOT_WIFI_PROV_MAC_STR_LEN);
    dummy_prov_data.wifi.security_type = IOT_WIFI_AUTH_WPA2_PSK;

    dummy_prov_data.cloud.broker_url = iot_os_strdup("test.mqtt.server.com");
    dummy_prov_data.cloud.broker_port = 8883;
    dummy_prov_data.cloud.label = iot_os_strdup("TestDevice");

    err = iot_nv_set_prov_data(&dummy_prov_data);
    assert_int_equal(err, IOT_ERROR_NONE);

    // When: cmd_only is false
    // device id in nv
    err = iot_nv_set_device_id(set_device_id);
    assert_int_equal(err, IOT_ERROR_NONE);
    err = iot_misc_info_store(IOT_MISC_INFO_DIP, (void *)&dip_example);
    assert_int_equal(err, IOT_ERROR_NONE);
    // Add DIP data
    context->devconf.dip = (struct iot_dip_data *)malloc(sizeof(struct iot_dip_data));
    iot_util_convert_str_uuid(REG_TEST_DIP_ID, &context->devconf.dip->dip_id);
    context->devconf.dip->dip_major_version = 0;
    context->devconf.dip->dip_minor_version = 1;

    err = _check_prov_status(context, false);
    // Then:
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_false(context->dip_need_update);

    // When: cmd_only is true
    err = _check_prov_status(context, true);
    // Then:
    assert_int_equal(err, IOT_ERROR_NONE);

    // Teardown
    if (dummy_prov_data.cloud.broker_url) {
        iot_os_free(dummy_prov_data.cloud.broker_url);
    }
    if (dummy_prov_data.cloud.label) {
        iot_os_free(dummy_prov_data.cloud.label);
    }
    iot_util_queue_delete(context->work_queue);
    iot_os_eventgroup_delete(context->work_queue_signal);
    iot_os_mutex_destroy(&context->st_conn_lock);
    iot_api_prov_data_mem_free(&context->prov_data);
    free(context);
    iot_nv_deinit();
    iot_nv_erase(IOT_NVD_DEVICE_ID);
    iot_nv_erase(IOT_NVD_MISC_INFO);
}

void TC_check_prov_status_device_id_present_success(void **state)
{
    iot_error_t err;
    struct iot_context *context;
    struct iot_device_prov_data dummy_prov_data = {0};
    UNUSED(state);

    err = iot_nv_init((unsigned char *)sample_device_info, strlen(sample_device_info));
    assert_int_equal(err, IOT_ERROR_NONE);
    // Given:
    context = (struct iot_context *)calloc(1, sizeof(struct iot_context));
    assert_non_null(context);
    context->work_queue = iot_util_queue_create(sizeof(struct iot_command));
    assert_non_null(context->work_queue);
    context->work_queue_signal = iot_os_eventgroup_create();
    assert_non_null(context->work_queue_signal);
    iot_os_mutex_init(&context->st_conn_lock);

    strncpy(dummy_prov_data.wifi.ssid, "TestSSID", IOT_WIFI_PROV_SSID_STR_LEN);
    strncpy(dummy_prov_data.wifi.password, "TestPassword", IOT_WIFI_PROV_PASSWORD_STR_LEN);
    strncpy(dummy_prov_data.wifi.mac_str, "00:11:22:33:44:55", IOT_WIFI_PROV_MAC_STR_LEN);
    dummy_prov_data.wifi.security_type = IOT_WIFI_AUTH_WPA2_PSK;

    dummy_prov_data.cloud.broker_url = iot_os_strdup("test.mqtt.server.com");
    dummy_prov_data.cloud.broker_port = 8883;
    dummy_prov_data.cloud.label = iot_os_strdup("TestDevice");

    err = iot_nv_set_prov_data(&dummy_prov_data);
    assert_int_equal(err, IOT_ERROR_NONE);

    // Set device ID to simulate already registered device
    strcpy(context->iot_reg_data.deviceId, "test-device-id");

    // When:
    err = _check_prov_status(context, false);

    // Then:
    assert_int_equal(err, IOT_ERROR_NONE);

    // Teardown
    if (dummy_prov_data.cloud.broker_url) {
        iot_os_free(dummy_prov_data.cloud.broker_url);
    }
    if (dummy_prov_data.cloud.label) {
        iot_os_free(dummy_prov_data.cloud.label);
    }
    iot_util_queue_delete(context->work_queue);
    iot_os_eventgroup_delete(context->work_queue_signal);
    iot_os_mutex_destroy(&context->st_conn_lock);
    iot_api_prov_data_mem_free(&context->prov_data);
    free(context);
    iot_nv_deinit();
}

void TC_check_prov_status_invalid_prov_data(void **state)
{
    iot_error_t err;
    struct iot_context *context;
    struct iot_device_prov_data dummy_prov_data = {0};
    UNUSED(state);

    err = iot_nv_init((unsigned char *)sample_device_info, strlen(sample_device_info));
    assert_int_equal(err, IOT_ERROR_NONE);

    // Given:
    context = (struct iot_context *)calloc(1, sizeof(struct iot_context));
    assert_non_null(context);
    context->work_queue = iot_util_queue_create(sizeof(struct iot_command));
    assert_non_null(context->work_queue);
    context->work_queue_signal = iot_os_eventgroup_create();
    assert_non_null(context->work_queue_signal);
    iot_os_mutex_init(&context->st_conn_lock);

    // when ssid is NULL
    memset(dummy_prov_data.wifi.ssid, 0, IOT_WIFI_PROV_SSID_STR_LEN);
    strncpy(dummy_prov_data.wifi.password, "TestPassword", IOT_WIFI_PROV_PASSWORD_STR_LEN);
    strncpy(dummy_prov_data.wifi.mac_str, "00:11:22:33:44:55", IOT_WIFI_PROV_MAC_STR_LEN);
    dummy_prov_data.wifi.security_type = IOT_WIFI_AUTH_WPA2_PSK;

    dummy_prov_data.cloud.broker_url = iot_os_strdup("test.mqtt.server.com");
    dummy_prov_data.cloud.broker_port = 8883;
    dummy_prov_data.cloud.label = iot_os_strdup("TestDevice");

    err = iot_nv_set_prov_data(&dummy_prov_data);
    assert_int_equal(err, IOT_ERROR_NONE);

    // When:
    err = _check_prov_status(context, false);
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_true(context->iot_reg_data.new_reged);

    // Teardown
    iot_util_queue_delete(context->work_queue);
    iot_os_eventgroup_delete(context->work_queue_signal);
    iot_os_mutex_destroy(&context->st_conn_lock);
    iot_api_prov_data_mem_free(&context->prov_data);
    free(context);
    iot_nv_deinit();
}

void TC_iot_put_device_work_null_context(void **state)
{
    iot_error_t err;
    UNUSED(state);

    // When: NULL context
    err = iot_put_device_work(NULL, NULL, NULL);
    // Then
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);
}

void TC_iot_put_device_work_success(void **state)
{
    iot_error_t err;
    struct iot_context *context;
    UNUSED(state);

    // Given: valid context with work queue
    context = (struct iot_context *)calloc(1, sizeof(struct iot_context));
    assert_non_null(context);
    context->work_queue = iot_util_queue_create(sizeof(device_work_data_t));
    assert_non_null(context->work_queue);
    context->work_queue_signal = iot_os_eventgroup_create();
    assert_non_null(context->work_queue_signal);

    // When: valid parameters
    err = iot_put_device_work(context, NULL, NULL);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);

    // Teardown
    iot_util_queue_delete(context->work_queue);
    iot_os_eventgroup_delete(context->work_queue_signal);
    free(context);
}

void TC_st_device_init_null_parameter(void **state)
{
    IOT_CTX *context;
    st_device_config_t config = {0};
    UNUSED(state);

    // When: NULL device_id
    context = st_device_init(&config);
    // Then
    assert_null(context);
}

void TC_st_device_init_invalid_identity_method(void **state)
{
    IOT_CTX *context;
    st_device_config_t config = {0};
    char test_device_id[] = "12345678-1234-1234-1234-123456789012";
    UNUSED(state);

    // Given: invalid identity method (using NONE as it's not valid for st_device_init)
    config.device_id = test_device_id;
    config.id_method = ST_IDENTITY_METHOD_NONE;

    // When
    context = st_device_init(&config);
    // Then
    assert_null(context);
}

void TC_st_device_init_success(void **state)
{
    IOT_CTX *context;
    st_device_config_t config = {0};
    char test_device_id[] = "12345678-1234-1234-1234-123456789012";
    char test_mnid[] = "TEST_MNID";
    UNUSED(state);

    // Given: valid config with MANUAL_ED25519 identity method
    config.device_id = test_device_id;
    config.id_method = ST_IDENTITY_METHOD_MANUAL_ED25519;
    config.mnId = test_mnid;
    config.identity.ed25519.prikey = TEST_DEVICE_SECRET_B64_KEY;
    config.identity.ed25519.pubkey = TEST_DEVICE_PUBLIC_B64_KEY;
    config.identity.ed25519.sn = TEST_DEVICE_SERIAL_NUMBER;

    // When
    context = st_device_init(&config);
    // Then
    assert_non_null(context);

    // Teardown
    struct iot_context *internal_context = (struct iot_context *)context;
    if (internal_context->work_queue_thread) {
        iot_os_eventgroup_set_bits(internal_context->work_queue_signal, DEVICE_WORK_QUEUE_KILL_SIGNAL);
        size_t count = 0;
        while (internal_context->work_queue_thread && count < 100) {
            iot_os_delay(50);
            count++;
        }
    }
    iot_os_mutex_destroy(&internal_context->st_conn_lock);
    iot_os_eventgroup_delete(internal_context->work_queue_signal);
    iot_os_eventgroup_delete(internal_context->iot_events);
    iot_os_eventgroup_delete(internal_context->usr_events);
    iot_util_queue_delete(internal_context->work_queue);
    if (internal_context->devconf.mnid) {
        iot_os_free(internal_context->devconf.mnid);
    }
    iot_nv_deinit();
    iot_os_free(internal_context);
}

void TC_st_register_child_dev_invalid_context_state(void **state)
{
    int err;
    struct iot_context context = {0};
    st_child_dev_reg_info reg_info = {0};
    UNUSED(state);

    // Given: context not in connected state
    context.curr_state = IOT_STATE_INITIALIZED;  // Not connected
    context.evt_mqttcli = (st_mqtt_client)1;     // Valid MQTT client

    // When: invalid context state
    err = st_register_child_dev((IOT_CTX *)&context, &reg_info);
    // Then
    assert_int_equal(err, IOT_ERROR_BAD_REQ);
}

void TC_st_register_child_dev_null_mqtt_client(void **state)
{
    int err;
    struct iot_context context = {0};
    st_child_dev_reg_info reg_info = {0};
    UNUSED(state);

    // Given: context in connected state but NULL MQTT client
    context.curr_state = IOT_STATE_CLOUD_CONNECTED;
    context.evt_mqttcli = NULL;  // NULL MQTT client

    // When: NULL MQTT client
    err = st_register_child_dev((IOT_CTX *)&context, &reg_info);
    // Then
    assert_int_equal(err, IOT_ERROR_BAD_REQ);
}

void TC_st_register_child_dev_mqtt_publish_failure(void **state)
{
    int err;
    iot_error_t iot_err;
    struct iot_context *context;
    st_mqtt_client client;
    MQTTClient *c;
    st_child_dev_reg_info reg_info = {0};
    UNUSED(state);

    // Given
    context = (struct iot_context *)calloc(1, sizeof(struct iot_context));
    assert_non_null(context);

    context->curr_state = IOT_STATE_CLOUD_CONNECTED;

    err = st_mqtt_create(&client, _dummy_client_callback, NULL, NULL, NULL);
    assert_return_code(err, 0);
    c = (MQTTClient *)client;
    c->isconnected = 1;
    port_net_mock_reset_socket_status(1);
    c->last_sent = iot_os_timer_create(NULL, 10000, NULL);
    iot_err = iot_os_timer_start(c->last_sent);
    assert_int_equal(iot_err, IOT_ERROR_NONE);

    c->last_received = iot_os_timer_create(NULL, 10000, NULL);
    iot_err = iot_os_timer_start(c->last_received);
    assert_int_equal(iot_err, IOT_ERROR_NONE);

    context->evt_mqttcli = (st_mqtt_client)client;

    // Set up registration info
    reg_info.mnid = "test_mnid";
    reg_info.serial_number = "test_serial";
    reg_info.vid = "test_vid";
    reg_info.device_type_id = "test_device_type";
    reg_info.dip_id = "test_dip_id";
    reg_info.dip_major_version = 1;
    reg_info.dip_minor_version = 0;

    // Set up mock to simulate MQTT publish failure
    set_mock_port_net_write_failure(1);

    // When: MQTT publish fails
    err = st_register_child_dev((IOT_CTX *)context, &reg_info);
    // Then
    assert_int_equal(err, IOT_ERROR_MQTT_PUBLISH_FAIL);

    // Teardown
    st_mqtt_destroy(client);
    free(context);
}

void TC_st_get_child_dev_null_context(void **state)
{
    IOT_CHILD_DEV child_dev;
    UNUSED(state);

    // When: NULL context
    child_dev = st_get_child_dev(NULL, "test_mnid", "test_serial");
    // Then
    assert_null(child_dev);
}

void TC_st_get_child_dev_null_mnid(void **state)
{
    IOT_CHILD_DEV child_dev;
    struct iot_context context = {0};
    UNUSED(state);

    // When: NULL mnId
    child_dev = st_get_child_dev((IOT_CTX *)&context, NULL, "test_serial");
    // Then
    assert_null(child_dev);
}

void TC_st_get_child_dev_null_serial_number(void **state)
{
    IOT_CHILD_DEV child_dev;
    struct iot_context context = {0};
    UNUSED(state);

    // When: NULL serial_number
    child_dev = st_get_child_dev((IOT_CTX *)&context, "test_mnid", NULL);
    // Then
    assert_null(child_dev);
}

void TC_st_get_child_dev_no_match(void **state)
{
    IOT_CHILD_DEV child_dev;
    struct iot_context context = {0};
    iot_child_device child1 = {0};
    iot_child_device child2 = {0};
    UNUSED(state);

    // Given: Set up a linked list of child devices
    child1.mnId = "MNID1";
    child1.serial_number = "serial1";
    child1.next = &child2;

    child2.mnId = "MNID2";
    child2.serial_number = "serial2";
    child2.next = NULL;

    context.child_device_list = &child1;

    // When: Search for a non-existent child device
    child_dev = st_get_child_dev((IOT_CTX *)&context, "NONEXISTENT_MNID", "nonexistent_serial");
    // Then
    assert_null(child_dev);
}

void TC_st_get_child_dev_success(void **state)
{
    IOT_CHILD_DEV child_dev;
    struct iot_context context = {0};
    iot_child_device child1 = {0};
    iot_child_device child2 = {0};
    UNUSED(state);

    // Given: Set up a linked list of child devices
    child1.mnId = "MNID1";
    child1.serial_number = "serial1";
    child1.next = &child2;

    child2.mnId = "MNID2";
    child2.serial_number = "serial2";
    child2.next = NULL;

    context.child_device_list = &child1;

    // When: Search for an existing child device
    child_dev = st_get_child_dev((IOT_CTX *)&context, "MNID2", "serial2");
    // Then
    assert_non_null(child_dev);
    assert_ptr_equal(child_dev, &child2);
}

void TC_st_child_dev_start_null_child_dev(void **state)
{
    int result;
    UNUSED(state);

    // When: NULL child device
    result = st_child_dev_start(NULL, NULL, NULL);
    // Then
    assert_int_equal(result, -1);
}

void TC_st_child_dev_start_success(void **state)
{
    int result;
    iot_child_device child_dev = {0};
    struct iot_context context = {0};
    UNUSED(state);

    // Given: Valid child device with context
    child_dev.ctx = &context;
    child_dev.is_online = false;  // Initially offline

    // When: Valid child device
    result = st_child_dev_start((IOT_CHILD_DEV)&child_dev, NULL, NULL);
    // Then
    assert_int_equal(result, 0);
    assert_true(child_dev.is_online);
    assert_null(child_dev.noti_cb);
    assert_null(child_dev.noti_usr_data);
}

void TC_st_register_child_dev_success(void **state)
{
    int err;
    iot_error_t iot_err;
    struct iot_context *context;
    st_mqtt_client client;
    MQTTClient *c;
    st_child_dev_reg_info reg_info = {0};
    UNUSED(state);

    // Given
    context = (struct iot_context *)calloc(1, sizeof(struct iot_context));
    assert_non_null(context);

    context->curr_state = IOT_STATE_CLOUD_CONNECTED;

    err = st_mqtt_create(&client, _dummy_client_callback, NULL, NULL, NULL);
    assert_return_code(err, 0);
    c = (MQTTClient *)client;
    c->isconnected = 1;
    port_net_mock_reset_socket_status(1);
    c->last_sent = iot_os_timer_create(NULL, 10000, NULL);
    iot_err = iot_os_timer_start(c->last_sent);
    assert_int_equal(iot_err, IOT_ERROR_NONE);

    c->last_received = iot_os_timer_create(NULL, 10000, NULL);
    iot_err = iot_os_timer_start(c->last_received);
    assert_int_equal(iot_err, IOT_ERROR_NONE);

    context->evt_mqttcli = (st_mqtt_client)client;

    // Set up registration info
    reg_info.mnid = "test_mnid";
    reg_info.serial_number = "test_serial";
    reg_info.vid = "test_vid";
    reg_info.device_type_id = "test_device_type";
    reg_info.dip_id = "test_dip_id";
    reg_info.dip_major_version = 1;
    reg_info.dip_minor_version = 0;

    // Set up mock expectations for the actual payload that will be sent
    set_mock_port_net_write_skip_buf_check(1);  // Skip buffer content checking
    set_mock_port_net_write_skip_len_check(1);  // Skip length checking

    // Set up mock response (PUBACK for QoS1)
    unsigned char mock_read_buffer_puback[4];
    mock_read_buffer_puback[0] = 0x40;  // PUBACK fixed header
    mock_read_buffer_puback[1] = 0x02;  // Remaining Length

    char packet_id_msb = 0x00;
    char packet_id_lsb = (char)(c->next_packetid + 1);
    mock_read_buffer_puback[2] = packet_id_msb;
    mock_read_buffer_puback[3] = packet_id_lsb;
    port_net_mock_reset_read_stream(mock_read_buffer_puback, 4);

    // When: valid parameters
    err = st_register_child_dev((IOT_CTX *)context, &reg_info);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);

    reset_mock_port_net_write_skip_flags();

    // Teardown
    st_mqtt_destroy(client);
    free(context);
}

void TC_check_prov_status_no_device_id(void **state)
{
    iot_error_t err;
    struct iot_context context = {0};
    struct iot_device_prov_data dummy_prov_data = {0};
    UNUSED(state);

    // Initialize NV data
    err = iot_nv_init((unsigned char *)sample_device_info, strlen(sample_device_info));
    assert_int_equal(err, IOT_ERROR_NONE);

    // Given:
    context.usr_events = iot_os_eventgroup_create();
    context.iot_events = iot_os_eventgroup_create();
    context.work_queue_signal = iot_os_eventgroup_create();
    iot_os_mutex_init(&context.st_conn_lock);

    strncpy(dummy_prov_data.wifi.ssid, "TestSSID", IOT_WIFI_PROV_SSID_STR_LEN);
    strncpy(dummy_prov_data.wifi.password, "TestPassword", IOT_WIFI_PROV_PASSWORD_STR_LEN);
    strncpy(dummy_prov_data.wifi.mac_str, "00:11:22:33:44:55", IOT_WIFI_PROV_MAC_STR_LEN);
    dummy_prov_data.wifi.security_type = IOT_WIFI_AUTH_WPA2_PSK;

    dummy_prov_data.cloud.broker_url = iot_os_strdup("test.mqtt.server.com");
    dummy_prov_data.cloud.broker_port = 8883;
    dummy_prov_data.cloud.label = iot_os_strdup("TestDevice");

    err = iot_nv_set_prov_data(&dummy_prov_data);
    assert_int_equal(err, IOT_ERROR_NONE);

    // When: No device_id is set
    err = _check_prov_status(&context, true);
    // Then:
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_true(context.iot_reg_data.new_reged);

    // Teardown
    iot_os_eventgroup_delete(context.usr_events);
    iot_os_eventgroup_delete(context.iot_events);
    iot_os_eventgroup_delete(context.work_queue_signal);
    iot_os_mutex_destroy(&context.st_conn_lock);
    iot_api_prov_data_mem_free(&context.prov_data);
}

void TC_delete_dev_card_by_usr_null_context(void **state)
{
    iot_error_t err;
    UNUSED(state);

    // When: NULL context
    err = _delete_dev_card_by_usr(NULL);

    // Then:
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);
}

void TC_delete_dev_card_by_usr_null_mqtt_client(void **state)
{
    iot_error_t err;
    struct iot_context context = {0};
    UNUSED(state);

    // Given:
    context.evt_mqttcli = NULL;
    context.curr_state = IOT_STATE_CLOUD_CONNECTED;

    // When:
    err = _delete_dev_card_by_usr(&context);

    // Then:
    assert_int_equal(err, IOT_ERROR_NONE);
}

void TC_delete_dev_card_by_usr_not_connected(void **state)
{
    iot_error_t err;
    struct iot_context context = {0};
    UNUSED(state);

    // Given:
    context.evt_mqttcli = (void *)0x12345678;  // Non-NULL pointer
    context.curr_state = IOT_STATE_CLOUD_DISCONNECTED;

    // When:
    err = _delete_dev_card_by_usr(&context);

    // Then:
    assert_int_equal(err, IOT_ERROR_NONE);
}

void TC_delete_dev_card_by_usr_mqtt_publish_failure(void **state)
{
    iot_error_t err;
    struct iot_context context = {0};
    UNUSED(state);

    // Given:
    err = st_mqtt_create(&context.evt_mqttcli, _dummy_client_callback, NULL, NULL, NULL);
    assert_return_code(err, 0);
    context.curr_state = IOT_STATE_CLOUD_CONNECTED;
    set_mock_iot_os_malloc_failure();

    // When:
    err = _delete_dev_card_by_usr(&context);

    // Then:
    assert_int_equal(err, IOT_ERROR_BAD_REQ);

    // Teardown
    st_mqtt_destroy(context.evt_mqttcli);
    do_not_use_mock_iot_os_malloc_failure();
}

void TC_delete_dev_card_by_usr_success(void **state)
{
    iot_error_t err;
    struct iot_context *context;
    struct mqtt_pub_test_data data[1] = {{st_mqtt_qos1, "/v1/devices/delete", "", 0x32, 0x40}};
    st_mqtt_client client;
    MQTTClient *c;
    char *mqtt_publish_buffers[sizeof(data) / sizeof(struct mqtt_pub_test_data)];
    unsigned char *mock_read_buffer_puback_buffers[sizeof(data) / sizeof(struct mqtt_pub_test_data)];
    UNUSED(state);

    // Given:
    context = (struct iot_context *)malloc(sizeof(struct iot_context));
    assert_non_null(context);
    memset(context, '\0', sizeof(struct iot_context));

    err = st_mqtt_create(&client, _dummy_client_callback, NULL, NULL, NULL);
    assert_return_code(err, 0);
    c = (MQTTClient *)client;
    c->isconnected = 1;
    port_net_mock_reset_socket_status(1);
    c->last_sent = iot_os_timer_create(NULL, 10000, NULL);
    err = iot_os_timer_start(c->last_sent);
    assert_int_equal(err, IOT_ERROR_NONE);

    c->last_received = iot_os_timer_create(NULL, 10000, NULL);
    context->evt_mqttcli = c;
    err = iot_os_timer_start(c->last_received);
    assert_int_equal(err, IOT_ERROR_NONE);
    context->curr_state = IOT_STATE_CLOUD_CONNECTED;
    for (int i = 0; i < sizeof(data) / sizeof(struct mqtt_pub_test_data); i++) {
        size_t mqtt_publish_header_len;
        char *mqtt_publish;
        unsigned int header_index = 0;
        unsigned char *mock_read_buffer_puback;
        st_mqtt_msg msg;
        char packet_id_msb;
        char packet_id_lsb;
        msg.payload = data[i].payload;
        msg.qos = data[i].qos;
        msg.retained = false;
        msg.payloadlen = 0;
        msg.topic = data[i].topic;
        mqtt_publish_header_len = 2 + 2 + strlen(data[i].topic) +
                                  2;  // 2 for fixed header, 2 for topic name length, variable topic, 2 for package id
        mqtt_publish = malloc(mqtt_publish_header_len + msg.payloadlen);
        assert_non_null(mqtt_publish);
        mqtt_publish[header_index++] = data[i].pub_fixed_header;
        mqtt_publish[header_index++] = (char)(2 + strlen(data[i].topic) + 2 + msg.payloadlen);  // Remaining Length
        mqtt_publish[header_index++] = 0x00;
        mqtt_publish[header_index++] = (char)strlen(data[i].topic);
        for (int j = 0; j < strlen(data[i].topic); j++) {
            mqtt_publish[header_index++] = data[i].topic[j];
        }
        packet_id_msb = 0x00;
        packet_id_lsb = (char)(c->next_packetid + 1);
        mqtt_publish[header_index++] = packet_id_msb;
        mqtt_publish[header_index++] = packet_id_lsb;
        memcpy(&mqtt_publish[header_index], msg.payload, msg.payloadlen);

        expect_value(__wrap_port_net_write, len, mqtt_publish_header_len + msg.payloadlen);
        expect_memory(__wrap_port_net_write, buf, mqtt_publish, mqtt_publish_header_len + msg.payloadlen);

        mock_read_buffer_puback = (unsigned char *)malloc(8);
        assert_non_null(mock_read_buffer_puback);

        // reference: https://docs.solace.com/MQTT-311-Prtl-Conformance-Spec/MQTT%20Control%20Packets.htm#_Toc430864907
        // reference: https://docs.solace.com/MQTT-311-Prtl-Conformance-Spec/MQTT%20Control%20Packets.htm#_Toc430864922
        mock_read_buffer_puback[0] = data[i].response_fixed_header;
        mock_read_buffer_puback[1] = 0x02;  // Remaining Length
        mock_read_buffer_puback[2] = packet_id_msb;
        mock_read_buffer_puback[3] = packet_id_lsb;

        port_net_mock_reset_read_stream(mock_read_buffer_puback, 4);

        // Store buffers to free after the function call
        mqtt_publish_buffers[i] = mqtt_publish;
        mock_read_buffer_puback_buffers[i] = mock_read_buffer_puback;
    }

    // When: Call _delete_dev_card_by_usr
    err = _delete_dev_card_by_usr(context);

    // Then:
    assert_int_equal(err, IOT_ERROR_NONE);

    // Teardown:
    for (int i = 0; i < sizeof(data) / sizeof(struct mqtt_pub_test_data); i++) {
        free(mqtt_publish_buffers[i]);
        free(mock_read_buffer_puback_buffers[i]);
    }
    st_mqtt_destroy(client);
    free(context);
}

extern iot_error_t _do_state_updating(struct iot_context *ctx, iot_state_t new_state);

void TC_do_state_updating_success(void **state)
{
    iot_error_t err;

    // Given:
    struct iot_context *context = (struct iot_context *)*state;
    context->work_queue = iot_util_queue_create(sizeof(struct iot_command));
    assert_non_null(context->work_queue);
    context->work_queue_signal = iot_os_eventgroup_create();
    assert_non_null(context->work_queue_signal);
    iot_os_mutex_init(&context->st_conn_lock);
    context->status_cb = _status_cb_test;
    context->child_device_list = (iot_child_device *)iot_os_malloc(sizeof(iot_child_device));
    memset(context->child_device_list, '\0', sizeof(iot_child_device));
    context->child_device_list->noti_cb = test_st_cap_noti_cb;
    context->child_device_list->next = NULL;  // Ensure the next pointer is NULL
    context->status_usr_data = NULL;
    context->state_timer = iot_os_timer_create(NULL, 10000, NULL);
    iot_os_timer_start(context->state_timer);
    context->cap_handle_list = NULL;
    err = st_mqtt_create(&context->evt_mqttcli, _dummy_client_callback, NULL, NULL, NULL);
    assert_return_code(err, 0);

    // When: curr_state is initialized,new_state is prov enter
    context->curr_state = IOT_STATE_INITIALIZED;
    context->es_ble_ready = false;
#if defined(CONFIG_STDK_IOT_CORE_EASYSETUP_HTTP)
    expect_value(__wrap_iot_bsp_wifi_set_mode, conf->mode, IOT_WIFI_MODE_SOFTAP);
    will_return(__wrap_iot_bsp_wifi_set_mode, IOT_ERROR_NONE);
#endif
    err = _do_state_updating(context, IOT_STATE_PROV_ENTER);
    // Then:
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_int_equal(context->curr_state, IOT_STATE_PROV_ENTER);

    // When: curr_state is initialized,new_state is cloud disconnected
    context->curr_state = IOT_STATE_INITIALIZED;
    err = _do_state_updating(context, IOT_STATE_CLOUD_DISCONNECTED);
    // Then:
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_int_equal(context->curr_state, IOT_STATE_CLOUD_DISCONNECTED);

    // When: new_state is IOT_STATE_CLOUD_CONNECTED
    // target connected to the server
    context->curr_state = IOT_STATE_CLOUD_DISCONNECTED;
    err = _do_state_updating(context, IOT_STATE_CLOUD_CONNECTED);
    // Then:
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_int_equal(context->curr_state, IOT_STATE_CLOUD_CONNECTED);
    st_mqtt_destroy(context->evt_mqttcli);

    // When: new_state is IOT_STATE_CLOUD_CONNECTED
    // target has not connected to the server
    context->evt_mqttcli = NULL;
    context->curr_state = IOT_STATE_CLOUD_DISCONNECTED;
    err = _do_state_updating(context, IOT_STATE_CLOUD_CONNECTED);
    // Then:
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_int_equal(context->curr_state, IOT_STATE_CLOUD_CONNECTED);

    // When: new_state is IOT_STATE_CLOUD_DISCONNECTED
    context->curr_state = IOT_STATE_CLOUD_CONNECTED;
    err = _do_state_updating(context, IOT_STATE_CLOUD_DISCONNECTED);
    // Then:
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_int_equal(context->curr_state, IOT_STATE_CLOUD_DISCONNECTED);

    // When: curr_state is prov sleep, new_state is prov enter
#if defined(CONFIG_STDK_IOT_CORE_EASYSETUP_HTTP)
    expect_value(__wrap_iot_bsp_wifi_set_mode, conf->mode, IOT_WIFI_MODE_SOFTAP);
    will_return(__wrap_iot_bsp_wifi_set_mode, IOT_ERROR_NONE);
#endif
    context->curr_state = IOT_STATE_PROV_SLEEP;
    err = _do_state_updating(context, IOT_STATE_PROV_ENTER);
    // Then:
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_int_equal(context->curr_state, IOT_STATE_PROV_ENTER);

    // When: curr_state is prov sleep, new_state is prov confirm
    context->curr_state = IOT_STATE_PROV_SLEEP;
    err = _do_state_updating(context, IOT_STATE_PROV_CONFIRM);
    // Then:
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_int_equal(context->curr_state, IOT_STATE_PROV_CONFIRM);

    // When: curr_state is prov sleep, new_state is prov done
    context->curr_state = IOT_STATE_PROV_SLEEP;
    err = _do_state_updating(context, IOT_STATE_PROV_DONE);
    // Then:
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_int_equal(context->curr_state, IOT_STATE_PROV_DONE);

    // When: curr_state is prov enter, new_state is prov confirm
    context->curr_state = IOT_STATE_PROV_ENTER;
    err = _do_state_updating(context, IOT_STATE_PROV_CONFIRM);
    // Then:
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_int_equal(context->curr_state, IOT_STATE_PROV_CONFIRM);

    // When: curr_state is prov confirm, new_state is prov done
    context->curr_state = IOT_STATE_PROV_CONFIRM;
    err = _do_state_updating(context, IOT_STATE_PROV_DONE);
    // Then:
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_int_equal(context->curr_state, IOT_STATE_PROV_DONE);

    // When: curr_state is prov done, new_state is cloud disconnected
    context->curr_state = IOT_STATE_PROV_DONE;
    err = _do_state_updating(context, IOT_STATE_CLOUD_DISCONNECTED);
    // Then:
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_int_equal(context->curr_state, IOT_STATE_CLOUD_DISCONNECTED);

    // When: curr_state is prov done, new_state is prov enter
    will_return(__wrap_iot_bsp_wifi_get_scan_result, 5);
    expect_value(__wrap_iot_bsp_wifi_set_mode, conf->mode, IOT_WIFI_MODE_SCAN);
    will_return(__wrap_iot_bsp_wifi_set_mode, IOT_ERROR_NONE);
#if defined(CONFIG_STDK_IOT_CORE_EASYSETUP_HTTP)
    expect_value(__wrap_iot_bsp_wifi_set_mode, conf->mode, IOT_WIFI_MODE_SOFTAP);
    will_return(__wrap_iot_bsp_wifi_set_mode, IOT_ERROR_NONE);
#endif
    context->curr_state = IOT_STATE_PROV_DONE;
    err = _do_state_updating(context, IOT_STATE_PROV_ENTER);
    // Then:
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_int_equal(context->curr_state, IOT_STATE_PROV_ENTER);

    // When: curr_state is prov done, new_state is prov confirm
    context->curr_state = IOT_STATE_PROV_DONE;
    err = _do_state_updating(context, IOT_STATE_PROV_CONFIRM);
    // Then:
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_int_equal(context->curr_state, IOT_STATE_PROV_CONFIRM);
}

void TC_do_state_updating_prov_sleep_success(void **state)
{
    iot_error_t err;
    struct iot_context *context;

    // Given:
    context = (struct iot_context *)malloc(sizeof(struct iot_context));
    assert_non_null(context);
    memset(context, '\0', sizeof(struct iot_context));
    context->status_cb = _status_cb_test;
    context->status_usr_data = NULL;
    context->es_http_ready = NULL;
    context->state_timer = NULL;

    // When: curr_state is prov enter, new_state is prov sleep
    expect_value(__wrap_iot_bsp_wifi_set_mode, conf->mode, IOT_WIFI_MODE_OFF);
    will_return(__wrap_iot_bsp_wifi_set_mode, IOT_ERROR_NONE);
    context->curr_state = IOT_STATE_PROV_ENTER;
    err = _do_state_updating(context, IOT_STATE_PROV_SLEEP);
    // Then:
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_int_equal(context->curr_state, IOT_STATE_PROV_SLEEP);

    // Teardown
    free(context);
}

void TC_do_state_updating_failure(void **state)
{
    iot_error_t err;
    struct iot_context *context;

    // Given:
    context = (struct iot_context *)malloc(sizeof(struct iot_context));
    assert_non_null(context);
    memset(context, '\0', sizeof(struct iot_context));

    context->curr_state = IOT_STATE_CLOUD_DISCONNECTED;

    // When: new_state is IOT_STATE_CLOUD_CONNECTED
    err = _do_state_updating(context, IOT_STATE_CLOUD_DISCONNECTED);

    // Then:
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);

    // Teardown:
    free(context);
}

#if defined(CONFIG_STDK_IOT_CORE_EASYSETUP_HTTP)
void TC_do_state_updating_prov_sleep_failure(void **state)
{
    iot_error_t err;
    struct iot_context *context;

    // Given:
    context = (struct iot_context *)malloc(sizeof(struct iot_context));
    assert_non_null(context);
    memset(context, '\0', sizeof(struct iot_context));

    context->curr_state = IOT_STATE_PROV_SLEEP;

    // When: new_state is IOT_STATE_PROV_ENTER
    err = _do_state_updating(context, IOT_STATE_PROV_ENTER);
    // Then:
    assert_int_equal(err, IOT_ERROR_NV_DATA_ERROR);

    // Teardown:
    free(context);
}
#endif

void TC_do_state_updating_prov_sleep_invalid_args_failure(void **state)
{
    iot_error_t err;
    struct iot_context *context;

    // Given:
    context = (struct iot_context *)malloc(sizeof(struct iot_context));
    assert_non_null(context);
    memset(context, '\0', sizeof(struct iot_context));

    context->curr_state = IOT_STATE_PROV_SLEEP;

    // When: new_state is invalid
    err = _do_state_updating(context, IOT_STATE_INITIALIZED);
    // Then:
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);

    // Teardown:
    free(context);
}

void TC_do_state_updating_state_initialized_failure(void **state)
{
    iot_error_t err;
    struct iot_context *context;

    // Given:
    context = (struct iot_context *)malloc(sizeof(struct iot_context));
    assert_non_null(context);
    memset(context, '\0', sizeof(struct iot_context));

    context->curr_state = IOT_STATE_INITIALIZED;

    // When: new_state is invalid
    err = _do_state_updating(context, IOT_STATE_INITIALIZED);
    // Then:
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);

    // Teardown:
    free(context);
}

void TC_do_state_updating_state_prov_enter_failure(void **state)
{
    iot_error_t err;
    struct iot_context *context;

    // Given:
    context = (struct iot_context *)malloc(sizeof(struct iot_context));
    assert_non_null(context);
    memset(context, '\0', sizeof(struct iot_context));

    context->curr_state = IOT_STATE_INITIALIZED;

    // When: new_state is invalid
    err = _do_state_updating(context, IOT_STATE_INITIALIZED);
    // Then:
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);

    // Teardown:
    free(context);
}

void TC_do_state_updating_state_prov_confirm_failure(void **state)
{
    iot_error_t err;
    struct iot_context *context;

    // Given:
    context = (struct iot_context *)malloc(sizeof(struct iot_context));
    assert_non_null(context);
    memset(context, '\0', sizeof(struct iot_context));

    context->curr_state = IOT_STATE_PROV_CONFIRM;

    // When: new_state is invalid
    err = _do_state_updating(context, IOT_STATE_INITIALIZED);
    // Then:
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);

    // Teardown:
    free(context);
}

void TC_do_state_updating_state_prov_done_failure(void **state)
{
    iot_error_t err;
    struct iot_context *context;

    // Given:
    context = (struct iot_context *)*state;
    context->curr_state = IOT_STATE_PROV_DONE;

    // When: new_state is invalid
    err = _do_state_updating(context, IOT_STATE_INITIALIZED);
    // Then:
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);

    // When: new state is prov enter and wifi scan failed
    expect_value(__wrap_iot_bsp_wifi_set_mode, conf->mode, IOT_WIFI_MODE_SCAN);
    will_return(__wrap_iot_bsp_wifi_set_mode, IOT_ERROR_CONN_OPERATE_FAIL);
    err = _do_state_updating(context, IOT_STATE_PROV_ENTER);
    // Then:
    assert_int_equal(err, IOT_ERROR_CONN_OPERATE_FAIL);

#if defined(CONFIG_STDK_IOT_CORE_EASYSETUP_HTTP)
    // When: new state is prov enter and softap failed
    will_return(__wrap_iot_bsp_wifi_get_scan_result, 5);
    expect_value(__wrap_iot_bsp_wifi_set_mode, conf->mode, IOT_WIFI_MODE_SCAN);
    will_return(__wrap_iot_bsp_wifi_set_mode, IOT_ERROR_NONE);
    expect_value(__wrap_iot_bsp_wifi_set_mode, conf->mode, IOT_WIFI_MODE_SOFTAP);
    will_return(__wrap_iot_bsp_wifi_set_mode, IOT_ERROR_INVALID_ARGS);
    err = _do_state_updating(context, IOT_STATE_PROV_ENTER);
    // Then:
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);
#endif
}

void TC_do_state_updating_prov_enter_invalid_args_failure(void **state)
{
    iot_error_t err;
    struct iot_context *context;

    // Given:
    context = (struct iot_context *)malloc(sizeof(struct iot_context));
    assert_non_null(context);
    memset(context, '\0', sizeof(struct iot_context));

    context->curr_state = IOT_STATE_PROV_ENTER;

    // When: new_state is invalid
    err = _do_state_updating(context, IOT_STATE_INITIALIZED);
    // Then:
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);

    // Teardown:
    free(context);
}

void TC_do_state_updating_invalid_args_failure(void **state)
{
    iot_error_t err;
    struct iot_context *context;

    // Given:
    context = (struct iot_context *)malloc(sizeof(struct iot_context));
    assert_non_null(context);
    memset(context, '\0', sizeof(struct iot_context));

    context->curr_state = IOT_STATE_CLOUD_CONNECTED + 1;

    // When: curr_state is invalid
    err = _do_state_updating(context, IOT_STATE_INITIALIZED);
    // Then:
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);

    // Teardown:
    free(context);
}

void TC_command_work_handler_null_cmd_data_N(void **state)
{
    struct iot_context context = {0};
    UNUSED(state);

    // When: NULL cmd_data parameter
    _command_work_handler(&context, NULL);
    // Then: should not crash (no assert needed as it's a void function)
}
void TC_command_work_handler_success_P(void **state)
{
    struct iot_context *context;
    struct iot_command *cmd_data;
    struct iot_state_data *state_data;
    UNUSED(state);

    // Given: valid context and command data
    context = (struct iot_context *)*state;
    assert_non_null(context);
    context->work_queue = iot_util_queue_create(sizeof(struct iot_command));
    assert_non_null(context->work_queue);
    context->work_queue_signal = iot_os_eventgroup_create();
    assert_non_null(context->work_queue_signal);
    iot_os_mutex_init(&context->st_conn_lock);
    context->curr_state = IOT_STATE_INITIALIZED;

    cmd_data = (struct iot_command *)calloc(1, sizeof(struct iot_command));
    assert_non_null(cmd_data);
    cmd_data->cmd_type = IOT_COMMAND_STATE_UPDATE;

    state_data = (struct iot_state_data *)calloc(1, sizeof(struct iot_state_data));
    assert_non_null(state_data);
    state_data->iot_state = IOT_STATE_PROV_ENTER;
    state_data->opt = IOT_STATE_OPT_NONE;
    cmd_data->param = state_data;

    // When: valid parameters
    _command_work_handler(context, (device_work_param)cmd_data);

    // Teardown
    iot_util_queue_delete(context->work_queue);
    iot_os_eventgroup_delete(context->work_queue_signal);
    iot_os_mutex_destroy(&context->st_conn_lock);
}
void TC_next_connection_retry_timeout_success_P(void **state)
{
    struct iot_context context = {0};
    UNUSED(state);

    // Given: valid context
    context.work_queue = iot_util_queue_create(sizeof(struct iot_command));
    assert_non_null(context.work_queue);
    context.work_queue_signal = iot_os_eventgroup_create();
    assert_non_null(context.work_queue_signal);
    iot_os_mutex_init(&context.st_conn_lock);

    // When: valid context
    _next_connection_retry_timeout(NULL, &context);

    // Teardown
    iot_util_queue_delete(context.work_queue);
    iot_os_eventgroup_delete(context.work_queue_signal);
    iot_os_mutex_destroy(&context.st_conn_lock);
}
void TC_iot_state_timeout_cb_P(void **state)
{
    struct iot_context context = {0};
    UNUSED(state);

    // Given: curr state is initialized state
    context.curr_state = IOT_STATE_INITIALIZED;

    // When: timeout callback for initialized state
    _iot_state_timeout_cb(NULL, &context);

    // When: timeout callback for prov sleep state
    context.curr_state = IOT_STATE_PROV_SLEEP;
    _iot_state_timeout_cb(NULL, &context);

    // When: timeout callback for prov confirm state
    context.curr_state = IOT_STATE_PROV_CONFIRM;
    _iot_state_timeout_cb(NULL, &context);

    // When: timeout callback for cloud disconnected state
    context.curr_state = IOT_STATE_CLOUD_DISCONNECTED;
    _iot_state_timeout_cb(NULL, &context);

    // When: timeout callback for cloud connected state
    context.curr_state = IOT_STATE_CLOUD_CONNECTED;
    _iot_state_timeout_cb(NULL, &context);
}
void TC_iot_state_timeout_cb_prov_enter_P(void **state)
{
    struct iot_context context = {0};
    UNUSED(state);

    // Given: context in PROV_ENTER state
    context.curr_state = IOT_STATE_PROV_ENTER;
    context.work_queue = iot_util_queue_create(sizeof(struct iot_command));
    assert_non_null(context.work_queue);
    context.work_queue_signal = iot_os_eventgroup_create();
    assert_non_null(context.work_queue_signal);
    iot_os_mutex_init(&context.st_conn_lock);

    // When: timeout callback for PROV_ENTER state
    _iot_state_timeout_cb(NULL, &context);

    // Teardown
    iot_util_queue_delete(context.work_queue);
    iot_os_eventgroup_delete(context.work_queue_signal);
    iot_os_mutex_destroy(&context.st_conn_lock);
}
void TC_iot_state_timeout_cb_prov_done_P(void **state)
{
    struct iot_context context = {0};
    UNUSED(state);

    // Given: context in PROV_DONE state
    context.curr_state = IOT_STATE_PROV_DONE;
    context.work_queue = iot_util_queue_create(sizeof(struct iot_command));
    assert_non_null(context.work_queue);
    context.work_queue_signal = iot_os_eventgroup_create();
    assert_non_null(context.work_queue_signal);
    iot_os_mutex_init(&context.st_conn_lock);

    // When: timeout callback for PROV_DONE state
    _iot_state_timeout_cb(NULL, &context);

    // Teardown
    iot_util_queue_delete(context.work_queue);
    iot_os_eventgroup_delete(context.work_queue_signal);
    iot_os_mutex_destroy(&context.st_conn_lock);
}
void TC_get_device_preference_null_mqtt_client_N(void **state)
{
    struct iot_context context = {0};
    UNUSED(state);

    // Given: NULL MQTT client
    context.evt_mqttcli = NULL;

    // When: _get_device_preference called with NULL MQTT client
    _get_device_preference(&context);
    // Then: should not crash (no assert needed as it's a void function)
}
void TC_get_device_preference_success_P(void **state)
{
    int err;
    iot_error_t iot_err;
    struct iot_context *context;
    st_mqtt_client client;
    MQTTClient *c;
    UNUSED(state);

    // Given: valid context with MQTT client
    context = (struct iot_context *)calloc(1, sizeof(struct iot_context));
    assert_non_null(context);

    err = st_mqtt_create(&client, _dummy_client_callback, NULL, NULL, NULL);
    assert_return_code(err, 0);
    c = (MQTTClient *)client;
    c->isconnected = 1;
    port_net_mock_reset_socket_status(1);
    c->last_sent = iot_os_timer_create(NULL, 10000, NULL);
    iot_err = iot_os_timer_start(c->last_sent);
    assert_int_equal(iot_err, IOT_ERROR_NONE);

    c->last_received = iot_os_timer_create(NULL, 10000, NULL);
    iot_err = iot_os_timer_start(c->last_received);
    assert_int_equal(iot_err, IOT_ERROR_NONE);

    context->evt_mqttcli = (st_mqtt_client)client;

    // Set up mock expectations for the actual payload that will be sent
    set_mock_port_net_write_skip_buf_check(1);
    set_mock_port_net_write_skip_len_check(1);

    // Set up mock response (PUBACK for QoS1)
    unsigned char mock_read_buffer_puback[4];
    mock_read_buffer_puback[0] = 0x40;  // PUBACK fixed header
    mock_read_buffer_puback[1] = 0x02;  // Remaining Length

    char packet_id_msb = 0x00;
    char packet_id_lsb = (char)(c->next_packetid + 1);
    mock_read_buffer_puback[2] = packet_id_msb;
    mock_read_buffer_puback[3] = packet_id_lsb;
    port_net_mock_reset_read_stream(mock_read_buffer_puback, 4);

    // When: valid parameters
    _get_device_preference(context);

    reset_mock_port_net_write_skip_flags();

    // Teardown
    st_mqtt_destroy(client);
    free(context);
}
