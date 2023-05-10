/*
   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

/****************************************************************************
*
* This demo showcases BLE GATT server. It can send adv data, be connected by client.
* Run the gatt_client demo, the client demo will automatically connect to the gatt_server demo.
* Client demo will enable gatt_server's notify after connection. The two devices will then exchange
* data.
*
****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "sdkconfig.h"
#include "iot_bsp_ble.h"
#include "esp_system.h"
#include "esp_log.h"
#include "nvs_flash.h"

#include "esp_bt.h"

#include "esp_gap_ble_api.h"
#include "esp_gatts_api.h"
#include "esp_bt_defs.h"
#include "esp_bt_main.h"
#include "esp_gatt_common_api.h"

#define GATTS_TAG "BLE_ONBOARD"

///Declare the static function
static void gatts_event_handler(esp_gatts_cb_event_t event, esp_gatt_if_t gatts_if, esp_ble_gatts_cb_param_t *param);

#define BLE_ONBOARDING_SERVICE_UUID   0xFD1D
#define GATTS_DESCR_UUID_TEST_A       0x3333
#define GATTS_NUM_HANDLE_TEST_A       4

#define TEST_DEVICE_NAME              "BLE_ONBOARDING"
#define TEST_MANUFACTURER_DATA_LEN    17

#define GATTS_CHAR_VAL_LEN_MAX        1024

#define PREPARE_BUF_MAX_SIZE          1024

#define MAX_CHAR_LEN                  1024
#define PROFILE_APP_ID 0

#define DISPLAY_SERIAL_NUMBER_SIZE 4

#define PACKET_MAX_SIZE     31
#define MAC_ADD_COUNT       6

#define ADV_FLAG_LEN        0x02
#define ADV_FLAG_TYPE       0x01
#define ADV_FLAG_VALUE        0x04
#define ADV_SERVICE_DATA_LEN        0x1B

#define CUSTOM_DATA_TYPE        0xFF
#define CUSTOM_DATA_LEN         0x06

#define CONTROL_VERSION_ACTIVE_SCAN_REQUIRED        0x42
#define PACKET_VERSION        0x83
#define SERVICE_ID        0x0c
#define OOB_SERVICE_INFO        0x05
#define SERVICE_FEATURE        0x59
#define SETUP_AVAILABLE_NETWORK_BLE        0x04

#define BT_ADDRESS_TRANSFER       0x01

#define SCAN_RESP_FLAG_TYPE     0x09
#define SCAN_RESP_MF_DATA_LEN   0x06

extern int g_flg;
static uint8_t ble_onboarding_char_uuid[16] = {0x09, 0x0E, 0xE6, 0x80, 0x02, 0x30, 0xC7, 0xA4, 0x8E, 0x4F, 0x2D, 0xAE, 0x0E, 0x0F, 0x94, 0xBE};

static uint8_t char_val[MAX_CHAR_LEN] = {0x00};
static esp_gatt_char_prop_t char_property = 0;

static esp_attr_value_t ble_onboard_char =
{
    .attr_max_len = GATTS_CHAR_VAL_LEN_MAX,
    .attr_len     = sizeof(char_val),
    .attr_value   = char_val,
};

static uint32_t g_mtu = 0;
static uint8_t adv_config_done = 0;
#define adv_config_flag      (1 << 0)
#define scan_rsp_config_flag (1 << 1)

static uint8_t adv_data[PACKET_MAX_SIZE];
static size_t adv_data_len;
static uint8_t scan_response_data[PACKET_MAX_SIZE];
static size_t scan_response_len;
static uint8_t manufacturer_id[2] = {0x75, 0x00};

CharWriteCallback CharWriteCb;

static esp_ble_adv_params_t adv_params = {
    .adv_int_min        = 0x20,
    .adv_int_max        = 0x40,
    .adv_type           = ADV_TYPE_IND,
    .own_addr_type      = BLE_ADDR_TYPE_PUBLIC,
    //.peer_addr            =
    //.peer_addr_type       =
    .channel_map        = ADV_CHNL_ALL,
    .adv_filter_policy = ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY,
};


struct gatts_profile_inst {
    uint16_t gatts_if;
    uint16_t app_id;
    uint16_t conn_id;
    uint16_t service_handle;
    esp_gatt_srvc_id_t service_id;
    uint16_t char_handle;
    esp_bt_uuid_t char_uuid;
    esp_gatt_perm_t perm;
    esp_gatt_char_prop_t property;
    uint16_t descr_handle;
    esp_bt_uuid_t descr_uuid;
};

/* One gatt-based profile one app_id and one gatts_if, this array will store the gatts_if returned by ESP_GATTS_REG_EVT */
static struct gatts_profile_inst gl_profile = {
    .gatts_if = ESP_GATT_IF_NONE,       /* Not get the gatt_if, so initial is ESP_GATT_IF_NONE */
};

static void gap_event_handler(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t *param)
{
    switch (event) {
    case ESP_GAP_BLE_ADV_DATA_RAW_SET_COMPLETE_EVT:
        adv_config_done &= (~adv_config_flag);
        if (adv_config_done==0){
            esp_ble_gap_start_advertising(&adv_params);
        }
        break;
    case ESP_GAP_BLE_SCAN_RSP_DATA_RAW_SET_COMPLETE_EVT:
        adv_config_done &= (~scan_rsp_config_flag);
        if (adv_config_done==0){
            esp_ble_gap_start_advertising(&adv_params);
        }
        break;
    case ESP_GAP_BLE_ADV_START_COMPLETE_EVT:
        //advertising start complete event to indicate advertising start successfully or failed
        if (param->adv_start_cmpl.status != ESP_BT_STATUS_SUCCESS) {
            ESP_LOGE(GATTS_TAG, "Advertising start failed\n");
        }
        break;
    case ESP_GAP_BLE_ADV_STOP_COMPLETE_EVT:
        if (param->adv_stop_cmpl.status != ESP_BT_STATUS_SUCCESS) {
            ESP_LOGE(GATTS_TAG, "Advertising stop failed\n");
        } else {
            ESP_LOGI(GATTS_TAG, "Stop adv successfully\n");
        }
        break;
    case ESP_GAP_BLE_UPDATE_CONN_PARAMS_EVT:
         ESP_LOGI(GATTS_TAG, "update connection params status = %d, min_int = %d, max_int = %d,conn_int = %d,latency = %d, timeout = %d",
                  param->update_conn_params.status,
                  param->update_conn_params.min_int,
                  param->update_conn_params.max_int,
                  param->update_conn_params.conn_int,
                  param->update_conn_params.latency,
                  param->update_conn_params.timeout);
        break;
    default:
        break;
    }
}

void iot_create_advertise_packet(char *mnid, char *setupid, char *serial)
{
    const uint8_t *mac;
    int count = 0;
    int i;
    int mnid_len = 0;
    int serial_len = 0;
    int setupid_len = 0;
    unsigned char display_serial[DISPLAY_SERIAL_NUMBER_SIZE + 1] = { 0,};

    serial_len = strlen(serial);

    for (i = 0; i < DISPLAY_SERIAL_NUMBER_SIZE; i++) {
		display_serial[i] = serial[serial_len - DISPLAY_SERIAL_NUMBER_SIZE + i];
    }
    display_serial[DISPLAY_SERIAL_NUMBER_SIZE] = '\0';
    ESP_LOGI(GATTS_TAG, ">> Display_Serial [%c%c%c%c] <<", display_serial[0], display_serial[1],
            display_serial[2], display_serial[3]);

    adv_data[count++] = ADV_FLAG_LEN;
    adv_data[count++] = ADV_FLAG_TYPE;
    adv_data[count++] = ADV_FLAG_VALUE;
    adv_data[count++] = ADV_SERVICE_DATA_LEN;
    adv_data[count++] = CUSTOM_DATA_TYPE;
    adv_data[count++] = manufacturer_id[0];
    adv_data[count++] = manufacturer_id[1];
    adv_data[count++] = CONTROL_VERSION_ACTIVE_SCAN_REQUIRED;
    adv_data[count++] = SERVICE_ID;
    adv_data[count++] = PACKET_VERSION;
	adv_data[count++] = OOB_SERVICE_INFO;
    adv_data[count++] = SERVICE_FEATURE;

    mnid_len = strlen(mnid);

    for(i = 0; i < mnid_len; i ++) {
        adv_data[count++] = (uint8_t ) mnid[i];
    }

    setupid_len = strlen(setupid);

    for(i = 0; i < setupid_len; i ++) {
        adv_data[count++] = (uint8_t ) setupid[i];
    }

    adv_data[count++] = SETUP_AVAILABLE_NETWORK_BLE;
    adv_data[count++] = BT_ADDRESS_TRANSFER;

    count += MAC_ADD_COUNT;

    adv_data[count++] = CUSTOM_DATA_LEN;
    adv_data[count++] = 0x02;
    adv_data[count++] = 0x04;
    adv_data[count++] = display_serial[0];

	adv_data_len = count;
}

void iot_create_scan_response_packet(char *device_onboarding_id, char *serial)
{
    int count = 0;
    int i;
    int serial_len = 0;
	size_t device_onboarding_id_len = 0;
    unsigned char display_serial[DISPLAY_SERIAL_NUMBER_SIZE + 1] = { 0,};

    serial_len = strlen(serial);

    for (i = 0; i < DISPLAY_SERIAL_NUMBER_SIZE; i++) {
		display_serial[i] = serial[serial_len - DISPLAY_SERIAL_NUMBER_SIZE + i];
    }
    display_serial[DISPLAY_SERIAL_NUMBER_SIZE] = '\0';

    device_onboarding_id_len = strlen(device_onboarding_id);

    scan_response_data[count++] = device_onboarding_id_len + 1;
    scan_response_data[count++] = SCAN_RESP_FLAG_TYPE;

    for (i = 0; i < device_onboarding_id_len; i++) {
        scan_response_data[count++] = (uint8_t ) device_onboarding_id[i];
    }

    scan_response_data[count++] = SCAN_RESP_MF_DATA_LEN;
    scan_response_data[count++] = CUSTOM_DATA_TYPE;
    scan_response_data[count++] = manufacturer_id[0];
    scan_response_data[count++] = manufacturer_id[1];

    for (i = 1; i < DISPLAY_SERIAL_NUMBER_SIZE; i++) {
        scan_response_data[count++] = (uint8_t ) display_serial[i];
    }

	scan_response_len = count;

    for (i = count; i < PACKET_MAX_SIZE; i++) {
        scan_response_data[count++] = 0;
    }
}

int iot_send_indication(uint8_t *buf, uint32_t len)
{
    if(NULL == buf || 0 == len) {
        return -1;
    }
    esp_ble_gatts_send_indicate(gl_profile.gatts_if, gl_profile.conn_id, gl_profile.char_handle, len, buf, true);

	return 0;
}

static void gatts_event_handler(esp_gatts_cb_event_t event, esp_gatt_if_t gatts_if, esp_ble_gatts_cb_param_t *param) 
{
	esp_attr_control_t control;
    if (event == ESP_GATTS_REG_EVT) {
        if (param->reg.status == ESP_GATT_OK) {
            gl_profile.gatts_if = gatts_if;
        } else {
            ESP_LOGE(GATTS_TAG, "reg app failed, app_id 0x0x%x, status %d",
                     param->reg.app_id,
                     param->reg.status);
            return;
        }
    }

    if (gatts_if != ESP_GATT_IF_NONE && gl_profile.gatts_if != gatts_if) {
        return;
    }

    switch (event) {
    case ESP_GATTS_REG_EVT:
        ESP_LOGI(GATTS_TAG, "REGISTER_APP_EVT, status %d, app_id %d\n", param->reg.status, param->reg.app_id);
        gl_profile.service_id.is_primary = true;
        gl_profile.service_id.id.inst_id = 0x00;
        gl_profile.service_id.id.uuid.len = ESP_UUID_LEN_16;
        gl_profile.service_id.id.uuid.uuid.uuid16 = BLE_ONBOARDING_SERVICE_UUID;

        esp_err_t set_dev_name_ret = esp_ble_gap_set_device_name(TEST_DEVICE_NAME);
        if (set_dev_name_ret){
            ESP_LOGE(GATTS_TAG, "set device name failed, error code = %x", set_dev_name_ret);
        }
        esp_err_t raw_adv_ret = esp_ble_gap_config_adv_data_raw(adv_data, adv_data_len);
        if (raw_adv_ret){
            ESP_LOGE(GATTS_TAG, "config raw adv data failed, error code = %x ", raw_adv_ret);
        }
        adv_config_done |= adv_config_flag;
        esp_err_t raw_scan_ret = esp_ble_gap_config_scan_rsp_data_raw(scan_response_data, scan_response_len);
        if (raw_scan_ret){
            ESP_LOGE(GATTS_TAG, "config raw scan rsp data failed, error code = %x", raw_scan_ret);
        }
        adv_config_done |= scan_rsp_config_flag;
        
	esp_ble_gatts_create_service(gatts_if, &gl_profile.service_id, GATTS_NUM_HANDLE_TEST_A);
        break;
    case ESP_GATTS_READ_EVT: {
        ESP_LOGI(GATTS_TAG, "GATT_READ_EVT, conn_id %d, trans_id %d, handle %d\n", param->read.conn_id, param->read.trans_id, param->read.handle);

	esp_gatt_rsp_t rsp;
        memset(&rsp, 0, sizeof(esp_gatt_rsp_t));
        rsp.attr_value.handle = param->read.handle;
        rsp.attr_value.len = 0;
	esp_ble_gatts_send_response(gatts_if, param->read.conn_id, param->read.trans_id,
                                    ESP_GATT_OK, &rsp);

        break;
    }
    case ESP_GATTS_WRITE_EVT: {
        ESP_LOGI(GATTS_TAG, "GATT_WRITE_EVT, conn_id %d, trans_id %d, handle %d need resp %d is_prep %d", param->write.conn_id, param->write.trans_id, param->write.handle, param->write.need_rsp, param->write.is_prep);
        esp_ble_gatts_send_response(gatts_if, param->write.conn_id, param->write.trans_id, ESP_GATT_OK, NULL);

        if (param->write.handle == gl_profile.char_handle) {
            // Do further process here
            if (CharWriteCb) {
                CharWriteCb(param->write.value, param->write.len);
            }
        }
        break;
    }
    case ESP_GATTS_EXEC_WRITE_EVT:
        ESP_LOGI(GATTS_TAG,"ESP_GATTS_EXEC_WRITE_EVT");
        esp_ble_gatts_send_response(gatts_if, param->write.conn_id, param->write.trans_id, ESP_GATT_OK, NULL);
        break;
    case ESP_GATTS_MTU_EVT:
        ESP_LOGI(GATTS_TAG, "ESP_GATTS_MTU_EVT, MTU %d", param->mtu.mtu);
        g_mtu = param->mtu.mtu;
        break;
    case ESP_GATTS_UNREG_EVT:
        break;
    case ESP_GATTS_CREATE_EVT:
        ESP_LOGI(GATTS_TAG, "CREATE_SERVICE_EVT, status %d,  service_handle %d\n", param->create.status, param->create.service_handle);
        gl_profile.service_handle = param->create.service_handle;
        gl_profile.char_uuid.len = ESP_UUID_LEN_128;
        memcpy(gl_profile.char_uuid.uuid.uuid128, ble_onboarding_char_uuid ,16);

		control.auto_rsp = ESP_GATT_RSP_BY_APP;
        esp_ble_gatts_start_service(gl_profile.service_handle);
        char_property = ESP_GATT_CHAR_PROP_BIT_READ | ESP_GATT_CHAR_PROP_BIT_WRITE | ESP_GATT_CHAR_PROP_BIT_NOTIFY | ESP_GATT_CHAR_PROP_BIT_INDICATE;
        esp_err_t add_char_ret = esp_ble_gatts_add_char(gl_profile.service_handle, &gl_profile.char_uuid,
                                                        ESP_GATT_PERM_READ | ESP_GATT_PERM_WRITE,
                                                        char_property,
                                                        &ble_onboard_char, &control);
        if (add_char_ret){
            ESP_LOGE(GATTS_TAG, "add char failed, error code =%x",add_char_ret);
        }
        break;
    case ESP_GATTS_ADD_INCL_SRVC_EVT:
        break;
    case ESP_GATTS_ADD_CHAR_EVT: {
        ESP_LOGI(GATTS_TAG, "ADD_CHAR_EVT, status %d,  attr_handle %d, service_handle %d\n",
                param->add_char.status, param->add_char.attr_handle, param->add_char.service_handle);
        gl_profile.char_handle = param->add_char.attr_handle;
#if(1)
        uint16_t length = 0;
        const uint8_t *prf_char;

        gl_profile.descr_uuid.len = ESP_UUID_LEN_16;
        gl_profile.descr_uuid.uuid.uuid16 = ESP_GATT_UUID_CHAR_CLIENT_CONFIG;
        esp_err_t get_attr_ret = esp_ble_gatts_get_attr_value(param->add_char.attr_handle,  &length, &prf_char);
        if (get_attr_ret == ESP_FAIL){
            ESP_LOGE(GATTS_TAG, "ILLEGAL HANDLE");
        }

        ESP_LOGI(GATTS_TAG, "the gatts demo char length = %x\n", length);
        esp_err_t add_descr_ret = esp_ble_gatts_add_char_descr(gl_profile.service_handle, &gl_profile.descr_uuid,
                                                                ESP_GATT_PERM_READ | ESP_GATT_PERM_WRITE, NULL, NULL);
        if (add_descr_ret){
            ESP_LOGE(GATTS_TAG, "add char descr failed, error code =%x", add_descr_ret);
        }
#endif
        break;
    }
    case ESP_GATTS_ADD_CHAR_DESCR_EVT:
        gl_profile.descr_handle = param->add_char_descr.attr_handle;
        ESP_LOGI(GATTS_TAG, "ADD_DESCR_EVT, status %d, attr_handle %d, service_handle %d\n",
                 param->add_char_descr.status, param->add_char_descr.attr_handle, param->add_char_descr.service_handle);
        break;
    case ESP_GATTS_DELETE_EVT:
        break;
    case ESP_GATTS_START_EVT:
        ESP_LOGI(GATTS_TAG, "SERVICE_START_EVT, status %d, service_handle %d\n",
                 param->start.status, param->start.service_handle);
        break;
    case ESP_GATTS_STOP_EVT:
        break;
    case ESP_GATTS_CONNECT_EVT: {
        esp_ble_conn_update_params_t conn_params = {0};
        memcpy(conn_params.bda, param->connect.remote_bda, sizeof(esp_bd_addr_t));
        /* For the IOS system, please reference the apple official documents about the ble connection parameters restrictions. */
        conn_params.latency = 0;
        conn_params.max_int = 0x20;    // max_int = 0x20*1.25ms = 40ms
        conn_params.min_int = 0x10;    // min_int = 0x10*1.25ms = 20ms
        conn_params.timeout = 400;     // timeout = 400*10ms = 4000ms
        ESP_LOGI(GATTS_TAG, "ESP_GATTS_CONNECT_EVT, conn_id %d, remote %02x:%02x:%02x:%02x:%02x:%02x:",
                 param->connect.conn_id,
                 param->connect.remote_bda[0], param->connect.remote_bda[1], param->connect.remote_bda[2],
                 param->connect.remote_bda[3], param->connect.remote_bda[4], param->connect.remote_bda[5]);
        gl_profile.conn_id = param->connect.conn_id;
        //start sent the update connection parameters to the peer device.
        esp_ble_gap_update_conn_params(&conn_params);
        break;
    }
    case ESP_GATTS_DISCONNECT_EVT:
        ESP_LOGI(GATTS_TAG, "ESP_GATTS_DISCONNECT_EVT, disconnect reason 0x%x", param->disconnect.reason);
        esp_ble_gap_start_advertising(&adv_params);
        break;
    case ESP_GATTS_CONF_EVT:
        ESP_LOGI(GATTS_TAG, "ESP_GATTS_CONF_EVT, status %d attr_handle %d", param->conf.status, param->conf.handle);
        if (param->conf.status != ESP_GATT_OK){
            esp_log_buffer_hex(GATTS_TAG, param->conf.value, param->conf.len);
        }
        g_flg = 1;
        break;
    case ESP_GATTS_OPEN_EVT:
    case ESP_GATTS_CANCEL_OPEN_EVT:
    case ESP_GATTS_CLOSE_EVT:
    case ESP_GATTS_LISTEN_EVT:
    case ESP_GATTS_CONGEST_EVT:
    default:
        break;
    }
}

void iot_bsp_ble_init(CharWriteCallback cb)
{
    esp_err_t ret;

    // Initialize NVS.
    ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK( ret );

    CharWriteCb = cb;

    ESP_ERROR_CHECK(esp_bt_controller_mem_release(ESP_BT_MODE_CLASSIC_BT));

    esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
    ret = esp_bt_controller_init(&bt_cfg);
    if (ret) {
        ESP_LOGE(GATTS_TAG, "%s initialize controller failed: %s\n", __func__, esp_err_to_name(ret));
        return;
    }

    ret = esp_bt_controller_enable(ESP_BT_MODE_BLE);
    if (ret) {
        ESP_LOGE(GATTS_TAG, "%s enable controller failed: %s\n", __func__, esp_err_to_name(ret));
        return;
    }
    ret = esp_bluedroid_init();
    if (ret) {
        ESP_LOGE(GATTS_TAG, "%s init bluetooth failed: %s\n", __func__, esp_err_to_name(ret));
        return;
    }
    ret = esp_bluedroid_enable();
    if (ret) {
        ESP_LOGE(GATTS_TAG, "%s enable bluetooth failed: %s\n", __func__, esp_err_to_name(ret));
        return;
    }
    ret = esp_ble_gatts_register_callback(gatts_event_handler);
    if (ret){
        ESP_LOGE(GATTS_TAG, "gatts register error, error code = %x", ret);
        return;
    }
    ret = esp_ble_gap_register_callback(gap_event_handler);
    if (ret){
        ESP_LOGE(GATTS_TAG, "gap register error, error code = %x", ret);
        return;
    }
    ret = esp_ble_gatts_app_register(PROFILE_APP_ID);
    if (ret){
        ESP_LOGE(GATTS_TAG, "gatts app register error, error code = %x", ret);
        return;
    }
    g_mtu = 500;
    esp_err_t local_mtu_ret = esp_ble_gatt_set_local_mtu(g_mtu);
    if (local_mtu_ret){
        ESP_LOGE(GATTS_TAG, "set local  MTU failed, error code = %x", local_mtu_ret);
    }

    return;
}

void iot_bsp_ble_deinit(void)
{
    return;
}

uint32_t iot_bsp_ble_get_mtu(void)
{
    return g_mtu;
}

