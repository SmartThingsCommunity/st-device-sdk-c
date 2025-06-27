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
#include <sys/time.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

#include "esp_system.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_bt.h"
#include "esp_mac.h"
#include "esp_gap_ble_api.h"
#include "esp_gatts_api.h"
#include "esp_bt_defs.h"
#include "esp_bt_main.h"
#include "esp_gatt_common_api.h"

#include "iot_bsp_ble.h"

/* LOG TAG */
#define GATTS_TAG "BLE_ONBOARD"

#define PROFILE_APP_ID 0

/* GATT server config */
#define BLE_ONBOARDING_SERVICE_UUID   0xFD1D
#define GATTS_NUM_HANDLE       4
#define GATTS_CHAR_VAL_LEN_MAX        1024

/* Advertising Define */
#define PACKET_MAX_SIZE     31
#define ADV_FLAG_LEN            0x02
#define ADV_FLAG_TYPE           0x01
#define ADV_FLAG_VALUE          0x04
#define ADV_MANUFACTURER_DATA_TYPE        0xFF
#define ADV_LOCAL_NAME_TYPE         0x09

#define ADV_CONFIG_FLAG         (1 << 0)
#define SCAN_RSP_CONFIG_FLAG    (1 << 1)

#define GATTS_MTU_MAX    517

/* BLE status */
enum esp_ble_status {
	ESP_BLE_STATUS_UNKNOWN,
	ESP_BLE_STATUS_INIT,
	ESP_BLE_STATUS_DEINIT,
};

/* GATT profile info struct */
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

/* GATT Characteristic info */
static uint8_t ble_onboarding_char_uuid[16] = {0x09, 0x0E, 0xE6, 0x80, 0x02, 0x30, 0xC7, 0xA4, 0x8E, 0x4F, 0x2D, 0xAE, 0x0E, 0x0F, 0x94, 0xBE};
static uint8_t char_val[GATTS_CHAR_VAL_LEN_MAX] = {0x00};
static esp_attr_value_t ble_onboard_char = {
    .attr_max_len = GATTS_CHAR_VAL_LEN_MAX,
    .attr_len     = sizeof(char_val),
    .attr_value   = char_val,
};

/* Advertising parameters */
static esp_ble_adv_params_t adv_params = {
    .adv_int_min        = 0x20,
    .adv_int_max        = 0x40,
    .adv_type           = ADV_TYPE_IND,
    .own_addr_type      = BLE_ADDR_TYPE_PUBLIC,
    .channel_map        = ADV_CHNL_ALL,
    .adv_filter_policy = ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY,
};

/* One gatt-based profile one app_id and one gatts_if, this array will store the gatts_if returned by ESP_GATTS_REG_EVT */
static struct gatts_profile_inst gl_profile = {
	.gatts_if = ESP_GATT_IF_NONE,       /* Not get the gatt_if, so initial is ESP_GATT_IF_NONE */
};

static int indication_need_confirmed;
static int gatt_connected;
static uint8_t adv_config_done = 0;
static uint8_t is_advertising = 0;;
static enum esp_ble_status g_ble_status = ESP_BLE_STATUS_UNKNOWN;
static uint32_t g_mtu = 0;
static iot_ble_cbs_t *g_ble_cbs;

static void gap_event_handler(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t *param)
{
	switch (event) {
	case ESP_GAP_BLE_ADV_DATA_RAW_SET_COMPLETE_EVT:
		adv_config_done &= (~ADV_CONFIG_FLAG);
		if (adv_config_done == 0 && is_advertising == 0){
			esp_ble_gap_start_advertising(&adv_params);
		}
		break;
	case ESP_GAP_BLE_SCAN_RSP_DATA_RAW_SET_COMPLETE_EVT:
		adv_config_done &= (~SCAN_RSP_CONFIG_FLAG);
		if (adv_config_done == 0 && is_advertising == 0){
			esp_ble_gap_start_advertising(&adv_params);
		}
		break;
	case ESP_GAP_BLE_ADV_START_COMPLETE_EVT:
		//advertising start complete event to indicate advertising start successfully or failed
		if (param->adv_start_cmpl.status != ESP_BT_STATUS_SUCCESS) {
			ESP_LOGE(GATTS_TAG,"Advertising start failed\n");
		} else {
                    is_advertising = 1;
			ESP_LOGI(GATTS_TAG, "Start adv successfully\n");
		}
		break;
	case ESP_GAP_BLE_ADV_STOP_COMPLETE_EVT:
		if (param->adv_stop_cmpl.status != ESP_BT_STATUS_SUCCESS) {
			ESP_LOGE(GATTS_TAG,"Advertising stop failed\n");
		} else {
                    is_advertising = 0;
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

int iot_bsp_ble_get_mac_address(uint8_t mac_address[6])
{
    esp_err_t err = esp_read_mac(mac_address, ESP_MAC_BT);
    if (err != ESP_OK) {
        ESP_LOGE(GATTS_TAG, "failed to read bt mac\n");
        return -1;
    }

    return 0;
}

int iot_bsp_ble_start_adv(uint16_t mn_code, uint8_t *mn_data, size_t mn_data_len, char *local_name)
{
    size_t offset_ind = 0;
    size_t offset_scan_res = 0;
    size_t mn_data_size_in_ind = 0;
    size_t mn_data_size_in_scan_res = 0;
    esp_err_t esp_ret;
    uint8_t adv_data[PACKET_MAX_SIZE];
    size_t adv_data_len;
    uint8_t scan_response_data[PACKET_MAX_SIZE];
    size_t scan_response_len;

    /* Advertising Flag Type */
    adv_data[offset_ind++] = ADV_FLAG_LEN;
    adv_data[offset_ind++] = ADV_FLAG_TYPE;
    adv_data[offset_ind++] = ADV_FLAG_VALUE;

    /* Advertising Manufacturer Data Type */
    /* Flag Size(Length(1byte) + Flag Length) +
     * Manufacturer Size(Length(1byte) + Type(1byte) + ManufacturerCode(2bytes) + Manufacturer Data Length */
    if ((1 + ADV_FLAG_LEN) + (1 + 1 + 2 + mn_data_len) >  PACKET_MAX_SIZE) {
        mn_data_size_in_ind = PACKET_MAX_SIZE - (ADV_FLAG_LEN + 1) - (4);
        mn_data_size_in_scan_res = mn_data_len - mn_data_size_in_ind;
    } else {
        mn_data_size_in_ind = mn_data_len;
        mn_data_size_in_scan_res = 0;
    }

    adv_data[offset_ind++] = mn_data_size_in_ind + 3;
    adv_data[offset_ind++] = ADV_MANUFACTURER_DATA_TYPE;
    adv_data[offset_ind++] = (mn_code & 0xFF);
    adv_data[offset_ind++] = ((mn_code >> 8) & 0xFF);
    memcpy(adv_data + offset_ind, mn_data, mn_data_size_in_ind);
    offset_ind += mn_data_size_in_ind;

    adv_data_len = offset_ind;

    /* Advertising Scan Local Name Type */
    scan_response_data[offset_scan_res++] = strlen(local_name) + 1;
    scan_response_data[offset_scan_res++] = ADV_LOCAL_NAME_TYPE;
    memcpy(scan_response_data + offset_scan_res, local_name, strlen(local_name));
    offset_scan_res += strlen(local_name);

    /* Advertising Scan Manufacturer Data Type */
    if (mn_data_size_in_scan_res) {
        scan_response_data[offset_scan_res++] = mn_data_size_in_scan_res + 3;
        scan_response_data[offset_scan_res++] = ADV_MANUFACTURER_DATA_TYPE;
        scan_response_data[offset_scan_res++] = (mn_code & 0xFF);
        scan_response_data[offset_scan_res++] = ((mn_code >> 8) & 0xFF);
        memcpy(scan_response_data + offset_scan_res, mn_data + mn_data_size_in_ind, mn_data_size_in_scan_res);
        offset_scan_res += mn_data_size_in_scan_res;
    }

    scan_response_len = offset_scan_res;

    adv_config_done |= (ADV_CONFIG_FLAG | SCAN_RSP_CONFIG_FLAG);
    esp_ret = esp_ble_gap_config_adv_data_raw(adv_data, adv_data_len);
    if (esp_ret){
        ESP_LOGE(GATTS_TAG,"config raw adv data failed, error code = %x\n", esp_ret);
    }
    esp_ret = esp_ble_gap_config_scan_rsp_data_raw(scan_response_data, scan_response_len);
    if (esp_ret){
        ESP_LOGE(GATTS_TAG,"config raw scan rsp data failed, error code = %x\n", esp_ret);
    }

    return 0;
}

int iot_send_indication(uint8_t *buf, uint32_t len)
{
	struct timeval start_tv = {0,}, elasped_tv = {0,};

	gettimeofday(&start_tv, NULL);

	while(indication_need_confirmed && gatt_connected) {
		gettimeofday(&elasped_tv, NULL);
		if (elasped_tv.tv_sec - start_tv.tv_sec >= 5) {
			ESP_LOGI(GATTS_TAG, "Wait confirm timeout 5s");
			return 1;
		}
	}

	if (!gatt_connected) {
		ESP_LOGI(GATTS_TAG, "%s No gatt connection", __func__);
		return 1;
	}

	indication_need_confirmed = 1;
	esp_ble_gatts_send_indicate(gl_profile.gatts_if, gl_profile.conn_id, gl_profile.char_handle, len, buf, true);

	return 0;
}

static void gatts_event_handler(esp_gatts_cb_event_t event, esp_gatt_if_t gatts_if, esp_ble_gatts_cb_param_t *param)
{
	esp_attr_control_t control;
        esp_err_t esp_ret;
	if (event == ESP_GATTS_REG_EVT) {
		if (param->reg.status == ESP_GATT_OK) {
			gl_profile.gatts_if = gatts_if;
		} else {
			ESP_LOGE(GATTS_TAG,"reg app failed, app_id %u, status 0x%02X\n",
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
		ESP_LOGI(GATTS_TAG, "REGISTER_APP_EVT, status 0x%02X, app_id %u\n", param->reg.status, param->reg.app_id);
		gl_profile.service_id.is_primary = true;
		gl_profile.service_id.id.inst_id = 0x00;
		gl_profile.service_id.id.uuid.len = ESP_UUID_LEN_16;
		gl_profile.service_id.id.uuid.uuid.uuid16 = BLE_ONBOARDING_SERVICE_UUID;
		esp_ble_gatts_create_service(gatts_if, &gl_profile.service_id, GATTS_NUM_HANDLE);
		break;
	case ESP_GATTS_READ_EVT: {
		ESP_LOGI(GATTS_TAG, "GATT_READ_EVT, conn_id %u, trans_id %lu, handle %u\n", param->read.conn_id, param->read.trans_id, param->read.handle);

		esp_gatt_rsp_t rsp;
		memset(&rsp, 0, sizeof(esp_gatt_rsp_t));
		rsp.attr_value.handle = param->read.handle;
		rsp.attr_value.len = 0;
		esp_ble_gatts_send_response(gatts_if, param->read.conn_id, param->read.trans_id,
			ESP_GATT_OK, &rsp);

		break;
	}
	case ESP_GATTS_WRITE_EVT: {
		ESP_LOGI(GATTS_TAG, "GATT_WRITE_EVT, conn_id %u, trans_id %lu, handle %u need resp %u is_prep %u", param->write.conn_id,
			param->write.trans_id, param->write.handle, param->write.need_rsp, param->write.is_prep);
		esp_ble_gatts_send_response(gatts_if, param->write.conn_id, param->write.trans_id, ESP_GATT_OK, NULL);

		if (param->write.handle == gl_profile.char_handle) {
			// Do further process here
			if (g_ble_cbs && g_ble_cbs->write_cb) {
			    g_ble_cbs->write_cb(param->write.value, param->write.len);
			}
		}
		break;
	}
	case ESP_GATTS_EXEC_WRITE_EVT:
		ESP_LOGI(GATTS_TAG,"ESP_GATTS_EXEC_WRITE_EVT");
		esp_ble_gatts_send_response(gatts_if, param->write.conn_id, param->write.trans_id, ESP_GATT_OK, NULL);
		break;
	case ESP_GATTS_MTU_EVT:
		ESP_LOGI(GATTS_TAG, "ESP_GATTS_MTU_EVT, MTU %u", param->mtu.mtu);
		g_mtu = param->mtu.mtu;
		break;
	case ESP_GATTS_UNREG_EVT:
		break;
	case ESP_GATTS_CREATE_EVT:
		ESP_LOGI(GATTS_TAG, "CREATE_SERVICE_EVT, status %u,  service_handle %u\n", param->create.status, param->create.service_handle);
		gl_profile.service_handle = param->create.service_handle;
		gl_profile.char_uuid.len = ESP_UUID_LEN_128;
		memcpy(gl_profile.char_uuid.uuid.uuid128, ble_onboarding_char_uuid ,16);

		control.auto_rsp = ESP_GATT_RSP_BY_APP;
		esp_ble_gatts_start_service(gl_profile.service_handle);
		esp_ret = esp_ble_gatts_add_char(gl_profile.service_handle, &gl_profile.char_uuid,
				ESP_GATT_PERM_READ | ESP_GATT_PERM_WRITE,
                                ESP_GATT_CHAR_PROP_BIT_READ | ESP_GATT_CHAR_PROP_BIT_WRITE |
                                ESP_GATT_CHAR_PROP_BIT_NOTIFY | ESP_GATT_CHAR_PROP_BIT_INDICATE
                                , &ble_onboard_char, &control);
		if (esp_ret){
			ESP_LOGE(GATTS_TAG,"add char failed, error code =%x\n",esp_ret);
		}
		break;
	case ESP_GATTS_ADD_INCL_SRVC_EVT:
		break;
	case ESP_GATTS_ADD_CHAR_EVT: {
		ESP_LOGI(GATTS_TAG, "ADD_CHAR_EVT, status 0x%02X,  attr_handle %u, service_handle %u\n",
			param->add_char.status, param->add_char.attr_handle, param->add_char.service_handle);
		gl_profile.char_handle = param->add_char.attr_handle;

		uint16_t length = 0;
		const uint8_t *prf_char;

		gl_profile.descr_uuid.len = ESP_UUID_LEN_16;
		gl_profile.descr_uuid.uuid.uuid16 = ESP_GATT_UUID_CHAR_CLIENT_CONFIG;
		esp_ret = esp_ble_gatts_get_attr_value(param->add_char.attr_handle,  &length, &prf_char);
		if (esp_ret == ESP_FAIL){
			ESP_LOGE(GATTS_TAG,"ILLEGAL HANDLE\n");
		}

		ESP_LOGI(GATTS_TAG, "the gatts demo char length = %x\n", length);
		esp_ret = esp_ble_gatts_add_char_descr(gl_profile.service_handle, &gl_profile.descr_uuid,
				ESP_GATT_PERM_READ | ESP_GATT_PERM_WRITE, NULL, NULL);
		if (esp_ret){
			ESP_LOGE(GATTS_TAG,"add char descr failed, error code =%x\n", esp_ret);
		}
		break;
	}
	case ESP_GATTS_ADD_CHAR_DESCR_EVT:
		gl_profile.descr_handle = param->add_char_descr.attr_handle;
		ESP_LOGI(GATTS_TAG, "ADD_DESCR_EVT, status 0x%02X, attr_handle %u, service_handle %u\n",
			param->add_char_descr.status, param->add_char_descr.attr_handle, param->add_char_descr.service_handle);
		break;
	case ESP_GATTS_DELETE_EVT:
		break;
	case ESP_GATTS_START_EVT:
		ESP_LOGI(GATTS_TAG, "SERVICE_START_EVT, status 0x%02X, service_handle %u\n",
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
		ESP_LOGI(GATTS_TAG, "ESP_GATTS_CONNECT_EVT, conn_id %u, remote %02x:%02x:%02x:%02x:%02x:%02x:",
			param->connect.conn_id,
			param->connect.remote_bda[0], param->connect.remote_bda[1], param->connect.remote_bda[2],
			param->connect.remote_bda[3], param->connect.remote_bda[4], param->connect.remote_bda[5]);
		gl_profile.conn_id = param->connect.conn_id;
		//start sent the update connection parameters to the peer device.
		esp_ble_gap_update_conn_params(&conn_params);
                if (is_advertising) {
                    esp_ret = esp_ble_gap_stop_advertising();
                    if (esp_ret != ESP_OK) {
                        ESP_LOGE(GATTS_TAG, "stop ble advertisement failed, error code = 0x%x\n", esp_ret);
                    }
                }
		if (g_ble_cbs && g_ble_cbs->conn_cb) {
                    g_ble_cbs->conn_cb(IOT_BLE_CONNECTION_EVENT_CONNECTED);
		}
		gatt_connected = 1;
		indication_need_confirmed = 0;
		break;
	}
	case ESP_GATTS_DISCONNECT_EVT:
		ESP_LOGI(GATTS_TAG, "ESP_GATTS_DISCONNECT_EVT, disconnect reason 0x%x", param->disconnect.reason);
                if (!is_advertising) {
                    esp_ret = esp_ble_gap_start_advertising(&adv_params);
                    if (esp_ret != ESP_OK) {
                        ESP_LOGE(GATTS_TAG, "start ble advertisement failed, error code = 0x%x\n", esp_ret);
                    }
                }
		if (g_ble_cbs && g_ble_cbs->conn_cb) {
                    g_ble_cbs->conn_cb(IOT_BLE_CONNECTION_EVENT_DISCONNECTED);
		}
		gatt_connected = 0;
		indication_need_confirmed = 0;
		break;
	case ESP_GATTS_CONF_EVT:
		ESP_LOGI(GATTS_TAG, "ESP_GATTS_CONF_EVT, status 0x%02X attr_handle %u", param->conf.status, param->conf.handle);
		if (param->conf.status != ESP_GATT_OK){
			esp_log_buffer_hex(GATTS_TAG, param->conf.value, param->conf.len);
		}
		indication_need_confirmed = 0;
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

iot_error_t iot_bsp_ble_init(iot_ble_cbs_t *ble_cbs)
{
	esp_err_t ret;

	if (g_ble_status == ESP_BLE_STATUS_INIT) {
		ESP_LOGI(GATTS_TAG, "ESP BLE already initialised");
		return IOT_ERROR_BAD_REQ;
	}

	// Initialize NVS.
	ret = nvs_flash_init();
	if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
		ESP_ERROR_CHECK(nvs_flash_erase());
		ret = nvs_flash_init();
	}
	ESP_ERROR_CHECK( ret );

	if (g_ble_status == ESP_BLE_STATUS_UNKNOWN) {
		ESP_ERROR_CHECK(esp_bt_controller_mem_release(ESP_BT_MODE_CLASSIC_BT));
	}

	esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
	ret = esp_bt_controller_init(&bt_cfg);
	if (ret) {
		ESP_LOGE(GATTS_TAG,"%s initialize controller failed: %s\n", __func__, esp_err_to_name(ret));
		return IOT_ERROR_BAD_REQ;
	}
	ret = esp_bt_controller_enable(ESP_BT_MODE_BLE);
	if (ret) {
		ESP_LOGE(GATTS_TAG,"%s enable controller failed: %s\n", __func__, esp_err_to_name(ret));
		return IOT_ERROR_BAD_REQ;
	}

	ret = esp_bluedroid_init();
	if (ret) {
		ESP_LOGE(GATTS_TAG,"%s init bluetooth failed: %s\n", __func__, esp_err_to_name(ret));
		return IOT_ERROR_BAD_REQ;
	}
	ret = esp_bluedroid_enable();
	if (ret) {
		ESP_LOGE(GATTS_TAG,"%s enable bluetooth failed: %s\n", __func__, esp_err_to_name(ret));
		return IOT_ERROR_BAD_REQ;
	}

	g_ble_status = ESP_BLE_STATUS_INIT;

	ret = esp_ble_gatts_register_callback(gatts_event_handler);
	if (ret){
		ESP_LOGE(GATTS_TAG,"gatts register error, error code = %x\n", ret);
		return IOT_ERROR_BAD_REQ;
	}
	ret = esp_ble_gap_register_callback(gap_event_handler);
	if (ret){
		ESP_LOGE(GATTS_TAG,"gap register error, error code = %x\n", ret);
		return IOT_ERROR_BAD_REQ;
	}

	ret = esp_ble_gatts_app_register(PROFILE_APP_ID);
	if (ret) {
		ESP_LOGE(GATTS_TAG,"gatts app register error, error code = %x\n", ret);
		return IOT_ERROR_BAD_REQ;
	}

	g_mtu = GATTS_MTU_MAX;
	esp_err_t local_mtu_ret = esp_ble_gatt_set_local_mtu(g_mtu);
	if (local_mtu_ret){
		ESP_LOGE(GATTS_TAG,"set local  MTU failed, error code = %x\n", local_mtu_ret);
	}

        g_ble_cbs = ble_cbs;

	return IOT_ERROR_NONE;
}

void iot_bsp_ble_deinit(void)
{
	esp_err_t ret;

	if (g_ble_status != ESP_BLE_STATUS_INIT) {
		ESP_LOGI(GATTS_TAG, "ESP BLE already deinitalised");
		return;
	}

	ret = esp_bluedroid_disable();
	if (ret) {
		ESP_LOGE(GATTS_TAG, "%s disable bluetooth failed: %s\n", __func__, esp_err_to_name(ret));
		return;
	}

	ret = esp_bluedroid_deinit();
	if (ret) {
		ESP_LOGE(GATTS_TAG, "%s deinit bluetooth failed: %s\n", __func__, esp_err_to_name(ret));
		return;
	}

	ret = esp_bt_controller_disable();
	if (ret) {
		ESP_LOGE(GATTS_TAG, "%s disable controller failed: %s\n", __func__, esp_err_to_name(ret));
		return;
	}

	ret = esp_bt_controller_deinit();
	if (ret) {
		ESP_LOGE(GATTS_TAG, "%s deinitialize controller failed: %s\n", __func__, esp_err_to_name(ret));
		return;
	}

	g_ble_status = ESP_BLE_STATUS_DEINIT;
	g_ble_cbs = NULL;
	return;
}

uint32_t iot_bsp_ble_get_mtu(void)
{
	return g_mtu;
}
