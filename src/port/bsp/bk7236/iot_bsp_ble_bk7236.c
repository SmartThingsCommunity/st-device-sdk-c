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

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <os/os.h>
#include <os/mem.h>
#include <stdarg.h>
#include <time.h>
#include <sys/time.h>
#include <driver/aon_rtc.h>
#include "components/bluetooth/bk_ble.h"

#include "components/bluetooth/bk_dm_bluetooth.h"
#include "components/bluetooth/bk_dm_gatts.h"

#include "iot_debug.h"
#include "iot_bsp_ble.h"
#include "iot_os_util.h"
#define GATTS_TAG "BLE_ONBOARD"

#define DISPLAY_SERIAL_NUMBER_SIZE 4

#define PACKET_MAX_SIZE     31
#define MAC_ADD_COUNT       6
#define BT_MAC_LENGTH       6

#define ADV_FLAG_LEN 0x02
#define ADV_FLAG_TYPE 0x01
#define ADV_FLAG_VALUE 0x04
#define ADV_SERVICE_DATA_LEN 0x1B
#define ADV_MANUFACTURER_DATA_TYPE 0xFF
#define ADV_LOCAL_NAME_TYPE 0x09

#define ADV_CONFIG_FLAG (1 << 0)
#define SCAN_RSP_CONFIG_FLAG (1 << 1)

#define CUSTOM_DATA_TYPE 0xFF
#if defined(CONFIG_STDK_IOT_CORE_EASYSETUP_X509)
#define CUSTOM_DATA_LEN 0x06
#define CUSTOM_TYPE 0x02
#define CUSTOM_TYPE_DATA_LEN 0x04
#else
#define CUSTOM_DATA_LEN 0x0A
#define CUSTOM_TYPE 0x03
#define CUSTOM_TYPE_DATA_LEN 0x08
#endif

#define CONTROL_VERSION_ACTIVE_SCAN_REQUIRED    0x42
#define PACKET_VERSION        0x83
#define SERVICE_ID            0x0c
#define OOB_SERVICE_INFO      0x05
#define WIFI_UPDATE_SERVICE_INFO 0x03
#define SERVICE_FEATURE       0x59
#define SETUP_AVAILABLE_NETWORK_BLE    0x04

#define BT_ADDRESS_TRANSFER 0x01

#define SCAN_RBK_FLAG_TYPE 0x09
#if defined(CONFIG_STDK_IOT_CORE_EASYSETUP_X509)
#define SCAN_RBK_MF_DATA_LEN       0x06
#define MAX_DEVICE_NAME_DATA_LEN    0x16
#else
#define SCAN_RBK_MF_DATA_LEN       0x0A
#define MAX_DEVICE_NAME_DATA_LEN    0x12
#endif

#define GATTS_MTU_MAX    23
#define GATT_SYNC_CMD_TIMEOUT_MS          3000
#define BLE_GATTS_ADV_INTERVAL_MIN 120
#define BLE_GATTS_ADV_INTERVAL_MAX 160
#define INVALID_HANDLE          0xFF
#define UNKNOW_ACT_IDX         0xFFU
#define DECL_PRIMARY_SERVICE_128     {0x00,0x28,0,0,0,0,0,0,0,0,0,0,0,0,0,0}
#define DECL_CHARACTERISTIC_128      {0x03,0x28,0,0,0,0,0,0,0,0,0,0,0,0,0,0}
#define DESC_CLIENT_CHAR_CFG_128     {0x02,0x29,0,0,0,0,0,0,0,0,0,0,0,0,0,0}
#define BLE_ONBOARDING_CHAR_UUID {0x09, 0x0E, 0xE6, 0x80, 0x02, 0x30, 0xC7, 0xA4, 0x8E, 0x4F, 0x2D, 0xAE, 0x0E, 0x0F, 0x94, 0xBE}
#define GATTS_CHARA_PROPERTIES_UUID			(0xEA01)
#define GATTS_SERVICE_UUID 					(0xFA00)
#define GATTS_UUID							(0xFD1D)
#define BLE_ONBOARDING_SERVICE_UUID BT_UUID_DECLARE_16(0xFD1D)

/* ble status */
enum bk_ble_status
{
	Bk_BLE_STATUS_UNKNOWN,
	Bk_BLE_STATUS_INIT,
	Bk_BLE_STATUS_DEINIT,
};

enum
{
	PRF_TASK_ID_GATTS = 10,
	PRF_TASK_ID_MAX,
};

enum {
    GATTS_IDX_SVC,
    GATTS_IDX_CHAR_DECL,
    GATTS_IDX_CHAR_VALUE,
	GATTS_IDX_CHAR_DESC,
	GATTS_IDX_NB,
};

static beken_semaphore_t gatt_sema = NULL;
size_t device_onboarding_id_len;
int indication_need_confirmed;
int gatt_connected;
static uint8_t is_advertising = 0;
static enum bk_ble_status g_ble_status = Bk_BLE_STATUS_UNKNOWN;
static uint32_t g_mtu = 0;
static uint8_t adv_config_done = 0;
//static uint8_t adv_data[PACKET_MAX_SIZE];
//static size_t adv_data_len;
static size_t adv_data_mac_address_offset;
//static uint8_t scan_response_data[PACKET_MAX_SIZE];
//static size_t scan_response_len;
static uint8_t manufacturer_id[2] = {0x75, 0x00};

static iot_ble_cbs_t *g_ble_cbs;

int actv_idx = 0;
ble_adv_param_t adv_param;
uint8 g_test_prf_task_id1 = 0;
static ble_err_t gatt_cmd_status = BK_ERR_BLE_SUCCESS;
static uint8_t gatt_conn_ind = INVALID_HANDLE;
static bk_ble_key_t s_ble_enc_key;

static ble_attm_desc_t gatts_service_db[GATTS_IDX_NB] = {
    //  Service Declaration
    [GATTS_IDX_SVC] = {DECL_PRIMARY_SERVICE_128 , BK_BLE_PERM_SET(RD, ENABLE), 0, 0},

    [GATTS_IDX_CHAR_DECL]  = { DECL_CHARACTERISTIC_128,  BK_BLE_PERM_SET(RD, ENABLE), 0, 0},
    // Characteristic ValueIND
    [GATTS_IDX_CHAR_VALUE] = {BLE_ONBOARDING_CHAR_UUID, BK_BLE_PERM_SET(WRITE_REQ, ENABLE)|BK_BLE_PERM_SET(IND, ENABLE), BK_BLE_PERM_SET(RI, ENABLE) | BK_BLE_PERM_SET(UUID_LEN, UUID_128), 128},
	//Client Characteristic Configuration Descriptor
	[GATTS_IDX_CHAR_DESC] = {DESC_CLIENT_CHAR_CFG_128, BK_BLE_PERM_SET(RD, ENABLE) | BK_BLE_PERM_SET(WRITE_REQ, ENABLE), 0, 0},
};

int iot_bsp_ble_get_mac_address(uint8_t mac_address[6])
{
    bt_err_t err = bk_bluetooth_get_address(mac_address);
    if (err != BK_OK) {
        IOT_INFO("failed to read bt mac");
        return -1;
    }

    return 0;
}

int iot_send_indication(uint8_t *buf, uint32_t len)
{
	struct timeval start_tv = {0,}, elasped_tv = {0,};

	bd_addr_t connect_addr;
	uint8_t conn_idx;
	bk_bluetooth_get_address(connect_addr.addr);
	conn_idx = bk_ble_find_conn_idx_from_addr(&connect_addr);

	gettimeofday(&start_tv, NULL);

	while(indication_need_confirmed && gatt_connected) {
		gettimeofday(&elasped_tv, NULL);
		if (elasped_tv.tv_sec - start_tv.tv_sec >= 5) {
			IOT_INFO("Wait confirm timeout 5s");
			return 1;
		}
	}

	if (!gatt_connected) {
		IOT_INFO(GATTS_TAG, "%s No gatt connection", __func__);
		return 1;
	}
    for (size_t i = 0; i < len; i++) {
        printf("%02X ", buf[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
    }

	ble_err_t result = bk_ble_send_ind_value(conn_idx, len, buf, PRF_TASK_ID_GATTS, GATTS_IDX_CHAR_VALUE);
	IOT_INFO("send indication result : %d",result);
	return 0;
}

static void ble_gatt_cmd_cb(ble_cmd_t cmd, ble_cmd_param_t *param)
{
    gatt_cmd_status = param->status;
	IOT_INFO("ble_gatt_cmd_cb : %d ",cmd);
    switch (cmd) {
        case BLE_CREATE_ADV:
        case BLE_SET_ADV_DATA:
        case BLE_SET_RSP_DATA:
        case BLE_START_ADV:
        case BLE_STOP_ADV:
        case BLE_CREATE_SCAN:
        case BLE_START_SCAN:
        case BLE_STOP_SCAN:
        case BLE_INIT_CREATE:
        case BLE_INIT_START_CONN:
        case BLE_INIT_STOP_CONN:
        case BLE_CONN_DIS_CONN:
        case BLE_CONN_UPDATE_PARAM:
        case BLE_DELETE_ADV:
        case BLE_DELETE_SCAN:
        case BLE_CONN_READ_PHY:
        case BLE_CONN_SET_PHY:
        case BLE_CONN_UPDATE_MTU:
        case BLE_SET_ADV_RANDOM_ADDR:
			if (gatt_sema != NULL)
                rtos_set_semaphore( &gatt_sema );
            break;
        default:
            break;
    }

}

static void ble_gatts_notice_cb(ble_notice_t notice, void *param)
{
	IOT_INFO("ble_gatts_notice_cb : %d ",notice);
    switch (notice) {
    case BLE_5_STACK_OK:
        IOT_INFO("ble stack ok");
        break;
    case BLE_5_WRITE_EVENT: {
        ble_write_req_t *w_req = (ble_write_req_t *)param;
        IOT_INFO("write_cb:conn_idx:%d, prf_id:%d, att_idx:%d, len:%d, data[0]:0x%02x",
                w_req->conn_idx, w_req->prf_id, w_req->att_idx, w_req->len, w_req->value[0]);

		if (bk_ble_get_controller_stack_type() == BK_BLE_CONTROLLER_STACK_TYPE_BTDM_5_2
            && w_req->prf_id == PRF_TASK_ID_GATTS) {
			switch(w_req->att_idx) {
            case GATTS_IDX_CHAR_DECL:
			IOT_INFO("write notify GATTS_IDX_CHAR_DECL: %02X %02X, length: %d", w_req->value[0], w_req->value[1], w_req->len);
                break;
            case GATTS_IDX_CHAR_VALUE:
				IOT_INFO("write notify GATTS_IDX_CHAR_VALUE: %02X %02X, length: %d", w_req->value[0], w_req->value[1], w_req->len);
				if (g_ble_cbs && g_ble_cbs->write_cb) {
					g_ble_cbs->write_cb(w_req->value, w_req->len);
				}
                break;
			case GATTS_IDX_CHAR_DESC: {
				IOT_INFO("write notify GATTS_IDX_CHAR_DESC: %02X %02X, length: %d", w_req->value[0], w_req->value[1], w_req->len);
				break;
			}
            default:
                break;
            }

        }
        break;
    }
    case BLE_5_READ_EVENT: {
        ble_read_req_t *r_req = (ble_read_req_t *)param;
        IOT_INFO("read_cb:conn_idx:%d, prf_id:%d, att_idx:%d",
                r_req->conn_idx, r_req->prf_id, r_req->att_idx);

        if (r_req->prf_id == g_test_prf_task_id1) {
            switch(r_req->att_idx)
            {
                case GATTS_IDX_CHAR_DECL:
                    break;
                case GATTS_IDX_CHAR_VALUE:
                    break;
				case GATTS_IDX_CHAR_DESC:
					break;
                default:
                    break;
            }
        }
        break;
    }
    case BLE_5_REPORT_ADV:
        break;
    case BLE_5_MTU_CHANGE: {
        ble_mtu_change_t *m_ind = (ble_mtu_change_t *)param;
		g_mtu = m_ind->mtu_size;
        IOT_INFO("%s m_ind:conn_idx:%d, mtu_size:%d, gtu_size : %d", __func__, m_ind->conn_idx, m_ind->mtu_size,g_mtu);
        break;
    }
    case BLE_5_CONNECT_EVENT: {
		ble_conn_ind_t *c_ind = (ble_conn_ind_t *)param;
		IOT_INFO("c_ind:conn_idx:%d, addr_type:%d, peer_addr:%02x:%02x:%02x:%02x:%02x:%02x",
		c_ind->conn_idx, c_ind->peer_addr_type, c_ind->peer_addr[0], c_ind->peer_addr[1],
		c_ind->peer_addr[2], c_ind->peer_addr[3], c_ind->peer_addr[4], c_ind->peer_addr[5]);
		gatt_conn_ind = c_ind->conn_idx;
		
		ble_conn_param_t conn_param = {0};
		conn_param.intv_min = 0x10;
		conn_param.intv_max = 0x20;
		conn_param.con_latency = 0;
		conn_param.sup_to = 400;
		conn_param.init_phys = 1;
		bk_ble_update_param(c_ind->conn_idx, &conn_param);
		if (is_advertising) {
			ble_err_t ret = bk_ble_stop_advertising(actv_idx,  ble_gatt_cmd_cb);
			if(ret != BK_ERR_BLE_SUCCESS) {
				IOT_INFO("stop ble advertisement failed, error code = 0x%x", ret);
			}
			ret = rtos_get_semaphore(&gatt_sema, GATT_SYNC_CMD_TIMEOUT_MS);
			if (ret != BK_OK) {
				IOT_INFO("wait semaphore failed at %d, %d", ret, __LINE__);
				// goto error;
			} else {
				is_advertising = 0;
				IOT_INFO("Stop adv successfully");
			}
		}
		
		if (g_ble_cbs && g_ble_cbs->conn_cb) {
			g_ble_cbs->conn_cb(IOT_BLE_CONNECTION_EVENT_CONNECTED);
		}
		
		gatt_connected = 1;
		indication_need_confirmed = 0;
        break;
    }
    case BLE_5_DISCONNECT_EVENT: {
        ble_discon_ind_t *d_ind = (ble_discon_ind_t *)param;
        IOT_INFO("d_ind:conn_idx:%d,reason:%d", d_ind->conn_idx, d_ind->reason);
        gatt_conn_ind = ~0;

		if (!is_advertising) {
			ble_err_t ret = bk_ble_start_advertising(actv_idx, 0, ble_gatt_cmd_cb);
			if (ret != BK_ERR_BLE_SUCCESS) {
				IOT_INFO("start ble advertisement failed, error code = 0x%x", ret);
			}
		}
		if (g_ble_cbs && g_ble_cbs->conn_cb) {
			g_ble_cbs->conn_cb(IOT_BLE_CONNECTION_EVENT_DISCONNECTED);
		}
		gatt_connected = 0;
		indication_need_confirmed = 0;
        break;
    }
	case BLE_5_ATT_INFO_REQ: {
		ble_att_info_req_t *a_ind = (ble_att_info_req_t *)param;
		IOT_INFO("a_ind:conn_idx:%d", a_ind->conn_idx);
		a_ind->length = 128;
		a_ind->status = BK_ERR_BLE_SUCCESS;
		break;
	}
	case BLE_5_CREATE_DB: {
		ble_create_db_t *cd_ind = (ble_create_db_t *)param;

		IOT_INFO("cd_ind:prf_id:%d, status:%d", cd_ind->prf_id, cd_ind->status);
		gatt_cmd_status = cd_ind->status;
		if (gatt_sema != NULL)
			rtos_set_semaphore( &gatt_sema );
		break;
	}
	case BLE_5_INIT_CONNECT_EVENT: {
		ble_conn_ind_t *c_ind = (ble_conn_ind_t *)param;
		IOT_INFO("BLE_5_INIT_CONNECT_EVENT:conn_idx:%d, addr_type:%d, peer_addr:%02x:%02x:%02x:%02x:%02x:%02x",
				c_ind->conn_idx, c_ind->peer_addr_type, c_ind->peer_addr[0], c_ind->peer_addr[1],
				c_ind->peer_addr[2], c_ind->peer_addr[3], c_ind->peer_addr[4], c_ind->peer_addr[5]);
		break;
	}
	case BLE_5_INIT_DISCONNECT_EVENT: {
		ble_discon_ind_t *d_ind = (ble_discon_ind_t *)param;
		IOT_INFO("BLE_5_INIT_DISCONNECT_EVENT:conn_idx:%d,reason:%d", d_ind->conn_idx, d_ind->reason);
		break;
	}
	case BLE_5_SDP_REGISTER_FAILED:
		IOT_INFO("BLE_5_SDP_REGISTER_FAILED");
		break;
	case BLE_5_READ_PHY_EVENT: {
		ble_read_phy_t *phy_param = (ble_read_phy_t *)param;
		IOT_INFO("BLE_5_READ_PHY_EVENT:tx_phy:0x%02x, rx_phy:0x%02x",phy_param->tx_phy, phy_param->rx_phy);
		break;
	}
	case BLE_5_TX_DONE:
		break;
	case BLE_5_CONN_UPDATA_EVENT: {
		ble_conn_param_t *updata_param = (ble_conn_param_t *)param;
		IOT_INFO("BLE_5_CONN_UPDATA_EVENT:conn_interval:0x%04x, con_latency:0x%04x, sup_to:0x%04x", updata_param->intv_max,
		updata_param->con_latency, updata_param->sup_to);
		break;
	}
	case BLE_5_PAIRING_REQ:
		IOT_INFO("BLE_5_PAIRING_REQ");
		ble_smp_ind_t *s_ind = (ble_smp_ind_t *)param;
		bk_ble_sec_send_auth_mode(s_ind->conn_idx, GAP_AUTH_REQ_NO_MITM_BOND, BK_BLE_GAP_IO_CAP_NO_INPUT_NO_OUTPUT,
			GAP_SEC1_NOAUTH_PAIR_ENC, GAP_OOB_AUTH_DATA_NOT_PRESENT);
		break;
	case BLE_5_PARING_PASSKEY_REQ:
		IOT_INFO("BLE_5_PARING_PASSKEY_REQ");
		break;
	case BLE_5_ENCRYPT_EVENT:
		IOT_INFO("BLE_5_ENCRYPT_EVENT");
		break;

	case BLE_5_PAIRING_SUCCEED:
		IOT_INFO("BLE_5_PAIRING_SUCCEED");
		break;
	case BLE_5_KEY_EVENT: {
		IOT_INFO("BLE_5_KEY_EVENT");
		s_ble_enc_key = *((bk_ble_key_t*)param);
		break;
	}
	case BLE_5_BOND_INFO_REQ_EVENT:
		IOT_INFO("BLE_5_BOND_INFO_REQ_EVENT");
		break;
	case BLE_5_GAP_CMD_CMP_EVENT: {
		ble_cmd_cmp_evt_t *event = (ble_cmd_cmp_evt_t *)param;
		switch(event->cmd) {
		case BLE_CONN_ENCRYPT:
			IOT_INFO("BLE_5_GAP_CMD_CMP_EVENT(BLE_CONN_ENCRYPT) , status %x",event->status);
			break;
		default:
			break;
		}
		break;
	}
	case BLE_5_PAIRING_FAILED: {
		IOT_INFO("BLE_5_PAIRING_FAILED");
		// os_memset(&s_ble_enc_key, 0 ,sizeof(s_ble_enc_key));
		break;
	}
	default:
		break;
	}
}

int iot_bsp_ble_start_adv(uint16_t mn_code, uint8_t *mn_data, size_t mn_data_len, char *local_name)
{
	bt_err_t ret;
	size_t offset_ind = 0;
	size_t offset_scan_res = 0;
	size_t mn_data_size_in_ind = 0;
	size_t mn_data_size_in_scan_res = 0;
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

	/* set adv parameters  */
	ret = bk_ble_set_adv_data(actv_idx, adv_data, 31, ble_gatt_cmd_cb);
	if (ret != BK_ERR_BLE_SUCCESS) {
		IOT_INFO("set adv data failed %d", ret);
		goto error;
	}

	ret = rtos_get_semaphore(&gatt_sema, GATT_SYNC_CMD_TIMEOUT_MS);
	if (ret != BK_OK) {
		IOT_INFO("wait semaphore failed at %d, %d", ret, __LINE__);
		goto error;
	} else {
		IOT_INFO("set adv data success");
	}
	//set scan response
	bk_ble_set_scan_rsp_data(actv_idx, scan_response_data, scan_response_len, ble_gatt_cmd_cb);

	ret = rtos_get_semaphore(&gatt_sema, GATT_SYNC_CMD_TIMEOUT_MS);
	if (ret != BK_OK) {
		IOT_INFO("wait semaphore failed at %d, %d", ret, __LINE__);
		goto error;
	} else {
		IOT_INFO("set scan response data success");
	}
	ret = bk_ble_start_advertising(actv_idx, 0, ble_gatt_cmd_cb);
	if (ret != BK_ERR_BLE_SUCCESS) {
		IOT_INFO("start adv failed %d", ret);
		goto error;
	}

	ret = rtos_get_semaphore(&gatt_sema, GATT_SYNC_CMD_TIMEOUT_MS);
	if (ret != BK_OK) {
		IOT_INFO("wait semaphore failed at %d, %d", ret, __LINE__);
		goto error;
	} else {
		is_advertising = 1;
		IOT_INFO("start adv success");
	}

	return 0;
error:
    IOT_ERROR("%s fail", __func__);
	return 1;
}

iot_error_t iot_bsp_ble_init(iot_ble_cbs_t *ble_cbs)
{
	bt_err_t ret = BK_FAIL;
	struct bk_ble_db_cfg ble_db_cfg;

	ret = rtos_init_semaphore(&gatt_sema, 2);
	if(ret != BK_OK) {
		IOT_INFO("gatts init sema fail");
		return IOT_ERROR_BAD_REQ;
	}

	bk_ble_set_notice_cb(ble_gatts_notice_cb);

	ble_db_cfg.att_db = (ble_attm_desc_t *)gatts_service_db;
	ble_db_cfg.att_db_nb = GATTS_IDX_NB;
	ble_db_cfg.prf_task_id = PRF_TASK_ID_GATTS;
	ble_db_cfg.start_hdl = 0;
	ble_db_cfg.svc_perm = BK_BLE_PERM_SET(SVC_UUID_LEN, UUID_16);
	ble_db_cfg.uuid[0] = GATTS_UUID & 0xFF;
	ble_db_cfg.uuid[1] = GATTS_UUID >> 8;

	ret = bk_ble_create_db(&ble_db_cfg);

	if (ret != BK_ERR_BLE_SUCCESS) {
		IOT_INFO("create gatt db failed %d", ret);
		return IOT_ERROR_BAD_REQ;
	}

	ret = rtos_get_semaphore(&gatt_sema, GATT_SYNC_CMD_TIMEOUT_MS);

	if (ret != BK_OK) {
		IOT_INFO("wait semaphore failed at %d, %d", ret, __LINE__);
		return IOT_ERROR_BAD_REQ;
	} else {
		IOT_INFO("create gatt db success");
	}
	/* set adv parameters  */
	ble_adv_param_t adv_param;
	int actv_idx = 0;

	memset(&adv_param, 0, sizeof(ble_adv_param_t));
	adv_param.chnl_map = ADV_ALL_CHNLS;
	adv_param.adv_intv_min = BLE_GATTS_ADV_INTERVAL_MIN;
	adv_param.adv_intv_max = BLE_GATTS_ADV_INTERVAL_MAX;

#if 1
	adv_param.own_addr_type = OWN_ADDR_TYPE_PUBLIC_ADDR;
#else
	adv_param.own_addr_type = OWN_ADDR_TYPE_RANDOM_ADDR;
#endif

	adv_param.adv_type = ADV_TYPE_LEGACY;
	adv_param.adv_prop = ADV_PROP_CONNECTABLE_BIT | ADV_PROP_SCANNABLE_BIT;
	adv_param.prim_phy = INIT_PHY_TYPE_LE_1M;
	adv_param.second_phy = INIT_PHY_TYPE_LE_1M;

	ret = bk_ble_create_advertising(actv_idx, &adv_param, ble_gatt_cmd_cb);
	if (ret != BK_ERR_BLE_SUCCESS) {
		IOT_INFO("config adv parameters  failed %d", ret);
		// goto error;
	}
	ret = rtos_get_semaphore(&gatt_sema, GATT_SYNC_CMD_TIMEOUT_MS);
	if (ret != BK_OK) {
		IOT_INFO("wait semaphore failed at %d, %d", ret, __LINE__);
		// goto error;
	} else {
		IOT_INFO("set adv parameters success");
	}

	g_mtu = GATTS_MTU_MAX;
	bt_err_t local_mtu_ret = bk_ble_set_max_mtu(g_mtu);
	if (local_mtu_ret) {
		IOT_INFO(GATTS_TAG,"set local  MTU failed, error code = %x", local_mtu_ret);
	}
	IOT_INFO("ble init done");
	g_ble_cbs = ble_cbs;
	return IOT_ERROR_NONE;
}

void iot_bsp_ble_deinit(void)
{
	bt_err_t ret;

	if (g_ble_status != Bk_BLE_STATUS_INIT) {
		IOT_INFO(GATTS_TAG, "BK BLE already deinitalised");
		return;
	}

	ret = bk_bluetooth_deinit();
	if (ret) {
		IOT_INFO(GATTS_TAG, "%s disable bluetooth failed", __func__);
		return;
	}

	g_ble_status = Bk_BLE_STATUS_DEINIT;
	g_ble_cbs = NULL;
	return;
}

uint32_t iot_bsp_ble_get_mtu(void)
{
	return g_mtu;
}
