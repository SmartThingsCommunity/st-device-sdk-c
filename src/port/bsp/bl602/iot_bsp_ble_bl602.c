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

#include "FreeRTOS.h"
#include "task.h"
#include "event_groups.h"
#include "sdkconfig.h"

#include "bluetooth.h"
//#include "bt_log.h"

#include <aos/kernel.h>
#include <aos/yloop.h>
#include <util.h>
#include "gap.h"
#include "conn.h"
#include "gatt.h"

#include "ble_lib_api.h"
#include "bluetooth.h"

#include "iot_debug.h"
#include "iot_bsp_ble.h"

#define GATTS_TAG "BLE_ONBOARD"

#define BLE_ONBOARDING_SERVICE_UUID BT_UUID_DECLARE_16(0xFD1D)
static uint8_t ble_onboarding_char_uuid[16] = {0x09, 0x0E, 0xE6, 0x80, 0x02, 0x30, 0xC7, 0xA4, 0x8E, 0x4F, 0x2D, 0xAE, 0x0E, 0x0F, 0x94, 0xBE};
#define BLE_ONBOARDING_CHAR_UUID BT_UUID_DECLARE_128(BT_UUID_128_ENCODE(0xBE940F0E, 0xAE2D, 0x4F8E, 0xA4C7, 0x300280E60E09))
#define BT_UUID_TEST_TX BT_UUID_DECLARE_16(0xFFF2)

#define TEST_DEVICE_NAME "BLE_ONBOARDING"

#define PACKET_MAX_SIZE 31
#define BT_MAC_LENGTH 6

#define ADV_FLAG_LEN 0x02

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

#define SCAN_RBL_FLAG_TYPE 0x09
#if defined(CONFIG_STDK_IOT_CORE_EASYSETUP_X509)
#define SCAN_RBL_MF_DATA_LEN 0x06
#define MAX_DEVICE_NAME_DATA_LEN 0x16
#else
#define SCAN_RBL_MF_DATA_LEN 0x0A
#define MAX_DEVICE_NAME_DATA_LEN 0x12
#endif

#define GATTS_MTU_MAX 247

int indication_need_confirmed;
int gatt_connected;
static uint8_t is_advertising = 0;

// static int is_sendindicate = 0;
/* ble status */
enum bl_ble_status
{
	BL_BLE_STATUS_UNKNOWN,
	BL_BLE_STATUS_INIT,
	BL_BLE_STATUS_DEINIT,
};

static void ble_bl_ccc_cfg_changed(const struct bt_gatt_attr *attr, u16_t vblfue);
static int ble_blf_recv(struct bt_conn *conn,
						const struct bt_gatt_attr *attr, const void *buf,
						u16_t len, u16_t offset, u8_t flags);

static uint8_t advInd_manufacturer_data[26];
static size_t adv_mn_data_len;
static uint8_t scanRsp_manufacturer_data[PACKET_MAX_SIZE];
static size_t scan_response_len;
static struct bt_data ad[2];
static struct bt_data rsp[1];

static struct bt_gatt_attr blattrs[] = {
	BT_GATT_PRIMARY_SERVICE(BLE_ONBOARDING_SERVICE_UUID),

	BT_GATT_CHARACTERISTIC(BLE_ONBOARDING_CHAR_UUID,
						   BT_GATT_CHRC_INDICATE|BT_GATT_CHRC_WRITE|BT_GATT_CHRC_READ,
						   BT_GATT_PERM_READ| BT_GATT_PERM_WRITE,
						   NULL,
						   ble_blf_recv,
						   NULL),
	BT_GATT_CCC(ble_bl_ccc_cfg_changed, BT_GATT_PERM_READ | BT_GATT_PERM_WRITE),

	};
// static bt_addr_le_t macaddr = { 0, { { 0, 0, 0, 0, 0, 0 } } };

static struct bt_conn *ble_bl_conn = NULL;
static bool indicate_flag = false;


static enum bl_ble_status g_ble_status = BL_BLE_STATUS_UNKNOWN;
static uint32_t g_mtu = 0;

static iot_ble_cbs_t *g_ble_cbs;

static void ble_bl_ccc_cfg_changed(const struct bt_gatt_attr *attr, u16_t vblfue)
{
	if (vblfue == BT_GATT_CCC_INDICATE)
	{
		IOT_INFO("enable indicate.");
		indicate_flag = true;
	}
	else
	{
		IOT_INFO("disable indicate.");
		indicate_flag = false;
	}
}

int iot_bsp_ble_get_mac_address(uint8_t mac_address[6])
{
	bt_addr_le_t macaddr ;
	size_t count = 6; // mac length
	bt_id_get(&macaddr, &count);
	memcpy(mac_address, macaddr.a.val, BT_MAC_LENGTH);
	return 0;
}

struct bt_gatt_service ble_bl_server = BT_GATT_SERVICE(blattrs);

static void bt_gatt_indicate_cb(struct bt_conn *conn,
					const struct bt_gatt_attr *attr,
					u8_t err)
{
	//add 
	//IOT_INFO("bt_gatt_indicate_cb entry");
	indication_need_confirmed = 0;

}

static struct bt_gatt_indicate_params params;
int iot_send_indication(uint8_t *buf, uint32_t len)
{

	struct timeval start_tv = {
						0,//
				   },
				   elasped_tv = {
						0,
					};

	gettimeofday(&start_tv, NULL);
	IOT_INFO("indicate_need_confirmed = %d", indication_need_confirmed);
	while (indication_need_confirmed && gatt_connected)
	{
		gettimeofday(&elasped_tv, NULL);
		if (elasped_tv.tv_sec - start_tv.tv_sec >= 5)
		{
			IOT_INFO("Wait confirm timeout 5s");
			return 1;
		}
	}

	memset(&params, 0, sizeof(params));
	params.attr = &blattrs[1];
	//params.attr = &ble_bl_server.attrs[1];
	params.data = buf;
	params.len = len;
	params.func = bt_gatt_indicate_cb;

	if (!gatt_connected)
	{
		IOT_INFO("%s No gatt connection", __func__);
		return 1;
	}
	
	if (ble_bl_conn != NULL && indicate_flag == true)
	{
		indication_need_confirmed = 1;
		int err = bt_gatt_indicate(ble_bl_conn, &params);
		if(err<0){
			IOT_ERROR("bt_gatt_indicate: %d",err);
		}
	}
	return 0;
}

static int ble_blf_recv(struct bt_conn *conn,
						const struct bt_gatt_attr *attr, const void *buf,
						u16_t len, u16_t offset, u8_t flags)
{
	uint8_t *recv_buffer;
	recv_buffer = pvPortMalloc(sizeof(uint8_t) * len);
	memcpy(recv_buffer, buf, len);

	if (g_ble_cbs && g_ble_cbs->write_cb) {
		g_ble_cbs->write_cb(recv_buffer, len);
	}

	vPortFree(recv_buffer);
	return (int)len;
}

int iot_bsp_ble_start_adv(uint16_t mn_code, uint8_t *mn_data, size_t mn_data_len, char *local_name)
{
	int err;
	size_t offset_ind = 0;
	size_t offset_scan_res = 0;
    size_t mn_data_size_in_ind = 0;
    size_t mn_data_size_in_scan_res = 0;

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

    advInd_manufacturer_data[offset_ind++] = (mn_code & 0xFF);
    advInd_manufacturer_data[offset_ind++] = ((mn_code >> 8) & 0xFF);
    memcpy(advInd_manufacturer_data + offset_ind, mn_data, mn_data_size_in_ind);
    offset_ind += mn_data_size_in_ind;

    adv_mn_data_len = offset_ind;

	struct bt_data ad_flag = BT_DATA_BYTES(BT_DATA_FLAGS, (BT_LE_AD_NO_BREDR));
	struct bt_data ad_mn = BT_DATA(BT_DATA_MANUFACTURER_DATA, advInd_manufacturer_data, adv_mn_data_len);
	ad[0] = ad_flag;
	ad[1] = ad_mn;

	/* Advertising Scan Manufacturer Data Type */
    if (mn_data_size_in_scan_res) {
		IOT_WARN("handle mn code");
        scanRsp_manufacturer_data[offset_scan_res++] = (mn_code & 0xFF);
        scanRsp_manufacturer_data[offset_scan_res++] = ((mn_code >> 8) & 0xFF);
        memcpy(scanRsp_manufacturer_data + offset_scan_res, mn_data + mn_data_size_in_ind, mn_data_size_in_scan_res);
        offset_scan_res += mn_data_size_in_scan_res;
    }

    scan_response_len = offset_scan_res;
	IOT_INFO("scan response length: %d", scan_response_len);

	//struct bt_data rsp_name = BT_DATA(BT_DATA_NAME_COMPLETE, local_name, strlen(local_name));
	struct bt_data rsp_mn = BT_DATA(BT_DATA_MANUFACTURER_DATA, scanRsp_manufacturer_data, scan_response_len);
	//rsp[0] = rsp_name;
	rsp[0] = rsp_mn;
	if (!gatt_connected) {
		err = bt_le_adv_start(BT_LE_ADV_CONN_NAME, ad, ARRAY_SIZE(ad), rsp, ARRAY_SIZE(rsp));
		if (err != 0) {
			IOT_ERROR("Advertising failed to start (err %d)", err);
			return 1;
		}
		is_advertising = 1;
	}

	return 0;
}

void bleapps_adv_stop(void)
{
	int err;
	IOT_INFO("Bluetooth Advertising stop");
	err = bt_le_adv_stop();
	if (err != 0) {
		IOT_ERROR("Advertising failed to stop (err %d)", err);
	} else {
		is_advertising = 0;
	}
}

static void bl_connected(struct bt_conn *conn, uint8_t err)
{
	struct bt_le_conn_param param;
	param.interval_max = 0x20; // max_int = 0x20*1.25ms = 40ms
	param.interval_min = 0x10; // min_int = 0x10*1.25ms = 20ms
	param.latency = 0;
	param.timeout = 400; // timeout = 400*10ms = 4000ms
	int update_err;
	if (err) {
		IOT_ERROR("Connection failed (err 0x%02x)", err);
	} else {
		IOT_INFO("Connected");
		ble_bl_conn = conn;
		update_err = bt_conn_le_param_update(conn, &param);

		if (update_err) {
			IOT_ERROR("conn update failed (err %d)", update_err);
		} else {
			IOT_INFO("conn update initiated");
		}
		if (is_advertising) {
			IOT_INFO("stop adv");
			bleapps_adv_stop();
		}
		if (g_ble_cbs && g_ble_cbs->conn_cb) {
			g_ble_cbs->conn_cb(IOT_BLE_CONNECTION_EVENT_CONNECTED);
		}
		gatt_connected = 1;
		indication_need_confirmed = 0;
	}
}

static void bl_disconnected(struct bt_conn *conn, uint8_t reason)
{
	IOT_INFO("Disconnected (reason 0x%02x)", reason);

	if (!is_advertising) {
		struct bt_data ad_flag = BT_DATA_BYTES(BT_DATA_FLAGS, (BT_LE_AD_NO_BREDR));
		struct bt_data ad_mn = BT_DATA(BT_DATA_MANUFACTURER_DATA, advInd_manufacturer_data, adv_mn_data_len);
		ad[0] = ad_flag;
		ad[1] = ad_mn;
		struct bt_data rsp_mn = BT_DATA(BT_DATA_MANUFACTURER_DATA, scanRsp_manufacturer_data, scan_response_len);
		//rsp[0] = rsp_name;
		rsp[0] = rsp_mn;
		int err = bt_le_adv_start(BT_LE_ADV_CONN_NAME, ad, ARRAY_SIZE(ad), rsp, ARRAY_SIZE(rsp));;
		if (err != 0) {
			IOT_ERROR("Advertising failed to start (err %d)", err);
		} else {
			is_advertising = 1;
		}
	}
	//bleapps_adv_starting();
	if (g_ble_cbs && g_ble_cbs->conn_cb) {
		g_ble_cbs->conn_cb(IOT_BLE_CONNECTION_EVENT_DISCONNECTED);
	}
	gatt_connected = 0;
	indication_need_confirmed = 0;
}

static struct bt_conn_cb conn_callbacks = {
	.connected = bl_connected,
	.disconnected = bl_disconnected,
};

#define sys_bitfield_test_bit(ptr, bit) ((*(ptr) & (1 << (bit))) != 0)
void print_gatt_service_info(struct bt_gatt_service *svc) {
    IOT_INFO("GATT Service address: %p", svc);

	IOT_INFO("size_t value: %zu", &svc->attr_count);
    IOT_INFO("Status register value: 0x%x", (unsigned int)sys_bitfield_test_bit((uint32_t *)&svc->node, 0));
}

static void mtu_change_cb(struct bt_conn *conn, int mtu){
	IOT_INFO("mtu change callback called, new mtu:%d", mtu);
	g_mtu = mtu;
}

static void bt_enable_cb(int err)
{
	if (err != 0) {
		IOT_ERROR("BT FAILED started");
	} else {
		g_ble_status = BL_BLE_STATUS_INIT;
		IOT_INFO("BT SUCCESS started");
	}
}

iot_error_t iot_bsp_ble_init(iot_ble_cbs_t *ble_cbs)
{
	int err;
	if (g_ble_status == BL_BLE_STATUS_INIT)
	{
		IOT_INFO("ESP BLE already initialised");
		return IOT_ERROR_BAD_REQ;
	}

	if (g_ble_status == BL_BLE_STATUS_UNKNOWN)
	{
		//ble_controller_reset();unrealized
	}

	// Initiblfize BLE controller
	ble_controller_init(configMAX_PRIORITIES - 1);
	extern int hci_driver_init(void);
	// Initiblfize BLE Host stack
	hci_driver_init();
	err = bt_enable(bt_enable_cb);
	if (err != 0) {
		IOT_ERROR("Failed to enable BT");
		return IOT_ERROR_BAD_REQ;
	}
	g_ble_status = BL_BLE_STATUS_INIT;

	bt_conn_cb_register(&conn_callbacks);

	//#if defined(CONFIG_BT_GATT_DYNAMIC_DB)
	print_gatt_service_info(&ble_bl_server);
	err = bt_gatt_service_register(&ble_bl_server);
	if (err == 0) {
		IOT_INFO("bt_gatt_service_register ok");
	} else {
		IOT_ERROR("bt_gatt_service_register err");
		return IOT_ERROR_BAD_REQ;
	}
	//#endif

	bt_gatt_register_mtu_callback(mtu_change_cb);
	g_mtu = GATTS_MTU_MAX;
	bt_gatt_set_mtu(g_mtu);

	g_ble_cbs = ble_cbs;
	return IOT_ERROR_NONE;
}

void iot_bsp_ble_deinit(void)
{
	if (g_ble_status != BL_BLE_STATUS_INIT)
	{
		IOT_INFO("BL BLE already deinitalised");
		return;
	}
	bt_disable();

	g_ble_status = BL_BLE_STATUS_DEINIT;
	g_ble_cbs = NULL;
	return;
}

uint32_t iot_bsp_ble_get_mtu(void)
{
	return g_mtu;
}
