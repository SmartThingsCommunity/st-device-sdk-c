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
#define TEST_MANUFACTURER_DATA_LEN 17

#define GATTS_CHAR_VAL_LEN_MAX 1024

#define PREPARE_BUF_MAX_SIZE 1024

#define MAX_CHAR_LEN 1024
#define PROFILE_APP_ID 0

#define EV_BLE_TEST 0x0504
#define BLE_DEV_CONN 0x03
#define BLE_DEV_DISCONN 0x04

#define DISPLAY_SERIAL_NUMBER_SIZE 4

#define PACKET_MAX_SIZE 31
#define MAC_ADD_COUNT 6
#define BT_MAC_LENGTH 6

#define ADV_FLAG_LEN 0x02
#define ADV_FLAG_TYPE 0x01
#define ADV_FLAG_VALUE 0x04
#define ADV_SERVICE_DATA_LEN 0x1B

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

#define CONTROL_VERSION_ACTIVE_SCAN_REQUIRED 0x42
#define PACKET_VERSION 0x83
#define SERVICE_ID 0x0c
#define OOB_SERVICE_INFO 0x05
#define SERVICE_FEATURE 0x59
#define SETUP_AVAILABLE_NETWORK_BLE 0x04

#define BT_ADDRESS_TRANSFER 0x01

#define SCAN_RBL_FLAG_TYPE 0x09
#if defined(CONFIG_STDK_IOT_CORE_EASYSETUP_X509)
#define SCAN_RBL_MF_DATA_LEN 0x06
#define MAX_DEVICE_NAME_DATA_LEN 0x16
#else
#define SCAN_RBL_MF_DATA_LEN 0x0A
#define MAX_DEVICE_NAME_DATA_LEN 0x12
#endif

#define GATTS_MTU_MAX 247

#define MANUFACTURER_ID 0x75

size_t device_onboarding_id_len;
int indication_need_confirmed;
int gatt_connected;

static int is_sendindicate_sleep = 0;
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

 static u8_t sam_manufacturer_id[26] = { 0x75,  0x0,  0x42,  0xc,  0x83,  0x5,  0x59,  0x66,  0x77,  0x43,  0x30,  0x30,  0x30,  0x33,  0x4,  0x1,  0x53,  0x54,  0x44,  0x4b,  0x59,  0x39,  0xa,  0x3,  0x8,  0x7a};
//  static u8_t sam_manufacturer_id[20] = { 0x75,  0x0,  0x42,  0xc,  0x83,  0x5,  0x59,  0x66,  0x77,  0x43,  0x30,  0x30,  0x30,  0x33,  0x4,  0x1,  0x53,  0x54,  0x44,  0x4b};
static u8_t sam_manufacturer_id1[9] = { 0x75,  0x0,  0x72,  0x2d,  0x71,  0x54,  0x55,  0x6d,  0x57};

static u8_t advInd_manufacturer_data[26];
static u8_t scanRsp_manufacturer_data[9];

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
static uint8_t adv_config_done = 0;
static uint8_t adv_data[PACKET_MAX_SIZE];
static size_t adv_data_len;
static size_t adv_data_mac_address_offset;
static size_t adv_data_mac_address_offset1;
static uint8_t scan_response_data[PACKET_MAX_SIZE];
static size_t scan_response_len;
static uint8_t manufacturer_id[2] = {0x75, 0x00};
static iot_bsp_ble_event_cb_t ble_event_cb;
static bool g_onboarding_complete;

CharWriteCallback CharWriteCb;

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
static bool iot_bsp_ble_get_onboarding_completion(void)
{
	return g_onboarding_complete;
}

void iot_bsp_ble_set_onboarding_completion(bool onboarding_complete)
{
	g_onboarding_complete = onboarding_complete;
}

void set_advertise_mac_addr(uint8_t **mac)
{
	int i;
	int counter = adv_data_mac_address_offset;
	int counterN = adv_data_mac_address_offset1;
	uint8_t *lmac = NULL;
	bt_addr_le_t macaddr ;
	size_t count = 6; // mac length

	lmac = (uint8_t *)malloc(BT_MAC_LENGTH);
	if (!lmac)
	{
		IOT_ERROR("failed to malloc for lmac");
		*mac = NULL;
		return;
	}
	bt_id_get(&macaddr, &count);
	memcpy(lmac, macaddr.a.val, BT_MAC_LENGTH);
	for (i = 0; i < BT_MAC_LENGTH; i++){
		IOT_INFO("macaddr.a.val[%d]: %x", i, macaddr.a.val[i]);
	}

	for (i = 0; i < BT_MAC_LENGTH; i++)
	{
		adv_data[counter++] = lmac[i];
		advInd_manufacturer_data[counterN++] = lmac[i];
	}

	*mac = lmac;
}

void iot_create_advertise_packet(char *mnid, char *setupid, char *serial)
{
	uint8_t *mac;
	int count = 0;
	int i;
	int mnid_len = 0;
	int setupid_len = 0;
	int countN  = 0;

#if !defined(CONFIG_STDK_IOT_CORE_EASYSETUP_X509)
	char *hybrid_serial = serial;
#else
	int serial_len = 0;
	unsigned char display_serial[DISPLAY_SERIAL_NUMBER_SIZE + 1] = {
		0,
	};

	serial_len = strlen(serial);

	for (i = 0; i < DISPLAY_SERIAL_NUMBER_SIZE; i++)
	{
		display_serial[i] = serial[serial_len - DISPLAY_SERIAL_NUMBER_SIZE + i];
	}
	display_serial[DISPLAY_SERIAL_NUMBER_SIZE] = '\0';
	IOT_INFO(">> Display_Serial [%c%c%c%c] <<", display_serial[0], display_serial[1],
			display_serial[2], display_serial[3]);
#endif

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
	
	advInd_manufacturer_data[countN++] = manufacturer_id[0];
	advInd_manufacturer_data[countN++] = manufacturer_id[1];
	advInd_manufacturer_data[countN++] = CONTROL_VERSION_ACTIVE_SCAN_REQUIRED;
	advInd_manufacturer_data[countN++] = SERVICE_ID;
	advInd_manufacturer_data[countN++] = PACKET_VERSION;
	advInd_manufacturer_data[countN++] = OOB_SERVICE_INFO;
	advInd_manufacturer_data[countN++] = SERVICE_FEATURE;

	mnid_len = strlen(mnid);

	for (i = 0; i < mnid_len; i++)
	{
		adv_data[count++] = (uint8_t)mnid[i];
		advInd_manufacturer_data[countN++] = (uint8_t)mnid[i];
	}

	setupid_len = strlen(setupid);

	for (i = 0; i < setupid_len; i++)
	{
		adv_data[count++] = (uint8_t)setupid[i];
		advInd_manufacturer_data[countN++] = (uint8_t)setupid[i];
	}

	adv_data[count++] = SETUP_AVAILABLE_NETWORK_BLE;
	adv_data[count++] = BT_ADDRESS_TRANSFER;

	advInd_manufacturer_data[countN++] = SETUP_AVAILABLE_NETWORK_BLE;
	advInd_manufacturer_data[countN++] = BT_ADDRESS_TRANSFER;

	adv_data_mac_address_offset = count;
	count += MAC_ADD_COUNT;
	adv_data_mac_address_offset1 = countN;
	countN += MAC_ADD_COUNT;
	set_advertise_mac_addr(&mac);
	free(mac);

	adv_data[count++] = CUSTOM_DATA_LEN;
	adv_data[count++] = CUSTOM_TYPE;
	adv_data[count++] = CUSTOM_TYPE_DATA_LEN;

	advInd_manufacturer_data[countN++] = CUSTOM_DATA_LEN;
	advInd_manufacturer_data[countN++] = CUSTOM_TYPE;
	advInd_manufacturer_data[countN++] = CUSTOM_TYPE_DATA_LEN;
#if defined(CONFIG_STDK_IOT_CORE_EASYSETUP_X509)
	adv_data[count++] = display_serial[0];
	advInd_manufacturer_data[countN++] = display_serial[0];
#else
	adv_data[count++] = hybrid_serial[0];
	advInd_manufacturer_data[countN++] = hybrid_serial[0];
#endif

	adv_data_len = count;

	printf("\n");
	printf("ADV_Data: \n");
	for (i = 0; i < count; i++)
	{
		printf("0x%x,  ", adv_data[i]);
	}
	printf("\n");
	for (i = 0; i < countN; i++)
	{
		printf("0x%x,  ", advInd_manufacturer_data[i]);
	}
	printf("\n");
}

void iot_create_scan_response_packet(char *device_onboarding_id, char *serial)
{
	int count = 0;
	int countN = 0;
	int i;
#if !defined(CONFIG_STDK_IOT_CORE_EASYSETUP_X509)
	char *hybrid_serial = serial;
#else
	int serial_len = 0;
	size_t device_onboarding_id_len = 0;
	unsigned char display_serial[DISPLAY_SERIAL_NUMBER_SIZE + 1] = {
		0,
	};

	serial_len = strlen(serial);

	for (i = 0; i < DISPLAY_SERIAL_NUMBER_SIZE; i++)
	{
		display_serial[i] = serial[serial_len - DISPLAY_SERIAL_NUMBER_SIZE + i];
	}
	display_serial[DISPLAY_SERIAL_NUMBER_SIZE] = '\0';
#endif
	IOT_INFO("device_onboarding_id: %s",device_onboarding_id);
	device_onboarding_id_len = (strlen(device_onboarding_id) > MAX_DEVICE_NAME_DATA_LEN) ? MAX_DEVICE_NAME_DATA_LEN : strlen(device_onboarding_id);

	scan_response_data[count++] = device_onboarding_id_len + 1;
	scan_response_data[count++] = SCAN_RBL_FLAG_TYPE;

	for (i = 0; i < device_onboarding_id_len; i++)
	{
		scan_response_data[count++] = (uint8_t)device_onboarding_id[i];
	}

	scan_response_data[count++] = SCAN_RBL_MF_DATA_LEN;
	scan_response_data[count++] = CUSTOM_DATA_TYPE;
	scan_response_data[count++] = manufacturer_id[0];
	scan_response_data[count++] = manufacturer_id[1];

	scanRsp_manufacturer_data[countN++] = manufacturer_id[0];
	scanRsp_manufacturer_data[countN++] = manufacturer_id[1];

#if defined(CONFIG_STDK_IOT_CORE_EASYSETUP_X509)
	for (i = 1; i < DISPLAY_SERIAL_NUMBER_SIZE; i++)
	{
		scan_response_data[count++] = (uint8_t)display_serial[i];
		scanRsp_manufacturer_data[countN++] = (uint8_t)display_serial[i];
	}
#else
	for (i = 1; i < HYBRID_SERIAL_NUMBER_SIZE; i++)
	{
		scan_response_data[count++] = (uint8_t)hybrid_serial[i];
		scanRsp_manufacturer_data[countN++] = (uint8_t)hybrid_serial[i];
	}
#endif

	scan_response_len = count;

	for (i = count; i < PACKET_MAX_SIZE; i++)
	{
		scan_response_data[count++] = 0;
		// scanRsp_manufacturer_data[countN++] = 0;
	}

	printf("\n");
	printf("scan_response_data: \n");
	for (i = 0; i < PACKET_MAX_SIZE; i++)
	{
		printf("0x%x,  ", scan_response_data[i]);
	}
	
	printf("\n");

	for (i = 0; i < countN; i++)
	{
		printf("0x%x,  ", scanRsp_manufacturer_data[i]);
	}
	printf("\n");
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

	if (CharWriteCb)
	{
	CharWriteCb(recv_buffer, len);
	}

	vPortFree(recv_buffer);
	
	return (int)len;
}


int bleapps_adv_starting(void)
{
	int err;

	IOT_INFO("Bluetooth Advertising start");
	struct bt_data ad[] = {
	// BT_DATA_BYTES(BT_DATA_FLAGS, (BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR)),
	BT_DATA_BYTES(BT_DATA_FLAGS, (BT_LE_AD_NO_BREDR)),
	//BT_DATA(BT_DATA_NAME_COMPLETE, "BL", 2),
	BT_DATA(BT_DATA_MANUFACTURER_DATA, advInd_manufacturer_data, sizeof(advInd_manufacturer_data))
};
	struct bt_data rsp[] = {
	// BT_DATA_BYTES(BT_DATA_FLAGS, (BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR)),
	// BT_DATA(BT_DATA_NAME_COMPLETE,"BL_602" ,6),
	//BT_DATA(BT_DATA_NAME_COMPLETE, "BL", 2),
	BT_DATA(BT_DATA_MANUFACTURER_DATA, scanRsp_manufacturer_data, sizeof(scanRsp_manufacturer_data))
};
	err = bt_le_adv_start(BT_LE_ADV_CONN_NAME, ad, ARRAY_SIZE(ad), rsp, ARRAY_SIZE(rsp));
	if (err)
	{
		IOT_ERROR("Advertising failed to start (err %d)", err);
	}
	return err;
}

static void bt_ready(void)
{

	// bt_set_name("blf_602");
	IOT_INFO("Bluetooth initiblfized");
	bleapps_adv_starting();
}

void bleapps_adv_stop(void)
{
	int err;
	IOT_INFO("Bluetooth Advertising stop");
	err = bt_le_adv_stop();
	if (err)
	{
		IOT_ERROR("Advertising failed to stop (err %d)", err);
	}
}

static void ble_app_init(int err)
{
	if (err != 0)
	{
		IOT_ERROR("BT FAILED started");
	}
	else
	{
		IOT_INFO("BT SUCCESS started");
		g_ble_status = BL_BLE_STATUS_INIT;
		bt_ready();
		IOT_INFO("BT SUCCESS started1");
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
	if (err)
	{
		IOT_ERROR("Connection failed (err 0x%02x)", err);
	}
	else
	{
		IOT_INFO("Connected");
		ble_bl_conn = conn;
		update_err = bt_conn_le_param_update(conn, &param);

		if (update_err)
		{
			IOT_ERROR("conn update failed (err %d)", update_err);
		}
		else
		{
			IOT_INFO("conn update initiated");
		}
		bleapps_adv_stop();
		if (ble_event_cb)
		{
			ble_event_cb(IOT_BLE_EVENT_GATT_JOIN, IOT_ERROR_NONE);
		}
		gatt_connected = 1;
		indication_need_confirmed = 0;
	}
}

static void bl_disconnected(struct bt_conn *conn, uint8_t reason)
{
	IOT_INFO("Disconnected (reason 0x%02x)", reason);
	/* Start ble advertisement only when onboarding is not completed */
		bool onboarding_completed = iot_bsp_ble_get_onboarding_completion();
		if (onboarding_completed == false) {
			int start_adv_ret = bleapps_adv_starting();;
			if (start_adv_ret) {
				//ESP_LOGE(GATTS_TAG, "start ble advertisement failed, error code = 0x%x\n", start_adv_ret);
			}
		}
	//bleapps_adv_starting();
	if (ble_event_cb)
	{
		ble_event_cb(IOT_BLE_EVENT_GATT_LEAVE, IOT_ERROR_NONE);
	}
	gatt_connected = 0;
	indication_need_confirmed = 0;
}

static struct bt_conn_cb conn_callbacks = {
	.connected = bl_connected,
	.disconnected = bl_disconnected,
};

static void ble_stack_start(void)
{
	// Initiblfize BLE controller
	ble_controller_init(configMAX_PRIORITIES - 1);
	extern int hci_driver_init(void);
	// Initiblfize BLE Host stack
	hci_driver_init();
	bt_enable(ble_app_init);
}
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
void iot_bsp_ble_init(CharWriteCallback cb)
{
	int err;
	if (g_ble_status == BL_BLE_STATUS_INIT)
	{
		IOT_INFO("ESP BLE already initialised");
		return;
	}

	CharWriteCb = cb;
	if (g_ble_status == BL_BLE_STATUS_UNKNOWN)
	{
		//ble_controller_reset();unrealized
	}

	ble_stack_start();
	g_ble_status = BL_BLE_STATUS_INIT;

	bt_conn_cb_register(&conn_callbacks);

	if (g_onboarding_complete == false)
	{
		//#if defined(CONFIG_BT_GATT_DYNAMIC_DB)
		print_gatt_service_info(&ble_bl_server);
		err = bt_gatt_service_register(&ble_bl_server);
		if (err == 0)
		{
			IOT_INFO("bt_gatt_service_register ok");
		}
		else
		{
			IOT_ERROR("bt_gatt_service_register err");
			return;
		}
		//#endif
	}
	bt_gatt_register_mtu_callback(mtu_change_cb);
	g_mtu = GATTS_MTU_MAX;
	bt_gatt_set_mtu(g_mtu);

	return;
}

iot_error_t iot_bsp_ble_register_event_cb(iot_bsp_ble_event_cb_t cb)
{
	if (cb == NULL)
		return IOT_ERROR_INVALID_ARGS;
	ble_event_cb = cb;
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
	CharWriteCb = NULL;
	ble_event_cb = NULL;
	return;
}

uint32_t iot_bsp_ble_get_mtu(void)
{
	return g_mtu;
}
