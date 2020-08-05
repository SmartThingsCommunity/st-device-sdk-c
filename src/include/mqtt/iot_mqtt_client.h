/*******************************************************************************
 * Copyright (c) 2019 Samsung Electronics All Rights Reserved.
 * Copyright (c) 2014, 2017 IBM Corp.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 *
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *   http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * Contributors:
 *    Allan Stockdill-Mander/Ian Craggs - initial API and implementation and/or initial documentation
 *    Ian Craggs - documentation and platform specific header
 *    Ian Craggs - add setMessageHandler function
 *******************************************************************************/

#if !defined(MQTT_CLIENT_H)
#define MQTT_CLIENT_H

#if defined(__cplusplus)
extern "C" {
#endif

#if defined(WIN32_DLL) || defined(WIN64_DLL)
#define DLLImport __declspec(dllimport)
#define DLLExport __declspec(dllexport)
#elif defined(LINUX_SO)
#define DLLImport extern
#define DLLExport  __attribute__ ((visibility ("default")))
#else
#define DLLImport
#define DLLExport
#endif

#include "st_dev.h"
#include "iot_mqtt_packet.h"
#include "iot_os_util.h"

#define MQTT_PUB_NOCOPY					1

#define MAX_PACKET_ID 					65535 	/* according to the MQTT specification - do not change! */
#define MAX_MESSAGE_HANDLERS 			5 		/* redefinable - how many subscriptions do you want? */
#define DEFAULT_COMMNAD_TIMEOUT 		30000
#define MQTT_PUBLISH_RETRY 				3
#define MQTT_PING_RETRY 				3
#define MQTT_WRITE_TIMEOUT				10000	/* in ms*/
#define MQTT_READ_TIMEOUT				10000	/* in ms*/
#define MQTT_RETRY_TIMEOUT				12000	/* in ms*/
#define MQTT_CONNECT_TIMEOUT			20000	/* in ms*/
#define MQTT_ACKPENDING_WAITCYCLE_IN_SYNC_FUNCTION			50		/* in ms*/

#define MQTT_DISCONNECT_MAX_SIZE		5
#define MQTT_PUBACK_MAX_SIZE			5
#define MQTT_PINGREQ_MAX_SIZE			5

#define MQTT_TASK_STACK_SIZE 			2048
#define MQTT_TASK_PRIORITY 				4
#define MQTT_TASK_CYCLE 				100

#define MQTT_CLIENT_STRUCT_MAGIC_NUMBER	0x19890107

enum packet_chunk_state {
	PACKET_CHUNK_INIT,
	PACKET_CHUNK_WRITE_PENDING,
	PACKET_CHUNK_WRITE_COMPLETED,
	PACKET_CHUNK_WRITE_FAIL,
	PACKET_CHUNK_ACK_PENDING,
	PACKET_CHUNK_READ_COMPLETED,
	PACKET_CHUNK_ACKNOWLEDGED,
	PACKET_CHUNK_TIMEOUT,
	PACKET_CHUNK_QUEUE_DESTROYED,
};

// Owner of packet chunk can be creator or caller of pop_queue()
typedef struct iot_mqtt_packet_chunk {
	int packet_type;
	unsigned int packet_id;
	int qos;

	unsigned char *chunk_data;
	size_t chunk_size;
	unsigned int chunk_id;
	int chunk_state;

	iot_os_timer expiry_time;
	int retry_count;

	unsigned char have_owner;
	int return_code;

	struct iot_mqtt_packet_chunk *next;
} iot_mqtt_packet_chunk_t;

typedef struct iot_mqtt_packet_chunk_queue {
	iot_os_mutex lock;
	struct iot_mqtt_packet_chunk *head;
	struct iot_mqtt_packet_chunk *tail;
} iot_mqtt_packet_chunk_queue_t;

typedef struct MQTTClient {
	int magic;
	unsigned int next_packetid;
	unsigned int keepAliveInterval;
	int isconnected;

	st_mqtt_event_callback user_callback_fp;
	void *user_callback_user_data;

	iot_net_interface_t *net;
	iot_os_timer last_sent, last_received;

	iot_os_mutex client_manage_lock;
	iot_os_thread thread;

	struct iot_mqtt_packet_chunk *ping_packet;

	iot_os_mutex write_lock;
	iot_os_mutex read_lock;

	iot_mqtt_packet_chunk_queue_t write_pending_queue;
	iot_mqtt_packet_chunk_queue_t ack_pending_queue;
	iot_mqtt_packet_chunk_queue_t user_event_callback_queue;
} MQTTClient;

#if defined(__cplusplus)
}
#endif

#endif
