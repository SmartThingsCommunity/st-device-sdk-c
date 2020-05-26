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

#define MQTT_DISCONNECT_MAX_SIZE		5
#define MQTT_PUBACK_MAX_SIZE			5
#define MQTT_PINGREQ_MAX_SIZE			5

#define MQTT_TASK_STACK_SIZE 			2048
#define MQTT_TASK_PRIORITY 				4
#define MQTT_TASK_CYCLE 				100

typedef struct MQTTConnackData {
	unsigned char rc;
	unsigned char sessionPresent;
} MQTTConnackData;

typedef struct MQTTSubackData {
	int granted_qos;
} MQTTSubackData;

enum packet_chunk_state {
	PACKET_CHUNK_INIT,
	PACKET_CHUNK_WRITE_PENDING,
	PACKET_CHUNK_WRITE_COMPLETED,
	PACKET_CHUNK_ACK_PENDING,
	PACKET_CHUNK_READ_COMPLETED,
	PACKET_CHUNK_ACKNOWLEDGED,
	PACKET_CHUNK_TIMEOUT,
};

// Owner of packet chunk can be creator or caller of pop_queue()
typedef struct iot_mqtt_packet_chunk {
	int packet_type;
	unsigned int packet_id;
	int qos;

	unsigned char *chunk_data;
	size_t chunk_size;
	size_t current_chunk_pos;
	unsigned char chunk_first_byte;
	unsigned char chunk_rem_size_bytes[MAX_NUM_OF_REMAINING_LENGTH_BYTES];
	size_t chunk_rem_size_length;
	unsigned int chunk_id;
	int chunk_state;

	iot_os_timer expiry_time;
	int retry_count;

	unsigned char is_owned;

	struct iot_mqtt_packet_chunk *next;
} iot_mqtt_packet_chunk_t;

typedef struct iot_mqtt_packet_chunk_queue {
	iot_os_mutex lock;
	unsigned char being_destroyed;
	struct iot_mqtt_packet_chunk *head;
	struct iot_mqtt_packet_chunk *tail;
} iot_mqtt_packet_chunk_queue_t;

typedef struct MQTTClient {
	unsigned int next_packetid,
			command_timeout_ms;
	size_t readbuf_size;
	unsigned char *readbuf;
	unsigned int keepAliveInterval;
	char ping_outstanding;
	int ping_retry_count;
	int isconnected;
	int cleansession;

	struct MessageHandlers {
		char *topicFilter;
		void (*fp)(st_mqtt_msg *, void *);
		void *userData;
	} messageHandlers[MAX_MESSAGE_HANDLERS];	  /* Message handlers are indexed by subscription topic */

	void (*defaultMessageHandler)(st_mqtt_msg *, void *);
	void *defaultUserData;

	iot_net_interface_t *net;
	iot_os_timer last_sent, last_received, ping_wait;

	iot_os_mutex mutex;
	iot_os_thread thread;

	struct iot_mqtt_packet_chunk *ping_packet;

	iot_os_mutex write_lock;
	struct iot_mqtt_packet_chunk *current_writing_chunk;
	iot_os_mutex read_lock;
	struct iot_mqtt_packet_chunk *current_reading_chunk;

	iot_mqtt_packet_chunk_queue_t write_pending_queue;
	iot_mqtt_packet_chunk_queue_t ack_pending_queue;
	iot_mqtt_packet_chunk_queue_t read_completed_queue;
} MQTTClient;

/** MQTT Connect - send an MQTT connect packet down the network and wait for a Connack
 *  @param options - connect options
 *  @return success code
 */
DLLExport int MQTTConnectWithResults(st_mqtt_client client, st_mqtt_broker_info_t *broker, st_mqtt_connect_data *connect_data,
									 MQTTConnackData *data);

/** MQTT SetMessageHandler - set or remove a per topic message handler
 *  @param client - the client object to use
 *  @param topicFilter - the topic filter set the message handler for
 *  @param messageHandler - pointer to the message handler function or NULL to remove
 *  @return success code
 */
DLLExport int MQTTSetMessageHandler(st_mqtt_client client, const char *topic, st_mqtt_msg_handler handler, void *user_data);

/** MQTT Subscribe - send an MQTT subscribe packet and wait for suback before returning.
 *  @param client - the client object to use
 *  @param topicFilter - the topic filter to subscribe to
 *  @param message - the message to send
 *  @param data - suback granted QoS returned
 *  @return success code
 */
DLLExport int MQTTSubscribeWithResults(st_mqtt_client client, const char *topic, int qos, st_mqtt_msg_handler handler, MQTTSubackData *data, void *user_data);

#if defined(__cplusplus)
}
#endif

#endif
