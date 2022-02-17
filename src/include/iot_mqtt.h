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

#if !defined(ST_MQTT_H)
#define ST_MQTT_H

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

#define ST_MQTT_TCP_KEEPALIVE_IDLE	(300)		/**< @brief tcp keep alive idle with seconds unit */
#define ST_MQTT_TCP_KEEPALIVE_COUNT	(3)		/**< @brief tcp keep alive count */
#define ST_MQTT_TCP_KEEPALIVE_INTERVAL	(2)		/**< @brief tcp keep alive intrval */

typedef void* st_mqtt_client;

typedef struct st_mqtt_broker_info {
	char *url;						/**< @brief server address */
	int port;						/**< @brief server port */
	const unsigned char *ca_cert;	/**< @brief a pointer to a CA certificate */
	unsigned int ca_cert_len;		/**< @brief a size of CA certificate */

	char ssl;						/**< @brief ssl support */
} st_mqtt_broker_info_t;

typedef struct
{
	/** Version of MQTT to be used.  3 = 3.1 4 = 3.1.1 5 = 5.0 */
	unsigned char mqtt_ver;			/**< @brief MQTT version */
	char *username;					/**< @brief connection user name */
	char *password;					/**< @brief connection passwor  */
	char *clientid;					/**< @brief connectino client id */

	unsigned short alive_interval;	/**< @brief PING request period */
	unsigned char cleansession;		/**< @brief request clean session */

	unsigned char will_flag;		/**< @brief using will property */
	char *will_topic;				/**< @brief MQTT will topic */
	char *will_message;				/**< @brief MQTT will message */
	unsigned char will_retained;	/**< @brief MQTT will retained */
	char will_qos;					/**< @brief MQTT will qos */
} st_mqtt_connect_data;

#define st_mqtt_default_alive_interval	120
#define st_mqtt_connect_data_initializer  { 4, NULL, NULL, NULL, st_mqtt_default_alive_interval, 1, 0, NULL, NULL, 0, 0}

typedef struct st_mqtt_msg {
	void *topic;					/**< @brief MQTT publish packet topic */
	int topiclen;					/**< @brief MQTT publish packet topic length */
	void *payload;					/**< @brief MQTT publish packet payload */
	int payloadlen;					/**< @brief MQTT publish packet payload length */

	int qos;						/**< @brief MQTT publish packet QoS */
	unsigned char retained;			/**< @brief MQTT publish packet retained */
} st_mqtt_msg;

typedef enum {
	ST_MQTT_EVENT_MSG_DELIVERED = 1,
	ST_MQTT_EVENT_PUBLISH_FAILED = 2,
	ST_MQTT_EVENT_PUBLISH_TIMEOUT = 3,
} st_mqtt_event;

typedef void (*st_mqtt_event_callback)(st_mqtt_event event, void *event_data, void *usr_data);

enum {
	st_mqtt_qos0,					/* MQTT QoS0 */
	st_mqtt_qos1,					/* MQTT QoS1 */
	st_mqtt_qos2					/* MQTT QoS2 */
};

enum {
	E_ST_MQTT_FAILURE = -1,							/* MQTT operation fail */
	E_ST_MQTT_DISCONNECTED = -2,					/* MQTT disconnect */
	E_ST_MQTT_BUFFER_OVERFLOW = -3,					/* MQTT buffer overflow */
	E_ST_MQTT_UNNACCEPTABLE_PROTOCOL = -4,			/* MQTT server does not support version requested by client */
	E_ST_MQTT_SERVER_UNAVAILABLE = -5,				/* MQTT service is unavailable */
	E_ST_MQTT_CLIENTID_REJECTED = -6,				/* MQTT connection client id not allowed by server */
	E_ST_MQTT_BAD_USERNAME_OR_PASSWORD = -7,		/* MQTT connection username or password is malformed */
	E_ST_MQTT_NOT_AUTHORIZED = -8,					/* MQTT client is not authorized to connect */
	E_ST_MQTT_NETWORK_ERROR = -9,					/* MQTT network error */
	E_ST_MQTT_PACKET_TIMEOUT = -10,					/* MQTT MQTT pending packet timeout */
	E_ST_MQTT_PING_FAIL = -11,						/* MQTT send ping fail */
	E_ST_MQTT_PING_TIMEOUT = -12,					/* MQTT send ping timeout */
};

/**
 * Create an MQTT client object
 * @param client - client object to create
 * @param callback_fp - callback function when mqtt event(msg delivery, packet fail, disconnect etc..) occurs
 * @param user_data - callback function user parameter
 * @return success code
 */
DLLExport int st_mqtt_create(st_mqtt_client *client, st_mqtt_event_callback callback_fp, void *user_data);

/** MQTT Connect - send an MQTT connect packet down the network and wait for a Connack
 *  @param client - the client object to use
 *  @param broker - broker network information
 *  @param connect_data - MQTT connect data
 *  @return success code
 */
DLLExport int st_mqtt_connect(st_mqtt_client client, st_mqtt_broker_info_t *broker, st_mqtt_connect_data *connect_data);

/** MQTT Publish - send an MQTT publish packet and wait for all acks to complete for all QoSs
 *  @param client - the client object to use
 *  @param msg - the publish packet message to send
 *  @return success code
 */
DLLExport int st_mqtt_publish(st_mqtt_client client, st_mqtt_msg *msg);

/** MQTT Publish Async - send an MQTT publish packet async call.
 * 			  if it fails, notify via callback function.
 *  @param client - the client object to use
 *  @param msg - the publish packet message to send
 *  @return 0 - success
 *  		others - error codes
 */
DLLExport int st_mqtt_publish_async(st_mqtt_client client, st_mqtt_msg *msg);

/** MQTT Change ping period - change MQTT PING request period time.
 *  @param client - the client object to use
 *  @param new_period - new PING request period to change
 */
DLLExport void st_mqtt_change_ping_period(st_mqtt_client client, unsigned int new_period);


/** MQTT Subscribe - send an MQTT subscribe packet and wait for suback before returning.
 *  @param client - the client object to use
 *  @param count - subscribe topic count
 *  @param topics - the topic filters to subscribe to
 *  @param qos - request subscribe QoS level
 *  @return success code
 */
DLLExport int st_mqtt_subscribe(st_mqtt_client client, int count, char* topics[], int qos[]);

/** MQTT Subscribe - send an MQTT unsubscribe packet and wait for unsuback before returning.
 *  @param client - the client object to use
 *  @param count - unsubscribe topic count
 *  @param topics - the topic filters to unsubscribe from
 *  @return success code
 */
DLLExport int st_mqtt_unsubscribe(st_mqtt_client client, int count, char* topics[]);

/** MQTT Disconnect - send an MQTT disconnect packet and close the connection
 *  @param client - the client object to use
 *  @return success code
 */
DLLExport int st_mqtt_disconnect(st_mqtt_client client);

/** Destroy an MQTT client object
 *  @param client - the client object to destroy
 *  @return success code
 */
DLLExport void st_mqtt_destroy(st_mqtt_client client);

/** MQTT Yield - MQTT background
 *  @param client - the client object to use
 *  @param time - the time, in milliseconds, to yield for
 *  @return negative values - error codes
 *  		0 - there is no work left
 *  		1 - there is work left
 */
DLLExport int st_mqtt_yield(st_mqtt_client client, int time);

/** MQTT start background thread for a client.	After this, MQTTYield should not be called.
*  @param client - the client object to use
*  @return success code
*/
DLLExport int st_mqtt_starttask(st_mqtt_client client);

/** MQTT end background thread for a client.
*  @param client - the client object to use
*/
DLLExport void st_mqtt_endtask(st_mqtt_client client);

#if defined(__cplusplus)
}
#endif

#endif
