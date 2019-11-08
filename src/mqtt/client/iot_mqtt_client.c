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
 *   Allan Stockdill-Mander/Ian Craggs - initial API and implementation and/or initial documentation
 *   Ian Craggs - fix for #96 - check rem_len in readPacket
 *   Ian Craggs - add ability to set message handler separately #6
 *******************************************************************************/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include "iot_main.h"
#include "iot_debug.h"

static void NewMessageData(MessageData *md, MQTTString *aTopicName, MQTTMessage *aMessage)
{
	md->topicName = aTopicName;
	md->message = aMessage;
}

static int getNextPacketId(MQTTClient *c)
{
	return c->next_packetid = (c->next_packetid == MAX_PACKET_ID) ? 1 : c->next_packetid + 1;
}

static int sendPacket(MQTTClient *c, int length, iot_os_timer timer)
{
	int rc = MQTT_FAILURE,
		sent = 0;

	while (sent < length && !iot_os_timer_isexpired(timer)) {
		rc = c->net->write(c->net, &c->buf[sent], length, timer);

		if (rc < 0) { // there was an error writing the data
			break;
		}

		sent += rc;
	}

	if (sent == length) {
		iot_os_timer_count_ms(c->last_sent, c->keepAliveInterval * 1000); // record the fact that we have successfully sent the packet
		rc = MQTT_SUCCESS;
	} else {
		rc = MQTT_FAILURE;
	}

	return rc;
}

bool MQTTClientInit(MQTTClient *c, iot_net_interface_t *network, unsigned int command_timeout_ms,
		unsigned char *sendbuf, size_t sendbuf_size, unsigned char *readbuf, size_t readbuf_size)
{
	int i;
	c->net = network;

	for (i = 0; i < MAX_MESSAGE_HANDLERS; ++i) {
		c->messageHandlers[i].topicFilter = 0;
	}

	if (command_timeout_ms != 0) {
		c->command_timeout_ms = command_timeout_ms;
	} else {
		c->command_timeout_ms = CONFIG_STDK_MQTT_SEND_CYCLE;
	}

#if defined(CONFIG_STDK_MQTT_DYNAMIC_BUFFER)
	c->buf = NULL;
	c->buf_size = 0;
	c->readbuf = NULL;
	c->readbuf_size = 0;
#else
	if (sendbuf) {
		c->buf = sendbuf;
		c->buf_size = sendbuf_size;
	} else {
		c->buf = (unsigned char *)malloc(CONFIG_STDK_MQTT_SEND_BUFFER);

		if (c->buf) {
			c->buf_size = CONFIG_STDK_MQTT_SEND_BUFFER;
		} else {
			return false;
		}
	}

	if (readbuf) {
		c->readbuf = readbuf;
		c->readbuf_size = readbuf_size;
	} else {
		c->readbuf = (unsigned char *)malloc(CONFIG_STDK_MQTT_RECV_BUFFER);

		if (c->readbuf) {
			c->readbuf_size = CONFIG_STDK_MQTT_RECV_BUFFER;
		} else {
			return false;
		}
	}
#endif

	c->isconnected = 0;
	c->cleansession = 0;
	c->ping_outstanding = 0;
	c->ping_retry_count = 0;
	c->defaultMessageHandler = NULL;
	c->defaultUserData = NULL;
	c->next_packetid = 1;
	iot_os_timer_init(&c->last_sent);
	iot_os_timer_init(&c->last_received);
	iot_os_timer_init(&c->ping_wait);
#if defined(STDK_MQTT_TASK)
	iot_os_mutex_init(&c->mutex);
	c->thread = NULL;
#endif
	return true;
}

static int decodePacket(MQTTClient *c, int *value, iot_os_timer timer)
{
	unsigned char i;
	int multiplier = 1;
	int len = 0;
	const int MAX_NO_OF_REMAINING_LENGTH_BYTES = 4;

	*value = 0;

	do {
		int rc = MQTTPACKET_READ_ERROR;

		if (++len > MAX_NO_OF_REMAINING_LENGTH_BYTES) {
			rc = MQTTPACKET_READ_ERROR; /* bad data */
			goto exit;
		}

		rc = c->net->read(c->net, &i, 1, timer);

		if (rc != 1) {
			goto exit;
		}

		*value += (i & 127) * multiplier;
		multiplier *= 128;
	} while ((i & 128) != 0);

exit:
	return len;
}


static int readPacket(MQTTClient *c, iot_os_timer timer)
{
	MQTTHeader header = {0};
	int len = 0;
	int rem_len = 0;

#if defined(CONFIG_STDK_MQTT_DYNAMIC_BUFFER)
	unsigned char i;
	/* 1. read the header byte.  This has the packet type in it */
	int rc = c->net->read(c->net, &i, 1, timer);
#else
	/* 1. read the header byte.  This has the packet type in it */
	int rc = c->net->read(c->net, c->readbuf, 1, timer);
#endif

	if (rc != 1) {
		goto exit;
	}

	len = 1;
	/* 2. read the remaining length.  This is variable in itself */
	decodePacket(c, &rem_len, timer);
#if defined(CONFIG_STDK_MQTT_DYNAMIC_BUFFER)
	if (c->readbuf != NULL) {
		free(c->readbuf);
		c->readbuf = NULL;
	}
	c->readbuf_size = 5 + rem_len;
	c->readbuf = (unsigned char *)malloc(c->readbuf_size);
	if (c->readbuf == NULL) {
		IOT_ERROR("buf malloc failed");
		rc = MQTT_BUFFER_OVERFLOW;
		goto exit;
	}

	c->readbuf[0] = i;
	len += MQTTPacket_encode(c->readbuf + 1, rem_len); /* put the original remaining length back into the buffer */
#else
	len += MQTTPacket_encode(c->readbuf + 1, rem_len); /* put the original remaining length back into the buffer */

	if (rem_len > (c->readbuf_size - len)) {
		IOT_ERROR("mqtt read buffer overflow");
		rc = MQTT_BUFFER_OVERFLOW;
		goto exit;
	}
#endif

	/* 3. read the rest of the buffer using a callback to supply the rest of the data */
	if (rem_len > 0 && (rc = c->net->read(c->net, c->readbuf + len, rem_len, timer) != rem_len)) {
		rc = 0;
		goto exit;
	}

	header.byte = c->readbuf[0];
	rc = header.bits.type;

	if (c->keepAliveInterval > 0) {
		iot_os_timer_count_ms(c->last_received, c->keepAliveInterval * 1000);	  // record the fact that we have successfully received a packet
	}

exit:
	return rc;
}


// assume topic filter and name is in correct format
// # can only be at end
// + and # can only be next to separator
static char isTopicMatched(char *topicFilter, MQTTString *topicName)
{
	char *curf = topicFilter;
	char *curn = topicName->lenstring.data;
	char *curn_end = curn + topicName->lenstring.len;

	while (*curf && curn < curn_end) {
		if (*curn == '/' && *curf != '/') {
			break;
		}

		if (*curf != '+' && *curf != '#' && *curf != *curn) {
			break;
		}

		if (*curf == '+') {
			// skip until we meet the next separator, or end of string
			char *nextpos = curn + 1;

			while (nextpos < curn_end && *nextpos != '/') {
				nextpos = ++curn + 1;
			}
		} else if (*curf == '#') {
			curn = curn_end - 1;	// skip until end of string
		}

		curf++;
		curn++;
	};

	return (curn == curn_end) && (*curf == '\0');
}


int deliverMessage(MQTTClient *c, MQTTString *topicName, MQTTMessage *message)
{
	int i;
	int rc = MQTT_FAILURE;

	// we have to find the right message handler - indexed by topic
	for (i = 0; i < MAX_MESSAGE_HANDLERS; ++i) {
		if (c->messageHandlers[i].topicFilter != 0 && (MQTTPacket_equals(topicName, (char *)c->messageHandlers[i].topicFilter) ||
				isTopicMatched((char *)c->messageHandlers[i].topicFilter, topicName))) {
			if (c->messageHandlers[i].fp != NULL) {
				MessageData md;
				NewMessageData(&md, topicName, message);
				c->messageHandlers[i].fp(&md, c->messageHandlers[i].userData);
				rc = MQTT_SUCCESS;
			}
		}
	}

	if (rc == MQTT_FAILURE && c->defaultMessageHandler != NULL) {
		MessageData md;
		NewMessageData(&md, topicName, message);
		c->defaultMessageHandler(&md, c->defaultUserData);
		rc = MQTT_SUCCESS;
	}

	return rc;
}


int keepalive(MQTTClient *c)
{
	int rc = MQTT_SUCCESS;

	if (c->keepAliveInterval == 0) {
		goto exit;
	}

	if (c->ping_outstanding && iot_os_timer_isexpired(c->ping_wait) && c->ping_retry_count >= CONFIG_STDK_MQTT_PING_RETRY) {
		IOT_WARN("mqtt didn't get PINGRESP");
		rc = MQTT_FAILURE; /* PINGRESP not received in keepalive interval */
	/* Send ping request when there is no ping response up to 3 times or ping period expired */
	} else if ((c->ping_outstanding && iot_os_timer_isexpired(c->ping_wait) && c->ping_retry_count < CONFIG_STDK_MQTT_PING_RETRY) ||
			(iot_os_timer_isexpired(c->last_sent) || iot_os_timer_isexpired(c->last_received))) {
		iot_os_timer timer;
		iot_os_timer_init(&timer);
		iot_os_timer_count_ms(timer, c->command_timeout_ms);
#if defined(CONFIG_STDK_MQTT_DYNAMIC_BUFFER)
		if (c->buf != NULL) {
			free(c->buf);
			c->buf = NULL;
		}
		c->buf_size = MQTTSerialize_pingreq_size();
		c->buf = (unsigned char *)malloc(c->buf_size);
		if (c->buf == NULL) {
			IOT_ERROR("buf malloc failed");
			rc = MQTT_BUFFER_OVERFLOW;
			iot_os_timer_destroy(&timer);
			goto exit;
		}
#endif
		int len = MQTTSerialize_pingreq(c->buf, c->buf_size);
		if (len > 0 && (rc = sendPacket(c, len, timer)) == MQTT_SUCCESS) { // send the ping packet
			c->ping_outstanding = 1;
			c->ping_retry_count++;
			iot_os_timer_count_ms(c->ping_wait, c->command_timeout_ms);
		}
		iot_os_timer_destroy(&timer);
	}

exit:
#if defined(CONFIG_STDK_MQTT_DYNAMIC_BUFFER)
	if (c->buf != NULL) {
		free(c->buf);
		c->buf = NULL;
	}
#endif
	return rc;
}


void MQTTCleanSession(MQTTClient *c)
{
	int i = 0;

	for (i = 0; i < MAX_MESSAGE_HANDLERS; ++i) {
		c->messageHandlers[i].topicFilter = NULL;
	}
}


void MQTTCloseSession(MQTTClient *c)
{
	IOT_WARN("mqtt close session");
	if (c->net && c->net->show_status)
		c->net->show_status(c->net);
	c->ping_outstanding = 0;
	c->ping_retry_count = 0;
	c->isconnected = 0;

	if (c->cleansession) {
		MQTTCleanSession(c);
	}
}


int cycle(MQTTClient *c, iot_os_timer timer)
{
	int len = 0,
		rc = MQTT_SUCCESS;

	int packet_type = readPacket(c, timer);		/* read the socket, see what work is due */

	switch (packet_type) {
	default:
		/* no more data to read, unrecoverable. Or read packet fails due to unexpected network error */
		rc = packet_type;
		goto exit;

	case 0: /* timed out reading packet */
		break;

	case CONNACK:
	case PUBACK:
	case SUBACK:
	case UNSUBACK:
		break;

	case PUBLISH: {
		MQTTString topicName;
		MQTTMessage msg;
		int intQoS;
		msg.payloadlen = 0; /* this is a size_t, but deserialize publish sets this as int */

		if (MQTTDeserialize_publish(&msg.dup, &intQoS, &msg.retained, &msg.id, &topicName,
									(unsigned char **)&msg.payload, (int *)&msg.payloadlen, c->readbuf, c->readbuf_size) != 1) {
			goto exit;
		}

		msg.qos = (enum QoS)intQoS;
		deliverMessage(c, &topicName, &msg);
#if defined(CONFIG_STDK_MQTT_DYNAMIC_BUFFER)
		if (c->readbuf != NULL) {
			free(c->readbuf);
			c->readbuf = NULL;
		}
#endif
		if (msg.qos != QOS0) {
#if defined(CONFIG_STDK_MQTT_DYNAMIC_BUFFER)
			if (c->buf != NULL) {
				free(c->buf);
				c->buf = NULL;
			}
			c->buf_size = MQTTSerialize_ack_size();
			c->buf = (unsigned char *)malloc(c->buf_size);
			if (c->buf == NULL) {
				IOT_ERROR("buf malloc fail");
				goto exit;
			}
#endif
			if (msg.qos == QOS1) {
				len = MQTTSerialize_ack(c->buf, c->buf_size, PUBACK, 0, msg.id);
			} else if (msg.qos == QOS2) {
				len = MQTTSerialize_ack(c->buf, c->buf_size, PUBREC, 0, msg.id);
			}

			if (len <= 0) {
				rc = MQTT_FAILURE;
			} else {
				rc = sendPacket(c, len, timer);
			}
			if (rc == MQTT_FAILURE) {
				goto exit;	  // there was a problem
			}
		}

		break;
	}

	case PUBREC:
	case PUBREL: {
		unsigned short mypacketid;
		unsigned char dup, type;

#if defined(CONFIG_STDK_MQTT_DYNAMIC_BUFFER)
		if (c->buf != NULL) {
			free(c->buf);
			c->buf = NULL;
		}
		c->buf_size = MQTTSerialize_ack_size();
		c->buf = (unsigned char *)malloc(c->buf_size);
		if (c->buf == NULL) {
			IOT_ERROR("buf malloc fail");
			goto exit;
		}
#endif
		if (MQTTDeserialize_ack(&type, &dup, &mypacketid, c->readbuf, c->readbuf_size) != 1) {
			rc = MQTT_FAILURE;
		} else if ((len = MQTTSerialize_ack(c->buf, c->buf_size,
											(packet_type == PUBREC) ? PUBREL : PUBCOMP, 0, mypacketid)) <= 0) {
			rc = MQTT_FAILURE;
		} else if ((rc = sendPacket(c, len, timer)) != MQTT_SUCCESS) { // send the PUBREL packet
			rc = MQTT_FAILURE;	 // there was a problem
		}
#if defined(CONFIG_STDK_MQTT_DYNAMIC_BUFFER)
		free(c->readbuf);
		c->readbuf = NULL;
#endif
		if (rc == MQTT_FAILURE) {
			goto exit;	  // there was a problem
		}

		break;
	}

	case PUBCOMP:
		break;

	case PINGRESP:
		c->ping_outstanding = 0;
		c->ping_retry_count = 0;
		break;
	}

	if (keepalive(c) != MQTT_SUCCESS) {
		//check only keepalive MQTT_FAILURE status so that previous FAILURE status can be considered as FAULT
		rc = MQTT_FAILURE;
	}

exit:
#if defined(CONFIG_STDK_MQTT_DYNAMIC_BUFFER)
	if (c->buf != NULL) {
		free(c->buf);
		c->buf = NULL;
	}
#endif
	if (rc == MQTT_SUCCESS) {
		rc = packet_type;
	} else if (c->isconnected) {
		MQTTCloseSession(c);
	}

	return rc;
}


int MQTTYield(MQTTClient *c, int timeout_ms)
{
	int rc = MQTT_SUCCESS;
	iot_os_timer timer;
	int ret;

	if (!c->isconnected)
		return rc;

	iot_os_timer_init(&timer);
	iot_os_timer_count_ms(timer, timeout_ms);

	do {
		if ((c->net == NULL) || (c->net->select == NULL)) {
			IOT_ERROR("net->select is null");
			rc = -1;
			break;
		}

		ret = c->net->select(c->net, iot_os_timer_left_ms(timer));
		if (ret > 0) {
			iot_os_timer command_timer;
			iot_os_timer_init(&command_timer);
			iot_os_timer_count_ms(command_timer, c->command_timeout_ms);
			rc = cycle(c, command_timer);
			iot_os_timer_destroy(&command_timer);
		} else if (ret < 0) {
			MQTTCloseSession(c);
			rc = -1;
		} else if ((rc = keepalive(c)) != MQTT_SUCCESS)
			MQTTCloseSession(c);
	} while (!iot_os_timer_isexpired(timer));
	iot_os_timer_destroy(&timer);

	return rc;
}

#if defined(STDK_MQTT_TASK)
void MQTTRun(void *parm)
{
	iot_os_timer timer;
	MQTTClient *c = (MQTTClient *)parm;

	if ((c->net == NULL) || (c->net->select == NULL)) {
		IOT_ERROR("net->select is null");
		return;
	}

	iot_os_timer_init(&timer);

	while (1) {
		iot_os_timer_count_ms(timer, CONFIG_STDK_MQTT_RECV_CYCLE); /* Don't wait too long if no traffic is incoming */

		iot_os_mutex_lock(&c->mutex);
		if (!c->isconnected) {
			IOT_WARN("MQTTRun task exit");
			iot_os_mutex_unlock(&c->mutex);
			iot_os_timer_destroy(&timer);
			c->thread = NULL;
			iot_os_thread_delete(NULL);
		}
		int rc = MQTT_SUCCESS;
		int ret = c->net->select(c->net, iot_os_timer_left_ms(timer));
		if (ret > 0) {
			iot_os_timer_count_ms(timer, c->command_timeout_ms);
			rc = cycle(c, timer);
		} else if (ret < 0) {
			MQTTCloseSession(c);
			rc = -1;
		} else if ((rc = keepalive(c)) != MQTT_SUCCESS)
			MQTTCloseSession(c);

		if (rc == MQTT_FAILURE) {
			IOT_WARN("MQTTRun task exit");
			iot_os_mutex_unlock(&c->mutex);
			iot_os_timer_destroy(&timer);
			c->thread = NULL;
			iot_os_thread_delete(NULL);
		}

		iot_os_mutex_unlock(&c->mutex);
		iot_os_thread_yield();
	}
}


int MQTTStartTask(MQTTClient *client)
{
	return iot_os_thread_create(MQTTRun, "MQTTTask",
			IOT_MQTT_STACK_SIZE, (void *)client, IOT_MQTT_PRIORITY,
			&client->thread);
}

void MQTTEndTask(MQTTClient *client)
{
	if (client->thread != NULL) {
		iot_os_thread_delete(client->thread);
		client->thread = NULL;
	}
}
#endif

int waitfor(MQTTClient *c, int packet_type, iot_os_timer timer)
{
	int rc = MQTT_FAILURE;

	do {
		if (iot_os_timer_isexpired(timer)) {
			break;	  // we timed out
		}

		rc = cycle(c, timer);
	} while (rc != packet_type && rc >= 0);

	return rc;
}

int MQTTConnectWithResults(MQTTClient *c, MQTTPacket_connectData *options, MQTTConnackData *data)
{
	iot_os_timer connect_timer = NULL;
	int rc = MQTT_FAILURE;
	MQTTPacket_connectData default_options = MQTTPacket_connectData_initializer;
	int len = 0;

#if defined(STDK_MQTT_TASK)
	iot_os_mutex_lock(&c->mutex);
#endif

	if (c->isconnected) { /* don't send connect packet again if we are already connected */
		goto exit;
	}

	iot_os_timer_init(&connect_timer);
	iot_os_timer_count_ms(connect_timer, c->command_timeout_ms);

	if (options == 0) {
		options = &default_options;    /* set default options if none were supplied */
	}

	c->keepAliveInterval = options->keepAliveInterval;
	c->cleansession = options->cleansession;
	iot_os_timer_count_ms(c->last_received, c->keepAliveInterval * 1000);

#if defined(CONFIG_STDK_MQTT_DYNAMIC_BUFFER)
	if (c->buf != NULL) {
		free(c->buf);
		c->buf = NULL;
	}
	c->buf_size = MQTTSerialize_connect_size(options);
	c->buf = (unsigned char *)malloc(c->buf_size);
	if (c->buf == NULL) {
		IOT_ERROR("buf malloc fail");
		goto exit;
	}
#endif
	if ((len = MQTTSerialize_connect(c->buf, c->buf_size, options)) <= 0) {
		goto exit;
	}

	if ((rc = sendPacket(c, len, connect_timer)) != MQTT_SUCCESS) { // send the connect packet
		goto exit;	  // there was a problem
	}

	// this will be a blocking call, wait for the connack
	if (waitfor(c, CONNACK, connect_timer) == CONNACK) {
		data->rc = 0;
		data->sessionPresent = 0;

		if (MQTTDeserialize_connack(&data->sessionPresent, &data->rc, c->readbuf, c->readbuf_size) == 1) {
			rc = data->rc;
		} else {
			rc = MQTT_FAILURE;
		}
#if defined(CONFIG_STDK_MQTT_DYNAMIC_BUFFER)
		free(c->readbuf);
		c->readbuf = NULL;
#endif
	} else {
		rc = MQTT_FAILURE;
	}

exit:
#if defined(CONFIG_STDK_MQTT_DYNAMIC_BUFFER)
	if (c->buf != NULL) {
		free(c->buf);
		c->buf = NULL;
	}
#endif

	if (connect_timer != NULL)
		iot_os_timer_destroy(&connect_timer);

	if (rc == MQTT_SUCCESS) {
		c->isconnected = 1;
		c->ping_outstanding = 0;
		c->ping_retry_count = 0;
	}

#if defined(STDK_MQTT_TASK)
	iot_os_mutex_unlock(&c->mutex);
#endif

	return rc;
}


int MQTTConnect(MQTTClient *c, MQTTPacket_connectData *options)
{
	MQTTConnackData data;
	return MQTTConnectWithResults(c, options, &data);
}


int MQTTSetMessageHandler(MQTTClient *c, const char *topicFilter, messageHandler messageHandler, void *userData)
{
	int rc = MQTT_FAILURE;
	int i = -1;

	/* first check for an existing matching slot */
	for (i = 0; i < MAX_MESSAGE_HANDLERS; ++i) {
		if (c->messageHandlers[i].topicFilter != NULL && strcmp(c->messageHandlers[i].topicFilter, topicFilter) == 0) {
			if (messageHandler == NULL) { /* remove existing */
				c->messageHandlers[i].topicFilter = NULL;
				c->messageHandlers[i].fp = NULL;
				c->messageHandlers[i].userData = userData;
			}

			rc = MQTT_SUCCESS; /* return i when adding new subscription */
			break;
		}
	}

	/* if no existing, look for empty slot (unless we are removing) */
	if (messageHandler != NULL) {
		if (rc == MQTT_FAILURE) {
			for (i = 0; i < MAX_MESSAGE_HANDLERS; ++i) {
				if (c->messageHandlers[i].topicFilter == NULL) {
					rc = MQTT_SUCCESS;
					break;
				}
			}
		}

		if (i < MAX_MESSAGE_HANDLERS) {
			c->messageHandlers[i].topicFilter = topicFilter;
			c->messageHandlers[i].fp = messageHandler;
			c->messageHandlers[i].userData = userData;
		}
	}

	return rc;
}


int MQTTSubscribeWithResults(MQTTClient *c, const char *topicFilter, enum QoS qos,
							 messageHandler messageHandler, MQTTSubackData *data, void *userData)
{
	int rc = MQTT_FAILURE;
	iot_os_timer timer = NULL;
	int len = 0;
	MQTTString topic = MQTTString_initializer;
	topic.cstring = (char *)topicFilter;

#if defined(STDK_MQTT_TASK)
	iot_os_mutex_lock(&c->mutex);
#endif

	if (!c->isconnected) {
		rc = MQTT_DISCONNECTED;
		goto exit;
	}

	iot_os_timer_init(&timer);
	iot_os_timer_count_ms(timer, c->command_timeout_ms);

#if defined(CONFIG_STDK_MQTT_DYNAMIC_BUFFER)
	if (c->buf != NULL) {
		free(c->buf);
		c->buf = NULL;
	}
	c->buf_size = MQTTSerialize_subscribe_size(1, &topic);
	c->buf = (unsigned char *)malloc(c->buf_size);
	if (c->buf == NULL) {
		IOT_ERROR("buf malloc fail");
		goto exit;
	}
#endif
	len = MQTTSerialize_subscribe(c->buf, c->buf_size, 0, getNextPacketId(c), 1, &topic, (int *)&qos);

	if (len <= 0) {
		goto exit;
	}

	if ((rc = sendPacket(c, len, timer)) != MQTT_SUCCESS) { // send the subscribe packet
		goto exit;	  // there was a problem
	}

	if (waitfor(c, SUBACK, timer) == SUBACK) {	  // wait for suback
		int count = 0;
		unsigned short mypacketid;
		data->grantedQoS = QOS0;

		if (MQTTDeserialize_suback(&mypacketid, 1, &count, (int *)&data->grantedQoS, c->readbuf, c->readbuf_size) == 1) {
			if (data->grantedQoS != 0x80) {
				rc = MQTTSetMessageHandler(c, topicFilter, messageHandler, userData);
			}
		}
#if defined(CONFIG_STDK_MQTT_DYNAMIC_BUFFER)
		free(c->readbuf);
		c->readbuf = NULL;
#endif
	} else {
		rc = MQTT_FAILURE;
	}

exit:
#if defined(CONFIG_STDK_MQTT_DYNAMIC_BUFFER)
	if (c->buf != NULL) {
		free(c->buf);
		c->buf = NULL;
	}
#endif
	if (timer != NULL)
		iot_os_timer_destroy(&timer);

	if (rc == MQTT_FAILURE) {
		IOT_WARN("mqtt subscribe fail");
		MQTTCloseSession(c);
	}

#if defined(STDK_MQTT_TASK)
	iot_os_mutex_unlock(&c->mutex);
#endif
	return rc;
}


int MQTTSubscribe(MQTTClient *c, const char *topicFilter, enum QoS qos,
				  messageHandler messageHandler, void *userData)
{
	MQTTSubackData data;
	return MQTTSubscribeWithResults(c, topicFilter, qos, messageHandler, &data, userData);
}


int MQTTUnsubscribe(MQTTClient *c, const char *topicFilter)
{
	int rc = MQTT_FAILURE;
	iot_os_timer timer = NULL;
	MQTTString topic = MQTTString_initializer;
	topic.cstring = (char *)topicFilter;
	int len = 0;

#if defined(STDK_MQTT_TASK)
	iot_os_mutex_lock(&c->mutex);
#endif

	if (!c->isconnected) {
		rc = MQTT_DISCONNECTED;
		goto exit;
	}

	iot_os_timer_init(&timer);
	iot_os_timer_count_ms(timer, c->command_timeout_ms);

#if defined(CONFIG_STDK_MQTT_DYNAMIC_BUFFER)
	if (c->buf != NULL) {
		free(c->buf);
		c->buf = NULL;
	}
	c->buf_size = MQTTSerialize_unsubscribe_size(1, &topic);
	c->buf = (unsigned char *)malloc(c->buf_size);
	if (c->buf == NULL) {
		IOT_ERROR("buf malloc fail");
		goto exit;
	}
#endif
	if ((len = MQTTSerialize_unsubscribe(c->buf, c->buf_size, 0, getNextPacketId(c), 1, &topic)) <= 0) {
		goto exit;
	}

	if ((rc = sendPacket(c, len, timer)) != MQTT_SUCCESS) { // send the subscribe packet
		goto exit;	  // there was a problem
	}

	if (waitfor(c, UNSUBACK, timer) == UNSUBACK) {
		unsigned short mypacketid;	// should be the same as the packetid above

		if (MQTTDeserialize_unsuback(&mypacketid, c->readbuf, c->readbuf_size) == 1) {
			/* remove the subscription message handler associated with this topic, if there is one */
			MQTTSetMessageHandler(c, topicFilter, NULL, NULL);
		}
#if defined(CONFIG_STDK_MQTT_DYNAMIC_BUFFER)
		free(c->readbuf);
		c->readbuf = NULL;
#endif
	} else {
		rc = MQTT_FAILURE;
	}

exit:
#if defined(CONFIG_STDK_MQTT_DYNAMIC_BUFFER)
	if (c->buf != NULL) {
		free(c->buf);
		c->buf = NULL;
	}
#endif
	if (timer != NULL)
		iot_os_timer_destroy(&timer);

	if (rc == MQTT_FAILURE) {
		IOT_WARN("mqtt unsubscribe fail");
		MQTTCloseSession(c);
	}

#if defined(STDK_MQTT_TASK)
	iot_os_mutex_unlock(&c->mutex);
#endif
	return rc;
}


int MQTTPublish(MQTTClient *c, const char *topicName, MQTTMessage *message)
{
	int rc = MQTT_FAILURE;
	iot_os_timer timer = NULL;
	MQTTString topic = MQTTString_initializer;
	topic.cstring = (char *)topicName;
	int len = 0;

#if defined(STDK_MQTT_TASK)
	iot_os_mutex_lock(&c->mutex);
#endif

	if (!c->isconnected) {
		rc = MQTT_DISCONNECTED;
		goto exit;
	}

	iot_os_timer_init(&timer);
	iot_os_timer_count_ms(timer, c->command_timeout_ms);

	if (message->qos == QOS1 || message->qos == QOS2) {
		message->id = getNextPacketId(c);
	}

	int retry = 0;
	do {
		iot_os_timer_count_ms(timer, c->command_timeout_ms);
		if (retry)
			IOT_WARN("mqtt publish retry(%d)", retry);
		retry++;
#if defined(CONFIG_STDK_MQTT_DYNAMIC_BUFFER)
		if (c->buf != NULL) {
			free(c->buf);
			c->buf = NULL;
		}
		/* First, send MQTT Connect header */
		c->buf_size = MQTTSerialize_publish_size(message->qos, topic, message->payloadlen) - message->payloadlen;
		c->buf = (unsigned char *)malloc(c->buf_size);
		if (c->buf == NULL) {
			IOT_ERROR("buf malloc fail");
			goto exit;
		}
		len = MQTTSerialize_publish_header(c->buf, 0, message->qos, message->retained, message->id,
									topic, message->payloadlen);
		if (len <= 0) {
			goto exit;
		}
		if ((rc = sendPacket(c, len, timer)) != MQTT_SUCCESS) { // send the subscribe packet
			goto exit;	  // there was a problem
		}
		free(c->buf);
		/* Second, send application payload itself(no-copy) */
		c->buf = message->payload;
		len = message->payloadlen;
		rc = sendPacket(c, len, timer);
		c->buf = NULL;
		if (rc != MQTT_SUCCESS) { // send the subscribe packet
			goto exit;	  // there was a problem
		}
#else
		len = MQTTSerialize_publish(c->buf, c->buf_size, 0, message->qos, message->retained, message->id,
									topic, (unsigned char *)message->payload, message->payloadlen);

		if (len <= 0) {
			goto exit;
		}
		if ((rc = sendPacket(c, len, timer)) != MQTT_SUCCESS) { // send the subscribe packet
			goto exit;	  // there was a problem
		}
#endif

		if (message->qos == QOS1) {
			if (waitfor(c, PUBACK, timer) == PUBACK) {
				unsigned short mypacketid;
				unsigned char dup, type;

				if (MQTTDeserialize_ack(&type, &dup, &mypacketid, c->readbuf, c->readbuf_size) != 1) {
					rc = MQTT_FAILURE;
				}
#if defined(CONFIG_STDK_MQTT_DYNAMIC_BUFFER)
				if (c->readbuf != NULL) {
					free(c->readbuf);
					c->readbuf = NULL;
				}
#endif
			} else {
				rc = MQTT_FAILURE;
			}
		} else if (message->qos == QOS2) {
			if (waitfor(c, PUBCOMP, timer) == PUBCOMP) {
				unsigned short mypacketid;
				unsigned char dup, type;

				if (MQTTDeserialize_ack(&type, &dup, &mypacketid, c->readbuf, c->readbuf_size) != 1) {
					rc = MQTT_FAILURE;
				}
#if defined(CONFIG_STDK_MQTT_DYNAMIC_BUFFER)
				free(c->readbuf);
				c->readbuf = NULL;
#endif
			} else {
				rc = MQTT_FAILURE;
			}
		}
	} while (rc != MQTT_SUCCESS && retry < CONFIG_STDK_MQTT_PUBLISH_RETRY);

exit:
#if defined(CONFIG_STDK_MQTT_DYNAMIC_BUFFER)
	if (c->buf != NULL) {
		free(c->buf);
		c->buf = NULL;
	}
#endif
	if (timer != NULL)
		iot_os_timer_destroy(&timer);

	if (rc == MQTT_FAILURE) {
		IOT_WARN("mqtt publish fail");
		MQTTCloseSession(c);
	}

#if defined(STDK_MQTT_TASK)
	iot_os_mutex_unlock(&c->mutex);
#endif
	return rc;
}


int MQTTDisconnect(MQTTClient *c)
{
	int rc = MQTT_FAILURE;
	iot_os_timer timer = NULL;		// we might wait for incomplete incoming publishes to complete
	int len = 0;

#if defined(STDK_MQTT_TASK)
	iot_os_mutex_lock(&c->mutex);
#endif

	if (!c->isconnected) {
		rc = MQTT_DISCONNECTED;
		goto exit;
	}

	iot_os_timer_init(&timer);
	iot_os_timer_count_ms(timer, c->command_timeout_ms);

#if defined(CONFIG_STDK_MQTT_DYNAMIC_BUFFER)
	if (c->buf != NULL) {
		free(c->buf);
		c->buf = NULL;
	}
	c->buf_size = MQTTSerialize_disconnect_size();
	c->buf = (unsigned char *)malloc(c->buf_size);
	if (c->buf == NULL) {
		IOT_ERROR("buf malloc fail");
		goto exit;
	}
#endif
	len = MQTTSerialize_disconnect(c->buf, c->buf_size);

	if (len > 0) {
		rc = sendPacket(c, len, timer);    // send the disconnect packet
	}
	IOT_INFO("mqtt send disconnect");
	MQTTCloseSession(c);

exit:
#if defined(CONFIG_STDK_MQTT_DYNAMIC_BUFFER)
	if (c->buf != NULL) {
		free(c->buf);
		c->buf = NULL;
	}
#endif
	if (timer != NULL)
		iot_os_timer_destroy(&timer);

#if defined(STDK_MQTT_TASK)
	iot_os_mutex_unlock(&c->mutex);
#endif
	return rc;
}
