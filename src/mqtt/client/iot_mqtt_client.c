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
#include "iot_util.h"
#include "iot_main.h"
#include "iot_debug.h"
#include "iot_mqtt_client.h"

static void _iot_mqtt_chunk_destroy(iot_mqtt_packet_chunk_t *chunk)
{
	if (chunk && chunk->chunk_data) {
		iot_os_free(chunk->chunk_data);
	}

	if (chunk && chunk->expiry_time) {
		iot_os_timer_destroy(&chunk->expiry_time);
	}

	if (chunk) {
		iot_os_free(chunk);
	}
}

static iot_mqtt_packet_chunk_t * _iot_mqtt_chunk_create(size_t chunk_size)
{
	iot_mqtt_packet_chunk_t *chunk = NULL;
	iot_error_t iot_err;

	chunk = iot_os_malloc(sizeof(iot_mqtt_packet_chunk_t));
	if (chunk == NULL) {
		IOT_ERROR("chunk malloc fail");
		return NULL;
	}
	memset(chunk, '\0', sizeof(iot_mqtt_packet_chunk_t));

	chunk->chunk_data = iot_os_malloc(chunk_size);
	if (chunk->chunk_data == NULL) {
		IOT_ERROR("chunk data malloc fail");
		iot_os_free(chunk);
		return NULL;
	}
	chunk->chunk_size = chunk_size;

	iot_err = iot_os_timer_init(&chunk->expiry_time);
	if (iot_err) {
		IOT_ERROR("fail to init chunk expiry");
		iot_os_free(chunk->chunk_data);
		iot_os_free(chunk);
		return NULL;
	}

	return chunk;
}

static int _iot_mqtt_queue_push(iot_mqtt_packet_chunk_queue_t *queue, iot_mqtt_packet_chunk_t *chunk)
{
	if((iot_os_mutex_lock(&queue->lock)) != IOT_OS_TRUE)
		return -1;

	if (queue->head == NULL || queue->tail == NULL) {
		queue->head = queue->tail = chunk;
	} else {
		queue->tail->next = chunk;
		queue->tail = chunk;
	}

	iot_os_mutex_unlock(&queue->lock);

	return 0;
}

static iot_mqtt_packet_chunk_t* _iot_mqtt_queue_pop_by_type_and_id(iot_mqtt_packet_chunk_queue_t *queue,
								int packet_type, unsigned int packet_id)
{
	iot_mqtt_packet_chunk_t *chunk = NULL, *iterator = NULL;

	if((iot_os_mutex_lock(&queue->lock)) != IOT_OS_TRUE)
		return NULL;

	if (queue->head == NULL || queue->tail == NULL) {
		chunk = NULL;
	} else if (queue->head == queue->tail) {
		if (queue->head->packet_type == packet_type && queue->head->packet_id == packet_id) {
			chunk = queue->head;
			queue->head = queue->tail = NULL;
		}
	} else {
		if (queue->head->packet_type == packet_type && queue->head->packet_id == packet_id) {
			chunk = queue->head;
			queue->head = queue->head->next;
			chunk->next = NULL;
		} else {
			iterator = queue->head;
			while (iterator->next) {
				if (iterator->next->packet_type == packet_type && iterator->next->packet_id == packet_id) {
					chunk = iterator->next;
					iterator->next = iterator->next->next;
					chunk->next = NULL;
					break;
				}
				iterator = iterator->next;
			}
		}
	}

	iot_os_mutex_unlock(&queue->lock);

	return chunk;
}

static iot_mqtt_packet_chunk_t* _iot_mqtt_queue_pop_by_expiry(iot_mqtt_packet_chunk_queue_t *queue)
{
	iot_mqtt_packet_chunk_t *chunk = NULL, *iterator = NULL;

	if((iot_os_mutex_lock(&queue->lock)) != IOT_OS_TRUE)
		return NULL;

	if (queue->head == NULL || queue->tail == NULL) {
		chunk = NULL;
	} else if (queue->head == queue->tail) {
		if (iot_os_timer_isexpired(queue->head->expiry_time)) {
			chunk = queue->head;
			queue->head = queue->tail = NULL;
		}
	} else {
		if (iot_os_timer_isexpired(queue->head->expiry_time)) {
			chunk = queue->head;
			queue->head = queue->head->next;
			chunk->next = NULL;
		} else {
			iterator = queue->head;
			while (iterator->next) {
				if (iot_os_timer_isexpired(iterator->next->expiry_time)) {
					chunk = iterator->next;
					iterator->next = iterator->next->next;
					chunk->next = NULL;
					break;
				}
				iterator = iterator->next;
			}
		}
	}

	iot_os_mutex_unlock(&queue->lock);

	return chunk;
}

static iot_mqtt_packet_chunk_t* _iot_mqtt_queue_pop(iot_mqtt_packet_chunk_queue_t *queue)
{
	iot_mqtt_packet_chunk_t *chunk = NULL;

	if((iot_os_mutex_lock(&queue->lock)) != IOT_OS_TRUE)
		return NULL;

	if (queue->head == NULL || queue->tail == NULL) {
		chunk = NULL;
	} else if (queue->head == queue->tail) {
		chunk = queue->head;
		queue->head = queue->tail = NULL;
	} else {
		chunk = queue->head;
		queue->head = queue->head->next;
		chunk->next = NULL;
	}

	iot_os_mutex_unlock(&queue->lock);

	return chunk;
}

static int _iot_mqtt_queue_init(iot_mqtt_packet_chunk_queue_t *queue)
{
	iot_os_mutex_init(&queue->lock);
	if (queue->lock.sem == NULL) {
		IOT_ERROR("fail to init queue lock");
		return -1;
	}
	queue->head = NULL;
	queue->tail = NULL;

	return 0;
}

static void _iot_mqtt_queue_destroy(iot_mqtt_packet_chunk_queue_t *queue)
{
	do {
		if (queue->lock.sem == NULL)
			return;
	} while ((iot_os_mutex_lock(&queue->lock)) != IOT_OS_TRUE);
	iot_mqtt_packet_chunk_t *iterator = queue->head, *tmp;
	while (iterator) {
		tmp = iterator;
		iterator = iterator->next;
		_iot_mqtt_chunk_destroy(tmp);
	}
	queue->head = queue->tail = NULL;
	iot_os_mutex_unlock(&queue->lock);

	if (queue->lock.sem != NULL) {
		iot_os_mutex_destroy(&queue->lock);
		queue->lock.sem = NULL;
	}
}

static void _iot_mqtt_process_post_write(MQTTClient *client, iot_mqtt_packet_chunk_t *chunk)
{
	switch(chunk->packet_type) {
		case CONNECT:
		case SUBSCRIBE:
		case UNSUBSCRIBE:
		case PUBREL:
		case PUBREC:
		case PINGREQ:
			chunk->chunk_state = PACKET_CHUNK_ACK_PENDING;
			iot_os_timer_count_ms(chunk->expiry_time, client->command_timeout_ms);
			_iot_mqtt_queue_push(&client->ack_pending_queue, chunk);
			break;
		case PUBLISH:
			if (chunk->qos == 0) {
				chunk->chunk_state = PACKET_CHUNK_WRITE_COMPLETED;
				if (!chunk->have_owner) {
					_iot_mqtt_chunk_destroy(chunk);
				}
			} else {
				chunk->chunk_state = PACKET_CHUNK_ACK_PENDING;
				iot_os_timer_count_ms(chunk->expiry_time, client->command_timeout_ms);
				_iot_mqtt_queue_push(&client->ack_pending_queue, chunk);
			}
			break;
		default:
			_iot_mqtt_chunk_destroy(chunk);
			break;;
	}
}

static int _iot_mqtt_run_write_stream(MQTTClient *client)
{
	int rc = 0, written = 0;
	iot_error_t iot_err;
	iot_mqtt_packet_chunk_t *w_chunk = NULL;
	iot_os_timer expiry_timer = NULL;

	if (client == NULL || client->magic != MQTT_CLIENT_STRUCT_MAGIC_NUMBER) {
		return E_ST_MQTT_FAILURE;
	}

	if((iot_os_mutex_lock(&client->write_lock)) != IOT_OS_TRUE) {
		return 0;
	}

	w_chunk = _iot_mqtt_queue_pop(&client->write_pending_queue);
	if (w_chunk == NULL) {
		goto exit;
	} else {
		iot_err = iot_os_timer_init(&expiry_timer);
		if (iot_err) {
			IOT_ERROR("fail to init timer");
			written = E_ST_MQTT_BUFFER_OVERFLOW;
			goto exit;
		}
		iot_os_timer_count_ms(expiry_timer, MQTT_WRITE_TIMEOUT);
	}

	if(!client->isconnected) {
		written = E_ST_MQTT_DISCONNECTED;
		goto exit;
	}

	while (!iot_os_timer_isexpired(expiry_timer)) {
		rc = client->net->write(client->net, &w_chunk->chunk_data[written],
				w_chunk->chunk_size - written, expiry_timer);

		if (rc > 0) {
			written += rc;
			iot_os_timer_count_ms(expiry_timer, MQTT_WRITE_TIMEOUT);
		} else if (rc < 0) {
			written = E_ST_MQTT_NETWORK_ERROR;
			goto exit;
		}

		if (written == w_chunk->chunk_size) {
			_iot_mqtt_process_post_write(client, w_chunk);
			break;
		}
	}

	if (written != w_chunk->chunk_size) {
		written = E_ST_MQTT_NETWORK_ERROR;
		goto exit;
	}

exit:
	iot_os_mutex_unlock(&client->write_lock);

	if (expiry_timer) {
		iot_os_timer_destroy(&expiry_timer);
	}

	if (written < 0) {
		w_chunk->chunk_state = PACKET_CHUNK_WRITE_FAIL;
		w_chunk->return_code = written;
		if (!w_chunk->have_owner) {
			_iot_mqtt_queue_push(&client->user_event_callback_queue, w_chunk);
		}
	}

	if (written > 0) {
		if (client != NULL && client->magic == MQTT_CLIENT_STRUCT_MAGIC_NUMBER) {
			if((iot_os_mutex_lock(&client->client_manage_lock)) == IOT_OS_TRUE) {
				iot_os_timer_count_ms(client->last_sent, client->keepAliveInterval * 1000);
				iot_os_mutex_unlock(&client->client_manage_lock);
			}
		}
	}

	return written;
}

static void _iot_mqtt_process_received_ack(MQTTClient *client, iot_mqtt_packet_chunk_t *chunk)
{
	iot_mqtt_packet_chunk_t *tmp = NULL;

	if (chunk->packet_type == CONNACK) {
		tmp = _iot_mqtt_queue_pop_by_type_and_id(&client->ack_pending_queue, CONNECT, 0);
	} else if (chunk->packet_type == PUBACK) {
		tmp = _iot_mqtt_queue_pop_by_type_and_id(&client->ack_pending_queue, PUBLISH, chunk->packet_id);
	} else if (chunk->packet_type == SUBACK) {
		tmp = _iot_mqtt_queue_pop_by_type_and_id(&client->ack_pending_queue, SUBSCRIBE, chunk->packet_id);
	} else if (chunk->packet_type == UNSUBACK) {
		tmp = _iot_mqtt_queue_pop_by_type_and_id(&client->ack_pending_queue, UNSUBSCRIBE, chunk->packet_id);
	} else if (chunk->packet_type == PUBCOMP) {
		tmp = _iot_mqtt_queue_pop_by_type_and_id(&client->ack_pending_queue, PUBREL, chunk->packet_id);
	} else if (chunk->packet_type == PINGRESP) {
		tmp = _iot_mqtt_queue_pop_by_type_and_id(&client->ack_pending_queue, PINGREQ, 0);
	} else {
		return;
	}

	if (tmp != NULL) {
		if (tmp->have_owner) {
			tmp->chunk_state = PACKET_CHUNK_ACKNOWLEDGED;
		} else {
			_iot_mqtt_chunk_destroy(tmp);
		}
	} else {
		IOT_ERROR("There is no ack packet matched");
	}
	_iot_mqtt_chunk_destroy(chunk);
}

static void _iot_mqtt_process_received_publish(MQTTClient *client, iot_mqtt_packet_chunk_t *chunk)
{
	// Send Ack back
	if (chunk->qos != st_mqtt_qos0) {
		iot_mqtt_packet_chunk_t *puback;
		puback = _iot_mqtt_chunk_create(MQTT_ACK_PACKET_SIZE);
		if (puback == NULL) {
			IOT_ERROR("chunk malloc fail");
			_iot_mqtt_chunk_destroy(chunk);
			return;
		}

		puback->packet_id = chunk->packet_id;
		if (chunk->qos == st_mqtt_qos1) {
			puback->packet_type = PUBACK;
			MQTTSerialize_ack(puback->chunk_data, puback->chunk_size, PUBACK, 0, puback->packet_id);
		} else if (chunk->qos == st_mqtt_qos2) {
			puback->packet_type = PUBREC;
			MQTTSerialize_ack(puback->chunk_data, puback->chunk_size, PUBREC, 0, puback->packet_id);
		}
		puback->chunk_state = PACKET_CHUNK_WRITE_PENDING;
		_iot_mqtt_queue_push(&client->write_pending_queue, puback);
	}

	_iot_mqtt_queue_push(&client->user_event_callback_queue, chunk);
}

static void _iot_mqtt_process_received_pubrec_pubrel(MQTTClient *client, iot_mqtt_packet_chunk_t *chunk)
{
	iot_mqtt_packet_chunk_t *tmp = NULL;

	if (chunk->packet_type == PUBREC) {
		tmp = _iot_mqtt_queue_pop_by_type_and_id(&client->ack_pending_queue, PUBLISH, chunk->packet_id);
	} else if (chunk->packet_type == PUBREL) {
		tmp = _iot_mqtt_queue_pop_by_type_and_id(&client->ack_pending_queue, PUBREC, chunk->packet_id);
	} else {
		return;
	}
	_iot_mqtt_chunk_destroy(chunk);

	// Recycling packet
	if (tmp != NULL) {
		iot_os_free(tmp->chunk_data);
		tmp->chunk_data = NULL;

		tmp->chunk_size = MQTT_ACK_PACKET_SIZE;
		tmp->chunk_data = iot_os_malloc(tmp->chunk_size);
		if (tmp->chunk_data == NULL) {
			IOT_ERROR("chunk data malloc fail");
			_iot_mqtt_chunk_destroy(tmp);
			return;
		}
		if (tmp->packet_type == PUBLISH) {
			tmp->packet_type = PUBREL;
			MQTTSerialize_ack(tmp->chunk_data, tmp->chunk_size, PUBREL, 0, tmp->packet_id);
		} else if (tmp->packet_type == PUBREC) {
			tmp->packet_type = PUBCOMP;
			MQTTSerialize_ack(tmp->chunk_data, tmp->chunk_size, PUBCOMP, 0, tmp->packet_id);
		}
		tmp->chunk_state = PACKET_CHUNK_WRITE_PENDING;
		_iot_mqtt_queue_push(&client->write_pending_queue, tmp);
	} else {
		IOT_ERROR("There is no ack packet matched");
	}
}

static void _iot_mqtt_process_post_read(MQTTClient *client, iot_mqtt_packet_chunk_t *chunk)
{
	switch (chunk->packet_type) {
		case CONNACK:
		case PUBACK:
		case SUBACK:
		case UNSUBACK:
		case PUBCOMP:
		case PINGRESP:
			_iot_mqtt_process_received_ack(client, chunk);
			_iot_mqtt_chunk_destroy(chunk);
			break;
		case PUBLISH:
			_iot_mqtt_process_received_publish(client, chunk);
			break;
		case PUBREC:
		case PUBREL:
			_iot_mqtt_process_received_pubrec_pubrel(client, chunk);
			break;
	}
}

static int _iot_mqtt_run_read_stream(MQTTClient *client)
{
	int rc = 0 , read = 0;
	iot_mqtt_packet_chunk_t *w_chunk = NULL;
	iot_error_t iot_err;
	iot_os_timer expiry_timer = NULL;
	unsigned char packet_fixed_header[MAX_NUM_OF_REMAINING_LENGTH_BYTES + 1];
	int rem_size = 0;

	if (client == NULL || client->magic != MQTT_CLIENT_STRUCT_MAGIC_NUMBER) {
		return E_ST_MQTT_FAILURE;
	}

	if((iot_os_mutex_lock(&client->read_lock)) != IOT_OS_TRUE) {
		return 0;
	}
	if(!client->isconnected) {
		read = E_ST_MQTT_DISCONNECTED;
		goto exit;
	}

	rc = client->net->select(client->net, 0);
	if (rc < 0) {
		read = E_ST_MQTT_NETWORK_ERROR;
		goto exit;
	} else if (rc == 0) {
		goto exit;
	} else {
		iot_err = iot_os_timer_init(&expiry_timer);
		if (iot_err) {
			IOT_ERROR("fail to init timer");
			read = E_ST_MQTT_BUFFER_OVERFLOW;
			goto exit;
		}
		iot_os_timer_count_ms(expiry_timer, MQTT_READ_TIMEOUT);
	}

	rc = client->net->read(client->net, &packet_fixed_header[0], 1, expiry_timer);
	if (rc <= 0) {
		read = E_ST_MQTT_NETWORK_ERROR;
		goto exit;
	}
	read++;
	do {
		if (read - 1 >= MAX_NUM_OF_REMAINING_LENGTH_BYTES) {
			read = E_ST_MQTT_NETWORK_ERROR;
			goto exit;
		}
		rc = client->net->read(client->net, &packet_fixed_header[read], 1, expiry_timer);
		if (rc <= 0) {
			read = E_ST_MQTT_NETWORK_ERROR;
			goto exit;
		}
		read++;
	} while ((packet_fixed_header[read - 1] & 128) != 0);

	MQTTPacket_decodeBuf(&packet_fixed_header[1], &rem_size);
	w_chunk = _iot_mqtt_chunk_create(read + rem_size);
	if (w_chunk) {
		IOT_ERROR("chunk malloc fail");
		read = E_ST_MQTT_BUFFER_OVERFLOW;
		goto exit;
	}
	memcpy(w_chunk->chunk_data, packet_fixed_header, read);

	while (!iot_os_timer_isexpired(expiry_timer)) {
		rc = client->net->read(client->net, w_chunk->chunk_data + read,
				w_chunk->chunk_size - read, expiry_timer);
		if (rc < 0) {
			read = E_ST_MQTT_NETWORK_ERROR;
			goto exit;
		} else {
			read += rc;
			iot_os_timer_count_ms(expiry_timer, MQTT_READ_TIMEOUT);
		}

		if (read == w_chunk->chunk_size) {
			w_chunk->chunk_state = PACKET_CHUNK_READ_COMPLETED;
			w_chunk->packet_type = (w_chunk->chunk_data[0] & 0xf0) >> 4;
			w_chunk->qos = (w_chunk->chunk_data[0] & 0x06) >> 1;
			w_chunk->packet_id = MQTTPacket_getPacketId(w_chunk->chunk_data);
			_iot_mqtt_process_post_read(client, w_chunk);
			break;
		}
	}

	if (read != w_chunk->chunk_size) {
		read = E_ST_MQTT_NETWORK_ERROR;
		goto exit;
	}

exit:
	iot_os_mutex_unlock(&client->read_lock);

	if (expiry_timer) {
		iot_os_timer_destroy(&expiry_timer);
	}

	if (read < 0 && w_chunk != NULL) {
		_iot_mqtt_chunk_destroy(w_chunk);
	}

	if (read > 0) {
		if (client != NULL && client->magic == MQTT_CLIENT_STRUCT_MAGIC_NUMBER) {
			if((iot_os_mutex_lock(&client->client_manage_lock)) == IOT_OS_TRUE) {
				iot_os_timer_count_ms(client->last_received, client->keepAliveInterval * 1000);
				iot_os_mutex_unlock(&client->client_manage_lock);
			}
		}
	}

	return read;
}

static int getNextPacketId(MQTTClient *c)
{
	return c->next_packetid = (c->next_packetid == MAX_PACKET_ID) ? 1 : c->next_packetid + 1;
}

static int sendPacket(MQTTClient *c, unsigned char *buf, int length, iot_os_timer timer)
{
	int rc = E_ST_MQTT_FAILURE, sent = 0;

	while (sent < length && !iot_os_timer_isexpired(timer)) {
		rc = c->net->write(c->net, &buf[sent], length, timer);

		if (rc < 0) { // there was an error writing the data
			break;
		}

		sent += rc;
	}

	if (sent == length) {
		iot_os_timer_count_ms(c->last_sent, c->keepAliveInterval * 1000); // record the fact that we have successfully sent the packet
		rc = 0;
	} else {
		IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_MQTT_SEND_FAIL, rc, 0);
		rc = E_ST_MQTT_FAILURE;
	}

	return rc;
}

int st_mqtt_create(st_mqtt_client *client, unsigned int command_timeout_ms)
{
	int i;
	MQTTClient *c = NULL;
	int rc = E_ST_MQTT_FAILURE;
	iot_error_t iot_err;

	*client = iot_os_malloc(sizeof(MQTTClient));
	if (*client == NULL) {
		IOT_ERROR("buf malloc fail");
		goto error_handle;
	}
	memset(*client, '\0', sizeof(MQTTClient));

	c = *client;
	c->magic = MQTT_CLIENT_STRUCT_MAGIC_NUMBER;

	for (i = 0; i < MAX_MESSAGE_HANDLERS; ++i) {
		c->messageHandlers[i].topicFilter = 0;
	}

	if (command_timeout_ms != 0) {
		c->command_timeout_ms = command_timeout_ms;
	} else {
		c->command_timeout_ms = DEFAULT_COMMNAD_TIMEOUT;
	}

	c->net = iot_os_malloc(sizeof(iot_net_interface_t));
	if (c->net == NULL) {
		IOT_ERROR("buf malloc fail");
		goto error_handle;
	}
	memset(c->net, '\0', sizeof(iot_net_interface_t));
	c->readbuf = NULL;
	c->readbuf_size = 0;
	c->isconnected = 0;
	c->cleansession = 0;
	c->ping_outstanding = 0;
	c->ping_retry_count = 0;
	c->defaultMessageHandler = NULL;
	c->defaultUserData = NULL;
	c->next_packetid = 1;
	iot_err = iot_os_timer_init(&c->last_sent);
	if (iot_err) {
		IOT_ERROR("fail to init last_send timer");
		goto error_handle;
	}
	iot_err = iot_os_timer_init(&c->last_received);
	if (iot_err) {
		IOT_ERROR("fail to init last_received timer");
		goto error_handle;
	}
	iot_err = iot_os_timer_init(&c->ping_wait);
	if (iot_err) {
		IOT_ERROR("fail to init ping_wait timer");
		goto error_handle;
	}
	iot_os_mutex_init(&c->mutex);
	if (c->mutex.sem == NULL) {
		IOT_ERROR("fail to init mutex");
		goto error_handle;
	}
	iot_os_mutex_init(&c->client_manage_lock);
	if (c->client_manage_lock.sem == NULL) {
		IOT_ERROR("fail to init mutex");
		goto error_handle;
	}
	c->thread = NULL;
	iot_os_mutex_init(&c->write_lock);
	if (c->write_lock.sem == NULL) {
		IOT_ERROR("fail to init write_lock");
		goto error_handle;
	}
	iot_os_mutex_init(&c->read_lock);
	if (c->read_lock.sem == NULL) {
		IOT_ERROR("fail to init read_lock");
		goto error_handle;
	}
	if ((_iot_mqtt_queue_init(&c->write_pending_queue))) {
		goto error_handle;
	}
	if ((_iot_mqtt_queue_init(&c->ack_pending_queue))) {
		goto error_handle;
	}
	if ((_iot_mqtt_queue_init(&c->user_event_callback_queue))) {
		goto error_handle;
	}
	if ((c->ping_packet = _iot_mqtt_chunk_create(MQTT_PINGREQ_PACKET_SIZE)) == NULL) {
		goto error_handle;
	}
	MQTTSerialize_pingreq(c->ping_packet->chunk_data, MQTT_PINGREQ_PACKET_SIZE);
	c->ping_packet->packet_type = PINGREQ;
	c->ping_packet->have_owner = 1;

	IOT_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_MQTT_CREATE_SUCCESS, command_timeout_ms, 0);
	return 0;
error_handle:
	if (c) {
		if (c->net)
			free(c->net);
		if (c->last_sent)
			iot_os_timer_destroy(&c->last_sent);
		if (c->last_received)
			iot_os_timer_destroy(&c->last_received);
		if (c->ping_wait)
			iot_os_timer_destroy(&c->ping_wait);
		if (c->mutex.sem)
			iot_os_mutex_destroy(&c->mutex);
		if (c->client_manage_lock.sem)
			iot_os_mutex_destroy(&c->client_manage_lock);
		if (c->write_lock.sem)
			iot_os_mutex_destroy(&c->write_lock);
		if (c->read_lock.sem)
			iot_os_mutex_destroy(&c->read_lock);
		_iot_mqtt_queue_destroy(&c->write_pending_queue);
		_iot_mqtt_queue_destroy(&c->ack_pending_queue);
		_iot_mqtt_queue_destroy(&c->user_event_callback_queue);
		if (c->ping_packet) {
			_iot_mqtt_chunk_destroy(c->ping_packet);
		}
		iot_os_free(c);
		*client = NULL;
	}
	IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_MQTT_CREATE_FAIL, rc, 0);
	return rc;
}

void MQTTCleanSession(MQTTClient *c)
{
	int i = 0;

	for (i = 0; i < MAX_MESSAGE_HANDLERS; ++i) {
		if (c->messageHandlers[i].topicFilter != NULL) {
			free(c->messageHandlers[i].topicFilter);
			c->messageHandlers[i].topicFilter = NULL;
		}
	}
}

static void _iot_mqtt_close_session(MQTTClient *c)
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
	if (c->net->disconnect != NULL)
		c->net->disconnect(c->net);
}

void st_mqtt_destroy(st_mqtt_client client)
{
	MQTTClient *c = client;

	iot_os_mutex_lock(&c->mutex);
	if (c->isconnected) {
		_iot_mqtt_close_session(c);
	}
	iot_os_free(c->net);

	iot_os_timer_destroy(&c->last_sent);
	iot_os_timer_destroy(&c->last_received);
	iot_os_timer_destroy(&c->ping_wait);
	iot_os_mutex_unlock(&c->mutex);

	iot_os_mutex_destroy(&c->mutex);
	iot_os_mutex_destroy(&c->write_lock);
	iot_os_mutex_destroy(&c->read_lock);
	iot_os_mutex_destroy(&c->client_manage_lock);
	c->client_manage_lock.sem = NULL;
	_iot_mqtt_queue_destroy(&c->write_pending_queue);
	_iot_mqtt_queue_destroy(&c->ack_pending_queue);
	_iot_mqtt_queue_destroy(&c->user_event_callback_queue);
	if (c->ping_packet) {
		_iot_mqtt_chunk_destroy(c->ping_packet);
	}
	c->magic = 0;
	iot_os_free(c);
	IOT_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_MQTT_DESTROY, 0, 0);
}

static int decodePacket(MQTTClient *c, int *value, iot_os_timer timer)
{
	unsigned char i;
	int multiplier = 1;
	int len = 0;

	*value = 0;

	do {
		int rc = MQTTPACKET_READ_ERROR;

		if (++len > MAX_NUM_OF_REMAINING_LENGTH_BYTES) {
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
	unsigned char i;

	/* 1. read the header byte.  This has the packet type in it */
	int rc = c->net->read(c->net, &i, 1, timer);
	if (rc != 1) {
		goto exit;
	}
	len = 1;

	/* 2. read the remaining length.  This is variable in itself */
	decodePacket(c, &rem_len, timer);
	if (c->readbuf != NULL) {
		free(c->readbuf);
		c->readbuf = NULL;
	}
	c->readbuf_size = 5 + rem_len;
	c->readbuf = (unsigned char *)malloc(c->readbuf_size);
	if (c->readbuf == NULL) {
		IOT_ERROR("buf malloc failed");
		rc = E_ST_MQTT_BUFFER_OVERFLOW;
		goto exit;
	}

	c->readbuf[0] = i;
	len += MQTTPacket_encode(c->readbuf + 1, rem_len); /* put the original remaining length back into the buffer */

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


int deliverMessage(MQTTClient *c, st_mqtt_msg *message)
{
	int i;
	int rc = E_ST_MQTT_FAILURE;
	MQTTString topic;
	topic.cstring = NULL;
	topic.lenstring.data = message->topic;
	topic.lenstring.len = message->topiclen;

	// we have to find the right message handler - indexed by topic
	for (i = 0; i < MAX_MESSAGE_HANDLERS; ++i) {
		if (c->messageHandlers[i].topicFilter != 0 && (MQTTPacket_equals(&topic, (char *)c->messageHandlers[i].topicFilter) ||
				isTopicMatched((char *)c->messageHandlers[i].topicFilter, &topic))) {
			if (c->messageHandlers[i].fp != NULL) {
				c->messageHandlers[i].fp(message, c->messageHandlers[i].userData);
				rc = 0;
			}
		}
	}

	if (rc == E_ST_MQTT_FAILURE && c->defaultMessageHandler != NULL) {
		c->defaultMessageHandler(message, c->defaultUserData);
		rc = 0;
	}

	return rc;
}

static int _iot_mqtt_check_alive(MQTTClient *client)
{
	int rc = 0;

	if (client == NULL || client->magic != MQTT_CLIENT_STRUCT_MAGIC_NUMBER) {
		return E_ST_MQTT_FAILURE;
	}

	if((iot_os_mutex_lock(&client->client_manage_lock)) != IOT_OS_TRUE) {
		return E_ST_MQTT_FAILURE;
	}
	if (iot_os_timer_isexpired(client->last_sent) || iot_os_timer_isexpired(client->last_received)) {
		switch (client->ping_packet->chunk_state) {
			case PACKET_CHUNK_ACKNOWLEDGED :
			case PACKET_CHUNK_INIT :
				client->ping_packet->chunk_state = PACKET_CHUNK_WRITE_PENDING;
				client->ping_packet->retry_count = 0;
				_iot_mqtt_queue_push(&client->write_pending_queue, client->ping_packet);
				break;
			case PACKET_CHUNK_TIMEOUT:
				client->ping_packet->chunk_state = PACKET_CHUNK_INIT;
				IOT_WARN("mqtt didn't get PINGRESP");
				rc = E_ST_MQTT_FAILURE;
				goto exit;
			default:
				break;
		}
	}

exit:
	iot_os_mutex_unlock(&client->client_manage_lock);

	return rc;
}

int keepalive(MQTTClient *c)
{
	int rc = 0;
	unsigned char pbuf[MQTT_PINGREQ_MAX_SIZE];
	iot_error_t iot_err;

	if (c->keepAliveInterval == 0) {
		goto exit;
	}

	if (c->ping_outstanding && iot_os_timer_isexpired(c->ping_wait) && c->ping_retry_count >= MQTT_PING_RETRY) {
		IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_MQTT_PING_FAIL, 0, 0);
		IOT_WARN("mqtt didn't get PINGRESP");
		rc = E_ST_MQTT_FAILURE; /* PINGRESP not received in keepalive interval */
	/* Send ping request when there is no ping response up to 3 times or ping period expired */
	} else if ((c->ping_outstanding && iot_os_timer_isexpired(c->ping_wait) && c->ping_retry_count < MQTT_PING_RETRY) ||
			(!c->ping_outstanding && (iot_os_timer_isexpired(c->last_sent) || iot_os_timer_isexpired(c->last_received)))) {
		iot_os_timer timer;
		iot_err = iot_os_timer_init(&timer);
		if (iot_err) {
			IOT_ERROR("fail to init timer");
			rc = E_ST_MQTT_FAILURE;
			goto exit;
		}
		iot_os_timer_count_ms(timer, c->command_timeout_ms);
		int len = MQTTSerialize_pingreq(pbuf, MQTT_PINGREQ_MAX_SIZE);

		if (len > 0 && !(rc = sendPacket(c, pbuf, len, timer))) { // send the ping packet
			c->ping_outstanding = 1;
			c->ping_retry_count++;
			iot_os_timer_count_ms(c->ping_wait, c->command_timeout_ms);
		}
		iot_os_timer_destroy(&timer);
	}

exit:
	return rc;
}

static void _iot_mqtt_process_pending_packets(MQTTClient *client)
{
	iot_mqtt_packet_chunk_t *w_chunk = NULL;

	while (1) {
		if (client == NULL || client->magic != MQTT_CLIENT_STRUCT_MAGIC_NUMBER) {
			return;
		}
		w_chunk = _iot_mqtt_queue_pop_by_expiry(&client->ack_pending_queue);
		if (w_chunk == NULL) {
			return;
		}
		w_chunk->retry_count++;
		if (w_chunk->retry_count < MQTT_PUBLISH_RETRY) {
			w_chunk->chunk_state = PACKET_CHUNK_WRITE_PENDING;
			if (client != NULL && client->magic == MQTT_CLIENT_STRUCT_MAGIC_NUMBER) {
				_iot_mqtt_queue_push(&client->write_pending_queue, w_chunk);
			} else {
				_iot_mqtt_chunk_destroy(w_chunk);
			}
		} else {
			w_chunk->chunk_state = PACKET_CHUNK_TIMEOUT;
			if (!w_chunk->have_owner) {
				if (client != NULL && client->magic == MQTT_CLIENT_STRUCT_MAGIC_NUMBER) {
					_iot_mqtt_queue_push(&client->user_event_callback_queue, w_chunk);
				} else {
					_iot_mqtt_chunk_destroy(w_chunk);
				}
			}
		}
	}
}

static void _iot_mqtt_deliver_publish(MQTTClient *client, iot_mqtt_packet_chunk_t *chunk)
{
	MQTTString topicName;
	st_mqtt_msg msg;
	int qos;
	unsigned char dup;
	unsigned short id;

	if (MQTTDeserialize_publish(&dup, &qos, &msg.retained, &id, &topicName,
							(unsigned char **)&msg.payload, (int *)&msg.payloadlen, chunk->chunk_data, chunk->chunk_size) != 1) {
		return;
	}

	msg.qos = qos;
	msg.topic = topicName.lenstring.data;
	msg.topiclen = topicName.lenstring.len;
	deliverMessage(client, &msg);
}

static void _iot_mqtt_process_user_callback(MQTTClient *client)
{
	iot_mqtt_packet_chunk_t *w_chunk = NULL;

	while (1) {
		if (client == NULL || client->magic != MQTT_CLIENT_STRUCT_MAGIC_NUMBER) {
			return;
		}
		w_chunk = _iot_mqtt_queue_pop(&client->user_event_callback_queue);
		if (w_chunk == NULL) {
			return;
		}
		switch (w_chunk->chunk_state) {
			case PACKET_CHUNK_TIMEOUT:
			case PACKET_CHUNK_WRITE_FAIL:
					/* TODO callback fail */
			case PACKET_CHUNK_READ_COMPLETED:
				if (w_chunk->packet_type == PUBLISH) {
					_iot_mqtt_deliver_publish(client, w_chunk);
				}
			default :
				break;
		}
		_iot_mqtt_chunk_destroy(w_chunk);
	}
}

static int _iot_mqtt_run_cycle(MQTTClient *client)
{
	int rc = 0;

	rc = _iot_mqtt_run_write_stream(client);
	if (rc < 0)
		return rc;

	rc = _iot_mqtt_run_read_stream(client);
	if (rc < 0)
		return rc;

	_iot_mqtt_process_pending_packets(client);

	rc = _iot_mqtt_check_alive(client);
	if (rc < 0)
		return rc;

	return rc;
}

int cycle(MQTTClient *c, iot_os_timer timer)
{
	int len = 0, rc = 0;

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
		st_mqtt_msg msg;
		int intQoS;
		unsigned char dup;
		unsigned short id;
		msg.payloadlen = 0; /* this is a size_t, but deserialize publish sets this as int */

		if (MQTTDeserialize_publish(&dup, &intQoS, &msg.retained, &id, &topicName,
									(unsigned char **)&msg.payload, (int *)&msg.payloadlen, c->readbuf, c->readbuf_size) != 1) {
			goto exit;
		}

		msg.qos = intQoS;
		msg.topic = topicName.lenstring.data;
		msg.topiclen = topicName.lenstring.len;
		deliverMessage(c, &msg);
		if (c->readbuf != NULL) {
			free(c->readbuf);
			c->readbuf = NULL;
		}
		if (msg.qos != st_mqtt_qos0) {
			unsigned char pbuf[MQTT_PUBACK_MAX_SIZE];
			if (msg.qos == st_mqtt_qos1) {
				len = MQTTSerialize_ack(pbuf, MQTT_PUBACK_MAX_SIZE, PUBACK, 0, id);
			} else if (msg.qos == st_mqtt_qos2) {
				len = MQTTSerialize_ack(pbuf, MQTT_PUBACK_MAX_SIZE, PUBREC, 0, id);
			}

			if (len <= 0) {
				rc = E_ST_MQTT_FAILURE;
			} else {
				rc = sendPacket(c, pbuf, len, timer);
			}
			if (rc == E_ST_MQTT_FAILURE) {
				goto exit;	  // there was a problem
			}
		}

		break;
	}

	case PUBREC:
	case PUBREL: {
		unsigned short mypacketid;
		unsigned char dup, type;
		unsigned char pbuf[MQTT_PUBACK_MAX_SIZE];

		if (MQTTDeserialize_ack(&type, &dup, &mypacketid, c->readbuf, c->readbuf_size) != 1) {
			rc = E_ST_MQTT_FAILURE;
		} else if ((len = MQTTSerialize_ack(pbuf, MQTT_PUBACK_MAX_SIZE,
											(packet_type == PUBREC) ? PUBREL : PUBCOMP, 0, mypacketid)) <= 0) {
			rc = E_ST_MQTT_FAILURE;
		} else if ((rc = sendPacket(c, pbuf, len, timer))) { // send the PUBREL packet
			rc = E_ST_MQTT_FAILURE;	 // there was a problem
		}
		free(c->readbuf);
		c->readbuf = NULL;
		if (rc == E_ST_MQTT_FAILURE) {
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

	if (keepalive(c)) {
		//check only keepalive MQTT_FAILURE status so that previous FAILURE status can be considered as FAULT
		rc = E_ST_MQTT_FAILURE;
	}

exit:
	if (!rc) {
		rc = packet_type;
	} else {
		IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_MQTT_CYCLE_FAIL, rc, packet_type);
	}

	return rc;
}

int st_mqtt_yield(st_mqtt_client client, int time)
{
	MQTTClient *c = client;
	int rc = 0;
	iot_error_t iot_err;
	iot_os_timer timer;
	int ret;

	if (!c->isconnected)
		return rc;

	iot_err = iot_os_timer_init(&timer);
	if (iot_err) {
		IOT_ERROR("fail to init timer");
		return E_ST_MQTT_FAILURE;
	}
	iot_os_timer_count_ms(timer, time);

	do {
		if ((c->net == NULL) || (c->net->select == NULL)) {
			IOT_ERROR("net->select is null");
			rc = -1;
			break;
		}

		ret = c->net->select(c->net, iot_os_timer_left_ms(timer));
		if (ret > 0) {
			iot_os_timer command_timer;
			iot_err = iot_os_timer_init(&command_timer);
			if (iot_err) {
				IOT_ERROR("fail to init command timer");
				rc = E_ST_MQTT_FAILURE;
				break;
			}
			iot_os_timer_count_ms(command_timer, c->command_timeout_ms);
			rc = cycle(c, command_timer);
			iot_os_timer_destroy(&command_timer);
		} else if (ret < 0) {
			rc = E_ST_MQTT_FAILURE;
			break;
		} else if ((rc = keepalive(c))) {
			break;
		}
	} while (!iot_os_timer_isexpired(timer));
	iot_os_timer_destroy(&timer);

	return rc;
}

void MQTTRun(void *parm)
{
	iot_os_timer timer;
	MQTTClient *c = (MQTTClient *)parm;
	iot_error_t iot_err;

	if ((c->net == NULL) || (c->net->select == NULL)) {
		IOT_ERROR("net->select is null");
		return;
	}

	iot_err = iot_os_timer_init(&timer);
	if (iot_err) {
		IOT_ERROR("fail to init timer");
		return;
	}

	while (1) {
		iot_os_timer_count_ms(timer, MQTT_TASK_CYCLE); /* Don't wait too long if no traffic is incoming */

		iot_os_mutex_lock(&c->mutex);
		if (!c->isconnected) {
			IOT_WARN("MQTTRun task exit");
			iot_os_mutex_unlock(&c->mutex);
			iot_os_timer_destroy(&timer);
			c->thread = NULL;
			iot_os_thread_delete(NULL);
		}
		int rc = 0;
		int ret = c->net->select(c->net, iot_os_timer_left_ms(timer));
		if (ret > 0) {
			iot_os_timer_count_ms(timer, c->command_timeout_ms);
			rc = cycle(c, timer);
		} else if (ret < 0) {
			rc = E_ST_MQTT_FAILURE;
		} else {
			rc = keepalive(c);
		}

		if (rc == E_ST_MQTT_FAILURE) {
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

int st_mqtt_starttask(st_mqtt_client client)
{
	MQTTClient *c = client;
	return iot_os_thread_create(MQTTRun, "MQTTTask",
			MQTT_TASK_STACK_SIZE, (void *)c, MQTT_TASK_PRIORITY,
			&c->thread);
}

void st_mqtt_endtask(st_mqtt_client client)
{
	MQTTClient *c = client;
	if (c->thread != NULL) {
		iot_os_thread_delete(c->thread);
		c->thread = NULL;
	}
}

int waitfor(MQTTClient *c, int packet_type, iot_os_timer timer)
{
	int rc = E_ST_MQTT_FAILURE;

	do {
		if (iot_os_timer_isexpired(timer)) {
			break;	  // we timed out
		}

		rc = cycle(c, timer);
	} while (rc != packet_type && rc >= 0);

	return rc;
}

static int _convert_return_code(int mqtt_rc)
{
	int rc;
	switch (mqtt_rc) {
	case MQTT_CONNECTION_ACCEPTED:
		rc = 0;
		break;
	case MQTT_UNNACCEPTABLE_PROTOCOL:
		rc = E_ST_MQTT_UNNACCEPTABLE_PROTOCOL;
		break;
	case MQTT_SERVER_UNAVAILABLE:
		rc = E_ST_MQTT_SERVER_UNAVAILABLE;
		break;
	case MQTT_CLIENTID_REJECTED:
		rc = E_ST_MQTT_CLIENTID_REJECTED;
		break;
	case MQTT_BAD_USERNAME_OR_PASSWORD:
		rc = E_ST_MQTT_BAD_USERNAME_OR_PASSWORD;
		break;
	case MQTT_NOT_AUTHORIZED:
		rc = E_ST_MQTT_NOT_AUTHORIZED;
		break;
	default:
		rc = E_ST_MQTT_FAILURE;
		break;
	}
	return rc;
}

int MQTTConnectWithResults(st_mqtt_client client, st_mqtt_broker_info_t *broker, st_mqtt_connect_data *connect_data,
									 MQTTConnackData *data)
{
	MQTTClient *c = client;
	iot_os_timer connect_timer = NULL;
	int rc = E_ST_MQTT_FAILURE;
	iot_error_t iot_err;
	MQTTPacket_connectData options = MQTTPacket_connectData_initializer;
	int len = 0, pbuf_size, connect_retry;
	unsigned char *pbuf = NULL;

	iot_os_mutex_lock(&c->mutex);
	if (client == NULL || broker == NULL || connect_data == NULL) {
		IOT_ERROR("Invalid arguments");
		goto exit;
	}

	if (c->isconnected) { /* don't send connect packet again if we are already connected */
		goto exit;
	}

	iot_err = iot_net_init(c->net);
	if (iot_err) {
		IOT_ERROR("failed to init network");
		goto exit;
	}

	c->net->connection.url = broker->url;
	c->net->connection.port = broker->port;
	c->net->connection.ca_cert = broker->ca_cert;
	c->net->connection.ca_cert_len = broker->ca_cert_len;

	connect_retry = 3;
	do {
		if (c->net->connect == NULL) {
			IOT_ERROR("net->connect is null");
			iot_err = IOT_ERROR_MQTT_NETCONN_FAIL;
			break;
		}

		iot_err = c->net->connect(c->net);
		if (iot_err) {
			IOT_ERROR("net->connect = %d, retry (%d)", iot_err, connect_retry);
			iot_err = IOT_ERROR_MQTT_NETCONN_FAIL;
			connect_retry--;
			iot_os_delay(2000);
		}
	} while ((iot_err != IOT_ERROR_NONE) && connect_retry);

	if (iot_err != IOT_ERROR_NONE) {
		IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_MQTT_CONNECT_NETWORK_FAIL, 0, 0);
		IOT_ERROR("MQTT net connection failed");
		goto exit;
	}

	iot_err = iot_os_timer_init(&connect_timer);
	if (iot_err) {
		IOT_ERROR("fail to init timer");
		goto exit_with_netcon;
	}
	iot_os_timer_count_ms(connect_timer, c->command_timeout_ms);

	if (connect_data->will_flag) {
		options.willFlag = 1;
		options.will.topicName.cstring = connect_data->will_topic;
		options.will.message.cstring = connect_data->will_message;
		options.will.retained = connect_data->will_retained;
		options.will.qos = connect_data->will_qos;
	} else
		options.willFlag = 0;

	options.MQTTVersion  = connect_data->mqtt_ver;
	options.clientID.cstring  = connect_data->clientid;
	options.username.cstring  = connect_data->username;
	options.password.cstring  = connect_data->password;
	options.keepAliveInterval = connect_data->alive_interval;
	options.cleansession = connect_data->cleansession;

	c->keepAliveInterval = options.keepAliveInterval;
	c->cleansession = options.cleansession;
	iot_os_timer_count_ms(c->last_received, c->keepAliveInterval * 1000);

	pbuf_size = MQTTSerialize_connect_size(&options);
	pbuf = (unsigned char *)malloc(pbuf_size);
	if (pbuf == NULL) {
		IOT_ERROR("buf malloc fail");
		goto exit_with_netcon;
	}
	if ((len = MQTTSerialize_connect(pbuf, pbuf_size, &options)) <= 0) {
		goto exit_with_netcon;
	}

	rc = sendPacket(c, pbuf, len, connect_timer);
	if (rc) { // send the connect packet
		goto exit_with_netcon;	  // there was a problem
	}
	free(pbuf);
	pbuf = NULL;

	// this will be a blocking call, wait for the connack
	if (waitfor(c, CONNACK, connect_timer) == CONNACK) {
		data->rc = 0;
		data->sessionPresent = 0;

		if (MQTTDeserialize_connack(&data->sessionPresent, &data->rc, c->readbuf, c->readbuf_size) == 1) {
			rc = _convert_return_code(data->rc);
        } else {
			rc = E_ST_MQTT_FAILURE;
		}
		free(c->readbuf);
		c->readbuf = NULL;
	} else {
		rc = E_ST_MQTT_FAILURE;
	}

exit_with_netcon:
	if (rc) {
		c->net->disconnect(c->net);
	} else {
		c->isconnected = 1;
		c->ping_outstanding = 0;
		c->ping_retry_count = 0;
	}

	if (pbuf != NULL)
		free(pbuf);

	if (connect_timer != NULL)
		iot_os_timer_destroy(&connect_timer);

exit:
	iot_os_mutex_unlock(&c->mutex);

	IOT_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_MQTT_CONNECT_RESULT, rc, connect_data->alive_interval);
	return rc;
}

int st_mqtt_connect(st_mqtt_client client, st_mqtt_broker_info_t *broker, st_mqtt_connect_data *connect_data)
{
	MQTTConnackData data;
	return MQTTConnectWithResults(client, broker, connect_data, &data);
}

int MQTTSetMessageHandler(st_mqtt_client client, const char *topic, st_mqtt_msg_handler handler, void *user_data)
{
	MQTTClient *c = client;
	int rc = E_ST_MQTT_FAILURE;
	int i = -1;

	/* first check for an existing matching slot */
	for (i = 0; i < MAX_MESSAGE_HANDLERS; ++i) {
		if (c->messageHandlers[i].topicFilter != NULL && strcmp(c->messageHandlers[i].topicFilter, topic) == 0) {
			if (handler == NULL) { /* remove existing */
				free(c->messageHandlers[i].topicFilter);
				c->messageHandlers[i].topicFilter = NULL;
				c->messageHandlers[i].fp = NULL;
				c->messageHandlers[i].userData = user_data;
			}

			rc = 0; /* return i when adding new subscription */
			break;
		}
	}

	/* if no existing, look for empty slot (unless we are removing) */
	if (handler != NULL) {
		if (rc == E_ST_MQTT_FAILURE) {
			for (i = 0; i < MAX_MESSAGE_HANDLERS; ++i) {
				if (c->messageHandlers[i].topicFilter == NULL) {
					rc = 0;
					break;
				}
			}
		}

		if (i < MAX_MESSAGE_HANDLERS) {
			c->messageHandlers[i].topicFilter = strdup(topic);
			c->messageHandlers[i].fp = handler;
			c->messageHandlers[i].userData = user_data;
		}
	}

	return rc;
}

int MQTTSubscribeWithResults(st_mqtt_client client, const char *topic, int qos, st_mqtt_msg_handler handler,
							MQTTSubackData *data, void *user_data)
{
	MQTTClient *c = client;
	int rc = E_ST_MQTT_FAILURE;
	iot_error_t iot_err;
	iot_os_timer timer = NULL;
	int len = 0, pbuf_size;
	unsigned char *pbuf = NULL;
	MQTTString Topic = MQTTString_initializer;
	Topic.cstring = (char *)topic;

	iot_os_mutex_lock(&c->mutex);

	if (!c->isconnected) {
		rc = E_ST_MQTT_DISCONNECTED;
		goto exit;
	}

	iot_err = iot_os_timer_init(&timer);
	if (iot_err) {
		IOT_ERROR("fail to init timer");
		goto exit;
	}
	iot_os_timer_count_ms(timer, c->command_timeout_ms);

	pbuf_size = MQTTSerialize_subscribe_size(1, &Topic);
	pbuf = (unsigned char *)malloc(pbuf_size);
	if (pbuf == NULL) {
		IOT_ERROR("buf malloc fail");
		goto exit;
	}

	len = MQTTSerialize_subscribe(pbuf, pbuf_size, 0, getNextPacketId(c), 1, &Topic, (int *)&qos);

	if (len <= 0) {
		goto exit;
	}

	rc = sendPacket(c, pbuf, len, timer);
	if (rc) { // send the subscribe packet
		goto exit;	  // there was a problem
	}
	free(pbuf);
	pbuf = NULL;

	if (waitfor(c, SUBACK, timer) == SUBACK) {	  // wait for suback
		int count = 0;
		unsigned short mypacketid;
		data->granted_qos = st_mqtt_qos0;

		if (MQTTDeserialize_suback(&mypacketid, 1, &count, (int *)&data->granted_qos, c->readbuf, c->readbuf_size) == 1) {
			if (data->granted_qos != 0x80) {
				rc = MQTTSetMessageHandler(client, topic, handler, user_data);
			}
		}
		free(c->readbuf);
		c->readbuf = NULL;
	} else {
		rc = E_ST_MQTT_FAILURE;
	}

exit:
	if (pbuf != NULL)
		free(pbuf);

	if (timer != NULL)
		iot_os_timer_destroy(&timer);

	iot_os_mutex_unlock(&c->mutex);

	IOT_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_MQTT_SUBSCRIBE, rc, 0);
	return rc;
}

int st_mqtt_subscribe(st_mqtt_client client, const char *topic, int qos, st_mqtt_msg_handler handler, void *user_data)
{
	MQTTSubackData data;
	return MQTTSubscribeWithResults(client, topic, qos, handler, &data, user_data);
}

int st_mqtt_unsubscribe(st_mqtt_client client, const char *topic)
{
	MQTTClient *c = client;
	int rc = E_ST_MQTT_FAILURE;
	iot_error_t iot_err;
	iot_os_timer timer = NULL;
	MQTTString Topic = MQTTString_initializer;
	Topic.cstring = (char *)topic;
	int len = 0, pbuf_size;
	unsigned char *pbuf = NULL;

	iot_os_mutex_lock(&c->mutex);

	if (!c->isconnected) {
		rc = E_ST_MQTT_DISCONNECTED;
		goto exit;
	}

	iot_err = iot_os_timer_init(&timer);
	if (iot_err) {
		IOT_ERROR("fail to init timer");
		goto exit;
	}
	iot_os_timer_count_ms(timer, c->command_timeout_ms);

	pbuf_size = MQTTSerialize_unsubscribe_size(1, &Topic);
	pbuf = (unsigned char *)malloc(pbuf_size);
	if (pbuf == NULL) {
		IOT_ERROR("buf malloc fail");
		goto exit;
	}

	if ((len = MQTTSerialize_unsubscribe(pbuf, pbuf_size, 0, getNextPacketId(c), 1, &Topic)) <= 0) {
		goto exit;
	}

	rc = sendPacket(c, pbuf, len, timer);
	if (rc) { // send the subscribe packet
		goto exit;	  // there was a problem
	}
	free(pbuf);
	pbuf = NULL;

	if (waitfor(c, UNSUBACK, timer) == UNSUBACK) {
		unsigned short mypacketid;	// should be the same as the packetid above

		if (MQTTDeserialize_unsuback(&mypacketid, c->readbuf, c->readbuf_size) == 1) {
			/* remove the subscription message handler associated with this topic, if there is one */
			MQTTSetMessageHandler(client, topic, NULL, NULL);
		}
		free(c->readbuf);
		c->readbuf = NULL;
	} else {
		rc = E_ST_MQTT_FAILURE;
	}

exit:
	if (pbuf != NULL)
		free(pbuf);

	if (timer != NULL)
		iot_os_timer_destroy(&timer);

	iot_os_mutex_unlock(&c->mutex);

	IOT_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_MQTT_UNSUBSCRIBE, rc, 0);
	return rc;
}

int st_mqtt_publish(st_mqtt_client client, st_mqtt_msg *msg)
{
	MQTTClient *c = client;
	int rc = E_ST_MQTT_FAILURE;
	iot_error_t iot_err;
	iot_os_timer timer = NULL;
	MQTTString topic = MQTTString_initializer;
	topic.cstring = (char *)msg->topic;
	int len = 0, pbuf_size;
	unsigned char *pbuf = NULL;
	unsigned short msg_id = 0;

	iot_os_mutex_lock(&c->mutex);

	if (!c->isconnected) {
		rc = E_ST_MQTT_DISCONNECTED;
		goto exit;
	}

	iot_err = iot_os_timer_init(&timer);
	if (iot_err) {
		IOT_ERROR("fail to init timer");
		goto exit;
	}
	iot_os_timer_count_ms(timer, c->command_timeout_ms);

	if (msg->qos == st_mqtt_qos1 || msg->qos == st_mqtt_qos2) {
		msg_id = getNextPacketId(c);
	}

	int retry = 0;
	do {
		iot_os_timer_count_ms(timer, c->command_timeout_ms);
		if (retry) {
			IOT_WARN("mqtt publish retry(%d)", retry);
		}
		retry++;
#if defined(MQTT_PUB_NOCOPY)
		/* First, send MQTT Connect header */
		pbuf_size = MQTTSerialize_publish_size(msg->qos, topic, msg->payloadlen) - msg->payloadlen;
		pbuf = (unsigned char *)malloc(pbuf_size);
		if (pbuf == NULL) {
			IOT_ERROR("buf malloc fail");
			goto exit;
		}
		len = MQTTSerialize_publish_header(pbuf, 0, msg->qos, msg->retained, msg_id,
									topic, msg->payloadlen);
		if (len <= 0 || (rc = sendPacket(c, pbuf, len, timer))) { // send the subscribe packet
			goto exit;	  // there was a problem
		}
		free(pbuf);
		/* Second, send application payload itself(no-copy) */
		pbuf = msg->payload;
		len = msg->payloadlen;
		rc = sendPacket(c, pbuf, len, timer);
		pbuf = NULL;
		if (rc) { // send the subscribe packet
			goto exit;	  // there was a problem
		}
#else
		pbuf_size = MQTTSerialize_publish_size(msg->qos, topic, msg->payloadlen);
		pbuf = (unsigned char *)malloc(pbuf_size);
		if (pbuf == NULL) {
			IOT_ERROR("buf malloc fail");
			goto exit;
		}
		len = MQTTSerialize_publish(pbuf, pbuf_size, 0, msg->qos, msg->retained, msg_id,
									topic, (unsigned char *)msg->payload, msg->payloadlen);

		if (len <= 0 || (rc = sendPacket(c, pbuf, len, timer))) { // send the subscribe packet
			goto exit;	  // there was a problem
		}
		free(pbuf);
		pbuf = NULL;
#endif
		if (msg->qos == st_mqtt_qos1) {
			if (waitfor(c, PUBACK, timer) == PUBACK) {
				unsigned short mypacketid;
				unsigned char dup, type;

				if (MQTTDeserialize_ack(&type, &dup, &mypacketid, c->readbuf, c->readbuf_size) != 1) {
					rc = E_ST_MQTT_FAILURE;
				}
				if (c->readbuf != NULL) {
					free(c->readbuf);
					c->readbuf = NULL;
				}
			} else {
				rc = E_ST_MQTT_FAILURE;
			}
		} else if (msg->qos == st_mqtt_qos2) {
			if (waitfor(c, PUBCOMP, timer) == PUBCOMP) {
				unsigned short mypacketid;
				unsigned char dup, type;

				if (MQTTDeserialize_ack(&type, &dup, &mypacketid, c->readbuf, c->readbuf_size) != 1) {
					rc = E_ST_MQTT_FAILURE;
				}
				free(c->readbuf);
				c->readbuf = NULL;
			} else {
				rc = E_ST_MQTT_FAILURE;
			}
		}
	} while (rc && retry < MQTT_PUBLISH_RETRY);

exit:
	if (pbuf != NULL)
		free(pbuf);

	if (timer != NULL)
		iot_os_timer_destroy(&timer);

	iot_os_mutex_unlock(&c->mutex);

	IOT_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_MQTT_PUBLISH, rc, msg_id);
	return rc;
}

int st_mqtt_disconnect(st_mqtt_client client)
{
	MQTTClient *c = client;
	int rc = E_ST_MQTT_FAILURE;
	iot_error_t iot_err;
	iot_os_timer timer = NULL;		// we might wait for incomplete incoming publishes to complete
	int len = 0;
	unsigned char pbuf[MQTT_DISCONNECT_MAX_SIZE];

	iot_os_mutex_lock(&c->mutex);

	if (!c->isconnected) {
		rc = E_ST_MQTT_DISCONNECTED;
		goto exit;
	}

	iot_err = iot_os_timer_init(&timer);
	if (iot_err) {
		IOT_ERROR("fail to init timer");
		goto exit;
	}
	iot_os_timer_count_ms(timer, c->command_timeout_ms);

	len = MQTTSerialize_disconnect(pbuf, MQTT_DISCONNECT_MAX_SIZE);

	if (len > 0) {
		rc = sendPacket(c, pbuf, len, timer);    // send the disconnect packet
	}
	IOT_INFO("mqtt send disconnect");
	_iot_mqtt_close_session(c);

exit:
	if (timer != NULL)
		iot_os_timer_destroy(&timer);

	iot_os_mutex_unlock(&c->mutex);

	IOT_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_MQTT_DISCONNECT, rc, 0);
	return rc;
}
