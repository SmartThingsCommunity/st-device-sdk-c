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
#include "port_net.h"

static void _iot_mqtt_pending_work(struct iot_context *ctx, device_work_param param);

static int _iot_mqtt_signal_pending_work(MQTTClient *client)
{
	device_work_data_t work;
	iot_error_t err;

	work.handler = _iot_mqtt_pending_work;
	work.param = (device_work_param)client;
	work.owner_id = client;

	err = iot_util_queue_send(client->work_queue, &work);
	if (err != IOT_ERROR_NONE)
	{
		IOT_ERROR("Failed to send work queue %d", err);
		return err;
	}
	iot_os_eventgroup_set_bits(client->work_queue_signal, DEVICE_PENDING_WORK_SIGNAL);

	return IOT_ERROR_NONE;
}

static int _iot_mqtt_write_net(PORT_NET_CONTEXT net_ctx, unsigned char *buf, int len)
{
	int sentLen = 0, ret = 0;

	IOT_DEBUG("%d@%p", len, buf);

	do {
		ret = port_net_write(net_ctx, buf + sentLen, (size_t)len - sentLen);

		if(ret >= 0) {
			sentLen += ret;
		} else {
			return ret;
		}
	} while (sentLen < len);

	return sentLen;
}

static int _iot_mqtt_read_net(PORT_NET_CONTEXT net_ctx, unsigned char *buf, int len)
{
	int recvLen = 0, ret = 0;

	IOT_DEBUG("%d@%p", len, buf);

	if (len == 0) {
		return 0;
	}

	do {
		ret = port_net_read(net_ctx, buf + recvLen, (size_t)len - recvLen);

		if(ret >= 0) {
			recvLen += ret;
		} else {
			return ret;
		}
	} while(recvLen < len);

	return recvLen;
}

static void _iot_mqtt_close_net(MQTTClient *client)
{
	do {
		if (client->read_lock.sem == NULL)
			return;
	} while ((iot_os_mutex_lock(&client->read_lock)) != IOT_OS_TRUE);

	do {
		if (client->write_lock.sem == NULL) {
			iot_os_mutex_unlock(&client->read_lock);
			return;
		}
	} while ((iot_os_mutex_lock(&client->write_lock)) != IOT_OS_TRUE);
	if (client->isconnected) {
		client->isconnected = 0;
		port_net_close(client->net_ctx);
	}
	iot_os_mutex_unlock(&client->write_lock);
	iot_os_mutex_unlock(&client->read_lock);

}

static int _iot_mqtt_connect_net(MQTTClient *client, st_mqtt_broker_info_t *broker)
{
	int rc = 0;
	port_net_tls_config tls_config = {0, };
	char port[5] = {0};

	if (client == NULL || client->magic != MQTT_CLIENT_STRUCT_MAGIC_NUMBER) {
		return E_ST_MQTT_FAILURE;
	}

	if((iot_os_mutex_lock(&client->read_lock)) != IOT_OS_TRUE) {
		return E_ST_MQTT_FAILURE;
	}

	if((iot_os_mutex_lock(&client->write_lock)) != IOT_OS_TRUE) {
		iot_os_mutex_unlock(&client->read_lock);
		return E_ST_MQTT_FAILURE;
	}

	snprintf(port, sizeof(port), "%d", broker->port);
	tls_config.ca_cert = (char *)broker->ca_cert;
	tls_config.ca_cert_len = broker->ca_cert_len;
	if (client->net_ctx) {
		port_net_free(client->net_ctx);
		client->net_ctx = NULL;
	}
	client->net_ctx = port_net_connect(broker->url, port, &tls_config);
	if (!client->net_ctx) {
		IOT_ERROR("MQTT net connection failed");
		rc = E_ST_MQTT_FAILURE;
		goto exit;
	}

	client->isconnected = 1;

exit:
	iot_os_mutex_unlock(&client->write_lock);
	iot_os_mutex_unlock(&client->read_lock);

	return rc;
}

static void _iot_mqtt_chunk_destroy(iot_mqtt_packet_chunk_t *chunk)
{
	if (chunk && chunk->chunk_data) {
		iot_os_free(chunk->chunk_data);
	}

	if (chunk && chunk->expiry_time) {
		iot_os_timer_delete(chunk->expiry_time);
	}

	if (chunk) {
		iot_os_free(chunk);
	}
}

static iot_mqtt_packet_chunk_t * _iot_mqtt_chunk_create(size_t chunk_size)
{
	iot_mqtt_packet_chunk_t *chunk = NULL;

	chunk = iot_os_malloc(sizeof(iot_mqtt_packet_chunk_t));
	if (chunk == NULL) {
		IOT_ERROR("chunk malloc fail");
		return NULL;
	}
	memset(chunk, '\0', sizeof(iot_mqtt_packet_chunk_t));

	chunk->chunk_data = iot_os_malloc(chunk_size);
	if (chunk_size != 0 && chunk->chunk_data == NULL) {
		IOT_ERROR("chunk data malloc fail");
		iot_os_free(chunk);
		return NULL;
	}
	chunk->chunk_size = chunk_size;

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
					if (iterator->next == queue->tail)
						queue->tail = iterator;
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
		if (queue->head->expiry_time && !iot_os_timer_is_active(queue->head->expiry_time)) {
			chunk = queue->head;
			queue->head = queue->tail = NULL;
		}
	} else {
		if (queue->head->expiry_time && !iot_os_timer_is_active(queue->head->expiry_time)) {
			chunk = queue->head;
			queue->head = queue->head->next;
			chunk->next = NULL;
		} else {
			iterator = queue->head;
			while (iterator->next) {
				if (iterator->next->expiry_time && !iot_os_timer_is_active(iterator->next->expiry_time)) {
					if (iterator->next == queue->tail)
						queue->tail = iterator;
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
		if (tmp->have_owner) {
			tmp->next = NULL;
			tmp->chunk_state = PACKET_CHUNK_QUEUE_DESTROYED;
		} else {
			_iot_mqtt_chunk_destroy(tmp);
		}
	}
	queue->head = queue->tail = NULL;
	iot_os_mutex_unlock(&queue->lock);

	if (queue->lock.sem != NULL) {
		iot_os_mutex_destroy(&queue->lock);
		queue->lock.sem = NULL;
	}
}

static void _iot_mqtt_chunk_expire_timeout(iot_os_timer_handle handle, void *user_data)
{
	MQTTClient *client = (MQTTClient *)user_data;
	IOT_INFO("Timeout");

	if (client->work_queue) {
		_iot_mqtt_signal_pending_work(client);
	}
}

static void _iot_mqtt_process_post_write(MQTTClient *client, iot_mqtt_packet_chunk_t *chunk)
{
	switch(chunk->packet_type) {
		case CONNECT:
			chunk->chunk_state = PACKET_CHUNK_ACK_PENDING;
			if (chunk->expiry_time) {
				iot_os_timer_delete(chunk->expiry_time);
			}
			chunk->expiry_time = iot_os_timer_create(_iot_mqtt_chunk_expire_timeout, MQTT_CONNECT_TIMEOUT, client);
			if (!chunk->expiry_time) {
				IOT_ERROR("Failed to create expiry timer");
			} else {
				iot_os_timer_start(chunk->expiry_time);
			}
			_iot_mqtt_queue_push(&client->ack_pending_queue, chunk);
			break;
		case SUBSCRIBE:
		case UNSUBSCRIBE:
		case PUBREL:
		case PUBREC:
		case PINGREQ:
			chunk->chunk_state = PACKET_CHUNK_ACK_PENDING;
			if (chunk->expiry_time) {
				iot_os_timer_delete(chunk->expiry_time);
			}
			chunk->expiry_time = iot_os_timer_create(_iot_mqtt_chunk_expire_timeout, MQTT_RETRY_TIMEOUT, client);
			if (!chunk->expiry_time) {
				IOT_ERROR("Failed to create expiry timer");
			} else {
				iot_os_timer_start(chunk->expiry_time);
			}
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
				if (chunk->expiry_time) {
					iot_os_timer_delete(chunk->expiry_time);
				}
				chunk->expiry_time = iot_os_timer_create(_iot_mqtt_chunk_expire_timeout, MQTT_RETRY_TIMEOUT, client);
				if (!chunk->expiry_time) {
					IOT_ERROR("Failed to create expiry timer");
				} else {
					iot_os_timer_start(chunk->expiry_time);
				}
				_iot_mqtt_queue_push(&client->ack_pending_queue, chunk);
			}
			break;
		case DISCONNECT:
			if (chunk->have_owner) {
				chunk->chunk_state = PACKET_CHUNK_WRITE_COMPLETED;
			} else {
				_iot_mqtt_chunk_destroy(chunk);
			}
			break;
		default:
			_iot_mqtt_chunk_destroy(chunk);
			break;
	}
}

static int _iot_mqtt_run_write_stream(MQTTClient *client)
{
	int rc = 0, written = 0;
	iot_mqtt_packet_chunk_t *w_chunk = NULL;

	if (client == NULL || client->magic != MQTT_CLIENT_STRUCT_MAGIC_NUMBER) {
		return E_ST_MQTT_FAILURE;
	}

	if((iot_os_mutex_lock(&client->write_lock)) != IOT_OS_TRUE) {
		return 0;
	}

	w_chunk = _iot_mqtt_queue_pop(&client->write_pending_queue);
	if (w_chunk == NULL) {
		goto exit;
	}

	if(!client->isconnected) {
		written = E_ST_MQTT_DISCONNECTED;
		goto exit;
	}

	while (written != w_chunk->chunk_size) {
		rc = _iot_mqtt_write_net(client->net_ctx, &w_chunk->chunk_data[written],
				w_chunk->chunk_size - written);

		if (rc > 0) {
			written += rc;
		} else if (rc < 0) {
			break;
		}
	}

	if (written == w_chunk->chunk_size) {
		_iot_mqtt_process_post_write(client, w_chunk);
		w_chunk = NULL;
	} else {
		written = E_ST_MQTT_NETWORK_ERROR;
	}

exit:
	iot_os_mutex_unlock(&client->write_lock);

	if (written < 0 && w_chunk != NULL) {
		w_chunk->chunk_state = PACKET_CHUNK_WRITE_FAIL;
		w_chunk->return_code = written;
		if (!w_chunk->have_owner) {
			_iot_mqtt_queue_push(&client->user_event_callback_queue, w_chunk);
		}
	}

	if (written > 0) {
		if (client != NULL && client->magic == MQTT_CLIENT_STRUCT_MAGIC_NUMBER) {
			if((iot_os_mutex_lock(&client->client_manage_lock)) == IOT_OS_TRUE) {
				iot_os_timer_start(client->last_sent);
				iot_os_mutex_unlock(&client->client_manage_lock);
			}
		}
	}

	if (written == E_ST_MQTT_NETWORK_ERROR) {
		iot_mqtt_packet_chunk_t *event_chunk = NULL;
		_iot_mqtt_close_net(client);
		event_chunk = _iot_mqtt_chunk_create(0);
		if (event_chunk != NULL) {
			event_chunk->chunk_state = EVENT_CHUNK_DISCONNECTED;
			event_chunk->return_code = MQTT_DISCONNECTED_NETWORK_ERROR;
			_iot_mqtt_queue_push(&client->user_event_callback_queue, event_chunk);
		}
	}

	return written;
}

static int _iot_mqtt_convert_return_code(int mqtt_rc)
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
		if (chunk->packet_type == CONNACK) {
			unsigned char ack_rc = 0;
			unsigned char sessionPresent = 0;

			MQTTDeserialize_connack(&sessionPresent, &ack_rc, chunk->chunk_data, chunk->chunk_size);
			tmp->return_code = _iot_mqtt_convert_return_code(ack_rc);
		} else if (chunk->packet_type == SUBACK) {
			int count = 0, ack_qos;
			unsigned short mypacketid;
			MQTTDeserialize_suback(&mypacketid, 1, &count, (int *)&ack_qos, chunk->chunk_data, chunk->chunk_size);
			if (ack_qos == 0x80) {
				tmp->return_code = E_ST_MQTT_FAILURE;
			} else {
				tmp->return_code = 0;
			}
		}

		if (tmp->have_owner) {
			tmp->chunk_state = PACKET_CHUNK_ACKNOWLEDGED;
			if (tmp->expiry_time) {
				iot_os_timer_delete(tmp->expiry_time);
				tmp->expiry_time = NULL;
			}
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

	if ((chunk->chunk_data[0] & MQTT_FIXED_HEADER_DUP_MASK) >> MQTT_FIXED_HEADER_DUP_OFFSET) {
		IOT_WARN("duplicated PUB packet %d", chunk->packet_id);
		_iot_mqtt_chunk_destroy(chunk);
	} else {
		_iot_mqtt_queue_push(&client->user_event_callback_queue, chunk);
	}
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
			break;
		case PUBLISH:
			_iot_mqtt_process_received_publish(client, chunk);
			break;
		case PUBREC:
		case PUBREL:
			_iot_mqtt_process_received_pubrec_pubrel(client, chunk);
			break;
		default:
			IOT_WARN("There is no read packet type handle %d", chunk->packet_type);
			_iot_mqtt_chunk_destroy(chunk);
			break;
	}
}

static int _iot_mqtt_run_read_stream(MQTTClient *client)
{
	int rc = 0 , read = 0;
	iot_mqtt_packet_chunk_t *w_chunk = NULL;
	unsigned char packet_fixed_header[MAX_NUM_OF_REMAINING_LENGTH_BYTES + 1];
	int rem_size = 0, multiplier = 1;

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

	rc = port_net_read_poll(client->net_ctx, 0);
	if (rc < 0) {
		read = E_ST_MQTT_NETWORK_ERROR;
		goto exit;
	} else if (rc == 0) {
		goto exit;
	}

	rc = _iot_mqtt_read_net(client->net_ctx, &packet_fixed_header[0], 1);
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
		rc = _iot_mqtt_read_net(client->net_ctx, &packet_fixed_header[read], 1);
		if (rc <= 0) {
			read = E_ST_MQTT_NETWORK_ERROR;
			goto exit;
		}
		rem_size += (packet_fixed_header[read] & 127) * multiplier;
		multiplier *= 128;
		read++;
	} while ((packet_fixed_header[read - 1] & 128) != 0);

	w_chunk = _iot_mqtt_chunk_create(read + rem_size);
	if (w_chunk == NULL) {
		IOT_ERROR("chunk malloc fail");
		read = E_ST_MQTT_BUFFER_OVERFLOW;
		goto exit;
	}
	memcpy(w_chunk->chunk_data, packet_fixed_header, read);

	while (read != w_chunk->chunk_size) {
		rc = _iot_mqtt_read_net(client->net_ctx, w_chunk->chunk_data + read,
				w_chunk->chunk_size - read);
		if (rc < 0) {
			break;
		} else {
			read += rc;
		}
	}

	if (read == w_chunk->chunk_size) {
		w_chunk->chunk_state = PACKET_CHUNK_READ_COMPLETED;
		w_chunk->packet_type = (w_chunk->chunk_data[0] & MQTT_FIXED_HEADER_PACKET_TYPE_MASK) >> MQTT_FIXED_HEADER_PACKET_TYPE_OFFSET;
		w_chunk->qos = (w_chunk->chunk_data[0] & MQTT_FIXED_HEADER_QOS_MASK) >> MQTT_FIXED_HEADER_QOS_OFFSET;
		w_chunk->packet_id = MQTTPacket_getPacketId(w_chunk->chunk_data);
		_iot_mqtt_process_post_read(client, w_chunk);

		w_chunk = NULL;
	} else {
		read = E_ST_MQTT_NETWORK_ERROR;
	}


exit:
	iot_os_mutex_unlock(&client->read_lock);

	if (w_chunk != NULL) {
		_iot_mqtt_chunk_destroy(w_chunk);
	}

	if (read > 0) {
		if (client != NULL && client->magic == MQTT_CLIENT_STRUCT_MAGIC_NUMBER) {
			if((iot_os_mutex_lock(&client->client_manage_lock)) == IOT_OS_TRUE) {
				iot_os_timer_start(client->last_received);
				iot_os_mutex_unlock(&client->client_manage_lock);
			}
		}
	}

	if (read == E_ST_MQTT_NETWORK_ERROR) {
		iot_mqtt_packet_chunk_t *event_chunk = NULL;
		_iot_mqtt_close_net(client);
		event_chunk = _iot_mqtt_chunk_create(0);
		if (event_chunk != NULL) {
			event_chunk->chunk_state = EVENT_CHUNK_DISCONNECTED;
			event_chunk->return_code = MQTT_DISCONNECTED_NETWORK_ERROR;
			_iot_mqtt_queue_push(&client->user_event_callback_queue, event_chunk);
		}
	}

	return read;
}

static int _iot_mqtt_check_alive(MQTTClient *client)
{
	int rc = 0;

	if (client == NULL || client->magic != MQTT_CLIENT_STRUCT_MAGIC_NUMBER) {
		return E_ST_MQTT_PING_FAIL;
	}

	if((iot_os_mutex_lock(&client->client_manage_lock)) != IOT_OS_TRUE) {
		return E_ST_MQTT_PING_FAIL;
	}
	if (!iot_os_timer_is_active(client->last_sent) || !iot_os_timer_is_active(client->last_received)) {
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
				rc = E_ST_MQTT_PING_TIMEOUT;
				goto exit;
			default:
				break;
		}
	}

exit:
	iot_os_mutex_unlock(&client->client_manage_lock);

	if (rc == E_ST_MQTT_PING_TIMEOUT) {
		iot_mqtt_packet_chunk_t *event_chunk = NULL;
		_iot_mqtt_close_net(client);
		event_chunk = _iot_mqtt_chunk_create(0);
		if (event_chunk != NULL) {
			event_chunk->chunk_state = EVENT_CHUNK_DISCONNECTED;
			event_chunk->return_code = MQTT_DISCONNECTED_PING_TIMEOUT;
			_iot_mqtt_queue_push(&client->user_event_callback_queue, event_chunk);
		}
	}

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
		switch (w_chunk->packet_type) {
			case CONNECT:
				if (w_chunk->have_owner) {
					w_chunk->chunk_state = PACKET_CHUNK_TIMEOUT;
				} else {
					w_chunk->chunk_state = PACKET_CHUNK_TIMEOUT;
					if (client != NULL && client->magic == MQTT_CLIENT_STRUCT_MAGIC_NUMBER) {
						_iot_mqtt_queue_push(&client->user_event_callback_queue, w_chunk);
					} else {
						_iot_mqtt_chunk_destroy(w_chunk);
					}
				}
				break;
			default:
				w_chunk->retry_count++;
				if (w_chunk->retry_count < MQTT_PUBLISH_RETRY) {
					w_chunk->chunk_state = PACKET_CHUNK_WRITE_PENDING;
					if (client != NULL && client->magic == MQTT_CLIENT_STRUCT_MAGIC_NUMBER) {
						_iot_mqtt_queue_push(&client->write_pending_queue, w_chunk);
					} else {
						_iot_mqtt_chunk_destroy(w_chunk);
					}
				} else {
					if (w_chunk->have_owner) {
						w_chunk->chunk_state = PACKET_CHUNK_TIMEOUT;
					} else {
						w_chunk->chunk_state = PACKET_CHUNK_TIMEOUT;
						if (client != NULL && client->magic == MQTT_CLIENT_STRUCT_MAGIC_NUMBER) {
							_iot_mqtt_queue_push(&client->user_event_callback_queue, w_chunk);
						} else {
							_iot_mqtt_chunk_destroy(w_chunk);
						}
					}
				}
				break;
		}
	}
}

static void _iot_mqtt_deliver_publish(MQTTClient *client, iot_mqtt_packet_chunk_t *chunk)
{
	st_mqtt_msg msg;
	MQTTString topic_name;
	int qos;
	unsigned char dup;
	unsigned short id;

	MQTTDeserialize_publish(&dup, &qos, &msg.retained, &id, &topic_name,
							(unsigned char **)&msg.payload, (int *)&msg.payloadlen, chunk->chunk_data, chunk->chunk_size);

	msg.qos = qos;
	msg.topic = topic_name.lenstring.data;
	msg.topiclen = topic_name.lenstring.len;
	client->user_callback_fp(ST_MQTT_EVENT_MSG_DELIVERED, &msg, client->user_callback_user_data);
}

static void _iot_mqtt_notify_publish_failed(MQTTClient *client, iot_mqtt_packet_chunk_t *chunk)
{
	st_mqtt_msg msg;
	MQTTString topic_name;
	int qos;
	unsigned char dup;
	unsigned short id;

	MQTTDeserialize_publish(&dup, &qos, &msg.retained, &id, &topic_name,
							(unsigned char **)&msg.payload, (int *)&msg.payloadlen, chunk->chunk_data, chunk->chunk_size);

	msg.qos = qos;
	msg.topic = topic_name.lenstring.data;
	msg.topiclen = topic_name.lenstring.len;
	if (chunk->chunk_state == PACKET_CHUNK_WRITE_FAIL) {
		client->user_callback_fp(ST_MQTT_EVENT_PUBLISH_FAILED, &msg, client->user_callback_user_data);
	} else if (chunk->chunk_state == PACKET_CHUNK_TIMEOUT) {
		client->user_callback_fp(ST_MQTT_EVENT_PUBLISH_TIMEOUT, &msg, client->user_callback_user_data);
	}
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
				if (w_chunk->packet_type == PUBLISH) {
					_iot_mqtt_notify_publish_failed(client, w_chunk);
				}
				break;
			case PACKET_CHUNK_READ_COMPLETED:
				if (w_chunk->packet_type == PUBLISH) {
					_iot_mqtt_deliver_publish(client, w_chunk);
				}
				break;
			case EVENT_CHUNK_DISCONNECTED:
				client->user_callback_fp(ST_MQTT_EVENT_DISCONNECTED, &w_chunk->return_code, client->user_callback_user_data);
				break;
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
	if (rc < 0) {
		IOT_DUMP(IOT_DEBUG_LEVEL_WARN, IOT_DUMP_MQTT_WRITE_STREAM_FAIL, rc, 0);
		return rc;
	}

	rc = _iot_mqtt_run_read_stream(client);
	if (rc < 0) {
		IOT_DUMP(IOT_DEBUG_LEVEL_WARN, IOT_DUMP_MQTT_READ_STREAM_FAIL, rc, 0);
		return rc;
	}

	_iot_mqtt_process_pending_packets(client);

	rc = _iot_mqtt_check_alive(client);
	if (rc < 0) {
		IOT_DUMP(IOT_DEBUG_LEVEL_WARN, IOT_DUMP_MQTT_PING_FAIL, rc, 0);
		return rc;
	}

	return rc;
}

static bool _iot_mqtt_is_pending_work(MQTTClient *client)
{
	bool rc = false;

	if((iot_os_mutex_lock(&client->read_lock)) == IOT_OS_TRUE) {
		if (client->write_pending_queue.head != NULL) {
			rc = true;
		} else if (client->user_event_callback_queue.head != NULL) {
			rc = true;
		}

		iot_os_mutex_unlock(&client->read_lock);
	}

	return rc;
}

static void _iot_mqtt_listen_socket(void *parm)
{
	MQTTClient *client = (MQTTClient *)parm;
	int rc;

	IOT_INFO("Enter Socket listen thread");
	do {
		rc = port_net_read_poll(client->net_ctx, PORT_NET_WAIT_FOREVER);
		if (rc > 0) {
			rc = _iot_mqtt_run_read_stream(client);
			if (client->work_queue) {
				_iot_mqtt_signal_pending_work(client);
			}
		}
	} while (rc >= 0 && client->isconnected);
	IOT_INFO("Exit Socket listen thread");
	client->socket_thread = NULL;
	iot_os_thread_delete(NULL);
}

static void _iot_mqtt_pending_work(struct iot_context *ctx, device_work_param param)
{
	MQTTClient *client = (MQTTClient *)param;

	if (client == NULL) {
		IOT_ERROR("MQTTClient is NULL");
		return;
	}

	do {
		_iot_mqtt_run_cycle(client);
		_iot_mqtt_process_user_callback(client);
	} while (_iot_mqtt_is_pending_work(client));
}

int st_mqtt_yield(st_mqtt_client client, int time)
{
	MQTTClient *c = client;
	int rc = 0;
	iot_os_timer_handle timer;

	if (time == 0) {
		rc = _iot_mqtt_run_cycle(c);
		_iot_mqtt_process_user_callback(c);
	} else {
		timer = iot_os_timer_create(NULL, time, NULL);
		if (!timer) {
			IOT_ERROR("Failed to create timer");
			return E_ST_MQTT_FAILURE;
		} else {
			iot_os_timer_start(timer);
		}

		do {
			rc = _iot_mqtt_run_cycle(c);
			_iot_mqtt_process_user_callback(c);
		} while (iot_os_timer_is_active(timer) && !rc);
		iot_os_timer_delete(timer);
	}

	// Check if there is left work to do.
	if (rc == 0 && _iot_mqtt_is_pending_work(c)) {
		rc = 1;
	}

	return rc;
}

int st_mqtt_create(st_mqtt_client *client, st_mqtt_event_callback callback_fp, void *user_data,
		iot_util_queue_t *work_queue, iot_os_eventgroup *work_queue_signal)
{
	MQTTClient *c = NULL;
	int rc = E_ST_MQTT_FAILURE;

	if (callback_fp == NULL) {
		return E_ST_MQTT_FAILURE;
	}

	*client = iot_os_malloc(sizeof(MQTTClient));
	if (*client == NULL) {
		IOT_ERROR("buf malloc fail");
		goto error_handle;
	}
	memset(*client, '\0', sizeof(MQTTClient));

	c = *client;
	c->magic = MQTT_CLIENT_STRUCT_MAGIC_NUMBER;
	c->user_callback_fp = callback_fp;
	c->user_callback_user_data = user_data;

	c->next_packetid = 1;
	iot_os_mutex_init(&c->client_manage_lock);
	if (c->client_manage_lock.sem == NULL) {
		IOT_ERROR("fail to init mutex");
		goto error_handle;
	}
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
	c->work_queue = work_queue;
	c->work_queue_signal = work_queue_signal;

	return 0;
error_handle:
	if (c) {
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

static void _iot_mqtt_delete_pending_task(MQTTClient *client)
{
	iot_util_queue_t *queue = client->work_queue;
	iot_util_queue_data_t *queue_data_iter, *queue_data_prev;

	if (queue == NULL)
		return;

	if((iot_os_mutex_lock(&queue->lock)) != IOT_OS_TRUE)
		return;

	queue_data_iter = queue->head;
	queue_data_prev = NULL;

	while (queue_data_iter) {
		if (((device_work_data_t *)(queue_data_iter->data))->owner_id == client) {
			if (queue->head == queue->tail) {
				iot_os_free(queue_data_iter->data);
				iot_os_free(queue_data_iter);
				queue_data_iter = queue->head = queue->tail = NULL;
			} else if (queue_data_iter == queue->head) {
				queue->head = queue->head->next;
				iot_os_free(queue_data_iter->data);
				iot_os_free(queue_data_iter);
				queue_data_iter = queue->head;
			} else if (queue_data_iter == queue->tail) {
				queue->tail = queue_data_prev;
				iot_os_free(queue_data_iter->data);
				iot_os_free(queue_data_iter);
				queue_data_iter = NULL;
			} else {
				queue_data_prev->next = queue_data_iter->next;
				iot_os_free(queue_data_iter->data);
				iot_os_free(queue_data_iter);
				queue_data_iter = queue_data_prev->next;
			}
		} else {
			queue_data_prev = queue_data_iter;
			queue_data_iter = queue_data_iter->next;
		}
	}

	iot_os_mutex_unlock(&queue->lock);
}

void st_mqtt_destroy(st_mqtt_client client)
{
	MQTTClient *c = client;

	if (c == NULL || c->magic != MQTT_CLIENT_STRUCT_MAGIC_NUMBER) {
		return;
	}
	// invalidate MQTTClient struct
	c->magic = 0;

	_iot_mqtt_close_net(c);
	while (c->socket_thread) {
		IOT_INFO("Waiting socket thread exit");
		iot_os_delay(100);
	}
	_iot_mqtt_delete_pending_task(c);
	if (c->net_ctx) {
		port_net_free(c->net_ctx);
		c->net_ctx = NULL;
	}
	iot_os_mutex_destroy(&c->write_lock);
	iot_os_mutex_destroy(&c->read_lock);

	_iot_mqtt_queue_destroy(&c->write_pending_queue);
	_iot_mqtt_queue_destroy(&c->ack_pending_queue);
	_iot_mqtt_queue_destroy(&c->user_event_callback_queue);
	do {
		if (c->client_manage_lock.sem == NULL)
			goto skip_manage_lock;
	} while ((iot_os_mutex_lock(&c->client_manage_lock)) != IOT_OS_TRUE);
	if (c->last_sent)
		iot_os_timer_delete(c->last_sent);
	if (c->last_received)
		iot_os_timer_delete(c->last_received);
	if (c->ping_packet) {
		_iot_mqtt_chunk_destroy(c->ping_packet);
	}
	iot_os_mutex_unlock(&c->client_manage_lock);
	iot_os_mutex_destroy(&c->client_manage_lock);

skip_manage_lock:
	iot_os_free(c);
}

static int _iot_mqtt_wait_for(MQTTClient *client, iot_mqtt_packet_chunk_t *chunk)
{
	iot_mqtt_packet_chunk_t *tmp = NULL;
	int rc = 0;

	while (1) {
		rc = _iot_mqtt_run_cycle(client);
		switch (chunk->chunk_state) {
			case PACKET_CHUNK_WRITE_PENDING:
				if (rc < 0) {
					tmp = _iot_mqtt_queue_pop_by_type_and_id(&client->write_pending_queue, chunk->packet_type, chunk->packet_id);
					if (tmp) {
						goto exit;
					}
				}
				break;
			case PACKET_CHUNK_ACK_PENDING:
				if (rc < 0) {
					tmp = _iot_mqtt_queue_pop_by_type_and_id(&client->ack_pending_queue, chunk->packet_type, chunk->packet_id);
					if (tmp) {
						goto exit;
					}
				} else {
					iot_os_delay(MQTT_ACKPENDING_WAITCYCLE_IN_SYNC_FUNCTION);
				}
				break;
			case PACKET_CHUNK_WRITE_COMPLETED:
			case PACKET_CHUNK_ACKNOWLEDGED:
				rc = chunk->return_code;
				goto exit;
			case PACKET_CHUNK_QUEUE_DESTROYED:
			case PACKET_CHUNK_WRITE_FAIL:
				rc = E_ST_MQTT_FAILURE;
				goto exit;
			case PACKET_CHUNK_TIMEOUT:
				rc = E_ST_MQTT_PACKET_TIMEOUT;
				goto exit;
			default:
				continue;
		}
	}

exit:
	_iot_mqtt_chunk_destroy(chunk);
	return rc;
}

static void _iot_mqtt_ping_timeout(iot_os_timer_handle handle, void *user_data)
{
	MQTTClient *c = (MQTTClient *)user_data;

	if (c->work_queue) {
		_iot_mqtt_signal_pending_work(c);
	}
}

int st_mqtt_connect(st_mqtt_client client, st_mqtt_broker_info_t *broker, st_mqtt_connect_data *connect_data)
{
	MQTTClient *c = client;
	int rc = 0;
	MQTTPacket_connectData options = MQTTPacket_connectData_initializer;
	int chunk_size;
	iot_mqtt_packet_chunk_t *connect_packet = NULL;

	rc = _iot_mqtt_connect_net(c, broker);
	if (rc < 0) {
		return rc;
	}

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

	chunk_size = MQTTSerialize_connect_size(&options);
	connect_packet = _iot_mqtt_chunk_create(chunk_size);
	if (connect_packet == NULL) {
		IOT_ERROR("buf malloc fail");
		rc = E_ST_MQTT_BUFFER_OVERFLOW;
		goto exit;
	}
	MQTTSerialize_connect(connect_packet->chunk_data, chunk_size, &options);
	connect_packet->packet_type = CONNECT;
	connect_packet->have_owner = 1;
	if (c->magic != MQTT_CLIENT_STRUCT_MAGIC_NUMBER) {
		rc = E_ST_MQTT_FAILURE;
		_iot_mqtt_chunk_destroy(connect_packet);
		goto exit;
	}
	c->keepAliveInterval = options.keepAliveInterval;
	c->last_sent = iot_os_timer_create(_iot_mqtt_ping_timeout, c->keepAliveInterval * 1000, c);
	if (!c->last_sent) {
		IOT_ERROR("Failed to create ping timer");
		rc = E_ST_MQTT_FAILURE;
		goto exit;
	} else {
		iot_os_timer_start(c->last_sent);
	}
	c->last_received = iot_os_timer_create(_iot_mqtt_ping_timeout, c->keepAliveInterval * 1000, c);
	if (!c->last_received) {
		IOT_ERROR("Failed to create ping timer");
		rc = E_ST_MQTT_FAILURE;
		goto exit;
	} else {
		iot_os_timer_start(c->last_received);
	}
	connect_packet->chunk_state = PACKET_CHUNK_WRITE_PENDING;
	_iot_mqtt_queue_push(&c->write_pending_queue, connect_packet);

	rc = _iot_mqtt_wait_for(c, connect_packet);

exit:
	if (rc < 0) {
		_iot_mqtt_close_net(c);
		if (c->last_sent) {
			iot_os_timer_delete(c->last_sent);
			c->last_sent = NULL;
		}
		if (c->last_received) {
			iot_os_timer_delete(c->last_received);
			c->last_received = NULL;
		}
	} else {
		iot_os_thread_create(_iot_mqtt_listen_socket, "MQTTSocketListen",
			MQTT_TASK_STACK_SIZE, (void *)c, MQTT_TASK_PRIORITY,
			&c->socket_thread);
	}

	IOT_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_MQTT_CONNECT_RESULT, rc, connect_data->alive_interval);
	return rc;
}

int st_mqtt_subscribe(st_mqtt_client client, int count, char* topics[], int qos[])
{
	MQTTClient *c = client;
	int rc = 0;
	int chunk_size;
	iot_mqtt_packet_chunk_t *sub_packet = NULL;
	MQTTString *Topics = NULL;

	if (count <= 0 || topics == NULL || qos == NULL) {
		IOT_ERROR("Invalid arguments");
		return E_ST_MQTT_FAILURE;
	}

	Topics = iot_os_malloc(count * sizeof(MQTTString));
	if (Topics == NULL) {
		IOT_ERROR("Topics malloc fail");
		return E_ST_MQTT_FAILURE;
	}
	memset(Topics, '\0', count * sizeof(MQTTString));
	for (int i = 0; i < count; i++) {
		Topics[i].cstring = (char *)topics[i];
	}

	chunk_size = MQTTSerialize_subscribe_size(count, Topics);
	sub_packet = _iot_mqtt_chunk_create(chunk_size);
	if (sub_packet == NULL) {
		IOT_ERROR("buf malloc fail");
		rc = E_ST_MQTT_BUFFER_OVERFLOW;
		goto exit;
	}
	if (c == NULL || c->magic != MQTT_CLIENT_STRUCT_MAGIC_NUMBER) {
		rc = E_ST_MQTT_FAILURE;
		_iot_mqtt_chunk_destroy(sub_packet);
		goto exit;
	}
	c->next_packetid = (c->next_packetid >= MAX_PACKET_ID) ? 1 : c->next_packetid + 1;
	sub_packet->packet_id = c->next_packetid;
	MQTTSerialize_subscribe(sub_packet->chunk_data, chunk_size, 0, sub_packet->packet_id, count, Topics, qos);
	sub_packet->packet_type = SUBSCRIBE;
	sub_packet->have_owner = 1;
	sub_packet->chunk_state = PACKET_CHUNK_WRITE_PENDING;
	_iot_mqtt_queue_push(&c->write_pending_queue, sub_packet);

	rc = _iot_mqtt_wait_for(c, sub_packet);

exit:
	if (Topics != NULL) {
		iot_os_free(Topics);
	}
	IOT_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_MQTT_SUBSCRIBE, rc, 0);
	return rc;
}

int st_mqtt_unsubscribe(st_mqtt_client client, int count, char* topics[])
{
	MQTTClient *c = client;
	int rc = 0;
	MQTTString *Topics = NULL;
	int chunk_size;
	iot_mqtt_packet_chunk_t *unsub_packet = NULL;

	if (count <= 0 || topics == NULL) {
		IOT_ERROR("Invalid arguments");
		return E_ST_MQTT_FAILURE;
	}

	Topics = iot_os_malloc(count * sizeof(MQTTString));
	if (Topics == NULL) {
		IOT_ERROR("Topics malloc fail");
		return E_ST_MQTT_FAILURE;
	}
	memset(Topics, '\0', count * sizeof(MQTTString));
	for (int i = 0; i < count; i++) {
		Topics[i].cstring = (char *)topics[i];
	}

	chunk_size = MQTTSerialize_unsubscribe_size(count, Topics);
	unsub_packet = _iot_mqtt_chunk_create(chunk_size);
	if (unsub_packet == NULL) {
		IOT_ERROR("buf malloc fail");
		rc = E_ST_MQTT_BUFFER_OVERFLOW;
		goto exit;
	}
	if (c == NULL || c->magic != MQTT_CLIENT_STRUCT_MAGIC_NUMBER) {
		rc = E_ST_MQTT_FAILURE;
		_iot_mqtt_chunk_destroy(unsub_packet);
		goto exit;
	}
	c->next_packetid = (c->next_packetid >= MAX_PACKET_ID) ? 1 : c->next_packetid + 1;
	unsub_packet->packet_id = c->next_packetid;
	MQTTSerialize_unsubscribe(unsub_packet->chunk_data, chunk_size, 0, unsub_packet->packet_id, count, Topics);
	unsub_packet->packet_type = UNSUBSCRIBE;
	unsub_packet->have_owner = 1;
	unsub_packet->chunk_state = PACKET_CHUNK_WRITE_PENDING;
	_iot_mqtt_queue_push(&c->write_pending_queue, unsub_packet);

	rc = _iot_mqtt_wait_for(c, unsub_packet);

exit:
	if (Topics != NULL) {
		iot_os_free(Topics);
	}
	IOT_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_MQTT_UNSUBSCRIBE, rc, 0);
	return rc;
}

static iot_mqtt_packet_chunk_t * _iot_mqtt_push_publish_packet(MQTTClient *c, st_mqtt_msg *msg, unsigned char is_sync)
{
	MQTTString topic = MQTTString_initializer;
	topic.cstring = (char *)msg->topic;
	int chunk_size;
	iot_mqtt_packet_chunk_t *pub_packet = NULL;

	if (c == NULL || c->magic != MQTT_CLIENT_STRUCT_MAGIC_NUMBER) {
		return NULL;
	}
	if((iot_os_mutex_lock(&c->client_manage_lock)) != IOT_OS_TRUE) {
		return NULL;
	}

	chunk_size = MQTTSerialize_publish_size(msg->qos, topic, msg->payloadlen);
	pub_packet = _iot_mqtt_chunk_create(chunk_size);
	if (pub_packet == NULL) {
		IOT_ERROR("buf malloc fail");
		goto exit;
	}

	if (msg->qos == st_mqtt_qos1 || msg->qos == st_mqtt_qos2) {
		c->next_packetid = (c->next_packetid >= MAX_PACKET_ID) ? 1 : c->next_packetid + 1;
		pub_packet->packet_id = c->next_packetid;
	}

	MQTTSerialize_publish(pub_packet->chunk_data, chunk_size, 0, msg->qos, msg->retained, pub_packet->packet_id,
									topic, (unsigned char *)msg->payload, msg->payloadlen);
	pub_packet->packet_type = PUBLISH;
	pub_packet->have_owner = is_sync;
	pub_packet->qos = msg->qos;
	pub_packet->chunk_state = PACKET_CHUNK_WRITE_PENDING;
	_iot_mqtt_queue_push(&c->write_pending_queue, pub_packet);

exit:
	iot_os_mutex_unlock(&c->client_manage_lock);

	return pub_packet;
}

void st_mqtt_change_ping_period(st_mqtt_client client, unsigned int new_period)
{
	MQTTClient *c = client;

	if (c != NULL && c->magic == MQTT_CLIENT_STRUCT_MAGIC_NUMBER) {
		if((iot_os_mutex_lock(&c->client_manage_lock)) == IOT_OS_TRUE) {
			c->keepAliveInterval = new_period;
			if (c->last_sent) {
				iot_os_timer_delete(c->last_sent);
			}
			c->last_sent = iot_os_timer_create(_iot_mqtt_ping_timeout, c->keepAliveInterval * 1000, c);
			if (!c->last_sent) {
				IOT_ERROR("Failed to create ping timer");
			} else {
				iot_os_timer_start(c->last_sent);
			}
			if (c->last_received) {
				iot_os_timer_delete(c->last_received);
			}
			c->last_received = iot_os_timer_create(_iot_mqtt_ping_timeout, c->keepAliveInterval * 1000, c);
			if (!c->last_received) {
				IOT_ERROR("Failed to create ping timer");
			} else {
				iot_os_timer_start(c->last_received);
			}
			iot_os_mutex_unlock(&c->client_manage_lock);
		}
	}
}

int st_mqtt_publish(st_mqtt_client client, st_mqtt_msg *msg)
{
	MQTTClient *c = client;
	int rc = 0;
	iot_mqtt_packet_chunk_t *pub_packet = NULL;

	pub_packet = _iot_mqtt_push_publish_packet(c, msg, 1);
	if (!pub_packet) {
		rc = E_ST_MQTT_FAILURE;
		goto exit;
	}
	rc = _iot_mqtt_wait_for(c, pub_packet);

exit:
	IOT_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_MQTT_PUBLISH, rc, 0);
	return rc;
}

int st_mqtt_publish_async(st_mqtt_client client, st_mqtt_msg *msg)
{
	MQTTClient *c = client;
	int rc = 0;

	if ((_iot_mqtt_push_publish_packet(c, msg, 0) == NULL)) {
		rc = E_ST_MQTT_FAILURE;
	}

	if (c->work_queue) {
		_iot_mqtt_signal_pending_work(c);
	}

	return rc;
}

int st_mqtt_disconnect(st_mqtt_client client)
{
	MQTTClient *c = client;
	int rc = 0;
	iot_mqtt_packet_chunk_t *disconnect_packet = NULL;

	disconnect_packet = _iot_mqtt_chunk_create(MQTT_DISCONNECT_PACKET_SIZE);
	if (disconnect_packet == NULL) {
		IOT_ERROR("buf malloc fail");
		rc = E_ST_MQTT_BUFFER_OVERFLOW;
		goto exit;
	}
	MQTTSerialize_disconnect(disconnect_packet->chunk_data, MQTT_DISCONNECT_PACKET_SIZE);
	disconnect_packet->packet_type = DISCONNECT;
	disconnect_packet->have_owner = 1;
	disconnect_packet->chunk_state = PACKET_CHUNK_WRITE_PENDING;
	if (c == NULL || c->magic != MQTT_CLIENT_STRUCT_MAGIC_NUMBER) {
		rc = E_ST_MQTT_FAILURE;
		_iot_mqtt_chunk_destroy(disconnect_packet);
		goto exit;
	}
	_iot_mqtt_queue_push(&c->write_pending_queue, disconnect_packet);

	rc = _iot_mqtt_wait_for(c, disconnect_packet);

exit:
	IOT_INFO("mqtt disconnect %d", rc);
	if (c != NULL && c->magic == MQTT_CLIENT_STRUCT_MAGIC_NUMBER) {
		_iot_mqtt_close_net(c);
	}

	IOT_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_MQTT_DISCONNECT, rc, 0);
	return rc;
}
