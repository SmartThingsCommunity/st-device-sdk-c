/* ***************************************************************************
 *
 * Copyright 2019 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#include <string.h>
#include <stdio.h>

#include "iot_error.h"
#include "iot_os_util.h"
#include "iot_debug.h"

#include "cmsis_os2.h"
#include "mbed.h"
#include "MbedStdkQueue.h"
#include "us_ticker_api.h"

/* TODO: set correct values */
const unsigned int iot_os_max_delay = osWaitForever;
const unsigned int iot_os_true = 1;
const unsigned int iot_os_false = 0;

/* Thread */
int iot_os_thread_create(void * thread_function, const char* name, int stack_size,
		void* data, int priority, iot_os_thread* thread_handle)
{
	return IOT_OS_TRUE;
}

void iot_os_thread_delete(iot_os_thread thread_handle)
{

}

void iot_os_thread_yield()
{

}

/* Queue */
iot_os_queue* iot_os_queue_create(int queue_length)
{
	MbedStdkQueue<void> *queue = new MbedStdkQueue<void>(queue_length);
	IOT_DEBUG("Queue Create | Handle %p", queue);
	return queue;
}

int iot_os_queue_reset(iot_os_queue* queue_handle)
{
	MbedStdkQueue<void> *queue = (MbedStdkQueue<void> *)queue_handle;
	IOT_WARN("Queue Reset | Handle %p", queue);
	queue->queueReset();
	return IOT_OS_TRUE;
}

void iot_os_queue_delete(iot_os_queue* queue_handle)
{
	IOT_DEBUG("Queue Delete | Handle %p", queue_handle);
	MbedStdkQueue<void> *queue = (MbedStdkQueue<void> *)queue_handle;
	delete queue;
}

int iot_os_queue_send(iot_os_queue* queue_handle, void * data, unsigned int wait_time_ms)
{
	//TODO: set default priority
	IOT_DEBUG("Queue Handle: %p", queue_handle);
	MbedStdkQueue<void> *queue = (MbedStdkQueue<void> *)queue_handle;
	if (queue->put (data) == osOK) {
		IOT_DEBUG("Data %p put to queue", data);
		return IOT_OS_TRUE;
	}
	IOT_ERROR("Failed to put data %p in queue %p", data, queue_handle);
	return IOT_OS_FALSE;
}

int iot_os_queue_receive(iot_os_queue* queue_handle, void ** data, unsigned int wait_time_ms)
{
	//TODO: set default priority
	IOT_DEBUG("Queue Handle: %p", queue_handle);
	MbedStdkQueue<void> *queue = (MbedStdkQueue<void> *)queue_handle;

	if (queue->empty()) {
		IOT_WARN("Queue Empty | Handle %p", queue);
		return IOT_OS_FALSE;
	}

	IOT_DEBUG("Queue Count: %d", queue->count());
	osEvent evt = queue->get();
	IOT_DEBUG("Queue STATUS: %d", evt.status);
	if (evt.status == osEventMessage) {
		*data = (void *)evt.value.p;
		IOT_DEBUG("Queue Return data %p", *data);
		return IOT_OS_TRUE;
	}
	IOT_ERROR("Failed to get data from queue %p", queue_handle);
	return IOT_OS_FALSE;
}

/* Event Group */
iot_os_eventgroup* iot_os_eventgroup_create(void)
{
	EventFlags *ef = new EventFlags();
	IOT_DEBUG("Create Event Group : %p", (void *)ef);
	return ef;
}

void iot_os_eventgroup_delete(iot_os_eventgroup* eventgroup_handle)
{
	EventFlags *ef = (EventFlags *)eventgroup_handle;
	IOT_DEBUG("Delete Event Group : %p", (void *)ef);
	delete ef;
}

unsigned int iot_os_eventgroup_wait_bits(iot_os_eventgroup* eventgroup_handle,
		const unsigned int bits_to_wait_for, const int clear_on_exit,
		const int wait_for_all_bits, const unsigned int wait_time_ms)
{
	//TODO: check options
	EventFlags *ef = (EventFlags *)eventgroup_handle;
	uint32_t ret;

	if (wait_for_all_bits) {
		IOT_DEBUG("all_of_bits_to_wait_for: 0x%x | Handle: %p",
				bits_to_wait_for, eventgroup_handle);
		ret =  ef->wait_all(bits_to_wait_for, wait_time_ms, clear_on_exit);
		if (ret & osFlagsError) {
			IOT_DEBUG("Event not received for bits 0x%x | Handle: %p [0x%x]",
					bits_to_wait_for, eventgroup_handle, ret);
			return 0;
		}
		IOT_DEBUG("Received ALL | Handle: %p | Bits: 0x%x | Value: 0x%x",
				eventgroup_handle, bits_to_wait_for, ret);
		return ret;
	}

	IOT_DEBUG("any_of_bits_to_wait_for: 0x%x | Handle: %p",
			bits_to_wait_for, eventgroup_handle);
	ret = ef->wait_any(bits_to_wait_for, wait_time_ms, clear_on_exit);
	if (ret & osFlagsError) {
		IOT_DEBUG("Did not receive Event for bits 0x%x | Handle: %p [0x%x]", bits_to_wait_for,
				eventgroup_handle, ret);
		return 0;
	}
	IOT_DEBUG("Received ANY | Handle: %p | Bits: 0x%x | Value: 0x%x",
			eventgroup_handle, bits_to_wait_for, ret);
	return ret;
}

unsigned int iot_os_eventgroup_set_bits(iot_os_eventgroup* eventgroup_handle,
		const unsigned int bits_to_set)
{
	EventFlags *ef = (EventFlags *)eventgroup_handle;
	IOT_DEBUG("bits_to_set: 0x%x | Handle: %p", bits_to_set, eventgroup_handle);
	return ef->set(bits_to_set);
}

unsigned int iot_os_eventgroup_get_bits(iot_os_eventgroup* eventgroup_handle)
{
	EventFlags *ef = (EventFlags *)eventgroup_handle;
	return ef->get();
}

unsigned int iot_os_eventgroup_clear_bits(iot_os_eventgroup* eventgroup_handle,
		const unsigned int bits_to_clear)
{
	EventFlags *ef = (EventFlags *)eventgroup_handle;
	IOT_INFO("bits_to_set: 0x%x | Handle: %p", bits_to_clear, (void *)ef);
	return ef->clear(bits_to_clear);
}

/* Mutex */
int iot_os_mutex_init(iot_os_mutex* mutex)
{
	return IOT_ERROR_NONE;
}

int iot_os_mutex_lock(iot_os_mutex* mutex)
{
	return  IOT_ERROR_NONE;
}

int iot_os_mutex_unlock(iot_os_mutex* mutex)
{
	return  IOT_ERROR_NONE;
}

void iot_os_mutex_destroy(iot_os_mutex* mutex)
{

}

/* Delay */
void iot_os_delay(unsigned int delay_ms)
{

}

void iot_os_timer_count_ms(iot_os_timer timer, unsigned int timeout_ms)
{

}

unsigned int iot_os_timer_left_ms(iot_os_timer timer)
{
	return 0;
}

char iot_os_timer_isexpired(iot_os_timer timer)
{
	return 0;
}

int iot_os_timer_init(iot_os_timer *timer)
{
	return IOT_ERROR_NONE;
}

void iot_os_timer_destroy(iot_os_timer *timer)
{

}
