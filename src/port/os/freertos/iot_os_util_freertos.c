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
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "event_groups.h"
#include "semphr.h"

#include "iot_error.h"
#include "iot_os_util.h"

const unsigned int iot_os_max_delay = portMAX_DELAY;
const unsigned int iot_os_true = pdTRUE;
const unsigned int iot_os_false = pdFALSE;

/* Thread */
int iot_os_thread_create(void * thread_function, const char* name, int stack_size,
		void* data, int priority, iot_os_thread* thread_handle)
{
	return xTaskCreate(thread_function, name, stack_size, data, priority, thread_handle);
}

void iot_os_thread_delete(iot_os_thread thread_handle)
{
	vTaskDelete(thread_handle);
}

void iot_os_thread_yield()
{
	taskYIELD();
}

/* Queue */
iot_os_queue* iot_os_queue_create(int queue_length)
{
	return xQueueCreate(queue_length, sizeof(void *));
}

int iot_os_queue_reset(iot_os_queue* queue_handle)
{
	return xQueueReset(queue_handle);
}

void iot_os_queue_delete(iot_os_queue* queue_handle)
{
	vQueueDelete(queue_handle);
}

int iot_os_queue_send(iot_os_queue* queue_handle, void * data, unsigned int wait_time_ms)
{
	return xQueueSend(queue_handle, data, pdMS_TO_TICKS(wait_time_ms));
}

int iot_os_queue_receive(iot_os_queue* queue_handle, void ** data, unsigned int wait_time_ms)
{
	return xQueueReceive(queue_handle, data, pdMS_TO_TICKS(wait_time_ms));
}

/* Event Group */
iot_os_eventgroup* iot_os_eventgroup_create(void)
{
	return xEventGroupCreate();
}

void iot_os_eventgroup_delete(iot_os_eventgroup* eventgroup_handle)
{
	vEventGroupDelete(eventgroup_handle);
}

unsigned int iot_os_eventgroup_wait_bits(iot_os_eventgroup* eventgroup_handle,
		const unsigned int bits_to_wait_for, const int clear_on_exit,
		const int wait_for_all_bits, const unsigned int wait_time_ms)
{
	return xEventGroupWaitBits(eventgroup_handle, bits_to_wait_for, clear_on_exit, wait_for_all_bits, wait_time_ms);
}

unsigned int iot_os_eventgroup_set_bits(iot_os_eventgroup* eventgroup_handle,
		const unsigned int bits_to_set)
{
	return xEventGroupSetBits(eventgroup_handle, bits_to_set);
}

unsigned int iot_os_eventgroup_clear_bits(iot_os_eventgroup* eventgroup_handle,
		const unsigned int bits_to_clear)
{
	return xEventGroupClearBits(eventgroup_handle, bits_to_clear);
}

/* Mutex */
int iot_os_mutex_init(iot_os_mutex* mutex)
{
	if (!mutex) {
		return IOT_ERROR_INVALID_ARGS;
	}

	mutex->sem = xSemaphoreCreateMutex();

	if (!mutex->sem) {
		return IOT_ERROR_MEM_ALLOC;
	}
	return IOT_ERROR_NONE;
}

int iot_os_mutex_lock(iot_os_mutex* mutex)
{
	int ret;

	if (!mutex) {
		return IOT_ERROR_INVALID_ARGS;
	}

	ret = xSemaphoreTake(mutex->sem, portMAX_DELAY);

	if (ret == pdTRUE) {
		ret = IOT_ERROR_NONE;
	} else {
		ret = IOT_ERROR_BAD_REQ;
	}

	return ret;
}

int iot_os_mutex_unlock(iot_os_mutex* mutex)
{
	int ret;

	if (!mutex) {
		return IOT_ERROR_INVALID_ARGS;
	}

	ret = xSemaphoreGive(mutex->sem);

	if (ret == pdTRUE) {
		ret = IOT_ERROR_NONE;
	} else {
		ret = IOT_ERROR_BAD_REQ;
	}

	return ret;
}

void iot_os_mutex_destroy(iot_os_mutex* mutex)
{
	if (!mutex || !mutex->sem)
		return;

	vSemaphoreDelete(mutex->sem);
}

/* Delay */
void iot_os_delay(unsigned int delay_ms)
{
	vTaskDelay(pdMS_TO_TICKS(delay_ms));
}

typedef struct Freertos_Timer {
	TickType_t xTicksToWait;
	TimeOut_t xTimeOut;
} Freertos_Timer;

void iot_os_timer_count_ms(iot_os_timer timer, unsigned int timeout_ms)
{
	((Freertos_Timer *)timer)->xTicksToWait = timeout_ms / portTICK_PERIOD_MS; /* convert milliseconds to ticks */
	vTaskSetTimeOutState(&((Freertos_Timer *)timer)->xTimeOut); /* Record the time at which this function was entered. */
}

unsigned int iot_os_timer_left_ms(iot_os_timer timer)
{
	Freertos_Timer *freertos_timer = timer;

	xTaskCheckForTimeOut(&freertos_timer->xTimeOut, &freertos_timer->xTicksToWait); /* updates xTicksToWait to the number left */
	return (freertos_timer->xTicksToWait <= 0) ? 0 : (freertos_timer->xTicksToWait * portTICK_PERIOD_MS);
}

char iot_os_timer_isexpired(iot_os_timer timer)
{
	return xTaskCheckForTimeOut(&((Freertos_Timer *)timer)->xTimeOut, &((Freertos_Timer *)timer)->xTicksToWait) == pdTRUE;
}

int iot_os_timer_init(iot_os_timer *timer)
{
	*timer = malloc(sizeof(Freertos_Timer));
	if (*timer == NULL)
		return IOT_ERROR_MEM_ALLOC;
	memset(*timer, '\0', sizeof(Freertos_Timer));

	return IOT_ERROR_NONE;
}

void iot_os_timer_destroy(iot_os_timer *timer)
{
	if (timer == NULL || *timer == NULL)
		return;

	free(*timer);
	*timer = NULL;
}
