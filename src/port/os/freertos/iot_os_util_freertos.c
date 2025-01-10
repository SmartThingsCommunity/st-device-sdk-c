/* ***************************************************************************
 *
 * Copyright 2019-2021 Samsung Electronics All Rights Reserved.
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
#include <stdbool.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/event_groups.h"
#include "freertos/semphr.h"
#include "freertos/timers.h"

#include "iot_error.h"
#include "iot_os_util.h"

const unsigned int iot_os_max_delay = portMAX_DELAY;
const unsigned int iot_os_true = pdTRUE;
const unsigned int iot_os_false = pdFALSE;

const char* iot_os_get_os_name()
{
       return "FreeRTOS";
}

const char* iot_os_get_os_version_string()
{
       return tskKERNEL_VERSION_NUMBER;
}

/* Thread */
int iot_os_thread_create(void * thread_function, const char* name, int stack_size,
		void* data, int priority, iot_os_thread* thread_handle)
{
	BaseType_t ret;

	ret = xTaskCreate(thread_function, name, stack_size, data, priority,(TaskHandle_t *)thread_handle);

	return (ret == pdTRUE) ? IOT_OS_TRUE : IOT_OS_FALSE;
}

void iot_os_thread_delete(iot_os_thread thread_handle)
{
	vTaskDelete(thread_handle);
}

void iot_os_thread_yield()
{
	taskYIELD();
}

int iot_os_thread_get_current_handle(iot_os_thread* thread_handle)
{
    if (thread_handle == NULL) {
        return IOT_OS_FALSE;
    }

#if ( ( INCLUDE_xTaskGetCurrentTaskHandle == 1 ) || ( configUSE_MUTEXES == 1 ) )
    *thread_handle = (iot_os_thread)xTaskGetCurrentTaskHandle();
    return IOT_OS_TRUE;
#else
    return IOT_OS_FALSE;
#endif
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

unsigned char iot_os_eventgroup_wait_bits(iot_os_eventgroup* eventgroup_handle,
		const unsigned char bits_to_wait_for, const int clear_on_exit, const unsigned int wait_time_ms)
{
	if (wait_time_ms == IOT_OS_WAIT_FOREVER) {
		return xEventGroupWaitBits(eventgroup_handle, (const EventBits_t) bits_to_wait_for, clear_on_exit, false, portMAX_DELAY);
	}

	return xEventGroupWaitBits(eventgroup_handle, (const EventBits_t) bits_to_wait_for, clear_on_exit, false, pdMS_TO_TICKS(wait_time_ms));
}

int iot_os_eventgroup_set_bits(iot_os_eventgroup* eventgroup_handle,
		const unsigned char bits_to_set)
{
	xEventGroupSetBits(eventgroup_handle, (const EventBits_t) bits_to_set);
	return IOT_OS_TRUE;
}

int iot_os_eventgroup_clear_bits(iot_os_eventgroup* eventgroup_handle,
		const unsigned char bits_to_clear)
{
	xEventGroupClearBits(eventgroup_handle, (const EventBits_t) bits_to_clear);
	return IOT_OS_TRUE;
}

/* Mutex */
int iot_os_mutex_init(iot_os_mutex* mutex)
{
	if (!mutex) {
		return IOT_OS_FALSE;
	}

	mutex->sem = xSemaphoreCreateMutex();

	if (!mutex->sem) {
		return IOT_OS_FALSE;
	}
	return IOT_OS_TRUE;
}

int iot_os_mutex_lock(iot_os_mutex* mutex)
{
	int ret;

	if (!mutex || !mutex->sem) {
		return IOT_OS_FALSE;
	}

	ret = xSemaphoreTake(mutex->sem, portMAX_DELAY);

	if (ret == pdTRUE) {
		ret = IOT_OS_TRUE;
	} else {
		ret = IOT_OS_FALSE;
	}

	return ret;
}

int iot_os_mutex_unlock(iot_os_mutex* mutex)
{
	int ret;

	if (!mutex) {
		return IOT_OS_FALSE;
	}

	ret = xSemaphoreGive(mutex->sem);

	if (ret == pdTRUE) {
		ret = IOT_OS_TRUE;
	} else {
		ret = IOT_OS_FALSE;
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
	((Freertos_Timer *)timer)->xTicksToWait = pdMS_TO_TICKS(timeout_ms); /* convert milliseconds to ticks */
	vTaskSetTimeOutState(&((Freertos_Timer *)timer)->xTimeOut); /* Record the time at which this function was entered. */
}

unsigned int iot_os_timer_left_ms(iot_os_timer timer)
{
	Freertos_Timer *freertos_timer = timer;

	if ((xTaskCheckForTimeOut(&freertos_timer->xTimeOut, &freertos_timer->xTicksToWait)) == pdTRUE) {
		return 0;
	}

	return (freertos_timer->xTicksToWait * portTICK_PERIOD_MS);
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

typedef struct _freertos_timer_handle {
	TimerHandle_t timer;
	bool is_started;
	iot_os_timer_cb user_cb;
	void *user_data;
} freertos_timer_handle_t;

static void _port_timer_cb(TimerHandle_t timer)
{
	freertos_timer_handle_t *timer_handle = pvTimerGetTimerID(timer);
	timer_handle->is_started = false;

	if (timer_handle->user_cb) {
		timer_handle->user_cb((iot_os_timer_handle)timer_handle, timer_handle->user_data);
	}
}

iot_os_timer_handle iot_os_timer_create(iot_os_timer_cb cb, unsigned int expiry_time_ms, void *user_data)
{
	freertos_timer_handle_t *new_timer_handle;

	new_timer_handle = (freertos_timer_handle_t *)malloc(sizeof(freertos_timer_handle_t));
	if (new_timer_handle == NULL) {
		return NULL;
	}
	memset(new_timer_handle, 0, sizeof(freertos_timer_handle_t));

	new_timer_handle->timer = xTimerCreate("PortTimer", pdMS_TO_TICKS(expiry_time_ms), pdFALSE, new_timer_handle, _port_timer_cb);
	if (new_timer_handle->timer == NULL) {
		free(new_timer_handle);
		return NULL;
	}
	new_timer_handle->user_cb = cb;
	new_timer_handle->user_data = user_data;
	new_timer_handle->is_started = false;

	return (iot_os_timer_handle)new_timer_handle;
}

void iot_os_timer_delete(iot_os_timer_handle timer_handle)
{
	BaseType_t err;
	freertos_timer_handle_t *port_timer_handle = (freertos_timer_handle_t *)timer_handle;

	err = xTimerDelete(port_timer_handle->timer, portMAX_DELAY);
	if (err != pdPASS) {
		printf("Failed to delete timer\n");
	}
	free(port_timer_handle);
}

int iot_os_timer_start(iot_os_timer_handle timer_handle)
{
	BaseType_t err;
	freertos_timer_handle_t *port_timer_handle = (freertos_timer_handle_t *)timer_handle;

	err = xTimerStart(port_timer_handle->timer, portMAX_DELAY);
	if (err != pdPASS) {
		printf("Failed to start timer\n");
	} else {
		port_timer_handle->is_started = true;
	}
	return (err == pdPASS) ? 0 : -1;
}

int iot_os_timer_stop(iot_os_timer_handle timer_handle)
{
	BaseType_t err;
	freertos_timer_handle_t *port_timer_handle = (freertos_timer_handle_t *)timer_handle;

	err = xTimerStop(port_timer_handle->timer, portMAX_DELAY);
	if (err != pdPASS) {
		printf("Failed to stop timer\n");
	} else {
		port_timer_handle->is_started = false;
	}
	return (err == pdPASS) ? 0 : -1;
}

bool iot_os_timer_is_active(iot_os_timer_handle timer_handle)
{
	freertos_timer_handle_t *port_timer_handle = (freertos_timer_handle_t *)timer_handle;
	return port_timer_handle->is_started;
}
