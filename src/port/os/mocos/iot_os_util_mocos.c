/* ***************************************************************************
 *
 * Copyright 2020 Samsung Electronics All Rights Reserved.
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
#include "iot_error.h"
#include "iot_os_util.h"
#include "iot_debug.h"
#include "mico_rtos.h"

#define pdFALSE 0
#define pdTRUE 1
#define portMAX_DELAY (0xffffffff)

const unsigned int iot_os_max_delay = portMAX_DELAY;
const unsigned int iot_os_true = pdTRUE;
const unsigned int iot_os_false = pdFALSE;

/* Queue */
#define MAX_QUEUE_NUM 20
typedef struct {
	void* 		handle;
	uint32_t 	item_size;
	int		queue_length;
}queue_info_t;
static queue_info_t iot_queues[MAX_QUEUE_NUM];

/* Event Group */
#define EG_MAX_CACHE 10
typedef struct _que_for_bmp{
	uint16_t used;
	uint16_t bits;
	mico_queue_t q;
	int fd;
	struct _que_for_bmp* next;
}que_for_bmp;

typedef struct _iot_moc_eventgroup {
	que_for_bmp resource;
	uint16_t	cache_bits[EG_MAX_CACHE]; /*save when no one is waiting*/
}iot_moc_eventgroup;

mico_mutex_t eg_mutex;

/* Timer */
typedef struct _moc_timer {
	mico_time_t ms_to_wait;
	mico_time_t time_out;
} moc_timer;

const char* iot_os_get_os_name()
{
	return "mocOS";
}

const char* iot_os_get_os_version_string()
{
#if defined(mocOS_VERSION)
	return mocOS_VERSION;
#else
	return "";
#endif
}

/* Thread */
int iot_os_thread_create(void * thread_function, const char* name, int stack_size,
		void* data, int priority, iot_os_thread* thread_handle)
{
	OSStatus ret = kNoErr;

	ret = mico_rtos_create_thread(thread_handle, priority, name, thread_function, stack_size, (mico_thread_arg_t)data);
	
	return (ret == kNoErr) ? IOT_OS_TRUE : IOT_OS_FALSE;
}

void iot_os_thread_delete(iot_os_thread thread_handle)
{
	mico_rtos_delete_thread(thread_handle);
}

void iot_os_thread_yield()
{
	mico_rtos_thread_yield();
}

int iot_os_thread_get_current_handle(iot_os_thread* thread_handle)
{
    return IOT_OS_FALSE;
}

/* Queue */
iot_os_queue* iot_os_queue_create(int queue_length, int item_size)
{
	int i;
	void* q = NULL;

	mico_rtos_init_queue(&q, "iot_queue", item_size, queue_length);

	for (i = 0; i < MAX_QUEUE_NUM; i++) {
		if (iot_queues[i].handle == NULL) {
			iot_queues[i].handle = q;
			iot_queues[i].item_size = item_size;
			iot_queues[i].queue_length = queue_length;
			break;
		}
	}

	return q;
}

int iot_os_queue_reset(iot_os_queue* queue_handle)
{
	int i = 0;
	void *buffer;

	for (i = 0; i < MAX_QUEUE_NUM; i++) {
		if (iot_queues[i].handle == queue_handle) {
			break;
		}
	}
	
	if (i == MAX_QUEUE_NUM) {
		IOT_ERROR("No queue is found to reset!");
		return IOT_OS_FALSE;
	}

	buffer = malloc(iot_queues[i].item_size);
	if (!buffer) {
		return IOT_OS_FALSE;
	}
	while (mico_rtos_pop_from_queue(queue_handle, buffer, 0) == kNoErr) {}

	free(buffer);

	return IOT_OS_TRUE;
}

void iot_os_queue_delete(iot_os_queue* queue_handle)
{
	int i;

	for (i = 0; i < MAX_QUEUE_NUM; i++) {
		if (iot_queues[i].handle == queue_handle) {
			iot_queues[i].handle = NULL;
			break;
		}
	}

	mico_rtos_deinit_queue(&queue_handle);
}

int iot_os_queue_send(iot_os_queue* queue_handle, void * data, unsigned int wait_time_ms)
{
	if (mico_rtos_push_to_queue(&queue_handle, data, wait_time_ms) != kNoErr) {
		IOT_DEBUG("mico push to queue failed.");
		return IOT_OS_FALSE;
	}

	return IOT_OS_TRUE;
}

int iot_os_queue_receive(iot_os_queue* queue_handle, void * data, unsigned int wait_time_ms)
{
	if (mico_rtos_pop_from_queue(&queue_handle, data, wait_time_ms) != kNoErr) {
		IOT_DEBUG("mico pop from queue failed.");
		return IOT_OS_FALSE;
	}
	
	return IOT_OS_TRUE;
}

/* Event Group */
static void _lock_eventgroup()
{
	if (eg_mutex == NULL) {
		mico_rtos_init_mutex(&eg_mutex);
	}
	mico_rtos_lock_mutex(&eg_mutex);
}

static void _unlock_eventgroup()
{
	mico_rtos_unlock_mutex(&eg_mutex);
}

static int _eventgroup_check_cache(iot_moc_eventgroup *eg, unsigned char bits_to_wait_for)
{
	int i = 0;
	int bits = 0;

	_lock_eventgroup();

	for (i = 0; i < EG_MAX_CACHE; i++) {
		if (eg->cache_bits[i] & bits_to_wait_for) {
			bits = eg->cache_bits[i];
			eg->cache_bits[i] = 0;
			break;
		}
	}
	_unlock_eventgroup();
	return bits;
}

static void _eventgroup_set_cache(iot_moc_eventgroup *eg, unsigned char bits_to_set)
{
	int i = 0;

	_lock_eventgroup();

	for (i = 0; i < EG_MAX_CACHE; i++) {
		if (eg->cache_bits[i] == 0) {
			eg->cache_bits[i] = (uint16_t)bits_to_set;
			break;
		}
	}
	_unlock_eventgroup();
}

static que_for_bmp* _eventgroup_get_available_res(iot_moc_eventgroup *eg, unsigned char bits_to_wait_for)
{
	que_for_bmp *list;
	que_for_bmp *new_que;

	_lock_eventgroup();
	list = &eg->resource;
	while (list->used && list->next) {
		list = list->next;
	}
	
	if (!list->used) {
		list->bits = (uint16_t)bits_to_wait_for;
		list->used = 1;
		_unlock_eventgroup();
		return list;
	}

	new_que = (que_for_bmp*)malloc(sizeof(que_for_bmp));
	IOT_ERROR_CHECK(new_que == NULL, NULL, "malloc queue failed.");
	memset(new_que, 0, sizeof(que_for_bmp));
	new_que->used = 1;
	new_que->bits = (uint16_t)bits_to_wait_for;
	mico_rtos_init_queue(&new_que->q, "eg_queue", sizeof(unsigned char), 2);
	new_que->fd = mico_create_event_fd(new_que->q);

	list->next = new_que;

	_unlock_eventgroup();
	return new_que;
}

static que_for_bmp* _eventgroup_get_res_to_send(iot_moc_eventgroup *eg, unsigned char bits_to_set)
{
	que_for_bmp *list = NULL;

	_lock_eventgroup();

	list = &eg->resource;
	while (list) {
		if (list->used && (list->bits & bits_to_set))
			break;

		list = list->next;
	}

	_unlock_eventgroup();
	return list;
}

static void _eventgroup_release_res(que_for_bmp* res)
{
	_lock_eventgroup();

	res->used = 0;

	_unlock_eventgroup();
}

iot_os_eventgroup* iot_os_eventgroup_create(void)
{
	iot_moc_eventgroup *eg;

	eg = malloc(sizeof(iot_moc_eventgroup));
	IOT_ERROR_CHECK(eg == NULL, NULL, "malloc eg failed.");
	memset(eg, 0, sizeof(iot_moc_eventgroup));

	mico_rtos_init_queue(&eg->resource.q, "eg_queue", sizeof(unsigned char), 2);
	eg->resource.fd = mico_create_event_fd(eg->resource.q);

	memset(eg->cache_bits, 0, sizeof(eg->cache_bits));
	return eg;
}

void iot_os_eventgroup_delete(iot_os_eventgroup* eventgroup_handle)
{
	iot_moc_eventgroup *eg;
	que_for_bmp *list = NULL;
	que_for_bmp *tmp = NULL;

	if (eventgroup_handle == NULL) {
		return;
	}

	eg = (iot_moc_eventgroup*)eventgroup_handle;
	list = &eg->resource; //first node don't need to free
	mico_delete_event_fd(list->fd);
	mico_rtos_deinit_queue(&list->q);
	list = list->next;
	
	while (list) {
		tmp = list;
		list = list->next;

		mico_delete_event_fd(tmp->fd);
		mico_rtos_deinit_queue(&tmp->q);
		free(tmp);
	}

	free(eventgroup_handle);
}

unsigned char iot_os_eventgroup_wait_bits(iot_os_eventgroup* eventgroup_handle,
		const unsigned char bits_to_wait_for, const int clear_on_exit, const unsigned int wait_time_ms)
{
	que_for_bmp* eg_res;
	iot_moc_eventgroup *eg;
	fd_set readfds;
	int qdata = 0;
	struct timeval tv;
	unsigned int bits = 0x00000000;

	IOT_ERROR_CHECK(eventgroup_handle == NULL, 0, "wait bits invalid handle.");

	eg = (iot_moc_eventgroup*)eventgroup_handle;
	FD_ZERO(&readfds);

	/*check any cache bits set*/
	if ((qdata = _eventgroup_check_cache(eg, bits_to_wait_for))) {
		return qdata;
	}

	eg_res = _eventgroup_get_available_res(eg, bits_to_wait_for);

	FD_SET(eg_res->fd, &readfds);

	tv.tv_sec = wait_time_ms / 1000;
	tv.tv_usec = (wait_time_ms % 1000) * 1000;

	int ret = select(eg_res->fd + 1, &readfds, NULL, NULL, &tv);
	if (ret == -1) { // Select Error
		_eventgroup_release_res(eg_res);
		return 0;
	} else if (ret == 0) { // Select Timeout
		_eventgroup_release_res(eg_res);
		return 0;
	} else {
		if (mico_rtos_pop_from_queue(&eg_res->q, &qdata, 0) != kNoErr || !(qdata & bits_to_wait_for)) {
			IOT_ERROR("can't read data from queue, or the data 0x%x is not waiting bits", qdata);
		}
		_eventgroup_release_res(eg_res);
	}

	return qdata;
}

int iot_os_eventgroup_set_bits(iot_os_eventgroup* eventgroup_handle,
		const unsigned char bits_to_set)
{
	iot_moc_eventgroup *eg;
	que_for_bmp* eg_res = NULL;

	IOT_ERROR_CHECK(eventgroup_handle == NULL, IOT_OS_FALSE, "set bits invalid handle.");

	eg = (iot_moc_eventgroup*)eventgroup_handle;
	eg_res = _eventgroup_get_res_to_send(eg, bits_to_set);
	if (eg_res == NULL) {
		IOT_DEBUG("No one is waiting, set cache.");
		_eventgroup_set_cache(eg, bits_to_set);
	} else {
		if (mico_rtos_push_to_queue(&eg_res->q, (void*)(&bits_to_set), 0) != kNoErr) {
			IOT_ERROR("mico_rtos_push_to_queue failed.");
		}
	}

	return IOT_OS_TRUE;
}

int iot_os_eventgroup_clear_bits(iot_os_eventgroup* eventgroup_handle,
		const unsigned char bits_to_clear)
{
	iot_moc_eventgroup *eg;
	que_for_bmp* eg_res = NULL;
	int data;

	IOT_ERROR_CHECK(eventgroup_handle == NULL, IOT_OS_FALSE, "clear bits invalid handle.");

	eg = (iot_moc_eventgroup*)eventgroup_handle;
	memset(eg->cache_bits, 0, sizeof(eg->cache_bits));

	eg_res = _eventgroup_get_res_to_send(eg, bits_to_clear);
	if (eg_res == NULL) {
		IOT_DEBUG("can't find queue to send bits.");
	} else {
		if (mico_rtos_pop_from_queue(&eg_res->q, (void*)(&data), 0) != kNoErr) {
			IOT_ERROR("mico_rtos_pop_from_queue failed.");
		}
	}

	return IOT_OS_TRUE;
}

/* Mutex */
int iot_os_mutex_init(iot_os_mutex* mutex)
{
	if (!mutex) {
		return IOT_OS_FALSE;
	}

	mico_rtos_init_mutex(&mutex->sem);

	if (!mutex->sem) {
		return IOT_OS_FALSE;
	}
	return IOT_OS_TRUE;
}

int iot_os_mutex_lock(iot_os_mutex* mutex)
{
	int ret;

	if (!mutex) {
		return IOT_OS_FALSE;
	}

	ret = mico_rtos_lock_mutex(&mutex->sem);

	return (ret == kNoErr) ? IOT_OS_TRUE : IOT_OS_FALSE;
}

int iot_os_mutex_unlock(iot_os_mutex* mutex)
{
	int ret;

	if (!mutex) {
		return IOT_OS_FALSE;
	}

	ret = mico_rtos_unlock_mutex(&mutex->sem);

	return (ret == kNoErr) ? IOT_OS_TRUE : IOT_OS_FALSE;
}

void iot_os_mutex_destroy(iot_os_mutex* mutex)
{
	if (!mutex || !mutex->sem)
		return;

	mico_rtos_deinit_mutex(&mutex->sem);
}

/* Delay */
void iot_os_delay(unsigned int delay_ms)
{
	mico_rtos_delay_milliseconds(delay_ms);
}

/* Timer */
static int _check_for_timeout(mico_time_t *const ptime_out, mico_time_t *const pms_to_wait)
{
	int ret = pdTRUE;

	/* Minor optimisation.  The tick count cannot change in this block. */
	const mico_time_t const_tick_count = mico_rtos_get_time();
	const mico_time_t elapsed_time = const_tick_count - *ptime_out;

	if (*pms_to_wait == portMAX_DELAY) {
		/*
		 * If INCLUDE_vTaskSuspend is set to 1 and the block time
		 * specified is the maximum block time then the task should block
		 * indefinitely, and therefore never time out
		 */
		ret = pdFALSE;
	} else if (elapsed_time < *pms_to_wait ) {
		/* Not a genuine timeout. Adjust parameters for time remaining. */
		*pms_to_wait -= elapsed_time;
		*ptime_out = mico_rtos_get_time();
		ret = pdFALSE;
	} else {
		*pms_to_wait = 0;
	}

	return ret;
}

void iot_os_timer_count_ms(iot_os_timer timer, unsigned int timeout_ms)
{
	((moc_timer *)timer)->ms_to_wait = timeout_ms;
	((moc_timer *)timer)->time_out = mico_rtos_get_time(); /* Record the time at which this function was entered. */
}

unsigned int iot_os_timer_left_ms(iot_os_timer timer)
{
	moc_timer *os_timer = (moc_timer *)timer;

	if (os_timer->ms_to_wait == portMAX_DELAY) {
		return portMAX_DELAY;
	}

	_check_for_timeout(&os_timer->time_out, &os_timer->ms_to_wait); /* updates ms_to_wait to the number left */
	return (os_timer->ms_to_wait <= 0) ? 0 : os_timer->ms_to_wait;
}

char iot_os_timer_isexpired(iot_os_timer timer)
{
	moc_timer *os_timer = (moc_timer *)timer;

	return _check_for_timeout(&os_timer->time_out, &os_timer->ms_to_wait) == pdTRUE;
}

int iot_os_timer_init(iot_os_timer *timer)
{
	*timer = malloc(sizeof(moc_timer));
	if (*timer == NULL) {
		return IOT_ERROR_MEM_ALLOC;
	}
	memset(*timer, '\0', sizeof(moc_timer));

	return IOT_ERROR_NONE;
}

void iot_os_timer_destroy(iot_os_timer *timer)
{
	if (timer == NULL || *timer == NULL)
		return;

	free(*timer);
	*timer = NULL;
}
