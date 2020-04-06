/* ***************************************************************************
 *
 * Copyright 2019-2020 Samsung Electronics All Rights Reserved.
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

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h>
#include <sched.h>
#include <mqueue.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include "iot_debug.h"
#include "iot_error.h"
#include "iot_os_util.h"
#include "iot_bsp_random.h"

const unsigned int iot_os_max_delay = 0xFFFFFFFF;
const unsigned int iot_os_true = true;
const unsigned int iot_os_false = false;

/* Thread */
int iot_os_thread_create(void * thread_function, const char* name, int stack_size,
		void* data, int priority, iot_os_thread* thread_handle)
{
	pthread_t* thread = malloc(sizeof(pthread_t));
	pthread_attr_t attr;

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	pthread_create(thread, &attr, thread_function, data);

	pthread_attr_destroy(&attr);

	if (thread_handle != NULL) {
		thread_handle = (iot_os_thread*)&thread;
	}

	return iot_os_true;
}

void iot_os_thread_delete(iot_os_thread thread_handle)
{
	if (thread_handle != NULL) {
		pthread_t* thread = (pthread_t*)thread_handle;
		pthread_cancel(*thread);
		free(thread);
	} else {
		pthread_cancel(pthread_self());
	}
}

void iot_os_thread_yield()
{
	sched_yield();
}

/* Queue */
typedef struct {
	char name[20];
	int length;
	int msg_size;
	mqd_t mqd;
} iot_os_queue_posix_t;

iot_os_queue* iot_os_queue_create(int queue_length)
{
	iot_os_queue_posix_t* queue = malloc(sizeof(iot_os_queue_posix_t));
	struct mq_attr attr;

	attr.mq_flags = 0;
	attr.mq_maxmsg = (queue_length <= 10) ? queue_length : 10;
	attr.mq_msgsize = sizeof(void *);
	attr.mq_curmsgs = 0;

	snprintf(queue->name, sizeof(queue->name), "/q%u", iot_bsp_random());
	queue->length = queue_length;
	queue->msg_size = sizeof(void *);

	queue->mqd = mq_open(queue->name, O_CREAT | O_RDWR, 0644, &attr);
	if (queue->mqd == -1) {
		free(queue);
		return NULL;
	}

	return (void*)queue;
}

int iot_os_queue_reset(iot_os_queue* queue_handle)
{
	iot_os_queue_posix_t* queue = (iot_os_queue_posix_t*)queue_handle;

	mq_close(queue->mqd);
	mq_unlink(queue->name);

	struct mq_attr attr;

	attr.mq_flags = 0;
	attr.mq_maxmsg = (queue->length <= 10) ? queue->length : 10;
	attr.mq_msgsize = queue->msg_size;
	attr.mq_curmsgs = 0;

	queue->mqd = mq_open(queue->name, O_CREAT | O_RDWR, 0644, &attr);
	if (queue->mqd == -1) {
		return iot_os_false;
	}

	return iot_os_true;
}

void iot_os_queue_delete(iot_os_queue* queue_handle)
{
	iot_os_queue_posix_t* queue = (iot_os_queue_posix_t*)queue_handle;

	mq_close(queue->mqd);
	mq_unlink(queue->name);
	free(queue);
}

int iot_os_queue_send(iot_os_queue* queue_handle, void * data, unsigned int wait_time_ms)
{
	iot_os_queue_posix_t* queue = (iot_os_queue_posix_t*)queue_handle;
	struct timespec ts = {0,};

	ts.tv_sec = wait_time_ms / 1000;
	ts.tv_nsec = (wait_time_ms % 1000) * 1000000;

	int ret = mq_timedsend(queue->mqd, data, queue->msg_size, 0, &ts);
	if (ret == -1) {
		return iot_os_false;
	}

	return iot_os_true;
}

int iot_os_queue_receive(iot_os_queue* queue_handle, void ** data, unsigned int wait_time_ms)
{
	iot_os_queue_posix_t* queue = (iot_os_queue_posix_t*)queue_handle;
	struct timespec ts = {0,};

	ts.tv_sec = wait_time_ms / 1000;
	ts.tv_nsec = (wait_time_ms % 1000) * 1000000;

	int ret = mq_timedreceive(queue->mqd, data, queue->msg_size, NULL, &ts);
	if (ret == -1) {
		return iot_os_false;
	}

	return iot_os_true;
}

/* Event Group */

#define EVENT_MAX 8

typedef struct {
	unsigned int id;
	int fd[2];
} event_t;

typedef struct {
	event_t group[EVENT_MAX];
} eventgroup_t;

iot_os_eventgroup* iot_os_eventgroup_create(void)
{
	eventgroup_t *eventgroup = malloc(sizeof(eventgroup_t));

	for (int i = 0; i < EVENT_MAX; i++) {
		eventgroup->group[i].id = (1 << i);
		int ret = pipe(eventgroup->group[i].fd);
		if (ret == -1) {
			free(eventgroup);
			return NULL;
		}
	}

	return eventgroup;
}

void iot_os_eventgroup_delete(iot_os_eventgroup* eventgroup_handle)
{
	eventgroup_t* eventgroup = eventgroup_handle;

	free(eventgroup);
}

unsigned int iot_os_eventgroup_wait_bits(iot_os_eventgroup* eventgroup_handle,
		const unsigned int bits_to_wait_for, const int clear_on_exit,
		const int wait_for_all_bits, const unsigned int wait_time_ms)
{
	eventgroup_t *eventgroup = eventgroup_handle;
	fd_set readfds;
	int fd_max = 0;

	FD_ZERO(&readfds);

	for (int i = 0; i < EVENT_MAX; i++) {
		if (eventgroup->group[i].id == (eventgroup->group[i].id & bits_to_wait_for)) {
			FD_SET(eventgroup->group[i].fd[0], &readfds);
			if (eventgroup->group[i].fd[0] >= fd_max) {
				fd_max = eventgroup->group[i].fd[0];
			}
		}
	}

	char buf[3] = {0,};
	struct timeval tv;
	memset(&tv, 0x00, sizeof(tv));
	unsigned int bits = 0x00000000;
	ssize_t read_size = 0;

	tv.tv_sec = wait_time_ms / 1000;
	tv.tv_usec = (wait_time_ms % 1000) * 1000;

	int ret = select(fd_max + 1, &readfds, NULL, NULL, &tv);
	if (ret == -1) {
		// Select Error
		return 0;
	} else if (ret == 0) {
		// Select Timeout
		return 0;
	} else {
		// read pipe
		for (int i = 0; i < EVENT_MAX; i++) {
			if (eventgroup->group[i].id == (eventgroup->group[i].id & bits_to_wait_for)) {
				if (FD_ISSET(eventgroup->group[i].fd[0], &readfds)) {
					memset(buf, 0, sizeof(buf));
					read_size = read(eventgroup->group[i].fd[0], buf, sizeof(buf));
					IOT_DEBUG("read_size = %d", read_size);
					bits |= eventgroup->group[i].id;
				}
			}
		}

		return bits;
	}
}

unsigned int iot_os_eventgroup_set_bits(iot_os_eventgroup* eventgroup_handle,
		const unsigned int bits_to_set)
{
	eventgroup_t *eventgroup = eventgroup_handle;
	unsigned int bits = 0x00000000;
	ssize_t write_size = 0;

	for (int i = 0; i < EVENT_MAX; i++) {
		if (eventgroup->group[i].id == (eventgroup->group[i].id & bits_to_set)) {
			write_size = write(eventgroup->group[i].fd[1], "Set", strlen("Set"));
			IOT_DEBUG("write_size = %d", write_size);
			bits |= eventgroup->group[i].id;
		}
	}

	return bits;
}

unsigned int iot_os_eventgroup_clear_bits(iot_os_eventgroup* eventgroup_handle,
		const unsigned int bits_to_clear)
{
	return IOT_ERROR_NONE;
}

/* Mutex */

int iot_os_mutex_init(iot_os_mutex* mutex)
{
	pthread_mutex_t* mutex_p = malloc(sizeof(pthread_mutex_t));

	pthread_mutex_init(mutex_p, NULL);
	mutex->sem = mutex_p;

	return iot_os_true;
}

int iot_os_mutex_lock(iot_os_mutex* mutex)
{
	pthread_mutex_t* mutex_p = mutex->sem;

	pthread_mutex_lock(mutex_p);

	return iot_os_true;
}

int iot_os_mutex_unlock(iot_os_mutex* mutex)
{
	pthread_mutex_t* mutex_p = mutex->sem;

	pthread_mutex_unlock(mutex_p);

	return iot_os_true;
}

void iot_os_mutex_destroy(iot_os_mutex* mutex)
{
}

/* Delay */
void iot_os_delay(unsigned int delay_ms)
{
	struct timespec ts = {0,};

	ts.tv_sec = delay_ms / 1000;
	ts.tv_nsec = (delay_ms % 1000) * 1000000;

	nanosleep(&ts, NULL);
}

void iot_os_timer_count_ms(iot_os_timer timer, unsigned int timeout_ms)
{
	timer_t timer_id = timer;
	struct itimerspec it;

	it.it_interval.tv_sec = 0;
	it.it_interval.tv_nsec = 0;
	it.it_value.tv_sec = timeout_ms / 1000;
	it.it_value.tv_nsec = (timeout_ms % 1000) * 1000000;

	int ret = timer_settime(timer_id, 0, &it, NULL);
	if (ret == -1) {
		return;
	}
}

unsigned int iot_os_timer_left_ms(iot_os_timer timer)
{
	timer_t timer_id = timer;
	struct itimerspec it = {0,};
	unsigned int left = 0;

	int ret = timer_gettime(timer_id, &it);
	if (ret == -1) {
		return 0;
	}

	return (it.it_value.tv_sec * 1000) + (it.it_value.tv_nsec / 1000000);
}

char iot_os_timer_isexpired(iot_os_timer timer)
{
	timer_t timer_id = timer;
	struct itimerspec it = {0,};

	int ret = timer_gettime(timer_id, &it);
	if (ret == -1) {
		return iot_os_true;
	}

	if (it.it_value.tv_sec == 0 && it.it_value.tv_nsec == 0) {
		return iot_os_true;
	} else {
		return iot_os_false;
	}
}

int iot_os_timer_init(iot_os_timer *timer)
{
	timer_t* timer_id = malloc(sizeof(timer_t));
	struct sigevent sig;

	sig.sigev_notify = SIGEV_NONE;
	sig.sigev_value.sival_ptr = timer_id;
	int ret = timer_create(CLOCK_REALTIME, &sig, timer_id);
	if (ret == -1) {
		return IOT_ERROR_BAD_REQ;
	}

	*timer = *timer_id;
	return IOT_ERROR_NONE;
}

void iot_os_timer_destroy(iot_os_timer *timer)
{
	timer_t timer_id = *timer;

	int ret = timer_delete(timer_id);
	if (ret == -1) {
		return;
	}
}

void *iot_os_malloc(size_t size)
{
    return malloc(size);
}

void *iot_os_calloc(size_t nmemb, size_t size)
{
    return calloc(nmemb, size);
}

void iot_os_free(void *ptr)
{
    return free(ptr);
}

char *iot_os_strdup(const char *src)
{
    return strdup(src);
}
